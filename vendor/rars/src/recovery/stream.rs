//! Bounded-memory recovery: repair volumes without holding them.
//!
//! The whole-buffer recovery paths were written against archives small
//! enough to keep resident. A usenet RAR volume is routinely 8-20 GB, and a
//! REV set is dozens of those, so "read it, clone it, return a repaired
//! copy" needed more than twice the volume's size in RAM - none of it
//! visible to the daemon's memory budget, and a failed allocation in Rust is
//! an abort rather than an error.
//!
//! Everything here addresses volumes by RANGE instead: recovery metadata is
//! parsed from bounded windows, damage is detected by streaming CRC, the
//! Reed-Solomon solve runs in stripes (see
//! [`super::rar5::repair_shards_striped`]), only the damaged ranges are
//! rebuilt, and untouched ranges are copied through a fixed buffer. Peak
//! memory depends on the DAMAGE and the caller's budget, never on the size
//! of the volume.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use super::rar5;
use super::rar5::{
    crc64_update, repair_shards_striped, Error as RecoveryError, InlineRecoveryPlan,
    StripeRepairPlan, CRC64_XZ_SEED, MIN_STRIPE_LEN,
};
use crate::error::{Error, Result};

/// Copy/scan buffer size. Large enough that sequential reads stay cheap,
/// small enough to be irrelevant next to any budget we accept.
const IO_BUF: usize = 256 * 1024;

/// Fixed part of a `{RB}` inline recovery chunk header.
const CHUNK_FIXED_HEADER: u64 = 0x48;

/// Ceiling on `{RB}` chunks retained from one scan. The format allows a u16
/// recovery count; real plans stay at or under 200. Each retained location
/// is small, but the cap keeps a hostile file from growing the list.
const MAX_CHUNKS: usize = 4096;

/// A byte source addressed by absolute range.
///
/// The point of the trait is testability: a test can declare a
/// multi-gigabyte volume and synthesize its bytes on demand, which is the
/// only way to exercise these paths at the sizes they exist for.
pub trait RangeSource {
    /// Total length of the source in bytes.
    fn len(&self) -> u64;

    /// Fills `buf` from `offset`. Short reads are an error - a recovery
    /// pass that silently accepted truncation would repair against zeros.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()>;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A file opened once and read by position, so no seek state is shared and
/// nothing is held between calls.
#[derive(Debug)]
pub struct FileSource {
    file: File,
    len: u64,
}

impl FileSource {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        Ok(Self { file, len })
    }
}

impl RangeSource for FileSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        read_exact_at_shared(&self.file, offset, buf)
    }
}

#[cfg(unix)]
fn read_exact_at_shared(file: &File, mut offset: u64, mut buf: &mut [u8]) -> Result<()> {
    use std::os::unix::fs::FileExt;
    while !buf.is_empty() {
        let read = file.read_at(buf, offset)?;
        if read == 0 {
            return Err(Error::TooShort);
        }
        offset += read as u64;
        buf = &mut buf[read..];
    }
    Ok(())
}

#[cfg(windows)]
fn read_exact_at_shared(file: &File, mut offset: u64, mut buf: &mut [u8]) -> Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        let read = file.seek_read(buf, offset)?;
        if read == 0 {
            return Err(Error::TooShort);
        }
        offset += read as u64;
        buf = &mut buf[read..];
    }
    Ok(())
}

/// An in-memory source, for callers that already hold the bytes (small
/// archives, tests) and for recovery data that had to be decoded.
#[derive(Debug)]
pub struct MemorySource(pub Vec<u8>);

impl RangeSource for MemorySource {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let start = usize::try_from(offset).map_err(|_| Error::TooShort)?;
        let end = start.checked_add(buf.len()).ok_or(Error::TooShort)?;
        buf.copy_from_slice(self.0.get(start..end).ok_or(Error::TooShort)?);
        Ok(())
    }
}

/// One `{RB}` inline recovery chunk, located but NOT loaded.
///
/// `parity` is a range into the source rather than bytes: a single chunk's
/// parity is `group_count` bytes, which for a 20 GB volume split 200 ways is
/// 100 MB - per chunk, with up to 200 of them. Holding the ranges lets the
/// stripe loop read only the window it is working on.
#[derive(Debug, Clone)]
pub struct ChunkLocation {
    pub plan: InlineRecoveryPlan,
    pub protected_size: u64,
    pub shard_index: usize,
    pub parity: std::ops::Range<u64>,
}

/// Recovery chunks found in `src`, with the shared data-shard state table.
#[derive(Debug, Clone)]
pub struct InlineRecoveryScan {
    pub chunks: Vec<ChunkLocation>,
    /// CRC64 state per data shard, for each GROUP in file order.
    ///
    /// Not one table per set: a table describes one group's slice of every
    /// data shard, and an archive over ~13 MB has several groups with
    /// different tables. Treating the first one as the set's own is what
    /// made every multi-group archive report all 200 shards damaged.
    ///
    /// A group with no surviving record has an empty table.
    pub group_states: Vec<Vec<u64>>,
}

impl InlineRecoveryScan {
    pub fn plan(&self) -> Option<InlineRecoveryPlan> {
        self.chunks.first().map(|chunk| chunk.plan)
    }

    pub fn protected_size(&self) -> Option<u64> {
        self.chunks.first().map(|chunk| chunk.protected_size)
    }

    /// Chunk slots grouped by the group whose parity they carry, in file
    /// order. Empty for a group no surviving record covers.
    ///
    /// Every chunk is assigned in ONE call, because the position of the
    /// recovery area is derived from the whole set - assigning a record on
    /// its own would take that record for group 0 of its own shard.
    pub fn chunks_by_group(&self) -> Result<Vec<Vec<usize>>> {
        let Some(plan) = self.plan() else {
            return Ok(Vec::new());
        };
        let groups = rar5::recovery_groups(plan)?;
        let records: Vec<(u64, usize, u64)> = self
            .chunks
            .iter()
            .map(|chunk| {
                (
                    chunk.parity.start.saturating_sub(plan.header_size),
                    chunk.shard_index,
                    chunk.parity.end - chunk.parity.start,
                )
            })
            .collect();
        // Floor: the recovery area cannot begin before the end of the data
        // it protects. A conservative lower bound is enough here - the
        // protected prefix may itself start at a non-zero source offset - and
        // it is what keeps an ambiguous base from failing closed on a set
        // whose layout is in fact decidable.
        let floor = self.chunks.first().map_or(0, |chunk| chunk.protected_size);
        let assigned = rar5::assign_recovery_groups(plan, &records, floor)?;
        let mut by_group = vec![Vec::new(); groups.len()];
        for (slot, group) in assigned.iter().enumerate() {
            if let Some(index) = group {
                by_group[*index].push(slot);
            }
        }
        Ok(by_group)
    }
}

/// Scans `src` for `{RB}` inline recovery chunks without loading it.
///
/// `budget` bounds the state table this may retain (one table, shared across
/// chunks - see [`InlineRecoveryScan`]).
///
/// The anti-quadratic hashing budget is the same one the in-memory scanner
/// carries: a rejected candidate resumes at `start + 1`, and validating a
/// candidate CRC64s everything from its marker to its declared end, so `{RB}`
/// sprinkled every few bytes - each declaring a record reaching near EOF -
/// re-hashes almost the same span once per byte. This CRC64 is the bitwise
/// one at 8 rounds per byte, so an unbounded scan turns a downloaded volume
/// into an unkillable job. A legitimate set hashes each record once.
pub fn scan_inline_recovery_chunks(
    src: &dyn RangeSource,
    budget: u64,
) -> Result<InlineRecoveryScan> {
    scan_inline_recovery_chunks_in(src, 0..src.len(), budget)
}

/// Scans only `range` of `src`, reporting parity ranges ABSOLUTE in `src`.
///
/// The parsed-archive path knows exactly where the recovery service's data
/// lives, so it scans that span in place rather than copying it out; the raw
/// fallback, whose headers were too damaged to locate anything, scans the
/// whole file. Both then hand the same source back as the parity reader.
pub fn scan_inline_recovery_chunks_in(
    src: &dyn RangeSource,
    range: std::ops::Range<u64>,
    budget: u64,
) -> Result<InlineRecoveryScan> {
    let source_len = range.end.min(src.len());
    let hash_budget = source_len
        .saturating_sub(range.start)
        .saturating_mul(4)
        .max(16 * 1024 * 1024);
    let mut hashed: u64 = 0;
    let mut chunks: Vec<ChunkLocation> = Vec::new();
    // One table per chunk, resolved into per-group tables once the scan is
    // done: which group a record belongs to depends on where it sits, so it
    // cannot be decided while the records are still being discovered.
    let mut tables: Vec<Vec<u64>> = Vec::new();

    let mut window = vec![0u8; IO_BUF];
    let mut offset = range.start;
    'scan: while offset + 4 <= source_len {
        let len = IO_BUF.min((source_len - offset) as usize);
        src.read_at(offset, &mut window[..len])?;

        // Markers inside this window. A candidate that fails validation
        // resumes at start + 1, exactly as the in-memory scanner does, so a
        // corrupt record cannot hide a good one behind it.
        let mut cursor = 0usize;
        let mut accepted_end = None;
        while let Some(relative) = find_marker(&window[cursor..len]) {
            if hashed > hash_budget || chunks.len() >= MAX_CHUNKS {
                // Hostile framing, not a real (even badly damaged) archive.
                // Stop with whatever verified so far; the caller reports an
                // unrepairable volume instead of burning hours.
                break 'scan;
            }
            let start = offset + (cursor + relative) as u64;
            match read_chunk_at(src, start, &mut hashed, budget) {
                Ok((chunk, table)) => {
                    // Chunks of different GROUPS legitimately carry different
                    // tables, so a table that disagrees with the first is not
                    // grounds to reject a record here. Coherence is settled
                    // per group below, once each record's position is known.
                    accepted_end = Some(chunk.parity.end);
                    chunks.push(chunk);
                    tables.push(table);
                    break;
                }
                Err(_) => cursor += relative + 1,
            }
        }

        offset = match accepted_end {
            // Resume past the accepted record, never inside its parity.
            Some(end) => end.max(offset + 1),
            // Nothing accepted here: slide on, carrying 3 bytes so a marker
            // straddling the window boundary is still found.
            None => offset + (len - 3.min(len)) as u64,
        };
    }

    if chunks.is_empty() {
        return Err(RecoveryError::BadRecoveryChunk.into());
    }

    // Resolve records into groups. A record that does not land on a group
    // boundary is dropped rather than guessed at, and a group whose records
    // disagree about their table is dropped whole - repairing on either
    // table would be a coin toss written into the file.
    let plan = chunks[0].plan;
    if chunks.iter().any(|chunk| chunk.plan != plan) {
        return Err(RecoveryError::BadRecoveryChunk.into());
    }
    let groups = rar5::recovery_groups(plan)?;
    let records: Vec<(u64, usize, u64)> = chunks
        .iter()
        .map(|chunk| {
            (
                chunk.parity.start.saturating_sub(plan.header_size),
                chunk.shard_index,
                chunk.parity.end - chunk.parity.start,
            )
        })
        .collect();
    let floor = chunks.first().map_or(0, |chunk| chunk.protected_size);
    let assigned = rar5::assign_recovery_groups(plan, &records, floor)?;

    let mut group_states: Vec<Vec<u64>> = vec![Vec::new(); groups.len()];
    let mut poisoned = vec![false; groups.len()];
    for (table, group) in tables.into_iter().zip(&assigned) {
        let Some(index) = *group else { continue };
        if group_states[index].is_empty() {
            group_states[index] = table;
        } else if group_states[index] != table {
            poisoned[index] = true;
        }
    }
    for (states, bad) in group_states.iter_mut().zip(&poisoned) {
        if *bad {
            states.clear();
        }
    }

    let kept: Vec<ChunkLocation> = chunks
        .into_iter()
        .zip(&assigned)
        .filter_map(|(chunk, group)| {
            let index = (*group)?;
            (!group_states[index].is_empty()).then_some(chunk)
        })
        .collect();
    if kept.is_empty() {
        return Err(RecoveryError::BadRecoveryChunk.into());
    }
    Ok(InlineRecoveryScan {
        chunks: kept,
        group_states,
    })
}

fn find_marker(window: &[u8]) -> Option<usize> {
    let mut offset = 0usize;
    while offset + 4 <= window.len() {
        let relative = window[offset..].iter().position(|&byte| byte == b'{')?;
        offset += relative;
        if window.get(offset..offset + 4) == Some(b"{RB}") {
            return Some(offset);
        }
        offset += 1;
    }
    None
}

/// Parses one chunk header at `start` and CRC64-verifies the chunk without
/// holding its parity.
fn read_chunk_at(
    src: &dyn RangeSource,
    start: u64,
    hashed: &mut u64,
    budget: u64,
) -> Result<(ChunkLocation, Vec<u64>)> {
    let source_len = src.len();
    if source_len.saturating_sub(start) < CHUNK_FIXED_HEADER {
        return Err(RecoveryError::BadRecoveryChunk.into());
    }
    let mut fixed = [0u8; CHUNK_FIXED_HEADER as usize];
    src.read_at(start, &mut fixed)?;
    if &fixed[..4] != b"{RB}" {
        return Err(RecoveryError::BadRecoveryChunk.into());
    }
    let expected_crc = u64::from_le_bytes(fixed[0x04..0x0c].try_into().unwrap());
    let total_size = u32::from_le_bytes(fixed[0x0c..0x10].try_into().unwrap()) as u64;
    let header_size = u32::from_le_bytes(fixed[0x10..0x14].try_into().unwrap()) as u64;
    if header_size < CHUNK_FIXED_HEADER || header_size > total_size {
        return Err(RecoveryError::BadRecoveryChunk.into());
    }
    if source_len.saturating_sub(start) < total_size {
        return Err(RecoveryError::BadRecoveryChunk.into());
    }
    if fixed[0x14] != 1 || fixed[0x15] != 1 {
        return Err(RecoveryError::BadRecoveryChunk.into());
    }

    // CRC64 over [0x0c, total_size), streamed. This is the expensive part
    // and the reason the caller carries a hashing budget.
    *hashed = hashed.saturating_add(total_size - 0x0c);
    let mut state = CRC64_XZ_SEED;
    let mut buf = vec![0u8; IO_BUF];
    let mut position = start + 0x0c;
    let end = start + total_size;
    while position < end {
        let len = IO_BUF.min((end - position) as usize);
        src.read_at(position, &mut buf[..len])?;
        state = crc64_update(&buf[..len], state);
        position += len as u64;
    }
    if state ^ CRC64_XZ_SEED != expected_crc {
        return Err(RecoveryError::BadRecoveryChunk.into());
    }

    let protected_size = u64::from_le_bytes(fixed[0x22..0x2a].try_into().unwrap());
    let group_count = u64::from_le_bytes(fixed[0x2a..0x32].try_into().unwrap());
    let shard_size = u64::from_le_bytes(fixed[0x32..0x3a].try_into().unwrap());
    let data_shards = u16::from_le_bytes(fixed[0x3a..0x3c].try_into().unwrap()) as u64;
    let recovery_shards = u16::from_le_bytes(fixed[0x3c..0x3e].try_into().unwrap()) as u64;
    let shard_index = u16::from_le_bytes(fixed[0x3e..0x40].try_into().unwrap()) as usize;
    let plan = InlineRecoveryPlan {
        data_shards,
        recovery_shards,
        group_count,
        header_size,
        shard_size,
    };
    if shard_index >= recovery_shards as usize
        || header_size != CHUNK_FIXED_HEADER + data_shards * 8
    {
        return Err(RecoveryError::BadRecoveryChunk.into());
    }
    // Shard counts past the reconstruction cap describe a grid no plan can
    // ever act on (`StripeRepairPlan::new` refuses them too), so a record
    // declaring one dies here at scan time instead of surviving to sizing.
    // Real WinRAR writes at most 200 data shards; the cap leaves a wide
    // margin above that while keeping a crafted u16 declaration from asking
    // for a 32k x 32k encoder matrix per damaged group.
    if data_shards > rar5::MAX_RECONSTRUCTION_SHARDS as u64
        || recovery_shards > rar5::MAX_RECONSTRUCTION_SHARDS as u64
    {
        return Err(RecoveryError::BadRecoveryChunk.into());
    }
    // The plan the record DECLARES must be one the format's own arithmetic
    // could have produced: `group_count = ceil(protected/data_shards)`
    // rounded up to even, whose capacity always lands inside
    // `protected_size + 2*data_shards`. Both fields come off the wire, so
    // without this a small crafted volume can ask for a terabyte-wide grid.
    // The even `group_count` also keeps the GF16 2-byte symbol walk from
    // reading one past the end of a shard.
    if data_shards == 0 || group_count == 0 || !group_count.is_multiple_of(2) {
        return Err(RecoveryError::BadRecoveryChunk.into());
    }
    let capacity = data_shards
        .checked_mul(group_count)
        .ok_or(RecoveryError::PlanOverflow)?;
    let max_capacity = protected_size
        .checked_add(data_shards.saturating_mul(2))
        .ok_or(RecoveryError::PlanOverflow)?;
    if capacity < protected_size || capacity > max_capacity {
        return Err(RecoveryError::BadRecoveryChunk.into());
    }
    if protected_size > source_len {
        return Err(RecoveryError::BadRecoveryChunk.into());
    }
    // This record carries ONE GROUP's parity, so its own size is a header
    // plus at most 64 KiB - not the shard's whole span, which covers a header
    // per group plus the entire row. Requiring the two to be equal is what
    // stopped the scan on every archive over ~13 MB.
    let parity_len = total_size - header_size;
    if parity_len == 0
        || parity_len > group_count
        || shard_size != rar5::shard_record_span(plan)?
    {
        return Err(RecoveryError::BadRecoveryChunk.into());
    }
    // The state table is the one thing this scan retains per set.
    let table_bytes = data_shards
        .checked_mul(8)
        .ok_or(RecoveryError::PlanOverflow)?;
    if table_bytes > budget {
        return Err(RecoveryError::RepairTooLarge.into());
    }

    let mut table_raw = vec![0u8; table_bytes as usize];
    src.read_at(start + 0x40, &mut table_raw)?;
    let table = table_raw
        .chunks_exact(8)
        .map(|word| u64::from_le_bytes(word.try_into().unwrap()))
        .collect();

    Ok((
        ChunkLocation {
            plan,
            protected_size,
            shard_index,
            parity: start + header_size..end,
        },
        table,
    ))
}

/// Data-shard indices whose streamed CRC64 disagrees with the recovery
/// record's table.
///
/// Reads one bounded window at a time, so detecting damage in a 20 GB volume
/// costs `IO_BUF` bytes rather than a shard (which at 200 shards would be
/// 100 MB) or the volume.
/// Data shards whose group-`group` slice does not match `states`.
///
/// The slice, not the whole shard: a table describes one group's columns, so
/// checking it against a shard's full `group_count` bytes matched nothing the
/// moment an archive had more than one group, and every shard came back
/// damaged.
pub fn damaged_shards(
    src: &dyn RangeSource,
    prefix_start: u64,
    protected_size: u64,
    plan: InlineRecoveryPlan,
    group: rar5::RecoveryGroup,
    states: &[u64],
) -> Result<Vec<usize>> {
    let data_shards = usize::try_from(plan.data_shards).map_err(|_| RecoveryError::PlanOverflow)?;
    if states.len() != data_shards {
        return Err(RecoveryError::BadRecoveryChunk.into());
    }
    let group_count = plan.group_count;
    let mut damaged = Vec::new();
    let mut buf = vec![0u8; IO_BUF];
    for (index, expected) in states.iter().enumerate() {
        let start = (index as u64)
            .checked_mul(group_count)
            .and_then(|base| base.checked_add(group.offset))
            .ok_or(RecoveryError::PlanOverflow)?
            .min(protected_size);
        let end = start.saturating_add(group.len).min(protected_size);
        let mut state = 0u64;
        let mut position = start.min(end);
        while position < end {
            let len = IO_BUF.min((end - position) as usize);
            src.read_at(prefix_start + position, &mut buf[..len])?;
            state = crc64_update(&buf[..len], state);
            position += len as u64;
        }
        if state != *expected {
            damaged.push(index);
        }
    }
    Ok(damaged)
}

/// Damaged shard lists for every group, from one pass over the prefix.
///
/// [`damaged_shards`] reads 64 KiB out of every `group_count` bytes and the
/// repair loop calls it once per group, so detection walks the prefix
/// `groups.len()` times in a strided pattern. The union of those slices is
/// the protected prefix in file order - shard-major, group-minor - so every
/// CRC64 comes off a single sequential pass here, and shards are
/// independent, which is what lets the `parallel` feature split the pass
/// across cores.
///
/// A group whose state table is empty gets an empty damaged list, matching
/// the repair loop, which has nothing to repair such a group with.
pub fn damaged_shards_by_group(
    src: &(dyn RangeSource + Sync),
    prefix_start: u64,
    protected_size: u64,
    plan: InlineRecoveryPlan,
    groups: &[rar5::RecoveryGroup],
    group_states: &[Vec<u64>],
) -> Result<Vec<Vec<usize>>> {
    let data_shards = usize::try_from(plan.data_shards).map_err(|_| RecoveryError::PlanOverflow)?;
    if groups.len() != group_states.len() {
        return Err(RecoveryError::BadRecoveryChunk.into());
    }
    for states in group_states {
        if !states.is_empty() && states.len() != data_shards {
            return Err(RecoveryError::BadRecoveryChunk.into());
        }
    }
    let crcs = shard_group_crcs(
        src,
        prefix_start,
        protected_size,
        plan.group_count,
        groups,
        data_shards,
    )?;
    Ok(group_states
        .iter()
        .enumerate()
        .map(|(group_index, states)| {
            if states.is_empty() {
                Vec::new()
            } else {
                (0..data_shards)
                    .filter(|&shard| crcs[shard][group_index] != states[shard])
                    .collect()
            }
        })
        .collect())
}

/// CRC64 of every (shard, group) slice, indexed `[shard][group]`.
#[cfg(feature = "parallel")]
fn shard_group_crcs(
    src: &(dyn RangeSource + Sync),
    prefix_start: u64,
    protected_size: u64,
    group_count: u64,
    groups: &[rar5::RecoveryGroup],
    data_shards: usize,
) -> Result<Vec<Vec<u64>>> {
    use rayon::prelude::*;
    (0..data_shards)
        .into_par_iter()
        .map(|shard| {
            let mut buf = vec![0u8; IO_BUF];
            shard_crcs(
                src,
                prefix_start,
                protected_size,
                group_count,
                groups,
                shard,
                &mut buf,
            )
        })
        .collect()
}

#[cfg(not(feature = "parallel"))]
fn shard_group_crcs(
    src: &(dyn RangeSource + Sync),
    prefix_start: u64,
    protected_size: u64,
    group_count: u64,
    groups: &[rar5::RecoveryGroup],
    data_shards: usize,
) -> Result<Vec<Vec<u64>>> {
    let mut buf = vec![0u8; IO_BUF];
    (0..data_shards)
        .map(|shard| {
            shard_crcs(
                src,
                prefix_start,
                protected_size,
                group_count,
                groups,
                shard,
                &mut buf,
            )
        })
        .collect()
}

/// Every group's CRC64 for one shard, read as one contiguous run: the
/// group slices of a shard tile `[shard * group_count, +group_count)`.
fn shard_crcs(
    src: &(dyn RangeSource + Sync),
    prefix_start: u64,
    protected_size: u64,
    group_count: u64,
    groups: &[rar5::RecoveryGroup],
    shard: usize,
    buf: &mut [u8],
) -> Result<Vec<u64>> {
    groups
        .iter()
        .map(|group| {
            let start = (shard as u64)
                .checked_mul(group_count)
                .and_then(|base| base.checked_add(group.offset))
                .ok_or(RecoveryError::PlanOverflow)?
                .min(protected_size);
            let end = start.saturating_add(group.len).min(protected_size);
            let mut state = 0u64;
            let mut position = start;
            while position < end {
                let len = buf.len().min((end - position) as usize);
                src.read_at(prefix_start + position, &mut buf[..len])?;
                state = crc64_update(&buf[..len], state);
                position += len as u64;
            }
            Ok(state)
        })
        .collect()
}

/// A sink that accepts rebuilt shard stripes by absolute destination offset.
trait ShardSink {
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<()>;
}

struct FileSink<'a>(&'a mut File);

impl ShardSink for FileSink<'_> {
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<()> {
        self.0.seek(SeekFrom::Start(offset))?;
        self.0.write_all(bytes)?;
        Ok(())
    }
}

/// Copies `len` bytes from `src` at `offset` into `dest` through a fixed
/// buffer. This is how untouched ranges reach the repaired file: a volume is
/// mostly undamaged, and none of it should be resident to be copied.
fn copy_range(src: &dyn RangeSource, offset: u64, len: u64, dest: &mut File) -> Result<()> {
    let mut buf = vec![0u8; IO_BUF];
    let mut position = offset;
    let end = offset.checked_add(len).ok_or(Error::TooShort)?;
    while position < end {
        let take = IO_BUF.min((end - position) as usize);
        src.read_at(position, &mut buf[..take])?;
        dest.write_all(&buf[..take])?;
        position += take as u64;
    }
    Ok(())
}

/// Replaces the file at `dest` with a copy of the file at `src`, preferring
/// a filesystem clone: `std::fs::copy` clones on APFS when the destination
/// does not exist and reflinks via `copy_file_range` where Linux supports
/// it, which turns the copy phase of a repair from a whole-volume
/// read+write into a metadata operation.
///
/// Returns `Ok(true)` when `dest` now holds a byte-complete copy (cloned or
/// not - a plain copy is still a valid prefill), `Ok(false)` when the caller
/// should fall back to the streaming copy path, and an error when the copy
/// came back as something other than a regular file, which is refused
/// rather than written through.
///
/// # Ownership (nzbfast-local change, 22 Aug 2026 - sweep 8, M10)
///
/// This used to `remove_file(dest)` and then `std::fs::copy(src, dest)` by
/// NAME. The caller claims `dest` with `create_new` precisely so it holds a
/// name nobody else has and no symlink can be followed through - and the
/// unlink threw that claim away. In the window that opened, another process
/// (or another repair in the same directory, which the deterministic
/// `.rrtmpN` names make a real possibility) could install a symlink at
/// `dest`; `std::fs::copy` follows one, so the volume was written over
/// whatever it pointed at, OUTSIDE the job. The `symlink_metadata` guard
/// below the copy saw only the end state, after the damage.
///
/// So the copy never touches `dest` by name. It lands in a directory this
/// call creates exclusively - `create_dir` refuses an existing entry of any
/// kind, symlinks included, so nothing can be pre-planted inside it - and is
/// published onto `dest` with `rename`, which replaces the entry atomically
/// and does not follow a symlink sitting there. The clone survives: the copy
/// destination still does not exist when `std::fs::copy` runs, which is the
/// condition APFS `fclonefileat` and `copy_file_range` need.
pub fn clone_prefill(src: &Path, dest: &Path) -> Result<bool> {
    let Some((stage_dir, staged)) = stage_beside(dest) else {
        return Ok(false);
    };
    let cleanup = || {
        let _ = std::fs::remove_file(&staged);
        let _ = std::fs::remove_dir(&stage_dir);
    };
    let Ok(copied) = std::fs::copy(src, &staged) else {
        cleanup();
        return Ok(false);
    };
    let meta = match std::fs::symlink_metadata(&staged) {
        Ok(m) => m,
        Err(error) => {
            cleanup();
            return Err(error.into());
        }
    };
    if !meta.is_file() {
        cleanup();
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "repair destination is not a regular file",
        )
        .into());
    }
    if meta.len() != copied {
        cleanup();
        return Ok(false);
    }
    // Atomic publish. A rename never follows a symlink at the target, so a
    // link smuggled onto `dest` is REPLACED rather than written through.
    if std::fs::rename(&staged, dest).is_err() {
        cleanup();
        return Ok(false);
    }
    let _ = std::fs::remove_dir(&stage_dir);
    Ok(true)
}

/// Claim a private staging directory beside `dest` and name a file in it.
/// (nzbfast-local change, 22 Aug 2026 - sweep 8, M10.)
///
/// `create_dir` is the exclusive primitive: it fails if the name exists at
/// all - regular file, directory or symlink - so a successful call means
/// this process owns the directory and nothing can already be inside it.
/// The candidate loop mirrors the caller's own `.rrtmpN` claim so two
/// concurrent repairs in one directory get separate staging areas instead of
/// stealing each other's.
fn stage_beside(dest: &Path) -> Option<(std::path::PathBuf, std::path::PathBuf)> {
    let parent = dest.parent()?;
    let leaf = dest.file_name()?.to_string_lossy().into_owned();
    for n in 0..1024 {
        let dir = parent.join(format!(".{leaf}.rrstage{n}"));
        if std::fs::create_dir(&dir).is_err() {
            continue;
        }
        // Best effort, and only a defence in depth: the directory is
        // already ours, this just keeps a world-writable parent from
        // making its CONTENTS reachable.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        let staged = dir.join("v");
        return Some((dir, staged));
    }
    None
}

/// Open a repair destination the caller claimed, refusing to follow a
/// symlink at the final component (nzbfast-local change, 22 Aug 2026 -
/// sweep 8, M10).
///
/// The three repair-to-path entry points open `dest` for writing right after
/// [`clone_prefill`], and a plain `OpenOptions::open` follows a symlink -
/// so a prefill that declined (returning `Ok(false)`, which leaves whatever
/// is at `dest` alone) handed the streaming path the same escape the clone
/// used to have. `O_NOFOLLOW` closes it: the open fails rather than writing
/// a repaired volume through a link.
///
/// Windows has no equivalent flag on `OpenOptions` and creating a symlink
/// there needs either administrator rights or developer mode, so it keeps
/// the plain open.
pub fn open_repair_dest(dest: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).read(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    opts.open(dest)
}

/// Repairs the protected prefix of `src` into `dest`, streaming.
///
/// `dest` is written as a full copy of `src` and then patched in place at the
/// damaged shard ranges, so an undamaged byte is copied exactly once and no
/// part of the volume is ever fully resident. `recovery` supplies the parity
/// (the archive itself when the recovery record is stored, a decoded buffer
/// when it is not).
///
/// Returns the damaged shard indices that were rebuilt.
pub fn repair_prefix_streaming(
    src: &(dyn RangeSource + Sync),
    prefix_start: u64,
    scan: &InlineRecoveryScan,
    recovery: &dyn RangeSource,
    dest: &mut File,
    budget: u64,
) -> Result<Vec<usize>> {
    repair_prefix_streaming_impl(src, prefix_start, scan, recovery, dest, budget, false)
}

/// [`repair_prefix_streaming`] for a `dest` that ALREADY holds a full copy
/// of `src` - a caller that owns both paths can produce that copy as a
/// filesystem clone (APFS `clonefile`, btrfs reflink via `copy_file_range`),
/// which makes the largest phase of an undamaged-tail repair near-free
/// instead of a whole-volume read+write.
///
/// The destination's length is still verified against the source before any
/// patch is written; a mismatch fails the repair rather than patching a file
/// that is not the copy it claims to be.
pub fn repair_prefix_streaming_prefilled(
    src: &(dyn RangeSource + Sync),
    prefix_start: u64,
    scan: &InlineRecoveryScan,
    recovery: &dyn RangeSource,
    dest: &mut File,
    budget: u64,
) -> Result<Vec<usize>> {
    repair_prefix_streaming_impl(src, prefix_start, scan, recovery, dest, budget, true)
}

fn repair_prefix_streaming_impl(
    src: &(dyn RangeSource + Sync),
    prefix_start: u64,
    scan: &InlineRecoveryScan,
    recovery: &dyn RangeSource,
    dest: &mut File,
    budget: u64,
    dest_prefilled: bool,
) -> Result<Vec<usize>> {
    let plan = scan.plan().ok_or(RecoveryError::BadRecoveryChunk)?;
    let protected_size = scan.protected_size().ok_or(RecoveryError::BadRecoveryChunk)?;
    if scan
        .chunks
        .iter()
        .any(|chunk| chunk.plan != plan || chunk.protected_size != protected_size)
    {
        return Err(RecoveryError::BadRecoveryChunk.into());
    }
    let source_len = src.len();
    if prefix_start.saturating_add(protected_size) > source_len {
        return Err(RecoveryError::BadRecoveryChunk.into());
    }

    if dest_prefilled {
        // The caller cloned the source into `dest` already; all this pass
        // owes is the same guarantee the copy below provides - that the
        // file being patched is exactly `source_len` bytes of source.
        if dest.metadata()?.len() != source_len {
            return Err(RecoveryError::BadRecoveryChunk.into());
        }
    } else {
        // Full copy first: the repaired file is the original everywhere the
        // recovery record says it is intact. The truncate matters because a
        // caller may hand us a destination that already has content - without
        // it, a shorter repair would leave the previous tail attached.
        dest.seek(SeekFrom::Start(0))?;
        copy_range(src, 0, source_len, dest)?;
        dest.set_len(source_len)?;
    }

    let groups = rar5::recovery_groups(plan)?;
    let by_group = scan.chunks_by_group()?;
    let group_count = plan.group_count;
    let data_shards = usize::try_from(plan.data_shards).map_err(|_| RecoveryError::PlanOverflow)?;
    let recovery_shards =
        usize::try_from(plan.recovery_shards).map_err(|_| RecoveryError::PlanOverflow)?;

    // Groups are repaired independently, each against its own parity and its
    // own CRC table. That is not only what the format requires - it also
    // means damage spread across groups needs only as many recovery shards
    // as the worst single group, not as many as the archive has holes.
    let damaged_by_group = damaged_shards_by_group(
        src,
        prefix_start,
        protected_size,
        plan,
        &groups,
        &scan.group_states,
    )?;
    let mut all_damaged: Vec<usize> = Vec::new();
    for (((group, slots), states), damaged) in groups
        .iter()
        .zip(&by_group)
        .zip(&scan.group_states)
        .zip(damaged_by_group)
    {
        if states.is_empty() || slots.is_empty() {
            // No usable record for this group. Nothing to repair it with; if
            // its data is damaged the caller's own verify reports the file
            // still broken rather than us writing a guess.
            continue;
        }
        if damaged.is_empty() {
            continue;
        }

        // Distinct recovery rows, one equation per damaged shard. Rows are
        // taken in ascending shard_index order so the choice is
        // deterministic.
        let mut rows: Vec<(usize, usize)> = slots
            .iter()
            .map(|&slot| (scan.chunks[slot].shard_index, slot))
            .collect();
        rows.sort_unstable();
        rows.dedup_by_key(|(row, _)| *row);
        if rows.len() < damaged.len() {
            return Err(RecoveryError::TooManyDamagedShards.into());
        }
        rows.truncate(damaged.len());

        let shard_len = usize::try_from(group.len).map_err(|_| RecoveryError::PlanOverflow)?;
        let row_indices: Vec<usize> = rows.iter().map(|(row, _)| *row).collect();
        let repair = StripeRepairPlan::new(
            data_shards,
            recovery_shards,
            shard_len,
            &damaged,
            &row_indices,
        )?;
        let stripe = repair.stripe_len_for_budget(budget)?;
        let group_offset = group.offset;

        let mut sink = FileSink(&mut *dest);
        repair_shards_striped(
            &repair,
            stripe,
            |index, offset, buf| {
                // Shard windows past `protected_size` are the code word's
                // zero padding, not file bytes: the last shard is short
                // whenever the prefix does not divide evenly.
                let base = (index as u64) * group_count + group_offset + offset as u64;
                read_padded(src, prefix_start, base, protected_size, buf)
            },
            |slot, offset, buf| {
                let range = &scan.chunks[rows[slot].1].parity;
                let at = range.start + offset as u64;
                if at + buf.len() as u64 > range.end {
                    return Err(RecoveryError::ShardSizeMismatch);
                }
                recovery
                    .read_at(at, buf)
                    .map_err(|_| RecoveryError::BadRecoveryChunk)
            },
            |slot, offset, bytes| {
                // Only the part of a rebuilt shard that lies inside the
                // protected prefix belongs in the file; the rest was padding.
                let base = (damaged[slot] as u64) * group_count + group_offset + offset as u64;
                if base >= protected_size {
                    return Ok(());
                }
                let take = (protected_size - base).min(bytes.len() as u64) as usize;
                sink.write_at(prefix_start + base, &bytes[..take])
                    .map_err(|_| RecoveryError::BadRecoveryChunk)
            },
        )?;
        all_damaged.extend_from_slice(&damaged);
    }

    dest.flush()?;
    all_damaged.sort_unstable();
    all_damaged.dedup();
    Ok(all_damaged)
}

fn read_padded(
    src: &dyn RangeSource,
    prefix_start: u64,
    base: u64,
    protected_size: u64,
    buf: &mut [u8],
) -> std::result::Result<(), RecoveryError> {
    let available = protected_size.saturating_sub(base).min(buf.len() as u64) as usize;
    if available > 0 {
        src.read_at(prefix_start + base, &mut buf[..available])
            .map_err(|_| RecoveryError::BadRecoveryChunk)?;
    }
    buf[available..].fill(0);
    Ok(())
}

/// Largest budget slice these paths will take for working buffers, and the
/// floor below which a streaming repair is refused outright.
pub fn clamp_budget(budget: u64) -> u64 {
    budget.max(MIN_STRIPE_LEN as u64 * 4)
}

/// Streams `src` through `dest`, returning the CRC32 of everything written.
pub fn copy_file_verified(src: &dyn RangeSource, dest: &mut File) -> Result<u32> {
    let mut buf = vec![0u8; IO_BUF];
    let mut crc = crate::crc32::Crc32::new();
    let mut position = 0u64;
    let len = src.len();
    while position < len {
        let take = IO_BUF.min((len - position) as usize);
        src.read_at(position, &mut buf[..take])?;
        crc.update(&buf[..take]);
        dest.write_all(&buf[..take])?;
        position += take as u64;
    }
    Ok(crc.finish())
}

/// CRC32 of a whole file, read in bounded windows.
pub fn crc32_of(path: &Path) -> Result<(u32, u64)> {
    let mut file = File::open(path)?;
    let mut buf = vec![0u8; IO_BUF];
    let mut crc = crate::crc32::Crc32::new();
    let mut total = 0u64;
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        crc.update(&buf[..read]);
        total += read as u64;
    }
    Ok((crc.finish(), total))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::rar5::build_structural_inline_recovery_data;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Builds the same shape the in-memory scanner is tested against: a
    /// protected prefix, an unrelated service header, the recovery chunks,
    /// then a trailing tail.
    fn archive_with_recovery(prefix_len: usize, percent: u64) -> (Vec<u8>, usize) {
        let prefix: Vec<u8> = (0..prefix_len).map(|index| (index * 13) as u8).collect();
        let recovery_data = build_structural_inline_recovery_data(&prefix, percent).unwrap();
        let mut archive = prefix;
        archive.extend_from_slice(b"service header bytes before chunks");
        archive.extend_from_slice(&recovery_data);
        archive.extend_from_slice(b"end bytes");
        (archive, prefix_len)
    }

    fn temp_path(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "rars-stream-{}-{}-{name}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        path
    }

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn streaming_scan_finds_the_same_chunks_as_the_in_memory_scanner() {
        let (archive, prefix_len) = archive_with_recovery(32_000, 20);
        let source = MemorySource(archive.clone());
        let scan = scan_inline_recovery_chunks(&source, 1 << 20).unwrap();

        assert!(!scan.chunks.is_empty());
        assert_eq!(scan.protected_size(), Some(prefix_len as u64));
        // One group at this size, so exactly one table.
        assert_eq!(scan.group_states.len(), 1);
        assert_eq!(
            scan.group_states[0].len(),
            scan.plan().unwrap().data_shards as usize
        );
        // Located, not loaded: every parity range must sit inside the file
        // and carry exactly one shard's worth of bytes.
        let plan = scan.plan().unwrap();
        for chunk in &scan.chunks {
            assert!(chunk.parity.end <= archive.len() as u64);
            assert_eq!(chunk.parity.end - chunk.parity.start, plan.group_count);
        }
    }

    #[test]
    fn streaming_repair_restores_a_damaged_prefix_byte_for_byte() {
        let (archive, _) = archive_with_recovery(32_000, 20);
        let mut damaged = archive.clone();
        damaged[256..320].fill(0x5a);

        let source = MemorySource(damaged);
        let scan = scan_inline_recovery_chunks(&source, 1 << 20).unwrap();
        let dest_path = temp_path("repair");
        let mut dest = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&dest_path)
            .unwrap();

        let rebuilt =
            repair_prefix_streaming(&source, 0, &scan, &source, &mut dest, 1 << 20).unwrap();
        assert!(!rebuilt.is_empty(), "the damaged shard must be rebuilt");
        drop(dest);

        let repaired = std::fs::read(&dest_path).unwrap();
        std::fs::remove_file(&dest_path).ok();
        assert_eq!(repaired, archive, "streamed repair must be byte-exact");
    }

    #[test]
    fn streaming_repair_of_an_undamaged_archive_is_an_exact_copy() {
        let (archive, _) = archive_with_recovery(32_000, 20);
        let source = MemorySource(archive.clone());
        let scan = scan_inline_recovery_chunks(&source, 1 << 20).unwrap();
        let dest_path = temp_path("clean");
        let mut dest = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&dest_path)
            .unwrap();

        let rebuilt =
            repair_prefix_streaming(&source, 0, &scan, &source, &mut dest, 1 << 20).unwrap();
        assert!(rebuilt.is_empty(), "nothing was damaged");
        drop(dest);

        let copied = std::fs::read(&dest_path).unwrap();
        std::fs::remove_file(&dest_path).ok();
        assert_eq!(copied, archive);
    }

    #[test]
    fn batch_detection_agrees_with_per_group_detection() {
        // Two groups, damage in both, plus one spot straddling nothing -
        // the batch pass must reproduce the per-group loop exactly.
        let prefix_len = 200 * 0x10000 + 8192;
        let (mut archive, protected) = archive_with_recovery(prefix_len, 10);
        archive[4096..4160].fill(0xa5);
        archive[protected - 64..protected].fill(0x5a);

        let source = MemorySource(archive);
        let scan = scan_inline_recovery_chunks(&source, 1 << 20).unwrap();
        let plan = scan.plan().unwrap();
        let groups = rar5::recovery_groups(plan).unwrap();
        assert!(groups.len() >= 2);

        let per_group: Vec<Vec<usize>> = groups
            .iter()
            .zip(&scan.group_states)
            .map(|(group, states)| {
                damaged_shards(&source, 0, protected as u64, plan, *group, states).unwrap()
            })
            .collect();
        let batch = damaged_shards_by_group(
            &source,
            0,
            protected as u64,
            plan,
            &groups,
            &scan.group_states,
        )
        .unwrap();
        assert_eq!(batch, per_group);
        assert!(batch.iter().any(|group| !group.is_empty()));
    }

    #[test]
    fn prefilled_repair_matches_the_streaming_copy_repair() {
        let (archive, _) = archive_with_recovery(32_000, 20);
        let mut damaged = archive.clone();
        damaged[256..320].fill(0x5a);

        // The caller's clone stands in for clone_prefill's fs::copy: the
        // destination already holds the damaged bytes when the repair runs.
        let src_path = temp_path("prefill-src");
        let dest_path = temp_path("prefill-dest");
        std::fs::write(&src_path, &damaged).unwrap();
        assert!(clone_prefill(&src_path, &dest_path).unwrap());

        let source = MemorySource(damaged);
        let scan = scan_inline_recovery_chunks(&source, 1 << 20).unwrap();
        let mut dest = File::options()
            .read(true)
            .write(true)
            .open(&dest_path)
            .unwrap();
        let rebuilt =
            repair_prefix_streaming_prefilled(&source, 0, &scan, &source, &mut dest, 1 << 20)
                .unwrap();
        assert!(!rebuilt.is_empty());
        drop(dest);

        let repaired = std::fs::read(&dest_path).unwrap();
        std::fs::remove_file(&src_path).ok();
        std::fs::remove_file(&dest_path).ok();
        assert_eq!(repaired, archive, "prefilled repair must be byte-exact");
    }

    #[test]
    fn a_prefilled_dest_of_the_wrong_length_is_refused() {
        let (archive, _) = archive_with_recovery(32_000, 20);
        let source = MemorySource(archive);
        let scan = scan_inline_recovery_chunks(&source, 1 << 20).unwrap();
        let dest_path = temp_path("prefill-short");
        std::fs::write(&dest_path, b"not the copy it claims to be").unwrap();
        let mut dest = File::options()
            .read(true)
            .write(true)
            .open(&dest_path)
            .unwrap();
        let result =
            repair_prefix_streaming_prefilled(&source, 0, &scan, &source, &mut dest, 1 << 20);
        drop(dest);
        std::fs::remove_file(&dest_path).ok();
        assert!(result.is_err(), "a length mismatch must fail, not patch");
    }

    /// Sweep 8, M10: a symlink at `dest` is REPLACED, never written
    /// through - including one that is already there when the prefill
    /// starts, which is the end state of the unlink/copy window the old
    /// shape opened.
    ///
    /// The old code unlinked `dest` and then copied to it BY NAME,
    /// throwing away the `create_new` claim the caller took precisely so
    /// no symlink could be followed. Anything installed at the name in
    /// that window received the whole volume, outside the job entirely;
    /// the `symlink_metadata` guard ran after the copy and saw only the
    /// end state. Now the copy lands in a directory this call creates
    /// exclusively and is published with `rename`, which does not follow
    /// a link at the target.
    #[cfg(unix)]
    #[test]
    fn clone_prefill_replaces_a_symlink_instead_of_writing_through_it() {
        let src_path = temp_path("symlink-src");
        let dest_path = temp_path("symlink-dest");
        let target_path = temp_path("symlink-target");
        std::fs::write(&src_path, b"source bytes").unwrap();
        std::fs::write(&target_path, b"must survive").unwrap();
        std::os::unix::fs::symlink(&target_path, &dest_path).unwrap();

        assert_eq!(clone_prefill(&src_path, &dest_path).unwrap(), true);
        assert_eq!(
            std::fs::read(&target_path).unwrap(),
            b"must survive",
            "the link target must never see a byte of the volume"
        );
        assert!(
            std::fs::symlink_metadata(&dest_path).unwrap().is_file(),
            "and the destination is a regular file the repair owns"
        );
        assert_eq!(std::fs::read(&dest_path).unwrap(), b"source bytes");
        // No staging litter left beside it.
        let parent = dest_path.parent().unwrap().to_path_buf();
        let leaf = dest_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert!(!parent.join(format!(".{leaf}.rrstage0")).exists());

        std::fs::remove_file(&dest_path).ok();
        std::fs::remove_file(&src_path).ok();
        std::fs::remove_file(&target_path).ok();
    }

    /// Sweep 8, M10, the other half: the streaming fallback opens the
    /// destination with `O_NOFOLLOW`, so a prefill that DECLINED - which
    /// leaves whatever is at `dest` alone - cannot hand the repair a
    /// link to write a volume through.
    #[cfg(unix)]
    #[test]
    fn the_repair_destination_open_refuses_a_symlink() {
        let dest_path = temp_path("nofollow-dest");
        let target_path = temp_path("nofollow-target");
        std::fs::write(&target_path, b"must survive").unwrap();
        std::os::unix::fs::symlink(&target_path, &dest_path).unwrap();

        let err = open_repair_dest(&dest_path).unwrap_err();
        assert_eq!(
            std::fs::read(&target_path).unwrap(),
            b"must survive",
            "{err}"
        );
        // A regular file at the same name opens normally.
        std::fs::remove_file(&dest_path).ok();
        std::fs::write(&dest_path, b"claimed").unwrap();
        open_repair_dest(&dest_path).expect("a regular destination still opens");

        std::fs::remove_file(&dest_path).ok();
        std::fs::remove_file(&target_path).ok();
    }

    /// Sweep 8, M10: two repairs publishing into the same directory at
    /// once get separate staging areas and separate outputs. The old
    /// deterministic path let concurrent repairs steal and clobber the
    /// same name.
    #[test]
    fn concurrent_prefills_do_not_share_a_staging_area() {
        let a_src = temp_path("conc-src-a");
        let b_src = temp_path("conc-src-b");
        let a_dest = temp_path("conc-dest-a");
        let b_dest = temp_path("conc-dest-b");
        std::fs::write(&a_src, vec![0xAAu8; 64 * 1024]).unwrap();
        std::fs::write(&b_src, vec![0xBBu8; 64 * 1024]).unwrap();

        let (ad, bd) = (a_dest.clone(), b_dest.clone());
        let (asrc, bsrc) = (a_src.clone(), b_src.clone());
        let ta = std::thread::spawn(move || clone_prefill(&asrc, &ad).unwrap());
        let tb = std::thread::spawn(move || clone_prefill(&bsrc, &bd).unwrap());
        assert!(ta.join().unwrap());
        assert!(tb.join().unwrap());
        assert_eq!(std::fs::read(&a_dest).unwrap(), vec![0xAAu8; 64 * 1024]);
        assert_eq!(std::fs::read(&b_dest).unwrap(), vec![0xBBu8; 64 * 1024]);

        for p in [&a_src, &b_src, &a_dest, &b_dest] {
            std::fs::remove_file(p).ok();
        }
    }

    #[test]
    /// The streaming path across MORE THAN ONE GROUP - the shape the daemon
    /// actually meets, and the one the single-group scan rejected outright
    /// (every archive over ~13 MB).
    #[test]
    fn streaming_repair_spans_groups() {
        // Two groups: 200 * 64 KiB is exactly one, so a little past it is two.
        let prefix_len = 200 * 0x10000 + 8192;
        let (archive, protected) = archive_with_recovery(prefix_len, 10);
        let pristine = archive.clone();

        let scan = scan_inline_recovery_chunks(&MemorySource(archive.clone()), 1 << 20).unwrap();
        let plan = scan.plan().unwrap();
        let groups = rar5::recovery_groups(plan).unwrap();
        assert!(groups.len() >= 2, "this test is pointless with one group");
        assert_eq!(scan.group_states.len(), groups.len());
        assert!(
            scan.group_states.iter().all(|states| !states.is_empty()),
            "an undamaged archive must yield a table for every group"
        );
        let by_group = scan.chunks_by_group().unwrap();
        assert!(
            by_group.iter().all(|slots| !slots.is_empty()),
            "every group must keep its own parity records"
        );

        // Damage in the FIRST and the LAST group at once, on different data
        // shards, so a single-group solve cannot cover both.
        let mut damaged_archive = archive;
        let first_hit = 2 * plan.group_count as usize + 11;
        let last_hit = 5 * plan.group_count as usize + groups.last().unwrap().offset as usize + 3;
        assert!(last_hit < protected);
        damaged_archive[first_hit] ^= 0xff;
        damaged_archive[last_hit] ^= 0xff;

        let source = MemorySource(damaged_archive);
        let scan = scan_inline_recovery_chunks(&source, 1 << 20).unwrap();
        let dest_path = temp_path("spans_groups");
        let mut dest = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&dest_path)
            .unwrap();
        let rebuilt =
            repair_prefix_streaming(&source, 0, &scan, &source, &mut dest, 1 << 20).unwrap();
        drop(dest);
        let repaired = std::fs::read(&dest_path).unwrap();
        std::fs::remove_file(&dest_path).ok();

        assert_eq!(rebuilt, vec![2, 5], "both damaged shards must be named");
        assert_eq!(repaired, pristine, "a streamed multi-group repair is byte-exact");
    }

    #[test]
    fn damaged_shard_detection_streams_and_names_the_right_shards() {
        let (archive, prefix_len) = archive_with_recovery(32_000, 20);
        let source = MemorySource(archive.clone());
        let scan = scan_inline_recovery_chunks(&source, 1 << 20).unwrap();
        let plan = scan.plan().unwrap();
        let group = rar5::recovery_groups(plan).unwrap()[0];
        assert!(damaged_shards(
            &source,
            0,
            prefix_len as u64,
            plan,
            group,
            &scan.group_states[0]
        )
        .unwrap()
        .is_empty());

        // Corrupt one byte and confirm exactly the shard covering it moves.
        let mut damaged_archive = archive;
        let hit = 700usize;
        damaged_archive[hit] ^= 0xff;
        let damaged_source = MemorySource(damaged_archive);
        let found = damaged_shards(
            &damaged_source,
            0,
            prefix_len as u64,
            plan,
            group,
            &scan.group_states[0],
        )
        .unwrap();
        assert_eq!(found, vec![hit / plan.group_count as usize]);
    }

    /// A volume far larger than the test could hold, synthesized on demand.
    /// Every read is counted so the test can assert the streaming paths keep
    /// their window inside the ceiling instead of pulling the volume in.
    struct SparseVolume {
        len: u64,
        peak_read: AtomicU64,
        total_read: AtomicU64,
    }

    impl RangeSource for SparseVolume {
        fn len(&self) -> u64 {
            self.len
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            if offset + buf.len() as u64 > self.len {
                return Err(Error::TooShort);
            }
            self.peak_read.fetch_max(buf.len() as u64, Ordering::Relaxed);
            self.total_read
                .fetch_add(buf.len() as u64, Ordering::Relaxed);
            // Deterministic content, generated rather than stored.
            for (index, byte) in buf.iter_mut().enumerate() {
                *byte = ((offset + index as u64) % 251) as u8;
            }
            Ok(())
        }
    }

    #[test]
    fn scanning_a_large_volume_never_reads_more_than_one_window() {
        // 64 MiB of generated bytes with no recovery record in them: the
        // scan runs the whole source and reports none. What is asserted is
        // that it did so through a fixed window - the property that lets the
        // same call be made against a 20 GB volume.
        let window = SparseVolume {
            len: 64 << 20,
            peak_read: AtomicU64::new(0),
            total_read: AtomicU64::new(0),
        };
        assert!(scan_inline_recovery_chunks(&window, 1 << 20).is_err());
        assert!(
            window.peak_read.load(Ordering::Relaxed) <= IO_BUF as u64,
            "the scanner must never ask for more than one window"
        );
        assert!(window.total_read.load(Ordering::Relaxed) >= 64 << 20);
    }

    #[test]
    fn scan_finds_a_chunk_whose_marker_straddles_the_window_boundary() {
        // The scanner slides a fixed window and carries 3 bytes across each
        // boundary so a 4-byte marker split by it is still found. Off by one
        // here and a real recovery record is silently invisible - the repair
        // then reports "no recovery record" on a volume that has one.
        let (archive, _) = archive_with_recovery(32_000, 20);
        let baseline = {
            let source = MemorySource(archive.clone());
            scan_inline_recovery_chunks(&source, 1 << 20).unwrap().chunks.len()
        };
        assert!(baseline > 0);

        // Push the first marker to each offset around the window edge.
        for delta in [-3i64, -2, -1, 0, 1, 2] {
            let pad = (IO_BUF as i64 + delta) as usize;
            let mut padded = vec![0u8; pad];
            padded.extend_from_slice(&archive);
            let source = MemorySource(padded);
            let found = scan_inline_recovery_chunks(&source, 1 << 20)
                .unwrap_or_else(|e| panic!("marker at window{delta:+} was missed: {e}"))
                .chunks
                .len();
            assert_eq!(
                found, baseline,
                "marker at window{delta:+} found {found} chunks, expected {baseline}"
            );
        }
    }

    #[test]
    fn streaming_scan_of_dense_markers_is_not_quadratic() {
        // The streaming scanner carries the same hash budget as the in-memory
        // one, and needs its own proof: a rejected candidate resumes at
        // start + 1 and validating one CRC64s everything to its declared end,
        // so {RB} every 80 bytes each reaching EOF re-hashes almost the whole
        // file once per marker - with a bitwise CRC64 at 8 rounds per byte.
        let len = 4 * 1024 * 1024;
        let mut hostile = vec![0x41u8; len];
        hostile[..8].copy_from_slice(b"Rar!\x1a\x07\x01\x00");
        let mut planted = 0;
        let mut pos = 8;
        while pos + 0x48 < len {
            hostile[pos..pos + 4].copy_from_slice(b"{RB}");
            hostile[pos + 0x0c..pos + 0x10]
                .copy_from_slice(&((len - pos) as u32).to_le_bytes());
            hostile[pos + 0x10..pos + 0x14].copy_from_slice(&0x48u32.to_le_bytes());
            planted += 1;
            pos += 80;
        }
        assert!(planted > 50_000, "{planted} markers is not a dense fixture");

        let source = MemorySource(hostile);
        let started = std::time::Instant::now();
        let result = scan_inline_recovery_chunks(&source, 1 << 20);
        let elapsed = started.elapsed();

        assert!(result.is_err(), "junk must not scan as a recovery set");
        assert!(
            elapsed.as_secs() < 5,
            "streaming scan took {elapsed:?} - the hash budget is not bounding it"
        );
    }

    /// A source that fails past `good`, standing in for a volume truncated
    /// or shrinking under the repair.
    struct TruncatedSource {
        inner: Vec<u8>,
        declared: u64,
    }

    impl RangeSource for TruncatedSource {
        fn len(&self) -> u64 {
            self.declared
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            let start = offset as usize;
            let end = start + buf.len();
            if end > self.inner.len() {
                return Err(Error::TooShort);
            }
            buf.copy_from_slice(&self.inner[start..end]);
            Ok(())
        }
    }

    #[test]
    fn a_source_that_ends_early_fails_the_repair_instead_of_repairing_zeros() {
        // A volume that shrinks (or was truncated in transit) must surface as
        // an error. Treating a short read as zeros would "repair" the file
        // against padding and publish confident garbage.
        let (archive, _) = archive_with_recovery(32_000, 20);
        let mut damaged = archive.clone();
        damaged[256..320].fill(0x5a);
        let full = MemorySource(damaged.clone());
        let scan = scan_inline_recovery_chunks(&full, 1 << 20).unwrap();

        let truncated = TruncatedSource {
            inner: damaged[..damaged.len() / 2].to_vec(),
            declared: damaged.len() as u64,
        };
        let dest_path = temp_path("truncated");
        let mut dest = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&dest_path)
            .unwrap();
        let result =
            repair_prefix_streaming(&truncated, 0, &scan, &full, &mut dest, 1 << 20);
        drop(dest);
        std::fs::remove_file(&dest_path).ok();
        assert!(result.is_err(), "a short source must not repair silently");
    }

    // 64-bit only. `group_count` is a u64 off the wire and the plan
    // measures shards in `usize`, so on a 32-bit host (armv7) a 20 GiB
    // group is refused at `usize::try_from(group.len) ->
    // RecoveryError::PlanOverflow` in `repair_stream` rather than
    // planned - a clean decline, which is the right answer when the
    // extent does not fit the address space. Spelled `20 << 30` through
    // a 32-bit `usize` the value is silently ZERO, so this used to fail
    // as `OddShardSize` and look like a bug in the planner.
    #[cfg(not(target_pointer_width = "32"))]
    #[test]
    fn a_multi_gigabyte_declared_volume_is_planned_without_reading_it() {
        // What must scale to 20 GB is the PLANNING: deciding the stripe and
        // the working set may not touch shard bytes. The byte-for-byte solve
        // is inherently one pass over the volume and is covered at a size a
        // test can actually run.
        let plan = InlineRecoveryPlan {
            data_shards: 200,
            recovery_shards: 10,
            group_count: 20 << 30,
            header_size: 0x48 + 200 * 8,
            shard_size: (20 << 30) + 0x48 + 200 * 8,
        };
        let repair = StripeRepairPlan::new(
            plan.data_shards as usize,
            plan.recovery_shards as usize,
            plan.group_count as usize,
            &[7],
            &[0],
        )
        .unwrap();
        let stripe = repair.stripe_len_for_budget(16 << 20).unwrap();
        assert!(repair.working_bytes(stripe) <= 16 << 20);
        assert!(stripe < plan.group_count as usize);
    }

    #[test]
    fn scan_rejects_a_record_declaring_a_wire_scale_grid() {
        // A record declares its shard counts as u16s, and everything else
        // about this one is internally consistent - sizes, version bytes,
        // capacity arithmetic, CRC64. The only thing wrong with it is a
        // 32767 x 32768 grid, which no plan may ever be sized from: the scan
        // has to drop the record, not carry it to the repair.
        let data_shards: u64 = 32_767;
        let recovery_shards: u64 = 32_768;
        let group_count: u64 = 2;
        let header_size = CHUNK_FIXED_HEADER + data_shards * 8;
        let total_size = header_size + group_count;
        let protected_size = data_shards * group_count;
        let shard_size = header_size + group_count;

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
        let crc = crc64_update(&record[0x0c..], CRC64_XZ_SEED) ^ CRC64_XZ_SEED;
        record[0x04..0x0c].copy_from_slice(&crc.to_le_bytes());

        let mut archive = vec![0u8; protected_size as usize];
        archive.extend_from_slice(&record);
        let source = MemorySource(archive);

        assert!(
            scan_inline_recovery_chunks(&source, 1 << 20).is_err(),
            "a wire-scale shard grid must not scan as a recovery set"
        );
    }
}
