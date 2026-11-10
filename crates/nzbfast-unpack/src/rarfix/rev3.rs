//! RAR 3.x / RAR 4 `.rev` recovery volumes (Weaver parity item 8, TODO
//! section 358): the pre-RAR5 format, which has NO leading signature.
//!
//! The RAR5 rung beside this one ([`super::try_rev_group`]) reads a `.rev`
//! that opens with `Rar!\x1aRev` and carries a table of every data
//! volume's size and CRC. A RAR 3.x `.rev` carries neither, so everything
//! that rung reads out of its header has to come from somewhere else here.
//! What the format IS was MEASURED, never read out of anyone's source: the
//! two `rev_newstyle.part{1,2}.rev` files under
//! `vendor/rars/tests/fixtures/rar15_40/rar300/` and the three that RARLAB
//! `rar` 7.23 writes for the same volumes (`rar rv3`) agree on this layout,
//! byte for byte against a GF(2^8) encoder (the test module carries it):
//!
//! - the file is as long as the set's longest volume, `L`;
//! - bytes `0 .. L-7` are the Reed-Solomon parity row of the first `L-7`
//!   bytes of every data volume, column by column (the code
//!   [`rars::recovery::rar3::reconstruct_data_volumes`] solves);
//! - the last 7 bytes are a trailer: `data_count - 1`, `recovery_count - 1`
//!   and this file's 0-based row, one byte each, then the CRC32 of every
//!   byte before the CRC, little-endian.
//!
//! The parity stops 7 bytes short because a RAR 4 volume written for a
//! recovery set reserves 7 zero bytes at the end of its end-of-archive
//! block (end-block flag `0x0004`): those columns are zero in every volume,
//! so the trailer takes their place. A rebuilt volume gets them back as
//! zeros.
//!
//! **Detection is by content, because posters obfuscate names.** A file is
//! a RAR 3.x `.rev` when its trailer is self-consistent (`row < m`,
//! `k + m <= 255`) and the CRC32 over the rest of the file matches - one
//! chance in 2^32 for a file that is not one. Reading a whole file to
//! learn that is not free, so the candidates are a `.rev` name, or a file
//! whose size is a full volume's size (`L` or `L - 7`, the two the RAR 4
//! writers produce) - a recovery file is never any other size.
//!
//! **Which volumes are intact is decided by the volume itself.** With no
//! size/CRC table to match against, a present volume is trusted only when
//! its end-of-archive block proves it: header CRC good, and the CRC32 the
//! block stores (flag `0x0002`, measured to cover every byte of the volume
//! before the block) matches. The same block's volume number (flag
//! `0x0008`) gives the slot, so a volume's position never rests on its
//! name when the bytes can say. A volume whose end block carries no data
//! CRC cannot be proved either way, and a set holding one is not attempted:
//! rebuilding against an unproved survivor can produce a confident wrong
//! volume. Every rebuild is put through the same proof before it is
//! published, so a wrong survivor or a wrong `.rev` costs a refusal, never
//! a bad file.
//!
//! **Not covered: RAR 3.00's old-style `.rev`** (`name_<count>_<n>.rev`, a
//! bare parity file with no trailer, over volumes whose end block carries
//! neither a data CRC nor a volume number). Nothing in it or its volumes
//! can prove a survivor, which is the precondition above.
//!
//! The rebuild is windowed rather than a call to
//! [`rars::rar15_40::repair_rev3_volumes_to`], which is the same solver over
//! WHOLE volumes held in memory: a 50 x 100 MB set would ask for 5 GB before
//! writing a byte. The parity is column-wise, so each window is an
//! independent solve, and the working set is
//! `(2 * data_count + recovery_count) * window`, held under the repair
//! budget.

use super::{
    collect_rar_volumes, derive_part_name, is_owned_rev_temp, rev_scan_width, scan_in_order,
};
use crate::archname::rar_magic;
use rars::recovery::stream::{FileSource, RangeSource};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// The trailer a RAR 3.x `.rev` ends with: three count bytes and a CRC32.
pub(crate) const TRAILER_LEN: u64 = 7;

/// RAR 4 end-of-archive block type.
const END_BLOCK: u8 = 0x7b;
/// End-block flag: a CRC32 of the volume's bytes before the block follows.
const END_DATACRC: u16 = 0x0002;
/// End-block flag: the 0-based volume number follows (after the data CRC).
const END_VOLNUMBER: u16 = 0x0008;

/// The smallest window the rebuild solves at once, budget permitting.
///
/// Each window re-derives the erasure matrix (one RS decode per surviving
/// volume), so a window far below a mebibyte spends more on the matrix than
/// on the fold for a large set. A set too wide to afford this floor under
/// the budget is refused rather than solved in slivers - see
/// [`rev3_window`].
const REV3_MIN_WINDOW: u64 = 256 << 10;

/// Chunk for the streamed CRC reads.
const CRC_CHUNK: usize = 1 << 20;

/// One RAR 3.x `.rev`, as its trailer describes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Rev3Trailer {
    pub(crate) data_count: usize,
    pub(crate) recovery_count: usize,
    pub(crate) row: usize,
    /// The whole file's length; the parity payload is `len - TRAILER_LEN`.
    pub(crate) len: u64,
}

/// CRC32 of `source[start..end]`, streamed.
fn crc32_range(source: &dyn RangeSource, start: u64, end: u64) -> rars::Result<u32> {
    let mut hasher = crc32fast::Hasher::new();
    let mut buf = vec![0u8; nzbkit::disk::chunk_len(end.saturating_sub(start), CRC_CHUNK)];
    let mut at = start;
    while at < end {
        let n = nzbkit::disk::chunk_len(end - at, buf.len());
        source.read_at(at, &mut buf[..n])?;
        hasher.update(&buf[..n]);
        at += n as u64;
    }
    Ok(hasher.finalize())
}

/// The trailer of a RAR 3.x `.rev`, or `None` when `source` is not one.
/// `None` covers every refusal - a short file, counts the code cannot
/// carry, a CRC that does not match - because each means the same thing to
/// the caller: this file is not a recovery volume it can use.
pub(crate) fn read_rev3_trailer(source: &dyn RangeSource) -> Option<Rev3Trailer> {
    let len = source.len();
    if len <= TRAILER_LEN {
        return None;
    }
    let mut tail = [0u8; TRAILER_LEN as usize];
    source.read_at(len - TRAILER_LEN, &mut tail).ok()?;
    let data_count = usize::from(tail[0]) + 1;
    let recovery_count = usize::from(tail[1]) + 1;
    let row = usize::from(tail[2]);
    if row >= recovery_count || data_count + recovery_count > 255 {
        return None;
    }
    let stored = u32::from_le_bytes([tail[3], tail[4], tail[5], tail[6]]);
    (crc32_range(source, 0, len - 4).ok()? == stored).then_some(Rev3Trailer {
        data_count,
        recovery_count,
        row,
        len,
    })
}

/// What a RAR 4 volume's end-of-archive block proves about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VolumeCheck {
    /// Every byte before the end block hashes to the CRC the block stores.
    Intact {
        /// The volume number the end block carries, when it carries one.
        slot: Option<usize>,
        len: u64,
        /// Where the end block finishes: the volume's true length.
        end: u64,
    },
    /// The headers do not parse, the end block is missing or fails its own
    /// CRC, or the data does not match the stored CRC.
    Damaged,
    /// The end block parses but stores no data CRC: nothing proves the
    /// volume either way.
    Unverifiable,
}

/// Prove (or fail to prove) one RAR 4 volume from its end-of-archive block.
pub(crate) fn check_volume(path: &Path) -> VolumeCheck {
    let Ok(archive) = rars::rar15_40::Archive::parse_path(path) else {
        return VolumeCheck::Damaged;
    };
    let Some(end) = archive.blocks.iter().find_map(|block| match block {
        rars::rar15_40::Block::End(header) => Some(header),
        _ => None,
    }) else {
        return VolumeCheck::Damaged;
    };
    let Ok(source) = FileSource::open(path) else {
        return VolumeCheck::Damaged;
    };
    let start = (archive.sfx_offset + end.offset) as u64;
    let head_size = u64::from(end.head_size);
    if head_size < 7 || start + head_size > source.len() {
        return VolumeCheck::Damaged;
    }
    let mut header = vec![0u8; head_size as usize];
    if source.read_at(start, &mut header).is_err() || header[2] != END_BLOCK {
        return VolumeCheck::Damaged;
    }
    let head_crc = u16::from_le_bytes([header[0], header[1]]);
    if (crc32fast::hash(&header[2..]) & 0xffff) as u16 != head_crc {
        return VolumeCheck::Damaged;
    }
    let flags = u16::from_le_bytes([header[3], header[4]]);
    if flags & END_DATACRC == 0 {
        return VolumeCheck::Unverifiable;
    }
    if header.len() < 11 {
        return VolumeCheck::Damaged;
    }
    let stored = u32::from_le_bytes([header[7], header[8], header[9], header[10]]);
    match crc32_range(&source, 0, start) {
        Ok(actual) if actual == stored => {}
        _ => return VolumeCheck::Damaged,
    }
    let slot = (flags & END_VOLNUMBER != 0 && header.len() >= 13)
        .then(|| usize::from(u16::from_le_bytes([header[11], header[12]])));
    let end = start + head_size + end.add_size.unwrap_or(0);
    VolumeCheck::Intact {
        slot,
        len: source.len(),
        end,
    }
}

/// The 0-based slot a volume NAME implies, for a volume whose end block
/// carries no number: `.partN.rar` is `N - 1`, `.rar` is 0, `.r00` is 1.
fn name_slot(name: &str) -> Option<usize> {
    let lower = name.to_ascii_lowercase();
    let (key, _) = nzbkit::extract::vol_sort_key(&lower);
    if key == u64::MAX {
        return None;
    }
    let one_based = super::rfind_ascii_ci(&lower, ".part")
        .is_some_and(|p| lower.as_bytes().get(p + 5).is_some_and(u8::is_ascii_digit))
        || lower
            .rsplit_once('.')
            .is_some_and(|(_, tail)| tail.bytes().all(|b| b.is_ascii_digit()));
    let slot = if one_based { key.checked_sub(1)? } else { key };
    usize::try_from(slot).ok()
}

/// Name for `slot` derived from `known`, an old-style (`.rar`, `.rNN`)
/// volume name that fills `known_slot`. `None` when `known` is not that
/// shape or the slot needs more digits than `.rNN` carries.
fn derive_old_name(known: &str, known_slot: usize, slot: usize) -> Option<String> {
    let (base, ext) = known.rsplit_once('.')?;
    let lower = ext.to_ascii_lowercase();
    let width = if lower == "rar" {
        if known_slot != 0 {
            return None;
        }
        2
    } else if lower.len() >= 3
        && lower.starts_with('r')
        && lower[1..].bytes().all(|b| b.is_ascii_digit())
    {
        if lower[1..].parse::<usize>().ok()? + 1 != known_slot {
            return None;
        }
        lower.len() - 1
    } else {
        return None;
    };
    let r = if ext.starts_with('R') { "R" } else { "r" };
    if slot == 0 {
        return Some(format!("{base}.{}", if r == "R" { "RAR" } else { "rar" }));
    }
    let n = slot - 1;
    (n < 10usize.pow(width as u32)).then(|| format!("{base}.{r}{n:0width$}"))
}

/// The window [`try_rev3_group`] solves at once, or `None` when even the
/// floor would not fit the budget.
pub(crate) fn rev3_window(
    budget: u64,
    data_count: usize,
    recovery_count: usize,
    payload_len: u64,
    floor: u64,
) -> Option<u64> {
    // Per window: a read buffer per survivor and per `.rev`, and the
    // solver's own output, one shard per data volume.
    let shards = (2 * data_count + recovery_count) as u64;
    let floor = floor.min(payload_len).max(1);
    if shards.saturating_mul(floor) > budget {
        return None;
    }
    Some((budget / shards).clamp(floor, payload_len.max(1)))
}

/// One verified `.rev` of a group.
struct Member {
    source: FileSource,
    trailer: Rev3Trailer,
}

/// Rebuild missing or destroyed volumes of every RAR 3.x `.rev` set in
/// `dir`. Returns true when at least one volume was rebuilt and published.
/// `budget` bounds the rebuild's working set.
pub(crate) fn try_rev3_reconstruct(dir: &Path, budget: u64) -> bool {
    try_rev3_reconstruct_in(dir, budget, REV3_MIN_WINDOW)
}

/// [`try_rev3_reconstruct`] with the window floor as a parameter, so a test
/// can drive the windowed solve across many windows on a small set.
pub(crate) fn try_rev3_reconstruct_in(dir: &Path, budget: u64, floor: u64) -> bool {
    let volumes = collect_rar_volumes(dir).unwrap_or_default();
    let candidates = rev3_candidates(dir, &volumes);
    if candidates.is_empty() {
        return false;
    }
    let opened = scan_in_order(
        &candidates,
        rev_scan_width(dir, candidates.len()),
        |path: &PathBuf| {
            let source = FileSource::open(path).ok()?;
            let trailer = read_rev3_trailer(&source)?;
            Some((source, trailer))
        },
    );
    // Group by the geometry the trailer states: the trailer names no files,
    // so two sets side by side are told apart by their counts and length,
    // and a wrong pairing is caught by the rebuild's own proof below.
    let mut groups: Vec<Vec<Member>> = Vec::new();
    for (path, outcome) in candidates.into_iter().zip(opened) {
        let Some((source, trailer)) = outcome else {
            if path
                .extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("rev"))
            {
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                warn!(target: "repair", "{name}: not a RAR3 .rev either (its trailer does not verify)");
            }
            continue;
        };
        let same = |m: &Member| {
            m.trailer.data_count == trailer.data_count
                && m.trailer.recovery_count == trailer.recovery_count
                && m.trailer.len == trailer.len
        };
        match groups.iter_mut().find(|g| same(&g[0])) {
            Some(group) if group.iter().any(|m| m.trailer.row == trailer.row) => {
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                warn!(target: "repair", "{name}: a second RAR3 .rev for row {}; ignored", trailer.row + 1);
            }
            Some(group) => group.push(Member { source, trailer }),
            None => groups.push(vec![Member { source, trailer }]),
        }
    }
    if groups.is_empty() {
        return false;
    }
    let checks = scan_in_order(
        &volumes,
        rev_scan_width(dir, volumes.len()),
        |path: &PathBuf| check_volume(path),
    );
    // A group is tried against every release in the folder whose volumes
    // fit it; the volume list is already sorted by release stem.
    let mut sets: Vec<Vec<usize>> = Vec::new();
    let mut last_stem: Option<String> = None;
    for (i, path) in volumes.iter().enumerate() {
        let stem = nzbkit::extract::release_stem(
            &path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_lowercase(),
        );
        if last_stem.as_deref() != Some(stem.as_str()) {
            sets.push(Vec::new());
            last_stem = Some(stem);
        }
        sets.last_mut().expect("pushed above").push(i);
    }
    let mut rebuilt_any = false;
    for group in &groups {
        for set in &sets {
            rebuilt_any |= try_rev3_group(dir, budget, floor, group, &volumes, &checks, set);
        }
    }
    rebuilt_any
}

/// The files in `dir` that could be a RAR 3.x `.rev`: a `.rev` name, or a
/// full volume's size. Volumes, `Rar!` files (RAR5 `.rev` included) and
/// this rung's own staging temps are never candidates.
fn rev3_candidates(dir: &Path, volumes: &[PathBuf]) -> Vec<PathBuf> {
    let mut sizes = std::collections::HashSet::new();
    for volume in volumes {
        if let Ok(meta) = std::fs::metadata(volume) {
            sizes.insert(meta.len());
            sizes.insert(meta.len() + TRAILER_LEN);
        }
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.path())
        .filter(|path| {
            if volumes.contains(path) {
                return false;
            }
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if is_owned_rev_temp(&name) {
                return false;
            }
            let by_name = path
                .extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("rev"));
            let by_size = std::fs::metadata(path).is_ok_and(|m| sizes.contains(&m.len()));
            (by_name || by_size) && !rar_magic(path)
        })
        .collect();
    out.sort();
    out
}

/// Create a staging temp beside the set under the grammar
/// [`super::sweep_stale_rev_temps`] owns.
fn stage_temp(dir: &Path, slot: usize) -> std::io::Result<(PathBuf, std::fs::File)> {
    for n in 0..1024 {
        let candidate = dir.join(format!("revtmp{}-{}-{n}", std::process::id(), slot));
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => return Ok((candidate, file)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other("no free temp name"))
}

/// Rebuild what one `.rev` group can for one release's volumes. Returns
/// true when at least one volume was published.
fn try_rev3_group(
    dir: &Path,
    budget: u64,
    floor: u64,
    group: &[Member],
    volumes: &[PathBuf],
    checks: &[VolumeCheck],
    set: &[usize],
) -> bool {
    let first = group[0].trailer;
    let k = first.data_count;
    let m = first.recovery_count;
    let payload_len = first.len - TRAILER_LEN;

    // Fit: every proved volume of this release sits inside the group's
    // slots and inside its length, and at least one is a full volume.
    let mut slot_of: Vec<Option<usize>> = vec![None; volumes.len()];
    let mut full = false;
    for &i in set {
        match checks[i] {
            VolumeCheck::Intact { slot, len, .. } => {
                let name = volumes[i].file_name().unwrap_or_default().to_string_lossy();
                let Some(slot) = slot.or_else(|| name_slot(&name)) else {
                    return false;
                };
                if slot >= k || len > first.len {
                    return false;
                }
                full |= len == first.len || len == payload_len;
                slot_of[i] = Some(slot);
            }
            VolumeCheck::Damaged => {}
            VolumeCheck::Unverifiable => {
                let name = volumes[i].file_name().unwrap_or_default().to_string_lossy();
                warn!(
                    target: "repair",
                    "{name}: no data checksum in its end block, so nothing proves it - RAR3 .rev not attempted"
                );
                return false;
            }
        }
    }
    if !full {
        return false;
    }
    info!(
        target: "repair",
        "trying RAR3 .rev recovery volumes ({} rev file(s), {k} data volume slot(s))…",
        group.len()
    );
    let mut slot_path: Vec<Option<PathBuf>> = vec![None; k];
    let mut slot_len: Vec<u64> = vec![0; k];
    for &i in set {
        if let (Some(slot), VolumeCheck::Intact { len, .. }) = (slot_of[i], checks[i])
            && slot_path[slot].is_none()
        {
            slot_path[slot] = Some(volumes[i].clone());
            slot_len[slot] = len.min(payload_len);
        }
    }
    let missing: Vec<usize> = (0..k).filter(|&s| slot_path[s].is_none()).collect();
    if missing.is_empty() {
        info!(target: "repair", "all data volumes verify; RAR3 .rev not needed");
        return false;
    }
    if missing.len() > group.len() {
        warn!(
            target: "repair",
            "✘ {} volume(s) missing or damaged but only {} usable RAR3 .rev file(s) - unrepairable",
            missing.len(),
            group.len()
        );
        return false;
    }
    let Some(window) = rev3_window(budget, k, m, payload_len, floor) else {
        warn!(
            target: "repair",
            "✘ RAR3 .rev set of {k}+{m} volumes does not fit the repair budget ({budget} bytes) - not attempted"
        );
        return false;
    };

    let mut sources: Vec<Option<FileSource>> = Vec::with_capacity(k);
    for path in &slot_path {
        sources.push(match path {
            Some(path) => match FileSource::open(path) {
                Ok(source) => Some(source),
                Err(e) => {
                    warn!(target: "repair", "✘ {} became unreadable ({e})", path.display());
                    return false;
                }
            },
            None => None,
        });
    }

    let mut temps: Vec<(PathBuf, std::fs::File)> = Vec::new();
    let cleanup = |temps: &[(PathBuf, std::fs::File)]| {
        for (path, _) in temps {
            let _ = std::fs::remove_file(path);
        }
    };
    for &slot in &missing {
        match stage_temp(dir, slot) {
            Ok(made) => temps.push(made),
            Err(e) => {
                warn!(target: "repair", "✘ cannot stage a rebuild for slot {} ({e})", slot + 1);
                cleanup(&temps);
                return false;
            }
        }
    }

    if let Err(e) = solve_windows(
        &sources,
        &slot_len,
        group,
        &missing,
        &mut temps,
        payload_len,
        window,
    ) {
        warn!(target: "repair", "✘ RAR3 .rev reconstruction failed ({e})");
        cleanup(&temps);
        return false;
    }

    // Prove every rebuild before any is published, by the same end-block
    // check the survivors passed, and cut each back to its true length.
    for (t, &slot) in missing.iter().enumerate() {
        let (path, file) = &temps[t];
        if let Err(e) = file.sync_all() {
            warn!(target: "repair", "✘ could not flush the rebuild for slot {} ({e})", slot + 1);
            cleanup(&temps);
            return false;
        }
        let proved = match check_volume(path) {
            VolumeCheck::Intact {
                slot: claimed, end, ..
            } if claimed.is_none_or(|c| c == slot) => trim_to(file, path, end),
            _ => false,
        };
        if !proved {
            warn!(
                target: "repair",
                "✘ rebuilt slot {} fails its checksum - discarded",
                slot + 1
            );
            cleanup(&temps);
            return false;
        }
    }

    // Publish by rename. A name is derived from a proved neighbour.
    let known = slot_path.iter().enumerate().find_map(|(i, p)| {
        p.as_ref()
            .and_then(|p| p.file_name())
            .map(|n| (i, n.to_string_lossy().into_owned()))
    });
    let mut rebuilt = 0usize;
    for (t, &slot) in missing.iter().enumerate() {
        let name = known
            .as_ref()
            .and_then(|(i, n)| {
                derive_part_name(n, *i, slot).or_else(|| derive_old_name(n, *i, slot))
            })
            .unwrap_or_else(|| format!("rebuilt.part{:02}.rar", slot + 1));
        let target = dir.join(&name);
        // Never over a volume that proved itself as another slot; a
        // damaged file at this name is exactly what the rebuild replaces.
        if slot_path
            .iter()
            .enumerate()
            .any(|(other, p)| other != slot && p.as_deref() == Some(target.as_path()))
        {
            warn!(
                target: "repair",
                "✘ {name} - not published: that file proved itself as another slot"
            );
            continue;
        }
        match std::fs::rename(&temps[t].0, &target) {
            Ok(()) => {
                info!(target: "repair", "✔ {name} - rebuilt from RAR3 .rev");
                rebuilt += 1;
            }
            Err(e) => warn!(target: "repair", "✘ {name} - could not be published ({e})"),
        }
    }
    cleanup(&temps);
    rebuilt > 0
}

/// The windowed solve: each window reads the survivors' and the `.rev`
/// files' bytes at one offset, solves the missing rows, and appends them
/// to the temps. Every rebuild ends with the 7 reserved zero bytes the
/// parity does not cover.
fn solve_windows(
    sources: &[Option<FileSource>],
    slot_len: &[u64],
    group: &[Member],
    missing: &[usize],
    temps: &mut [(PathBuf, std::fs::File)],
    payload_len: u64,
    window: u64,
) -> rars::Result<()> {
    use std::io::Write;
    let k = sources.len();
    let m = group[0].trailer.recovery_count;
    let mut data_bufs: Vec<Vec<u8>> = vec![Vec::new(); k];
    let mut rec_bufs: Vec<Vec<u8>> = vec![Vec::new(); group.len()];
    let mut offset = 0u64;
    while offset < payload_len {
        // `window` is at most the budget, which is the repair cap (at most
        // 512 MiB), so `n` and every span below it fit a 32-bit usize.
        let n = window.min(payload_len - offset);
        for (slot, source) in sources.iter().enumerate() {
            if let Some(source) = source {
                let take = slot_len[slot].saturating_sub(offset).min(n) as usize;
                data_bufs[slot].resize(take, 0);
                source.read_at(offset, &mut data_bufs[slot])?;
            }
        }
        for (member, buf) in group.iter().zip(rec_bufs.iter_mut()) {
            buf.resize(n as usize, 0);
            member.source.read_at(offset, buf)?;
        }
        let data: Vec<Option<&[u8]>> = sources
            .iter()
            .zip(&data_bufs)
            .map(|(source, buf)| source.as_ref().map(|_| buf.as_slice()))
            .collect();
        let recovery: Vec<(usize, &[u8])> = group
            .iter()
            .zip(&rec_bufs)
            .map(|(member, buf)| (member.trailer.row, buf.as_slice()))
            .collect();
        let out = rars::recovery::rar3::reconstruct_data_volumes(&data, m, &recovery)
            .map_err(rars::Error::from)?;
        for (t, &slot) in missing.iter().enumerate() {
            temps[t].1.write_all(&out[slot])?;
        }
        offset += n;
    }
    for (_, file) in temps.iter_mut() {
        file.write_all(&[0u8; TRAILER_LEN as usize])?;
    }
    Ok(())
}

/// Cut a proved rebuild back to `end` when everything past it is the zero
/// padding the solve left (the set's short last volume). Bytes past `end`
/// that are not zero are left alone: they are the volume's own.
fn trim_to(file: &std::fs::File, path: &Path, end: u64) -> bool {
    let Ok(source) = FileSource::open(path) else {
        return false;
    };
    let len = source.len();
    if end >= len {
        return true;
    }
    // Streamed: on a set whose last volume is small, the padding is nearly
    // a whole volume long.
    let mut buf = vec![0u8; nzbkit::disk::chunk_len(len - end, CRC_CHUNK)];
    let mut at = end;
    while at < len {
        let n = nzbkit::disk::chunk_len(len - at, buf.len());
        if source.read_at(at, &mut buf[..n]).is_err() {
            return false;
        }
        if buf[..n].iter().any(|&b| b != 0) {
            return true;
        }
        at += n as u64;
    }
    file.set_len(end).and_then(|()| file.sync_all()).is_ok()
}

#[cfg(test)]
#[path = "rev3_tests.rs"]
mod tests;
