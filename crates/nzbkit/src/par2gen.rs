//! Native PAR2 creator: build a recovery set over real files with no
//! external `par2` binary.
//!
//! `par2.rs` parses and verifies, `par2repair.rs` reconstructs; this is
//! the third direction, and it exists because `nzbfast post`'s no-RAR
//! mode needs a recovery set that carries the REAL names while the wire
//! carries nothing. Shelling out to par2cmdline was the obvious answer
//! and is the wrong one for exactly one measured reason: par2cmdline
//! prints "Skipping 0 byte file" and OMITS the member outright (matrix
//! finding F3, `research/NORAR-DEOBF-MATRIX-2026-08-29.md`), so the
//! VIDEO_TS-placeholder shape - a 0-byte file whose only name lives in
//! the FileDesc - cannot be produced by it at all. `nzbfast post
//! --allow-empty` admits that shape deliberately, so the creator that
//! names it has to describe it too. The `e2e_norar` fixtures work
//! around the same hole by PATCHING par2cmdline output after the fact;
//! this writes it correctly the first time.
//!
//! ## What it emits
//!
//! The index file (`<base>.par2`) and, at non-zero redundancy, volume
//! files (`<base>.volNNN+MM.par2`). Every file repeats the CRITICAL
//! packets - Main, one FileDesc and one IFSC per member, Creator -
//! because that is what makes a set whose index article was lost still
//! nameable from its volumes (the `a_damaged_par2_index_still_names_
//! the_post_from_its_volumes` row), and it is what par2cmdline does.
//!
//! ## The Reed-Solomon half
//!
//! Input slice `i` (files in Main-packet id order, slices in file
//! order) carries constant g_i = 2^{k_i}, k_i the i-th natural coprime
//! to 65535 - [`crate::par2repair::input_base_logs`], the SAME sequence
//! the repair side reads, so the two cannot part company. Recovery
//! slice `e` is
//!
//! ```text
//!     R_e = Σ_i g_i^e · D_i
//! ```
//!
//! over GF(2^16) with slices read as little-endian u16 words, which is
//! [`crate::gf16::MulTable::xor_mul_into`] accumulated across the input
//! blocks.
//!
//! ## How it is judged
//!
//! The tests beside this file damage a member and have our OWN
//! `par2repair` put it back from these slices, which proves the two
//! halves agree and no more: a writer and a reader that share a mistake
//! pass that together. The claim that matters is made where it cannot
//! be self-consistent, in
//! `crates/nzbkit/tests/integration/par2gen_interop.rs`, where
//! par2cmdline verifies a set we wrote and REPAIRS real damage from our
//! recovery slices back to byte-exact. That is the whole point of the
//! producer: a set only our own client could read would be a private
//! format wearing PAR2's name.

use std::path::{Path, PathBuf};

use md5::{Digest, Md5};

use crate::par2::{TYPE_FILEDESC, TYPE_IFSC, TYPE_MAIN, TYPE_RECVSLIC};

/// Packet type of the Creator packet - free-form ASCII body naming the
/// program that built the set. Not in `par2.rs`'s list because nothing
/// on the READ side needs it (the parser skips it), so it lives with
/// the only code that writes one.
const TYPE_CREATOR: &[u8; 16] = b"PAR 2.0\0Creator\0";

/// The PAR2 spec's own input-slice ceiling: 32768 naturals below 65535
/// are coprime to it, and each input slice needs its own constant.
const MAX_INPUT_SLICES: usize = 32768;

/// Recovery-set members hold at most this many files. par2cmdline has
/// no such limit; ours exists because the Main packet lists every file
/// id and every volume repeats every critical packet, so a set of a
/// hundred thousand members is megabytes of duplicated header before a
/// single recovery byte.
const MAX_FILES: usize = 32768;

#[derive(Debug, thiserror::Error)]
pub enum Par2GenError {
    #[error("I/O reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{0}")]
    Other(String),
}

fn io(path: &Path) -> impl Fn(std::io::Error) -> Par2GenError + '_ {
    move |source| Par2GenError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// One file to describe. `name` is what the FileDesc packet carries -
/// the RELATIVE path, forward-slashed, which is how a set preserves a
/// directory tree - and `path` is where the bytes are read from.
#[derive(Debug, Clone)]
pub struct Member {
    pub name: String,
    pub path: PathBuf,
}

/// How much parity to build. `redundancy_pct` is a percentage of the
/// input slice count, rounded up, and 0 means an INDEX-ONLY set: Main,
/// FileDesc, IFSC and Creator, no recovery slices at all. That is a
/// complete and useful set - it names every member and carries the
/// block checksums our live verify runs on - and it is the manifest-only
/// shape the matrix already sweeps.
#[derive(Debug, Clone, Copy, Default)]
pub struct Par2Spec {
    pub redundancy_pct: u32,
    /// Slice size in bytes. Must be a positive multiple of 4 (spec).
    /// `None` picks one from the payload size.
    pub block_size: Option<u64>,
}

/// Peak bytes of recovery accumulator held at once. Recovery slices are
/// built in batches sized to fit this, each batch costing one pass over
/// the payload: without a bound, a 20%-redundancy set over a 1.4 GB post
/// is ~280 MB of accumulators, which an ops tool has no business
/// allocating on a laptop that is also running a daemon.
const ACCUM_BUDGET: u64 = 64 << 20;

/// Peak bytes of INPUT block held at once, on top of the accumulators.
///
/// The fold takes a batch of sources at a time (see [`recovery_slices`])
/// so the payload is read a batch at a time rather than a block at a
/// time. 16 MB is enough that the per-call thread scope and coefficient
/// tables are amortized over ~125 sources at the default block size and
/// over thousands at the 4,096-byte floor, while adding a quarter to the
/// accumulator budget rather than doubling it. It is a CEILING, not a
/// target: a batch is also capped at the set's whole slice count, so a
/// small post holds only what it has.
const READ_BUDGET: u64 = 16 << 20;

/// Test door: [`ACCUM_BUDGET`], so the large-set suite in `tests/` can
/// PROVE its fixture really crosses the batching boundary instead of
/// asserting it against a number copied out of here, which would go
/// stale the day the budget moves and leave the suite quietly covering
/// one pass. Same reason `par2repair` exposes its two bench doors: not
/// part of the supported API.
#[doc(hidden)]
pub const ACCUM_BUDGET_BYTES: u64 = ACCUM_BUDGET;

/// One PAR2 packet: magic ‖ length ‖ MD5(set_id‖type‖body) ‖ set_id ‖
/// type ‖ body. The body must already be padded to a multiple of 4;
/// the length field counts the whole packet including its 64-byte head.
fn packet(set_id: &[u8; 16], ptype: &[u8; 16], body: &[u8]) -> Vec<u8> {
    debug_assert_eq!(body.len() % 4, 0, "PAR2 packet bodies are 4-aligned");
    let mut md5 = Md5::new();
    md5.update(set_id);
    md5.update(ptype);
    md5.update(body);
    let mut out = Vec::with_capacity(64 + body.len());
    out.extend_from_slice(crate::par2::MAGIC);
    out.extend_from_slice(&(64 + body.len() as u64).to_le_bytes());
    out.extend_from_slice(&md5.finalize());
    out.extend_from_slice(set_id);
    out.extend_from_slice(ptype);
    out.extend_from_slice(body);
    out
}

/// Null-pad to the next multiple of 4. A FileDesc name is stored
/// exactly this way, which is why `par2.rs` trims trailing NULs when it
/// reads one back.
fn pad4(mut v: Vec<u8>) -> Vec<u8> {
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
    v
}

/// Everything measured about one member in the single read pass.
struct Scanned {
    name_padded: Vec<u8>,
    file_id: [u8; 16],
    md5_whole: [u8; 16],
    md5_16k: [u8; 16],
    length: u64,
    /// Per-block (MD5, CRC32) over the block ZERO-PADDED to `block_size`,
    /// per spec. Empty for a 0-byte file - a real creator emits no IFSC
    /// packet for one, and neither do we.
    blocks: Vec<([u8; 16], u32)>,
    path: PathBuf,
}

/// Read exactly `want` bytes, or say which file ran out. A member that
/// shrinks mid-build would otherwise silently produce a set describing
/// bytes that are not there.
fn read_exact_or_short(
    r: &mut impl std::io::Read,
    buf: &mut [u8],
    path: &Path,
) -> Result<(), Par2GenError> {
    let mut got = 0usize;
    while got < buf.len() {
        let n = r.read(&mut buf[got..]).map_err(io(path))?;
        if n == 0 {
            return Err(Par2GenError::Other(format!(
                "{} shrank while the recovery set was being built",
                path.display()
            )));
        }
        got += n;
    }
    Ok(())
}

/// Read one member once: whole-file MD5, first-16 KiB MD5, and the
/// per-block checksums. Streamed at `block_size` so a member never has
/// to fit in memory.
fn scan(m: &Member, block_size: u64) -> Result<Scanned, Par2GenError> {
    let f = std::fs::File::open(&m.path).map_err(io(&m.path))?;
    let length = f.metadata().map_err(io(&m.path))?.len();
    let mut r = std::io::BufReader::new(f);

    let mut whole = Md5::new();
    let mut head = Md5::new();
    let mut head_left = 16384usize;
    let mut blocks = Vec::new();
    let mut buf = vec![0u8; block_size as usize];
    let mut left = length;
    while left > 0 {
        let want = left.min(block_size) as usize;
        read_exact_or_short(&mut r, &mut buf[..want], &m.path)?;
        whole.update(&buf[..want]);
        if head_left > 0 {
            let n = head_left.min(want);
            head.update(&buf[..n]);
            head_left -= n;
        }
        // The spec hashes the block zero-padded to the full slice, so
        // the tail block's checksum covers `block_size` bytes and not
        // `want` of them.
        buf[want..].fill(0);
        blocks.push((Md5::digest(&buf).into(), crc32fast::hash(&buf)));
        left -= want as u64;
    }
    let md5_whole: [u8; 16] = whole.finalize().into();
    // A file SHORTER than 16 KiB has md5_16k == the whole-file MD5,
    // because the "first 16k" is all of it. For a 0-byte file both are
    // the MD5 of the empty string, which is exactly what a real creator
    // stores and what `e2e_norar`'s empty-FileDesc patch writes.
    let md5_16k: [u8; 16] = head.finalize().into();

    let name_padded = pad4(m.name.as_bytes().to_vec());
    // File id = MD5(md5_16k ‖ length ‖ padded name). The stored id is
    // authoritative on the read side (readers key Main/FileDesc/IFSC by
    // it and never recompute), but it has to be RIGHT here or a
    // conforming reader that does recompute rejects the set.
    let mut id = Md5::new();
    id.update(md5_16k);
    id.update(length.to_le_bytes());
    id.update(&name_padded);

    Ok(Scanned {
        name_padded,
        file_id: id.finalize().into(),
        md5_whole,
        md5_16k,
        length,
        blocks,
        path: m.path.clone(),
    })
}

/// Pick a slice size for `total` payload bytes: a multiple of 4 that
/// keeps the input-slice count in a range a creator would actually
/// choose, and never over the parser's own 256 MiB ceiling. Small sets
/// get the 4 KiB floor rather than an absurdly fine slicing.
fn default_block_size(total: u64) -> u64 {
    const TARGET_SLICES: u64 = 2000;
    const FLOOR: u64 = 4096;
    const CEIL: u64 = 16 << 20;
    let raw = total.div_ceil(TARGET_SLICES).clamp(FLOOR, CEIL);
    // Round UP to a multiple of 4: rounding down could land on 0 for a
    // tiny total, and the spec requires the multiple either way.
    raw.div_ceil(4) * 4
}

/// Volume layout for `n_recovery` slices: exponentially growing counts
/// (1, 2, 4, 8, …), the par2cmdline convention, so a client that wants a
/// little parity fetches one small volume rather than the whole set.
/// Capped at `max_per_vol` so one volume's accumulators always fit the
/// memory budget.
fn volume_layout(n_recovery: usize, max_per_vol: usize) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let (mut first, mut want) = (0usize, 1usize);
    while first < n_recovery {
        let count = want.min(max_per_vol).min(n_recovery - first);
        out.push((first, count));
        first += count;
        want = want.saturating_mul(2);
    }
    out
}

/// Build the recovery set for `members` into `dir`, and return the
/// generated file names in order (the index first, then any volumes).
///
/// Volumes are WRITTEN as they are computed rather than returned as
/// bytes: a 20%-redundancy set over a large post is hundreds of
/// megabytes, and the caller's next move is to put it on disk anyway.
///
/// Members are described in the order given; the Main packet lists
/// their ids SORTED, which is what the spec requires and what decides
/// input-slice order.
pub fn create_into(
    dir: &Path,
    members: &[Member],
    base: &str,
    spec: &Par2Spec,
) -> Result<Vec<String>, Par2GenError> {
    if members.is_empty() {
        return Err(Par2GenError::Other(
            "a PAR2 set needs at least one member".into(),
        ));
    }
    if members.len() > MAX_FILES {
        return Err(Par2GenError::Other(format!(
            "{} members exceeds the {MAX_FILES}-file limit for a set",
            members.len()
        )));
    }
    if base.is_empty() || base.contains('/') || base.contains('\\') {
        return Err(Par2GenError::Other(format!(
            "PAR2 base name {base:?} must be a non-empty single path component"
        )));
    }
    // A duplicate name is not a naming nit here: two FileDesc packets
    // sharing a name give a reader two equally good answers for one
    // slot, and the file id is derived from the name, so two members
    // with identical heads and lengths would collide outright.
    let mut seen = std::collections::HashSet::new();
    for m in members {
        if m.name.is_empty() {
            return Err(Par2GenError::Other(format!(
                "{} would be described under an empty name",
                m.path.display()
            )));
        }
        if !seen.insert(m.name.as_str()) {
            return Err(Par2GenError::Other(format!(
                "two members would be described as {:?} - a PAR2 set cannot name one \
                 slot twice",
                m.name
            )));
        }
    }

    let mut total = 0u64;
    for m in members {
        total += std::fs::metadata(&m.path).map_err(io(&m.path))?.len();
    }
    let block_size = match spec.block_size {
        Some(bs) => {
            if bs == 0 || !bs.is_multiple_of(4) {
                return Err(Par2GenError::Other(format!(
                    "PAR2 block size {bs} must be a positive multiple of 4"
                )));
            }
            bs
        }
        None => default_block_size(total),
    };

    let mut scanned: Vec<Scanned> = Vec::with_capacity(members.len());
    for m in members {
        scanned.push(scan(m, block_size)?);
    }
    // Main lists file ids sorted, and that order defines the global
    // input-slice index space the RS constants are assigned along - so
    // the caller's order and the slice order are deliberately two
    // different things.
    scanned.sort_by_key(|s| s.file_id);

    let n_slices: usize = scanned.iter().map(|s| s.blocks.len()).sum();
    if n_slices > MAX_INPUT_SLICES {
        return Err(Par2GenError::Other(format!(
            "{n_slices} input slices at a {block_size}-byte block exceeds the PAR2 \
             limit of {MAX_INPUT_SLICES} - raise the block size"
        )));
    }

    let (set_id, critical) = critical_packets(&scanned, block_size);

    let index = format!("{base}.par2");
    let mut out = vec![index.clone()];
    std::fs::write(dir.join(&index), &critical).map_err(io(&dir.join(&index)))?;

    let n_recovery = if spec.redundancy_pct == 0 {
        0
    } else {
        (n_slices as u64)
            .saturating_mul(spec.redundancy_pct as u64)
            .div_ceil(100)
            .max(1) as usize
    };
    if n_recovery == 0 {
        return Ok(out);
    }
    // Every recovery slice needs its own exponent against the same
    // coprime sequence the input slices walk, so the input limit is the
    // practical ceiling here too.
    if n_recovery > MAX_INPUT_SLICES {
        return Err(Par2GenError::Other(format!(
            "{n_recovery} recovery slices exceeds the PAR2 limit of {MAX_INPUT_SLICES} \
             - lower the redundancy or raise the block size"
        )));
    }
    if n_slices == 0 {
        return Err(Par2GenError::Other(
            "a set of only 0-byte members has no slices to build parity over - post it \
             at zero redundancy"
                .into(),
        ));
    }

    let per_batch = (ACCUM_BUDGET / block_size).max(1) as usize;
    let layout = volume_layout(n_recovery, per_batch);
    // Group whole volumes into batches that share one pass over the
    // payload: a batch costs `slices * block_size` of accumulator, and
    // one volume already fits by construction.
    let mut vi = 0usize;
    while vi < layout.len() {
        let mut vj = vi;
        let mut held = 0usize;
        while vj < layout.len() && (held == 0 || held + layout[vj].1 <= per_batch) {
            held += layout[vj].1;
            vj += 1;
        }
        let first = layout[vi].0;
        let slices = recovery_slices(&scanned, block_size, n_slices, first, held, READ_BUDGET)?;
        for &(vfirst, count) in &layout[vi..vj] {
            let mut data = critical.clone();
            for i in 0..count {
                let e = vfirst + i;
                let mut body = Vec::with_capacity(4 + block_size as usize);
                body.extend_from_slice(&(e as u32).to_le_bytes());
                body.extend_from_slice(&slices[e - first]);
                data.extend_from_slice(&packet(&set_id, TYPE_RECVSLIC, &body));
            }
            let name = format!("{base}.vol{vfirst:03}+{count:02}.par2");
            std::fs::write(dir.join(&name), &data).map_err(io(&dir.join(&name)))?;
            out.push(name);
        }
        vi = vj;
    }
    Ok(out)
}

/// The Main / FileDesc / IFSC / Creator block that every file in the set
/// repeats, and the set id it is sealed under. Repeating it is what
/// makes a set whose index article was lost still nameable from its
/// volumes (the `a_damaged_par2_index_still_names_the_post_from_its_
/// volumes` row), and it is what par2cmdline does.
fn critical_packets(scanned: &[Scanned], block_size: u64) -> ([u8; 16], Vec<u8>) {
    let mut main_body = Vec::with_capacity(12 + scanned.len() * 16);
    main_body.extend_from_slice(&block_size.to_le_bytes());
    main_body.extend_from_slice(&(scanned.len() as u32).to_le_bytes());
    for s in scanned {
        main_body.extend_from_slice(&s.file_id);
    }
    // Every member is IN the recovery set, so the non-recovery id list
    // that would follow the recovery ids is empty.
    let set_id: [u8; 16] = Md5::digest(&main_body).into();

    let mut critical = packet(&set_id, TYPE_MAIN, &main_body);
    for s in scanned {
        let mut fd = Vec::with_capacity(56 + s.name_padded.len());
        fd.extend_from_slice(&s.file_id);
        fd.extend_from_slice(&s.md5_whole);
        fd.extend_from_slice(&s.md5_16k);
        fd.extend_from_slice(&s.length.to_le_bytes());
        fd.extend_from_slice(&s.name_padded);
        critical.extend_from_slice(&packet(&set_id, TYPE_FILEDESC, &fd));
        // A 0-byte member has no slices, so it gets no IFSC packet -
        // the shape par2cmdline refuses to emit at all. Its FileDesc
        // alone is what names the placeholder on the way out.
        if s.blocks.is_empty() {
            continue;
        }
        let mut ifsc = Vec::with_capacity(16 + s.blocks.len() * 20);
        ifsc.extend_from_slice(&s.file_id);
        for (m, c) in &s.blocks {
            ifsc.extend_from_slice(m);
            ifsc.extend_from_slice(&c.to_le_bytes());
        }
        critical.extend_from_slice(&packet(&set_id, TYPE_IFSC, &ifsc));
    }
    let creator = pad4(format!("nzbfast {}", env!("CARGO_PKG_VERSION")).into_bytes());
    critical.extend_from_slice(&packet(&set_id, TYPE_CREATOR, &creator));
    (set_id, critical)
}

/// Compute recovery slices for exponents `[first, first + count)`.
///
/// One pass over the payload, folding each input slice into every
/// accumulator in the batch: the alternative - one pass per recovery
/// slice - re-reads the whole post `count` times. Peak memory is
/// `count * block_size` for the accumulators, plus `read_budget` of
/// input blocks - [`READ_BUDGET`] from the one production caller, and a
/// tunable for the tests, which drive the SAME set at several budgets
/// and demand byte-identical slices out of every one of them.
///
/// The arithmetic is [`crate::par2repair::linalg::fold_parallel`], the
/// repair side's own fold. Reaching for it rather than writing a loop
/// here is what fixed two separate things at once, which is also why
/// they were fixed together: both lived in this one loop nest, and two
/// lanes editing one loop nest a day apart is the collision this repo
/// keeps paying for.
///
/// * IT IS PARALLEL. This was a plain nested loop on ONE core, and that
///   was the whole of the wall-clock gap against par2cmdline - measured
///   31 Aug 2026 over a 256 MB set at 10%, we were 1.7x SLOWER in wall
///   clock while being 3.3x FASTER in CPU-seconds, which is what a
///   single-threaded implementation of a parallel job looks like. Pool
///   width comes from `nzbkit::mem::cpu_workers()`, the house door, so
///   a phone sizes it off its big cores rather than its core count.
/// * It builds the right TABLE. The loop called `MulTable::new(c)` per
///   (block, exponent) - 512 field multiplies - when the only thing it
///   ever asked of that table was `xor_mul_into`, the fold.
///   [`crate::gf16::FoldTable`] is the same fold at 64 multiplies, and
///   on a target with a fused multi-source kernel
///   ([`crate::gf16::multi_fold_width`] - NEON, or GFNI+AVX2) the steady
///   state builds no table at all. That build cost is 2.3% of the fold
///   at a 700 KB block and 759% of it at the 4,096-byte floor, so a
///   small post spent most of its time building tables.
///
/// Feeding it means holding a BATCH of input blocks rather than reusing
/// one buffer: a fold call amortizes its thread scope and its
/// coefficient tables over every source in the batch, and one source per
/// call would spawn a pool per block.
fn recovery_slices(
    scanned: &[Scanned],
    block_size: u64,
    n_slices: usize,
    first: usize,
    count: usize,
    read_budget: u64,
) -> Result<Vec<Vec<u8>>, Par2GenError> {
    let words = (block_size / 2) as usize;
    let logs = crate::par2repair::input_base_logs(n_slices)
        .map_err(|e| Par2GenError::Other(format!("assigning RS constants: {e}")))?;
    let mut acc: Vec<Vec<u16>> = vec![vec![0u16; words]; count];

    let bs = block_size as usize;
    let per_read = ((read_budget / block_size).max(1) as usize).min(n_slices);
    let mut arena = vec![0u8; per_read * bs];
    // Base log of each block now in the arena, in arena order. Its
    // LENGTH is how many blocks the arena holds, so it is both the fold's
    // coefficient input and the read loop's fill cursor.
    let mut held: Vec<u32> = Vec::with_capacity(per_read);

    let mut si = 0usize;
    for s in scanned {
        if s.blocks.is_empty() {
            continue;
        }
        let f = std::fs::File::open(&s.path).map_err(io(&s.path))?;
        let mut r = std::io::BufReader::new(f);
        let mut left = s.length;
        while left > 0 {
            let want = left.min(block_size) as usize;
            let slot = &mut arena[held.len() * bs..][..bs];
            read_exact_or_short(&mut r, &mut slot[..want], &s.path)?;
            // The tail block takes part in the arithmetic zero-padded,
            // exactly as its checksum was taken - a repair that
            // reconstructs it gets the padding back and truncates.
            // Padded rather than handed over short, though the fold
            // takes either: a full-width source stays on the fused
            // kernel where a short one drops to the remainder path.
            slot[want..].fill(0);
            held.push(logs[si]);
            si += 1;
            left -= want as u64;
            if held.len() == per_read {
                fold_batch(&mut acc, &arena, bs, &held, first);
                held.clear();
            }
        }
    }
    if !held.is_empty() {
        fold_batch(&mut acc, &arena, bs, &held, first);
    }
    debug_assert_eq!(si, n_slices);
    Ok(acc
        .into_iter()
        .map(|w| crate::gf16::words_as_bytes(&w).to_vec())
        .collect())
}

/// Fold one arena-full of input blocks into every accumulator.
///
/// `held[i]` is the base log k_i of the block at `arena[i * bs..]`, and
/// accumulator `j` carries exponent `first + j`, so the coefficient is
/// g_i^e = 2^(k_i * e mod 65535) - the same constant the repair side
/// derives for the same slice off the same
/// [`crate::par2repair::input_base_logs`] sequence.
fn fold_batch(acc: &mut [Vec<u16>], arena: &[u8], bs: usize, held: &[u32], first: usize) {
    let srcs: Vec<&[u8]> = (0..held.len()).map(|i| &arena[i * bs..][..bs]).collect();
    crate::par2repair::linalg::fold_parallel(acc, &srcs, &|j, i| {
        // The multiply happens in u64 before the reduction, so a large
        // exponent times a large log cannot wrap.
        crate::gf16::pow2(held[i] as u64 * (first + j) as u64 % crate::gf16::ORDER as u64)
    });
}

#[cfg(test)]
#[path = "par2gen_tests.rs"]
mod tests;
