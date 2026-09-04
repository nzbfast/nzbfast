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

use crate::md5fast::{Digest, Md5};

use crate::par2::{MAX_BLOCK_SIZE, TYPE_FILEDESC, TYPE_IFSC, TYPE_MAIN, TYPE_RECVSLIC};

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
/// the payload - and a pass is the whole cost: the GF work is the same
/// however it is batched, so every extra pass is another read of the
/// payload and another stretch where the hashing thread has nothing to
/// overlap. Scaled to the machine: an eighth of physical RAM, floored
/// at 256 MiB (a 10% set over 1 GiB at 1 MiB blocks stays one pass on
/// any box) and capped at 8 GiB (a 10% set over a 23 GB member at
/// 2 MiB blocks is 2.2 GB of accumulators - nine passes under the old
/// flat 256 MiB, measured 2 Sep 2026 at 89 s against ParPar's 37).
/// `NZBFAST_PAR2GEN_ACCUM` (bytes) overrides, which is how the
/// large-set suite pins a small budget to prove its fixture crosses
/// the batching boundary.
///
/// **Derived from the PROCESS budget, not from physical RAM, and the two
/// agree by construction wherever no budget was published.** This used to
/// read `physical_ram() / 8` directly, which meant a daemon started with
/// `--mem-limit 512M` still let one create hold up to 8 GiB of
/// accumulators - measured 3 Sep 2026 at a peak RSS of 2.247 GB, 4.2x the
/// whole published budget, on a 2 GiB / 1 MiB / 50% set. `MemBudget::auto`
/// is `clamp(ram / 4, 256 MiB, 16 GiB)`, so taking half of it and clamping
/// to the same `[256 MiB, 8 GiB]` reproduces `clamp(ram / 8, 256 MiB,
/// 8 GiB)` EXACTLY on every host that publishes nothing: same floor, half
/// the ratio, half the ceiling. The only hosts whose figure moves are the
/// ones that asked for a smaller process, which is the defect.
fn accum_budget() -> u64 {
    accum_budget_from(crate::mem::process_budget().total)
}

/// [`accum_budget`] against an explicit ceiling, which is what the
/// process-wide admission below hands it once another create is already
/// live. The pin and the environment override come FIRST, so a test or a
/// research round still pins the batching boundary exactly.
fn accum_budget_from(avail: u64) -> u64 {
    let pinned = ACCUM_OVERRIDE.load(std::sync::atomic::Ordering::Relaxed);
    if pinned > 0 {
        return pinned;
    }
    if let Some(v) = std::env::var("NZBFAST_PAR2GEN_ACCUM")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
    {
        return v;
    }
    (avail / 2).clamp(ACCUM_MIN_BYTES, ACCUM_MAX_BYTES)
}

const ACCUM_MIN_BYTES: u64 = 256 << 20;
const ACCUM_MAX_BYTES: u64 = 8 << 30;

/// Smallest resident window the creator will hand to the transform, in
/// slices: below this the per-window structural cost outweighs what the
/// transform saves over the fold (measured, audit record section 13).
const NTT_WINDOW_MIN: usize = 1024;

/// Resident input window when the create-side NTT is admissible for this
/// exact recovery batch. The single-member source-fusion dispatcher asks this
/// same function before choosing the fold: sharing the predicate keeps a
/// newly admitted NTT shape from being silently captured by the fused path,
/// which cannot feed the transform from its sequential hash pass.
fn create_ntt_window(
    block_size: usize,
    n_slices: usize,
    first: usize,
    count: usize,
) -> Option<usize> {
    if matches!(std::env::var("NZBFAST_NTT").as_deref(), Ok("0") | Ok("off")) {
        return None;
    }
    let needed = first.checked_add(count)?;
    if !create_ntt_shape_possible(block_size, n_slices, needed, count) {
        return None;
    }
    let budget = crate::par2repair::ntt_budget_env()
        .saturating_sub(crate::par2repair::ntt_worker_arenas(block_size, needed));
    create_ntt_window_with_budget(block_size, n_slices, needed, count, budget)
}

fn create_ntt_shape_possible(
    block_size: usize,
    n_slices: usize,
    needed: usize,
    count: usize,
) -> bool {
    block_size > 0
        && needed <= crate::par2ntt::N
        && count >= crate::par2repair::NTT_MIN_MISSING
        && n_slices >= crate::par2repair::NTT_MIN_PRESENT
}

/// Pure half of [`create_ntt_window`], kept separate so boundary tests can pin
/// the transform's memory gate without mutating the process environment.
fn create_ntt_window_with_budget(
    block_size: usize,
    n_slices: usize,
    needed: usize,
    count: usize,
    budget: usize,
) -> Option<usize> {
    if !create_ntt_shape_possible(block_size, n_slices, needed, count) {
        return None;
    }
    let window = (budget / block_size).min(n_slices);
    (window >= NTT_WINDOW_MIN.min(n_slices)).then_some(window)
}

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
const READ_BUDGET: u64 = 64 << 20;

/// Test door: [`accum_budget`], so the large-set suite in `tests/` can
/// PROVE its fixture really crosses the batching boundary instead of
/// asserting it against a number copied out of here, which would go
/// stale the day the budget moves and leave the suite quietly covering
/// one pass. Same reason `par2repair` exposes its two bench doors: not
/// part of the supported API.
#[doc(hidden)]
pub fn accum_budget_bytes() -> u64 {
    accum_budget()
}

/// Test door: [`scan_pool_budget`] at this process's published budget, so a
/// harness can print the aggregate scan ceiling it is actually measuring
/// rather than recomputing the clamp from constants that move. Not part of
/// the supported API.
#[doc(hidden)]
pub fn scan_pool_budget_bytes() -> u64 {
    scan_pool_budget(crate::mem::process_budget().total)
}

static ACCUM_OVERRIDE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Test door: pin the accumulator budget for this process (0 lifts the
/// pin), so a suite can put the batching boundary where its fixture
/// crosses it without an environment write. Not part of the supported
/// API.
#[doc(hidden)]
pub fn pin_accum_budget_for_tests(bytes: u64) {
    ACCUM_OVERRIDE.store(bytes, std::sync::atomic::Ordering::Relaxed);
}

/// Append one PAR2 packet directly to its destination: magic , length ,
/// MD5(set_id,type,body) , set_id , type , body. The body must already be
/// padded to a multiple of 4; the length field counts the whole packet
/// including its 64-byte head. Building the body IN PLACE matters for the
/// recovery packets: a slice can be many MiB, and the volume writer used to
/// copy it into a body, then into a packet, then into the final volume
/// buffer.
fn append_packet(
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
fn write_recovery_packet(
    out: &mut impl std::io::Write,
    set_id: &[u8; 16],
    exponent: u32,
    slice: &[u8],
) -> std::io::Result<()> {
    debug_assert_eq!(slice.len() % 4, 0, "PAR2 recovery slices are 4-aligned");
    let exponent = exponent.to_le_bytes();
    let mut md5 = Md5::new();
    md5.update(set_id);
    md5.update(TYPE_RECVSLIC);
    md5.update(exponent);
    md5.update(slice);

    // The exponent is the first four bytes of the body, so one small header
    // write followed by the accumulator bytes is the complete packet.
    let mut header = [0u8; 68];
    header[..8].copy_from_slice(crate::par2::MAGIC);
    header[8..16].copy_from_slice(&(68 + slice.len() as u64).to_le_bytes());
    header[16..32].copy_from_slice(&md5.finalize());
    header[32..48].copy_from_slice(set_id);
    header[48..64].copy_from_slice(TYPE_RECVSLIC);
    header[64..68].copy_from_slice(&exponent);
    out.write_all(&header)?;
    out.write_all(slice)
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
}

/// Identity and change time of the source descriptor pinned for a fused pass.
#[derive(Clone, Debug, Eq, PartialEq)]
struct SourceStamp {
    length: u64,
    #[cfg(unix)]
    identity: (u64, u64, i64, i64),
}

impl SourceStamp {
    fn of(metadata: &std::fs::Metadata) -> SourceStamp {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        SourceStamp {
            length: metadata.len(),
            #[cfg(unix)]
            identity: (
                metadata.dev(),
                metadata.ino(),
                metadata.ctime(),
                metadata.ctime_nsec(),
            ),
        }
    }
}

/// Ordered checksum state for the sole member of a fused pass: the whole-file
/// and 16 KiB chains plus the per-block products, all advanced from the SAME
/// arena the parity fold is already reading, so the create makes one pass over
/// the payload instead of two.
struct FusedScan {
    file: std::fs::File,
    stamp: SourceStamp,
    expected_head: [u8; 16],
    whole: Md5,
    head: Md5,
    head_left: usize,
    blocks: Vec<([u8; 16], u32)>,
}

impl FusedScan {
    fn open(
        length: u64,
        expected_head: [u8; 16],
        member: &Member,
        block_size: u64,
    ) -> Result<Option<FusedScan>, Par2GenError> {
        let file = std::fs::File::open(&member.path).map_err(io(&member.path))?;
        let metadata = file.metadata().map_err(io(&member.path))?;
        // Pipes and devices have no stable positional snapshot contract. The
        // ordinary scanner is the correct fallback for them.
        if !metadata.is_file() {
            return Ok(None);
        }
        let stamp = SourceStamp::of(&metadata);
        if stamp.length != length {
            return Err(Par2GenError::Other(format!(
                "{} changed length while the PAR2 set was being built",
                member.path.display()
            )));
        }
        Ok(Some(FusedScan {
            file,
            stamp,
            expected_head,
            whole: Md5::new(),
            head: Md5::new(),
            head_left: scan_head_len(length),
            blocks: Vec::with_capacity(length.div_ceil(block_size) as usize),
        }))
    }

    /// The fused pass reads through a descriptor pinned before the fold, so
    /// the "member changed under us" case the placeholder-and-backfill design
    /// refuses has to be caught here instead: both the pinned handle and the
    /// path must still carry the identity the head scan saw.
    fn finish(self, member: &Member) -> Result<Scanned, Par2GenError> {
        let handle_now = self.file.metadata().map_err(io(&member.path))?;
        let path_now = std::fs::metadata(&member.path).map_err(io(&member.path))?;
        if SourceStamp::of(&handle_now) != self.stamp || SourceStamp::of(&path_now) != self.stamp {
            return Err(Par2GenError::Other(format!(
                "{} changed while the PAR2 set was being built",
                member.path.display()
            )));
        }
        let actual = finish_scan(
            member,
            self.stamp.length,
            self.whole.finalize().into(),
            self.head.finalize().into(),
            self.blocks,
        );
        if actual.md5_16k != self.expected_head {
            return Err(Par2GenError::Other(format!(
                "{} changed identity while the PAR2 set was being built",
                member.path.display()
            )));
        }
        Ok(actual)
    }
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
/// Scan every member across threads. Files are independent, so the
/// scan used to be the creator's one serial pass - every byte through
/// the whole-file MD5 and again through its block MD5 on ONE core,
/// which on a 1 GiB set is ~3 s of the 4.3 s a create took while 31
/// cores idled (measured 2 Sep 2026, M3 Ultra; ParPar did the same set
/// in 0.74 s). Largest file first off a shared queue, so no fixed-chunk
/// straggler, and each file-level worker hands its file a fair share of
/// the remaining cores for block-parallel hashing - the split
/// `par2repair::verify_all_targets` uses, for the same reason: one big
/// file on a wide box gets every lane instead of one.
fn scan_all(
    members: &[Member],
    sizes: &[u64],
    block_size: u64,
    scan_pool: u64,
) -> Result<Vec<Scanned>, Par2GenError> {
    debug_assert_eq!(members.len(), sizes.len());
    let mut order: Vec<usize> = (0..members.len()).collect();
    order.sort_by_key(|&i| sizes[i]); // pop() takes the largest
    let queue = std::sync::Mutex::new(order);
    let machine = crate::mem::cpu_workers().max(1);
    let (outer, inner) = scan_pool_geometry(sizes, block_size, machine, scan_pool);
    let mut per_thread: Vec<Result<Vec<(usize, Scanned)>, Par2GenError>> = Vec::new();
    std::thread::scope(|s| {
        let handles: Vec<_> = (0..outer)
            .map(|_| {
                s.spawn(|| {
                    let mut out = Vec::new();
                    loop {
                        let next = queue.lock().unwrap_or_else(|e| e.into_inner()).pop();
                        let Some(i) = next else { return Ok(out) };
                        out.push((i, scan_at_length(&members[i], sizes[i], block_size, inner)?));
                    }
                })
            })
            .collect();
        per_thread = handles
            .into_iter()
            .map(|h| h.join().expect("par2gen scan worker panicked"))
            .collect();
    });
    let mut slots: Vec<Option<Scanned>> = (0..members.len()).map(|_| None).collect();
    for r in per_thread {
        for (i, sc) in r? {
            slots[i] = Some(sc);
        }
    }
    Ok(slots
        .into_iter()
        .map(|s| s.expect("every member scanned"))
        .collect())
}

/// Below this many bytes a file is hashed on its worker alone: the
/// block fan-out is not worth its thread setup (the same threshold
/// `par2repair`'s verify pool uses).
const SCAN_PAR_MIN_BYTES: u64 = 8 << 20;
/// Ceiling on the owned reader/hasher buffer pool of ONE file. This still
/// matters for a single large member, but it is not an aggregate bound:
/// with 32 independent files the dispatcher could allocate it 32 times.
const SCAN_FILE_POOL_BYTES: u64 = 64 << 20;
/// Aggregate ceiling on every member scan's owned payload buffers. A quarter
/// of the process budget keeps a small configured box honest; 64 MiB is enough
/// for all 32 ordinary two-buffer lanes, and 256 MiB keeps the same full
/// fan-out through 128 workers on large machines. The 320 MiB upper edge also
/// retains all 32 lanes at the 4.1 MiB default block of an 8 GiB post, leaving
/// that common path byte-for-byte and scheduler-for-scheduler unchanged. One
/// checksum vector per input slice is separate and globally bounded by
/// `MAX_INPUT_SLICES` (under 1 MiB).
const SCAN_POOL_MIN_BYTES: u64 = 64 << 20;
const SCAN_POOL_MAX_BYTES: u64 = 320 << 20;
/// Hash several small PAR2 blocks per hand-off. A channel trip per 4 KiB
/// slice is measurable on a warm, finely sliced set; a roughly MiB chunk
/// amortizes scheduling while every checksum still observes one exact
/// zero-padded PAR2 block.
const SCAN_HASH_CHUNK_BYTES: u64 = 1 << 20;
/// Piece size for the one-worker large-block pipeline. Four MiB amortizes the
/// channel and incremental-digest calls while 32 files still fit exactly in
/// the 256 MiB aggregate ceiling (two pieces per file).
const SCAN_STREAM_PIECE_BYTES: u64 = 4 << 20;
/// Below eight MiB, retaining two whole blocks is at most 16 MiB per file and
/// saves splitting the creator's common ~4 MiB default block across messages.
const SCAN_STREAM_MIN_BLOCK_BYTES: u64 = 8 << 20;
/// One GiB / one-MiB and larger single-member folds show a repeatable benefit
/// from reading the payload once. Smaller inputs stay on the established
/// overlapping scan/recovery path; `NZBFAST_PAR2GEN_FUSE=1` lowers only these
/// measured floors, and `=0` refuses the route outright.
const FUSED_SOURCE_MIN_BYTES: u64 = 1 << 30;
const FUSED_SOURCE_MIN_BLOCK_BYTES: u64 = 1 << 20;

fn source_fusion_shape_admitted(member_count: usize, n_recovery: usize, per_batch: usize) -> bool {
    cfg!(unix) && member_count == 1 && n_recovery > 0 && n_recovery <= per_batch
}

/// A fine-sliced, low-redundancy set can have 8,192 or more inputs while
/// sitting far below the NTT's 320-row crossover, so an input count alone is
/// the wrong gate: 8 GiB at 1 MiB slices and 1% recovery is 8,193 inputs and
/// only 82 rows, and its only arithmetic route is the fold either way.
fn source_fusion_rows_admitted(n_slices: usize, n_recovery: usize) -> bool {
    n_slices < crate::par2repair::NTT_MIN_PRESENT || n_recovery < crate::par2repair::NTT_MIN_MISSING
}

fn scan_pool_budget(process_budget: u64) -> u64 {
    (process_budget / 4).clamp(SCAN_POOL_MIN_BYTES, SCAN_POOL_MAX_BYTES)
}

/// Payload-buffer bytes claimed by every `create_into` call LIVE in this
/// process right now.
///
/// Every create budget above is a share of the process budget computed
/// independently by each invocation, so before this gauge existed two
/// simultaneous creates each took a full share and the process held twice
/// the intended footprint - measured 3 Sep 2026 on an M3 Ultra, exactly
/// linear in the lane count: peak RSS 619 MB / 1,119 MB / 2,233 MB at one,
/// two and four concurrent `create_into` calls over the same 2 GiB set, and
/// 2.247 GB / 4.273 GB under a published 512 MiB budget. The same shape as
/// [`crate::mem::LZMA_DICT_OUTSTANDING`], and for the same reason: a
/// per-call ceiling is not a process ceiling.
static CREATE_ADMITTED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Test-only exclusivity between the admission gauge's own tests and every
/// other create running in the same process. Nothing here reaches a shipped
/// build.
///
/// [`CREATE_ADMITTED`] is process-global by design, and `cargo test` puts a
/// crate's whole lib in ONE process with its tests on parallel threads - so
/// "the FIRST create in an idle process", which is exactly what the two
/// admission tests assert on, is not a fact a test may simply assume. It was
/// not one: on 3 Sep 2026 the one-process line
/// (`cargo test -p nzbkit-base --lib --features test-support`, and CI's
/// `unit-one-process` job) failed deterministically because
/// `a_block_size_past_the_parsers_own_ceiling_is_refused_at_create_time` - a
/// `create_into` at `MAX_BLOCK_SIZE`, slow enough to still be running, and
/// adjacent in the alphabetical order the runner starts tests in - held one
/// whole share while the concurrent-admission test read the gauge. Its
/// "solo" create therefore divided a ceiling that was already spoken for:
/// 4,093,640,704 accumulator bytes against the 8,589,934,592 the formula
/// gives at an idle 16 GiB ceiling, the arithmetic of exactly one
/// outstanding share. Nextest cannot see this class at all - it gives every
/// test its own process - so every CI shard was green throughout.
///
/// Every acquire takes the READ side, so creates still run together exactly
/// as they do in production and no shipped path is serialised; the admission
/// tests take the WRITE side and so measure a gauge that really is idle.
#[cfg(test)]
static ADMISSION_QUIESCE: std::sync::RwLock<()> = std::sync::RwLock::new(());

#[cfg(test)]
thread_local! {
    /// Set on the one thread holding [`ADMISSION_QUIESCE`] exclusively.
    ///
    /// The exclusive holder is itself a test that RUNS creates - measuring
    /// what a first and a second create are handed is the whole point of it
    /// - and a `std::sync::RwLock` is not reentrant, so without this the
    /// guard would deadlock against its owner's very next `acquire`. Its own
    /// creates pass straight through; every other thread still waits.
    static ADMISSION_OWNED_HERE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// [`CREATE_ADMITTED`] to the calling test alone, for as long as this is
/// held. It subsumes plain mutual exclusion between the admission tests, so
/// it is the only lock they need.
#[cfg(test)]
pub(crate) fn admission_quiesced_for_tests() -> AdmissionQuiesced {
    let held = ADMISSION_QUIESCE
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    ADMISSION_OWNED_HERE.with(|owned| owned.set(true));
    AdmissionQuiesced(held)
}

/// The guard [`admission_quiesced_for_tests`] returns.
#[cfg(test)]
pub(crate) struct AdmissionQuiesced(#[allow(dead_code)] std::sync::RwLockWriteGuard<'static, ()>);

#[cfg(test)]
impl Drop for AdmissionQuiesced {
    fn drop(&mut self) {
        ADMISSION_OWNED_HERE.with(|owned| owned.set(false));
    }
}

/// One live create's share of the process's create budget, released when the
/// call returns - by ANY path, which is why this is a guard and not a pair of
/// statements around the body.
///
/// The FIRST create in an idle process finds nothing outstanding, so it
/// derives exactly the figures the per-invocation formulas gave before this
/// existed: no shipping single-create path changes by a byte. A create that
/// starts while another is running divides what is LEFT, and the floors in
/// both formulas ([`SCAN_POOL_MIN_BYTES`], [`ACCUM_MIN_BYTES`]) mean it
/// always gets a workable plan rather than blocking - so a late create pays
/// extra passes over its own payload instead of the process paying another
/// whole footprint, and nothing can deadlock waiting for a share.
struct CreateAdmission {
    scan_pool: u64,
    accum: u64,
    claimed: u64,
    /// Held for this create's whole life so a test asserting on an idle
    /// gauge can wait it out - `None` only on the exclusive holder's own
    /// thread, which already has it. See [`ADMISSION_QUIESCE`].
    #[cfg(test)]
    _quiesce: Option<std::sync::RwLockReadGuard<'static, ()>>,
}

impl CreateAdmission {
    fn acquire() -> Self {
        // Taken before the ceiling is read, so a test holding the write side
        // sees this create wholly outside its window or wholly inside it,
        // never half-charged against the gauge it is measuring.
        #[cfg(test)]
        let _quiesce = (!ADMISSION_OWNED_HERE.with(|owned| owned.get())).then(|| {
            ADMISSION_QUIESCE
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        });
        let ceiling = crate::mem::process_budget().total;
        let mut plan = (0u64, 0u64, 0u64);
        // A CAS loop rather than a load-then-add: two creates entering
        // together must not both read the pre-claim total and both take a
        // full share, which is precisely the overshoot this exists to bound.
        let _ = CREATE_ADMITTED.fetch_update(
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
            |outstanding| {
                let avail = ceiling.saturating_sub(outstanding);
                let scan_pool = scan_pool_budget(avail);
                let accum = accum_budget_from(avail);
                let claimed = scan_pool.saturating_add(accum).saturating_add(READ_BUDGET);
                plan = (scan_pool, accum, claimed);
                Some(outstanding.saturating_add(claimed))
            },
        );
        Self {
            scan_pool: plan.0,
            accum: plan.1,
            claimed: plan.2,
            #[cfg(test)]
            _quiesce,
        }
    }
}

impl Drop for CreateAdmission {
    fn drop(&mut self) {
        CREATE_ADMITTED.fetch_sub(self.claimed, std::sync::atomic::Ordering::AcqRel);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScanPlan {
    /// The whole-file MD5 chain streams on the caller's thread inside a
    /// 1 MiB reader while `workers` independent positional readers hash
    /// contiguous block ranges. The payload is read twice, and that is
    /// DELIBERATE: a one-read pipeline that hands the MD5 lane's own buffers
    /// to the block hashers was measured on a quiet 20-core M1 at 16 GiB /
    /// 8 MiB slices and cost 5.0% of wall (31.97 -> 33.56 s median of three,
    /// byte-identical output) while retired instructions FELL 0.14% - the
    /// MD5 lane's working set goes from a 1 MiB buffer to a whole block, and
    /// every hash worker then waits on that one lane through a shared receive
    /// lock. See the drop record in
    /// research/PAR2-TWO-LANES-COMPARED-2026-09-03.md.
    Positional { workers: usize },
    /// One sequential reader and one sequential block hasher exchange small
    /// PIECES. This is the same two CPU lanes as a one-worker `Positional`
    /// plan, without retaining a whole 32-256 MiB slice or reading the file
    /// twice - so at a huge block it is strictly better on both counts and
    /// there is no fan-out to throttle.
    Streamed { piece_bytes: usize },
    /// Tiny files and explicitly single-threaded tests hash both products on
    /// one lane, with scratch capped independently of the PAR2 slice size.
    Serial { scratch_bytes: usize },
}

impl ScanPlan {
    fn buffer_bytes(self) -> u64 {
        match self {
            // Sized by `scan_plan_bytes`, which knows the slice size.
            ScanPlan::Positional { .. } => 0,
            ScanPlan::Streamed { piece_bytes } => piece_bytes.saturating_mul(2) as u64,
            // `BufReader` retains its default 8 KiB beside the scratch.
            ScanPlan::Serial { scratch_bytes } => scratch_bytes.saturating_add(8 << 10) as u64,
        }
    }
}

fn scan_plan(length: u64, block_size: u64, threads: usize) -> ScanPlan {
    let n_blocks = length.div_ceil(block_size) as usize;
    if length >= SCAN_PAR_MIN_BYTES && n_blocks >= 2 && threads > 0 {
        let workers = threads
            .min(n_blocks)
            .min((SCAN_FILE_POOL_BYTES / block_size.max(1)).max(1) as usize)
            .max(1);
        // At one hash worker, retaining a whole multi-MiB block buys no block
        // parallelism and costs a second full read. Stream pieces to that same
        // worker instead: one lane either way, a fixed small pool, one read.
        if workers == 1 && block_size >= SCAN_STREAM_MIN_BLOCK_BYTES {
            return ScanPlan::Streamed {
                piece_bytes: SCAN_STREAM_PIECE_BYTES.min(block_size) as usize,
            };
        }
        return ScanPlan::Positional { workers };
    }
    ScanPlan::Serial {
        scratch_bytes: SCAN_HASH_CHUNK_BYTES.min(block_size) as usize,
    }
}

/// Payload buffers one member's scan holds at once, for the aggregate bound.
/// `Positional` is sized here rather than in [`ScanPlan::buffer_bytes`]
/// because its cost depends on the slice size the plan does not carry.
fn scan_plan_bytes(plan: ScanPlan, block_size: u64) -> u64 {
    match plan {
        ScanPlan::Positional { workers } => (workers as u64)
            .saturating_mul(block_size)
            .saturating_add(1 << 20),
        other => other.buffer_bytes(),
    }
}

/// Choose the widest file-level fan-out whose worst possible simultaneous
/// payload-buffer set fits one aggregate budget. The plan is recomputed at
/// each candidate width because the remaining CPU lanes per file affect its
/// owned chunk pool. Descending search keeps every normal lane: on a 32-core
/// host, ordinary slices cost 32 x 2 MiB and retain all 32 outer workers.
fn scan_pool_geometry(
    sizes: &[u64],
    block_size: u64,
    machine: usize,
    budget: u64,
) -> (usize, usize) {
    let natural = machine.max(1).min(sizes.len()).max(1);
    for outer in (1..=natural).rev() {
        let inner = (machine / outer).max(1);
        let mut needs: Vec<u64> = sizes
            .iter()
            .map(|&length| scan_plan_bytes(scan_plan(length, block_size, inner), block_size))
            .collect();
        needs.sort_unstable_by(|a, b| b.cmp(a));
        let worst = needs
            .iter()
            .take(outer)
            .fold(0u64, |sum, &n| sum.saturating_add(n));
        if worst <= budget || outer == 1 {
            return (outer, inner);
        }
    }
    unreachable!("one scan worker is always admitted")
}

/// Per-block (MD5, CRC32) for `[first, last)` blocks of `f`, each block
/// zero-padded to `block_size` exactly as the serial scan pads it.
fn hash_block_range(
    f: &std::fs::File,
    path: &Path,
    length: u64,
    block_size: u64,
    first: usize,
    last: usize,
    out: &mut [([u8; 16], u32)],
) -> Result<(), Par2GenError> {
    let mut buf = vec![0u8; block_size as usize];
    for (k, bi) in (first..last).enumerate() {
        let off = bi as u64 * block_size;
        let want = (length - off).min(block_size) as usize;
        crate::disk::read_exact_at(f, &mut buf[..want], off).map_err(io(path))?;
        buf[want..].fill(0);
        out[k] = (Md5::digest(&buf).into(), crc32fast::hash(&buf));
    }
    Ok(())
}

/// Whole-file MD5 and the 16 KiB head stream on the calling thread (MD5 is
/// one sequential chain; nothing splits it) while the per-block MD5+CRC -
/// independent streams - run across `workers` positional readers over
/// contiguous block ranges.
///
/// The BLOCK WORKERS share the caller's handle on every platform, and
/// that is correct on every platform: they read only through
/// `disk::read_exact_at`, which is `pread` on unix and `seek_read` on
/// Windows, and both take the offset per call. `seek_read` also leaves
/// the shared file POINTER somewhere arbitrary, which matters to a
/// reader that goes through the cursor and to nothing else.
///
/// The SEQUENTIAL lane below is that reader, and it is the one that
/// reopens on Windows - see the comment at its `reopen_read_handle`.
/// This doc used to say "other platforms open independent handles",
/// which reads as a claim about the workers, is false of them, and sent
/// a 4 Sep 2026 review hunting a race that 674a5d80f had already fixed
/// in the lane that really had it. An 8-worker test over a shared
/// handle (`par2gen_tests`, agrees-with-one-reader) covers this and has
/// passed on a real Win11 box.
fn scan_parallel_positional(
    f: &std::fs::File,
    path: &Path,
    length: u64,
    block_size: u64,
    n_blocks: usize,
    workers: usize,
) -> Result<([u8; 16], [u8; 16], Vec<([u8; 16], u32)>), Par2GenError> {
    let mut blocks = vec![([0u8; 16], 0); n_blocks];
    let per = n_blocks.div_ceil(workers);
    let whole = std::thread::scope(|s| -> Result<([u8; 16], [u8; 16]), Par2GenError> {
        let handles: Vec<_> = blocks
            .chunks_mut(per)
            .enumerate()
            .map(|(wi, chunk)| {
                s.spawn(move || -> Result<(), Par2GenError> {
                    let first = wi * per;
                    hash_block_range(
                        f,
                        path,
                        length,
                        block_size,
                        first,
                        first + chunk.len(),
                        chunk,
                    )
                })
            })
            .collect();

        // THE BLOCK LANES SHARE `f` AND `read_exact_at` MOVES ITS CURSOR ON
        // WINDOWS (see `disk::read_exact_at`), so this sequential lane - the
        // only one here that reads THROUGH the cursor - cannot use the same
        // handle there: it would digest whatever bytes a positional worker
        // last left the pointer on, and write that as the member's FileDesc
        // MD5. Unix `pread` leaves the cursor alone, so it keeps the original
        // descriptor and both digest products stay on ONE inode even if the
        // member is replaced mid-create. `ReOpenFile` resolves from the live
        // handle rather than from a pathname, so the Windows arm keeps that
        // property too. (Fix and the real-Win11 verdict: 674a5d80f.)
        #[cfg(windows)]
        let owned = crate::disk::reopen_read_handle(f).map_err(io(path))?;
        #[cfg(windows)]
        let source = &owned;
        #[cfg(not(windows))]
        let source = f;
        let mut reader = std::io::BufReader::with_capacity(1 << 20, source);
        let mut whole = Md5::new();
        let mut head = Md5::new();
        let mut head_left = 16384usize;
        let mut buf = vec![0u8; 1 << 20];
        let mut left = length;
        while left > 0 {
            let want = left.min(buf.len() as u64) as usize;
            read_exact_or_short(&mut reader, &mut buf[..want], path)?;
            whole.update(&buf[..want]);
            if head_left > 0 {
                let n = head_left.min(want);
                head.update(&buf[..n]);
                head_left -= n;
            }
            left -= want as u64;
        }
        for h in handles {
            h.join().expect("par2gen block hasher panicked")?;
        }
        Ok((whole.finalize().into(), head.finalize().into()))
    })?;
    Ok((whole.0, whole.1, blocks))
}

struct ScanPiece {
    block_index: usize,
    used: usize,
    end_block: bool,
    padding: usize,
    bytes: Vec<u8>,
    hash: Option<([u8; 16], u32)>,
}

fn recycle_scan_piece(
    done: &std::sync::mpsc::Receiver<ScanPiece>,
    blocks: &mut [([u8; 16], u32)],
    finished: &mut usize,
    free: &mut Vec<ScanPiece>,
) -> Result<(), Par2GenError> {
    let mut piece = done.recv().map_err(|_| {
        Par2GenError::Other("PAR2 streaming block hasher stopped before the scan completed".into())
    })?;
    if let Some(hash) = piece.hash.take() {
        let Some(slot) = blocks.get_mut(piece.block_index) else {
            return Err(Par2GenError::Other(
                "PAR2 streaming block hasher returned an invalid block index".into(),
            ));
        };
        *slot = hash;
        *finished += 1;
    }
    free.push(piece);
    Ok(())
}

/// Feed `zeros` zero bytes through `md5` using `scratch` as the source, so a
/// tail block's spec-mandated zero padding costs no allocation of its own.
fn update_md5_zeros(md5: &mut Md5, mut zeros: usize, scratch: &mut [u8]) {
    if zeros == 0 {
        return;
    }
    scratch.fill(0);
    while zeros > 0 {
        let take = zeros.min(scratch.len());
        md5.update(&scratch[..take]);
        zeros -= take;
    }
}

/// One file read, with the whole-file MD5 on the reader lane and block
/// MD5/CRC on one worker lane. PIECES, rather than whole PAR2 blocks, cross
/// the bounded queue, so a 256 MiB slice has the same eight-MiB footprint as
/// an eight-MiB slice. This supersedes the huge-block fallback, which
/// allocated one full block per concurrent file and read every payload byte
/// twice.
fn scan_parallel_streamed(
    f: &mut std::fs::File,
    path: &Path,
    length: u64,
    block_size: usize,
    n_blocks: usize,
    piece_bytes: usize,
) -> Result<([u8; 16], [u8; 16], Vec<([u8; 16], u32)>), Par2GenError> {
    let mut blocks = vec![([0u8; 16], 0); n_blocks];
    let mut free: Vec<ScanPiece> = (0..2)
        .map(|_| ScanPiece {
            block_index: 0,
            used: 0,
            end_block: false,
            padding: 0,
            bytes: vec![0u8; piece_bytes],
            hash: None,
        })
        .collect();
    let (jobs_tx, jobs_rx) = std::sync::mpsc::sync_channel::<ScanPiece>(1);
    let (done_tx, done_rx) = std::sync::mpsc::channel::<ScanPiece>();
    let mut reader_result: Option<Result<([u8; 16], [u8; 16]), Par2GenError>> = None;
    let mut finished = 0usize;

    std::thread::scope(|s| {
        let worker = s.spawn(move || {
            let mut block_md5 = Md5::new();
            let mut block_crc = crc32fast::Hasher::new();
            while let Ok(mut piece) = jobs_rx.recv() {
                block_md5.update(&piece.bytes[..piece.used]);
                block_crc.update(&piece.bytes[..piece.used]);
                if piece.end_block {
                    update_md5_zeros(&mut block_md5, piece.padding, &mut piece.bytes);
                    let md5 = std::mem::replace(&mut block_md5, Md5::new())
                        .finalize()
                        .into();
                    let crc = crate::yenc_simd::crc32_zeros(
                        std::mem::replace(&mut block_crc, crc32fast::Hasher::new()).finalize(),
                        piece.padding as u64,
                    );
                    piece.hash = Some((md5, crc));
                }
                if done_tx.send(piece).is_err() {
                    break;
                }
            }
        });

        reader_result = Some((|| {
            let mut whole = Md5::new();
            let mut head = Md5::new();
            let mut head_left = 16384usize;
            let mut file_left = length;
            for bi in 0..n_blocks {
                let block_data = file_left.min(block_size as u64) as usize;
                let mut block_left = block_data;
                while block_left > 0 {
                    if free.is_empty() {
                        recycle_scan_piece(&done_rx, &mut blocks, &mut finished, &mut free)?;
                    }
                    let mut piece = free.pop().expect("the scan reader owns a free piece");
                    let take = block_left.min(piece_bytes);
                    read_exact_or_short(f, &mut piece.bytes[..take], path)?;
                    whole.update(&piece.bytes[..take]);
                    if head_left > 0 {
                        let n = head_left.min(take);
                        head.update(&piece.bytes[..n]);
                        head_left -= n;
                    }
                    piece.block_index = bi;
                    piece.used = take;
                    piece.end_block = take == block_left;
                    piece.padding = if piece.end_block {
                        block_size - block_data
                    } else {
                        0
                    };
                    jobs_tx.send(piece).map_err(|_| {
                        Par2GenError::Other(
                            "PAR2 streaming block hasher stopped before accepting the scan".into(),
                        )
                    })?;
                    block_left -= take;
                }
                file_left -= block_data as u64;
            }
            while free.len() < 2 {
                recycle_scan_piece(&done_rx, &mut blocks, &mut finished, &mut free)?;
            }
            debug_assert_eq!(file_left, 0);
            if finished != n_blocks {
                return Err(Par2GenError::Other(format!(
                    "PAR2 streaming block hasher returned {finished} of {n_blocks} checksums"
                )));
            }
            Ok((whole.finalize().into(), head.finalize().into()))
        })());
        drop(jobs_tx);
        worker
            .join()
            .expect("par2gen streaming block hasher panicked");
    });

    let (whole, head) = reader_result.expect("the PAR2 streamed reader ran")?;
    Ok((whole, head, blocks))
}

fn scan_at_length(
    m: &Member,
    expected_length: u64,
    block_size: u64,
    threads: usize,
) -> Result<Scanned, Par2GenError> {
    let mut f = std::fs::File::open(&m.path).map_err(io(&m.path))?;
    let length = f.metadata().map_err(io(&m.path))?.len();
    if length != expected_length {
        return Err(Par2GenError::Other(format!(
            "{} changed length while the PAR2 set was being built",
            m.path.display()
        )));
    }
    let n_blocks = length.div_ceil(block_size) as usize;
    let block_size_usize = usize::try_from(block_size)
        .map_err(|_| Par2GenError::Other("PAR2 block size does not fit this platform".into()))?;
    match scan_plan(length, block_size, threads) {
        ScanPlan::Positional { workers } => {
            let (md5_whole, md5_16k, blocks) =
                scan_parallel_positional(&f, &m.path, length, block_size, n_blocks, workers)?;
            Ok(finish_scan(m, length, md5_whole, md5_16k, blocks))
        }
        ScanPlan::Streamed { piece_bytes } => {
            let (md5_whole, md5_16k, blocks) = scan_parallel_streamed(
                &mut f,
                &m.path,
                length,
                block_size_usize,
                n_blocks,
                piece_bytes,
            )?;
            Ok(finish_scan(m, length, md5_whole, md5_16k, blocks))
        }
        ScanPlan::Serial { scratch_bytes } => {
            let mut r = std::io::BufReader::new(f);
            let mut whole = Md5::new();
            let mut head = Md5::new();
            let mut head_left = 16384usize;
            let mut blocks = Vec::with_capacity(n_blocks);
            let mut buf = vec![0u8; scratch_bytes];
            let mut left = length;
            while left > 0 {
                let block_data = left.min(block_size) as usize;
                let mut block_left = block_data;
                let mut block_md5 = Md5::new();
                let mut block_crc = crc32fast::Hasher::new();
                while block_left > 0 {
                    let take = block_left.min(buf.len());
                    read_exact_or_short(&mut r, &mut buf[..take], &m.path)?;
                    whole.update(&buf[..take]);
                    block_md5.update(&buf[..take]);
                    block_crc.update(&buf[..take]);
                    if head_left > 0 {
                        let n = head_left.min(take);
                        head.update(&buf[..n]);
                        head_left -= n;
                    }
                    block_left -= take;
                }
                // The spec hashes the block zero-padded to the full slice, so
                // the tail block's checksum covers `block_size` bytes and not
                // `block_data` of them.
                let padding = block_size_usize - block_data;
                update_md5_zeros(&mut block_md5, padding, &mut buf);
                blocks.push((
                    block_md5.finalize().into(),
                    crate::yenc_simd::crc32_zeros(block_crc.finalize(), padding as u64),
                ));
                left -= block_data as u64;
            }
            let md5_whole: [u8; 16] = whole.finalize().into();
            // A file SHORTER than 16 KiB has md5_16k == the whole-file MD5,
            // because the "first 16k" is all of it. For a 0-byte file both are
            // the MD5 of the empty string, which is exactly what a real creator
            // stores and what `e2e_norar`'s empty-FileDesc patch writes.
            let md5_16k: [u8; 16] = head.finalize().into();
            Ok(finish_scan(m, length, md5_whole, md5_16k, blocks))
        }
    }
}

#[cfg(test)]
fn scan(m: &Member, block_size: u64, threads: usize) -> Result<Scanned, Par2GenError> {
    let length = std::fs::metadata(&m.path).map_err(io(&m.path))?.len();
    scan_at_length(m, length, block_size, threads)
}

fn scan_head_len(length: u64) -> usize {
    length.min(16_384) as usize
}

/// Read the identities needed to order recovery slices across the worker
/// pool. A directory with thousands of small members used to open and hash
/// every 16 KiB head serially before either the full scan or the recovery
/// work could start. The full scan already fans files out, and the head pass
/// has the same independent-per-file shape.
fn scan_heads(members: &[Member]) -> Result<Vec<(usize, u64, [u8; 16], [u8; 16])>, Par2GenError> {
    map_members_parallel(members, |i, member| {
        let (length, md5_16k, file_id) = scan_head(member)?;
        Ok((i, length, md5_16k, file_id))
    })
}

/// Lengths are the only pre-scan data an index-only set needs. Recovery sets
/// get them as part of [`scan_heads`], but doing the head read at zero
/// redundancy only duplicated the first 16 KiB of every file without buying
/// any overlap or ordering information.
fn scan_lengths(members: &[Member]) -> Result<Vec<u64>, Par2GenError> {
    map_members_parallel(members, |_, member| {
        std::fs::metadata(&member.path)
            .map(|v| v.len())
            .map_err(io(&member.path))
    })
}

/// Apply an independent metadata/identity probe to every member, preserving
/// caller order in the result. Both creation prepasses are tiny per file but
/// directory-wide, so one shared fan-out keeps their scheduling identical.
fn map_members_parallel<T, F>(members: &[Member], f: F) -> Result<Vec<T>, Par2GenError>
where
    T: Send,
    F: Fn(usize, &Member) -> Result<T, Par2GenError> + Sync,
{
    // These are short positional reads and metadata probes, not the CPU-heavy
    // body hashes below. Thread setup is not repaid by ordinary 20-file sets;
    // at the other end, beyond eight readers the filesystem queue is the
    // bottleneck and extra threads only amplify seek/metadata contention.
    let workers = if members.len() < 64 {
        1
    } else {
        crate::mem::cpu_workers().min(8).min(members.len())
    };
    if workers == 1 {
        return members.iter().enumerate().map(|(i, m)| f(i, m)).collect();
    }
    let per = members.len().div_ceil(workers);
    let mut per_thread: Vec<Result<Vec<T>, Par2GenError>> = Vec::new();
    std::thread::scope(|s| {
        let handles: Vec<_> = members
            .chunks(per)
            .enumerate()
            .map(|(chunk_index, chunk)| {
                let f = &f;
                s.spawn(move || {
                    chunk
                        .iter()
                        .enumerate()
                        .map(|(offset, member)| f(chunk_index * per + offset, member))
                        .collect()
                })
            })
            .collect();
        per_thread = handles
            .into_iter()
            .map(|h| h.join().expect("par2gen member scanner panicked"))
            .collect();
    });
    let mut out = Vec::with_capacity(members.len());
    for result in per_thread {
        out.extend(result?);
    }
    Ok(out)
}

/// The recovery fold starts from the head scan's file-id order while the full
/// scan runs beside it. Compare identities by their ORIGINAL member index
/// rather than comparing only the final sorted Main packet: two same-length
/// members could otherwise exchange contents and leave the set of file ids
/// unchanged while the fold's coefficient order had changed.
fn heads_match_scanned(heads: &[(usize, u64, [u8; 16], [u8; 16])], scanned: &[Scanned]) -> bool {
    heads.len() == scanned.len()
        && heads.iter().all(|&(i, length, md5_16k, file_id)| {
            scanned.get(i).is_some_and(|actual| {
                actual.length == length && actual.md5_16k == md5_16k && actual.file_id == file_id
            })
        })
}

/// The identity of a member without hashing its body: length, the
/// 16 KiB head digest, and the file id derived from them - all a
/// creator needs to fix the input-slice ORDER (Main lists ids sorted)
/// before the whole-file and block hashes exist. Sixteen KiB per
/// member, so it is cheap enough to run serially ahead of everything.
fn scan_head(m: &Member) -> Result<(u64, [u8; 16], [u8; 16]), Par2GenError> {
    let f = std::fs::File::open(&m.path).map_err(io(&m.path))?;
    let length = f.metadata().map_err(io(&m.path))?.len();
    // Clamp in u64 before narrowing. On a 32-bit target, narrowing a
    // 4-GiB-aligned file length first produces zero and hashes an empty
    // identity prefix instead of the required first 16 KiB.
    let mut buf = vec![0u8; scan_head_len(length)];
    crate::disk::read_exact_at(&f, &mut buf, 0).map_err(io(&m.path))?;
    let md5_16k: [u8; 16] = Md5::digest(&buf).into();
    let mut id = Md5::new();
    id.update(md5_16k);
    id.update(length.to_le_bytes());
    // The UNPADDED name - see `finish_scan` for the whole story.
    id.update(m.name.as_bytes());
    Ok((length, md5_16k, id.finalize().into()))
}

/// The sort key a PAR2 file id carries, and the ONE spelling of it.
///
/// # A file id sorts as a 16-byte LITTLE-ENDIAN number
///
/// Not lexicographically. The spec's Main packet lists the recovery-set
/// ids in ascending order, and "ascending" there means the numeric order
/// of the id read little-endian - compare from the LAST byte back - so
/// `df10..28` sorts before `7404..50` because 0x28 < 0x50, where a
/// bytewise sort puts them the other way round.
///
/// That order is not cosmetic: `Par2Set::files` IS the global input
/// slice index space, laid out by walking the Main list, so every
/// recovery constant is keyed to it. Getting it wrong changes the
/// recovery DATA.
///
/// # Why nothing caught it until 3 Sep 2026
///
/// A set built under the wrong order SELF-VERIFIES, and so does every
/// repair from it, because each tool reads the order out of the Main
/// packet it was handed rather than deriving one. Our own reader agreed
/// with our own writer; par2cmdline agreed with both, on our sets and on
/// its own. Only a byte-level diff against the reference over a set with
/// at least two members whose ids straddle the difference shows it - the
/// conformance harness's first such set, and the trap was already
/// written down in `~/Claude/parfast/HANDOFF.md`, from the standalone
/// build that hit it in August and never had a way to carry the finding
/// back into this engine. That is the copy this crate's `parfast` front
/// exists to end.
fn id_order(id: &[u8; 16]) -> [u8; 16] {
    let mut k = *id;
    k.reverse();
    k
}

/// The identity half of a scan, shared by the serial and fan-out paths
/// so the file id is spelled once.
fn finish_scan(
    m: &Member,
    length: u64,
    md5_whole: [u8; 16],
    md5_16k: [u8; 16],
    blocks: Vec<([u8; 16], u32)>,
) -> Scanned {
    let name_padded = pad4(m.name.as_bytes().to_vec());
    // File id = MD5(md5_16k | length | name), over the name WITHOUT its
    // null padding. The stored id is authoritative on the read side
    // (readers key Main/FileDesc/IFSC by it and never recompute), but it
    // has to be RIGHT here or a conforming reader that does recompute
    // rejects the set.
    //
    // IT WAS NOT, until 3 Sep 2026: both hashes here fed `name_padded`,
    // so every member whose name length is not already a multiple of 4
    // got an id derived from trailing NULs the spec does not hash. A
    // name of 4, 8 or 12 characters padded to itself and came out right,
    // which is why nothing caught it - the fixture names in this
    // repository's own par2gen tests are `text.txt`, `data.bin`,
    // `movie.mkv`: eight and eight and nine, and the nine-character one
    // never had its id checked against the reference. The conformance
    // harness found it on the first two-member set with a five-character
    // name in it (`a.bin`), 3 Sep 2026: par2cmdline-turbo's FileDesc
    // packets for the same bytes carried a different id, and the
    // reference's matched `par2::filedesc_id` - this crate's own READER
    // - while ours did not.
    //
    // What it cost: nothing that self-verifies. Every reader takes the
    // id out of the packet, so our sets were internally consistent and
    // par2cmdline verified and repaired them (which is what the interop
    // suite proves and why it stayed green). What it cost was
    // CONFORMANCE - a reader that recomputes would reject the set - and
    // byte-identity with the reference, because the Main packet sorts
    // members by id, so a wrong id also permutes the global slice index
    // space and therefore every recovery constant.
    let mut id = Md5::new();
    id.update(md5_16k);
    id.update(length.to_le_bytes());
    id.update(m.name.as_bytes());

    Scanned {
        name_padded,
        file_id: id.finalize().into(),
        md5_whole,
        md5_16k,
        length,
        blocks,
    }
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

/// How the recovery slices are split across volume files.
///
/// `Variable` is what nzbfast itself posts and what par2cmdline writes
/// when neither `-u` nor `-n` is given; `Even` is the shape those two
/// switches ask for, and exists because parfast is a drop-in and a
/// switch that parses but does not steer the output is the divergence
/// the spec calls worse than an honest refusal (section 5, R.2).
/// Measured against par2cmdline 1.3.0 on 3 Sep 2026 and recorded in
/// `research/CLI-SUBSTITUTION-2026-09-03.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumePlan {
    /// Exponentially growing counts (1, 2, 4, 8, …), so a client that
    /// wants a little parity fetches one small volume rather than the
    /// whole set.
    Variable,
    /// Exactly this many volumes, the recovery count spread as evenly as
    /// it divides and the remainder handed to the EARLIEST volumes -
    /// which is the order par2cmdline uses: 20 blocks over 3 volumes is
    /// 7, 7, 6 and never 6, 7, 7.
    Even(usize),
}

/// How many copies of the critical block a volume file carries, and
/// where.
///
/// `Head` is one copy at the front, which is what nzbfast posts: the
/// packets are on Usenet either way and a second copy inside the same
/// volume buys a downloader nothing it cannot get from the next
/// article. `Interleaved` is par2cmdline's shape - the block repeated
/// through the file, so a volume truncated anywhere still yields a
/// nameable set - and exists because `parfast` is a drop-in and four
/// e2e fixtures turn on the volume SIZE the repetition produces
/// (research/CLI-SUBSTITUTION-2026-09-03.md, G2). It is opt-in for
/// exactly that reason: it multiplies the critical bytes in every
/// volume, and on a file-heavy set the critical block is the larger
/// half of what a volume weighs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CriticalLayout {
    /// One copy, at offset 0, then the recovery packets.
    Head,
    /// A recovery packet first, then critical packets, repeating - the
    /// distribution measured off par2cmdline 1.3.0 and pinned in
    /// [`interleave_schedule`].
    Interleaved,
}

/// Everything about a create that is a LAYOUT choice rather than a
/// property of the payload: how the recovery slices are split into
/// volumes, and how many copies of the critical block each volume
/// carries.
///
/// One value threaded through one parameter, so a third layout knob
/// lands here rather than growing a third argument. Every engine caller
/// wants [`CreatePlan::ENGINE`]; the drop-in CLI is the only thing that
/// asks for anything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreatePlan {
    /// How the recovery slices are split across volume files.
    pub volumes: VolumePlan,
    /// How many copies of the critical block each volume carries.
    pub critical: CriticalLayout,
    /// The exponent the FIRST recovery slice carries.
    ///
    /// Zero for everything nzbfast posts. par2cmdline's `-f` names it,
    /// so a user can create a set that COMPLEMENTS one they already
    /// have rather than restating it: `-f16 -c16` beside an existing
    /// 0..15 set gives thirty-two distinct blocks, where starting at 0
    /// again would give sixteen blocks twice over and volume names that
    /// collide with the existing files.
    ///
    /// The exponent is already absolute everywhere below this - the
    /// fold raises `pow2(log * first)`, the NTT prunes rows
    /// `first..first + count`, and the writer stamps `e` into the
    /// packet - so this only has to move where `volume_layout` starts
    /// counting.
    pub first_exponent: usize,
    /// The largest number of recovery slices ONE volume may carry, or
    /// `None` for no limit beyond the memory cap.
    ///
    /// par2cmdline's `-l` ("limit the size of the recovery files"),
    /// which is a bound on a volume's SIZE expressed in slices: no
    /// recovery file larger than the largest input file. It is a
    /// ceiling and never a target, so it cannot make a volume bigger
    /// and it does not change the plan when the plan already fits.
    pub max_blocks_per_volume: Option<usize>,
}

impl CreatePlan {
    /// What nzbfast itself posts, and what every caller inside the
    /// engine uses: the exponential split, one critical block per file,
    /// exponents from zero, no size ceiling of its own.
    pub const ENGINE: CreatePlan = CreatePlan {
        volumes: VolumePlan::Variable,
        critical: CriticalLayout::Head,
        first_exponent: 0,
        max_blocks_per_volume: None,
    };

    /// This plan with a different volume split.
    pub const fn with_volumes(self, volumes: VolumePlan) -> CreatePlan {
        CreatePlan { volumes, ..self }
    }

    /// This plan with a different critical-block layout.
    pub const fn with_critical(self, critical: CriticalLayout) -> CreatePlan {
        CreatePlan { critical, ..self }
    }

    /// This plan starting at a different recovery exponent.
    pub const fn with_first_exponent(self, first_exponent: usize) -> CreatePlan {
        CreatePlan {
            first_exponent,
            ..self
        }
    }

    /// This plan with a ceiling on one volume's slice count.
    pub const fn with_max_blocks_per_volume(self, max: Option<usize>) -> CreatePlan {
        CreatePlan {
            max_blocks_per_volume: max,
            ..self
        }
    }
}

/// How many volumes the `Variable` plan produces for `n_recovery`
/// slices - the term count of 1, 2, 4, 8, … - which is also the volume
/// count par2cmdline's `-u` asks for when no `-n` names one.
pub fn variable_volume_count(n_recovery: usize) -> usize {
    let (mut left, mut size, mut n) = (n_recovery, 1usize, 0usize);
    while left > 0 {
        let take = size.min(left);
        left -= take;
        n += 1;
        size = size.saturating_mul(2);
    }
    n
}

/// Volume layout for `n_recovery` slices under `plan`.
///
/// Capped at `max_per_vol` so one volume's accumulators always fit the
/// memory budget. THE CAP OUTRANKS THE PLAN: an `Even` split whose
/// volumes would not fit is widened into more volumes rather than
/// spilling the budget, so a caller asking for `-n2` over a set too
/// large for two volumes gets more of them, not an allocation failure.
fn volume_layout(
    n_recovery: usize,
    max_per_vol: usize,
    plan: VolumePlan,
    first_exponent: usize,
) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    match plan {
        VolumePlan::Variable => {
            let (mut first, mut want) = (0usize, 1usize);
            while first < n_recovery {
                let count = want.min(max_per_vol).min(n_recovery - first);
                out.push((first, count));
                first += count;
                want = want.saturating_mul(2);
            }
        }
        VolumePlan::Even(k) => {
            let k = k.clamp(1, n_recovery.max(1));
            let (base, rem) = (n_recovery / k, n_recovery % k);
            let mut first = 0usize;
            for i in 0..k {
                let mut want = base + usize::from(i < rem);
                while want > 0 {
                    let count = want.min(max_per_vol);
                    out.push((first, count));
                    first += count;
                    want -= count;
                }
            }
        }
    }
    // The split above is over the SHAPE - how many slices per volume -
    // and is independent of where the exponents start, so the offset is
    // applied once, here, rather than threaded through both arms.
    if first_exponent > 0 {
        for (first, _) in &mut out {
            *first += first_exponent;
        }
    }
    out
}

/// How many critical packets follow each recovery packet in one
/// interleaved volume of `count` slices, over a critical block of
/// `n_cycle` packets (everything but the Creator).
///
/// MEASURED off par2cmdline 1.3.0 on 4 Sep 2026, by dumping the packet
/// order of real volumes at counts 1, 2, 4, 5, 8, 16, 23, 32 and 64
/// over one- and three-member sets, and reproduced exactly by two
/// rules:
///
/// * the file carries `copies` whole copies of the block, where
///   `copies` is the BIT LENGTH of `count` - 1 slice gets 1 copy, 2
///   gets 2, 4 gets 3, 23 gets 5, 64 gets 7. A big volume is not
///   proportionally more redundant, it is logarithmically more;
/// * the `copies * n_cycle` packets are spread over the slices by the
///   running total `floor((i + 1) * total / count)`, which is why 12
///   packets over 8 slices come out 1, 2, 1, 2, 1, 2, 1, 2 rather than
///   4 fours or a block of ones followed by a block of twos.
///
/// The packets themselves are taken cyclically from the block in its
/// own order, restarting at the Main packet in every file - and since
/// the total is a whole number of copies, the cycle always closes.
fn interleave_schedule(count: usize, n_cycle: usize) -> Vec<usize> {
    debug_assert!(count > 0, "a volume file holds at least one slice");
    let copies = (usize::BITS - count.leading_zeros()) as usize;
    let total = copies.saturating_mul(n_cycle);
    let mut out = Vec::with_capacity(count);
    let mut done = 0usize;
    for i in 0..count {
        // u128 because a pathological file-heavy set can put the
        // product past 64 bits, and a wrapped target would silently
        // drop every remaining copy.
        let target = ((i as u128 + 1) * total as u128 / count as u128) as usize;
        out.push(target - done);
        done = target;
    }
    debug_assert_eq!(done, total, "the last slice closes the last copy");
    out
}

/// The packet boundaries inside a critical block: every packet that
/// takes part in the interleave cycle, and the trailing Creator packet
/// that does not.
///
/// Walks the block we just built rather than being handed offsets by
/// the builder, so the two cannot drift apart as packets are added -
/// and the walk is total because the input is our own output.
struct CriticalIndex {
    /// `(offset, len)` of Main, every FileDesc and every IFSC packet,
    /// in the order the block holds them.
    cycle: Vec<(usize, usize)>,
    /// `(offset, len)` of the Creator packet, which every file carries
    /// exactly once, at its end.
    creator: (usize, usize),
}

fn critical_index(critical: &[u8]) -> CriticalIndex {
    let mut cycle = Vec::new();
    let mut creator = None;
    let mut off = 0usize;
    while off + 64 <= critical.len() {
        let len =
            u64::from_le_bytes(critical[off + 8..off + 16].try_into().expect("8 bytes")) as usize;
        debug_assert!(len >= 64 && off + len <= critical.len(), "our own packet");
        if &critical[off + 48..off + 64] == TYPE_CREATOR {
            creator = Some((off, len));
        } else {
            cycle.push((off, len));
        }
        // `.max(64)` is termination insurance and nothing else: a
        // declared length below the header size cannot come out of
        // `critical_packets`, and a release build with the assertion
        // compiled out must still not spin on one.
        off += len.max(64);
    }
    debug_assert_eq!(off, critical.len(), "the walk consumed the whole block");
    CriticalIndex {
        cycle,
        creator: creator.expect("the critical block ends with a Creator packet"),
    }
}

/// Where a finished file's copies of the critical block sit, so the
/// real block can be written over the placeholder once the member
/// hashes land.
enum CriticalPatch {
    /// One copy at offset 0 - the index file, and every volume the
    /// [`CriticalLayout::Head`] layout writes.
    Head,
    /// The file offset of every critical PACKET copy, in write order;
    /// the k-th of them is `CriticalIndex::cycle[k % cycle.len()]`.
    /// RECORDED by the writer rather than recomputed here, so the patch
    /// cannot disagree with what was written.
    Interleaved(Vec<u64>),
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
    create_into_inner(dir, members, base, spec, None, CreatePlan::ENGINE)
}

/// [`create_into`] with an EXACT recovery slice count instead of a
/// percentage.
///
/// A percentage cannot express one, and par2cmdline's `-c<n>` asks for
/// exactly n. `parfast`, the drop-in over this engine, converted its
/// count into a percentage for one afternoon and the round trip rounded
/// twice: measured on the conformance payload (1,774 input slices, a
/// default 5% set) it asked for 90 recovery blocks and got 108. The
/// volume split follows the count, so every recovery file name moved
/// with it and the whole create half of the conformance table diverged.
///
/// `0` is the index-only set `redundancy_pct == 0` describes. Every
/// caller inside the engine wants the percentage and should keep using
/// [`create_into`]; this door exists for a command line that has a
/// number.
///
/// `plan` carries the layout choices a drop-in command line has to be
/// able to make and the engine never does: the volume split that
/// par2cmdline's `-u` and `-n` steer, and whether each volume repeats
/// the critical block the way par2cmdline does. Every engine caller
/// wants [`CreatePlan::ENGINE`], which is the shape the set nzbfast
/// posts has always had.
pub fn create_into_exact(
    dir: &Path,
    members: &[Member],
    base: &str,
    block_size: Option<u64>,
    recovery_blocks: usize,
    plan: CreatePlan,
) -> Result<Vec<String>, Par2GenError> {
    let spec = Par2Spec {
        redundancy_pct: 0,
        block_size,
    };
    create_into_inner(dir, members, base, &spec, Some(recovery_blocks), plan)
}

/// The one implementation. `exact_recovery` overrides
/// `spec.redundancy_pct` when it is `Some`.
fn create_into_inner(
    dir: &Path,
    members: &[Member],
    base: &str,
    spec: &Par2Spec,
    exact_recovery: Option<usize>,
    plan: CreatePlan,
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
    // The exponent field is 16 bits and the generator field's order is
    // 65535, so an exponent at or past it is not a large set - it is a
    // different, wrong slice. Refused here rather than wrapped, because
    // wrapping would silently emit a volume whose blocks duplicate ones
    // already in the set it was meant to complement.
    if let Some(last) = plan
        .first_exponent
        .checked_add(exact_recovery.unwrap_or(0))
        .filter(|&n| n > 65535)
    {
        return Err(Par2GenError::Other(format!(
            "recovery exponents {}..{} run past the PAR2 limit of 65535",
            plan.first_exponent, last
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

    // `NZBFAST_REPAIR_TIMING=1` prints the create's phase split on the
    // repair path's own key, so the two engines are read the same way.
    let timing = std::env::var_os("NZBFAST_REPAIR_TIMING").is_some();
    let t0 = std::time::Instant::now();

    // Recovery needs the head digest early to put input slices in file-id
    // order while the full hashes run beside the fold. Index-only creation has
    // no fold to overlap and can defer that digest to the one full scan, so it
    // reads lengths alone. Either way this is the ONE prepass: the metadata
    // loop, the head loop and the scan's own stat used to be three.
    let wants_recovery = exact_recovery.map_or(spec.redundancy_pct != 0, |n| n != 0);
    let mut heads = if !wants_recovery {
        None
    } else {
        Some(scan_heads(members)?)
    };
    let lengths: Vec<u64> = match &heads {
        Some(heads) => heads.iter().map(|&(_, length, _, _)| length).collect(),
        None => scan_lengths(members)?,
    };
    let Some(total) = lengths
        .iter()
        .try_fold(0u64, |total, &length| total.checked_add(length))
    else {
        return Err(Par2GenError::Other(
            "the total PAR2 member length overflowed u64".into(),
        ));
    };
    let block_size = match spec.block_size {
        Some(bs) => {
            if bs == 0 || !bs.is_multiple_of(4) || bs > MAX_BLOCK_SIZE {
                return Err(Par2GenError::Other(format!(
                    "PAR2 block size {bs} must be a positive multiple of 4 no larger than \
                     {MAX_BLOCK_SIZE}"
                )));
            }
            bs
        }
        None => default_block_size(total),
    };

    // Count in the on-disk width and validate BEFORE narrowing. On 32-bit, a
    // 16 GiB file at the four-byte minimum has 2^32 slices, and casting each
    // quotient to usize first wrapped that impossible request to zero.
    let Some(n_slices_u64) = lengths.iter().try_fold(0u64, |total, &length| {
        total.checked_add(length.div_ceil(block_size))
    }) else {
        return Err(Par2GenError::Other(
            "the PAR2 input-slice count overflowed u64".into(),
        ));
    };
    if n_slices_u64 > MAX_INPUT_SLICES as u64 {
        return Err(Par2GenError::Other(format!(
            "{n_slices_u64} input slices at a {block_size}-byte block exceeds the PAR2 \
             limit of {MAX_INPUT_SLICES} - raise the block size"
        )));
    }
    let n_slices = n_slices_u64 as usize;

    let n_recovery_u64 = match exact_recovery {
        Some(n) => n as u64,
        None if spec.redundancy_pct == 0 => 0,
        None => n_slices_u64
            .saturating_mul(spec.redundancy_pct as u64)
            .div_ceil(100)
            .max(1),
    };
    // Every recovery slice needs its own exponent against the same
    // coprime sequence the input slices walk, so the input limit is the
    // practical ceiling here too.
    if n_recovery_u64 > MAX_INPUT_SLICES as u64 {
        return Err(Par2GenError::Other(format!(
            "{n_recovery_u64} recovery slices exceeds the PAR2 limit of {MAX_INPUT_SLICES} \
             - lower the redundancy or raise the block size"
        )));
    }
    let n_recovery = n_recovery_u64 as usize;
    if n_recovery > 0 && n_slices == 0 {
        return Err(Par2GenError::Other(
            "a set of only 0-byte members has no slices to build parity over - post it \
             at zero redundancy"
                .into(),
        ));
    }

    // Claim this create's share of the process's create budget for the whole
    // of the body below, by any exit. Held from here rather than from the top
    // of the function so a request refused for its shape never charges the
    // gauge, and taken before the first scan because the scan is the first
    // thing that allocates against it.
    let admission = CreateAdmission::acquire();

    // With no recovery packets there is no reason to prebuild a placeholder
    // critical block and overwrite it after the scan. Scan once, sort by the
    // resulting file ids, and write the finished index once.
    if n_recovery == 0 {
        let mut scanned = scan_all(members, &lengths, block_size, admission.scan_pool)?;
        scanned.sort_by_key(|s| id_order(&s.file_id));
        let (_, critical) = critical_packets(&scanned, block_size);
        let index = format!("{base}.par2");
        std::fs::write(dir.join(&index), &critical).map_err(io(&dir.join(&index)))?;
        if timing {
            tracing::info!(target: "repair-timing", "create index-only scan: {:.2?}", t0.elapsed());
        }
        return Ok(vec![index]);
    }

    // Main lists file ids sorted, and that order defines the global
    // input-slice index space the RS constants are assigned along - so
    // the caller's order and the slice order are deliberately two
    // different things. The id needs only the 16 KiB head, so the
    // order is fixed HERE, before the body hashes exist, which is what
    // lets the recovery fold start alongside the hashing below.
    let mut heads = heads.take().expect("recovery sets scanned their heads");
    heads.sort_by_key(|&(_, _, _, id)| id_order(&id));
    let slots: Vec<(PathBuf, u64)> = heads
        .iter()
        .map(|&(i, length, _, _)| (members[i].path.clone(), length))
        .collect();

    // The critical block's SHAPE - and the set id, which is the MD5 of
    // the Main body (block size, count, sorted file ids) and nothing
    // else - are known from the heads alone. So the recovery packets
    // can be sealed and every volume written while the member hashes
    // are still being computed, with a placeholder critical block of
    // exactly the right length at the front of each file, backfilled
    // with the real one once the hashing thread joins. That is what
    // lets the whole-file MD5 chains - the create's one sequential cost
    // - overlap every recovery batch instead of only the first: on a
    // 23 GB single-member set they were 31 s that the fold waited on.
    let placeholder: Vec<Scanned> = heads
        .iter()
        .map(|&(i, length, md5_16k, file_id)| Scanned {
            name_padded: pad4(members[i].name.as_bytes().to_vec()),
            file_id,
            md5_whole: [0u8; 16],
            md5_16k,
            length,
            blocks: vec![([0u8; 16], 0u32); length.div_ceil(block_size) as usize],
        })
        .collect();
    let (set_id, critical_shape) = critical_packets(&placeholder, block_size);
    let index = format!("{base}.par2");
    let mut out: Vec<(String, CriticalPatch)> = vec![(index.clone(), CriticalPatch::Head)];
    std::fs::write(dir.join(&index), &critical_shape).map_err(io(&dir.join(&index)))?;
    // Only the interleave needs the packet boundaries, and on a
    // file-heavy set walking them is tens of thousands of headers.
    let cidx = matches!(plan.critical, CriticalLayout::Interleaved)
        .then(|| critical_index(&critical_shape));

    // The memory cap and `-l`'s size ceiling are the same KIND of bound
    // - "no volume larger than this" - so they meet as a min and the
    // tighter one wins. `-l` can only ever make volumes smaller, which
    // is why it cannot widen past the budget.
    let per_batch = (admission.accum / block_size).max(1) as usize;
    let per_vol = plan
        .max_blocks_per_volume
        .map_or(per_batch, |l| per_batch.min(l.max(1)));
    let layout = volume_layout(n_recovery, per_vol, plan.volumes, plan.first_exponent);
    // One large regular member whose recovery rows fit ONE fold batch, below
    // the NTT crossover, can take its checksums straight off the arenas the
    // fold is already reading, which removes the create's remaining second
    // pass over the payload. Everything else - several members, several
    // batches, the transform, small sets, non-unix - keeps the established
    // overlapped scan. Lane B's own multi-member prototype was decisively
    // slower (0.7-1.0 s to about 1.9 s), which is why the gate is exactly one
    // member even under its research override.
    let fuse = std::env::var("NZBFAST_PAR2GEN_FUSE").ok();
    let forced = matches!(fuse.as_deref(), Some("1") | Some("on"));
    let eligible_shape = source_fusion_shape_admitted(members.len(), n_recovery, per_batch)
        && !matches!(fuse.as_deref(), Some("0") | Some("off"))
        // The fused arm is written for the whole set in ONE batch
        // starting at exponent 0, and it asserts both. A `-f` set starts
        // somewhere else, so it takes the ordinary overlapped scan - a
        // complementary create is a rare hand-run command and not a
        // shape worth teaching the fast path.
        && plan.first_exponent == 0
        && (forced
            || (total >= FUSED_SOURCE_MIN_BYTES && block_size >= FUSED_SOURCE_MIN_BLOCK_BYTES));
    // Ask the transform's exact dispatcher rather than approximating it with
    // an input-count threshold, and do not even price the NTT for shapes
    // fusion cannot capture - that keeps the multi-member, multi-batch and
    // non-unix paths literally unchanged. An NTT-eligible shape stays
    // byte-for-byte on the established overlapped scan.
    let create_ntt_admitted =
        eligible_shape && create_ntt_window(block_size as usize, n_slices, 0, n_recovery).is_some();
    // Keep high-row folds on their established scan lane even when a tight
    // NTT retention budget refuses the transform. At 8,193 x 1 MiB and 328
    // rows, lane B measured broad fusion saving the extra read and 7.7% RSS
    // for only 1.1% of wall while adding 3.0% of cycles; the low-row band
    // below the crossover is the conservative win.
    let fuse_admitted =
        eligible_shape && !create_ntt_admitted && source_fusion_rows_admitted(n_slices, n_recovery);
    let mut fused_scan = if fuse_admitted {
        FusedScan::open(heads[0].1, heads[0].2, &members[0], block_size)?
    } else {
        None
    };
    let mut fused_res: Option<Result<Vec<Scanned>, Par2GenError>> = None;
    let mut scan_res: Result<Vec<Scanned>, Par2GenError> = Ok(Vec::new());
    let batches: Result<(), Par2GenError> = std::thread::scope(|sc| {
        let h = if fused_scan.is_none() {
            Some(sc.spawn(|| {
                let mut scanned = scan_all(members, &lengths, block_size, admission.scan_pool)?;
                if !heads_match_scanned(&heads, &scanned) {
                    return Err(Par2GenError::Other(
                        "member identity changed between the head scan and the hash scan - a \
                         file was modified while the set was being built"
                            .into(),
                    ));
                }
                scanned.sort_by_key(|s| id_order(&s.file_id));
                Ok(scanned)
            }))
        } else {
            None
        };
        let mut body = || -> Result<(), Par2GenError> {
            // Group whole volumes into batches that share one pass over
            // the payload: a batch costs `slices * block_size` of
            // accumulator, and one volume already fits by construction.
            let mut vi = 0usize;
            while vi < layout.len() {
                let mut vj = vi;
                let mut held = 0usize;
                while vj < layout.len() && (held == 0 || held + layout[vj].1 <= per_batch) {
                    held += layout[vj].1;
                    vj += 1;
                }
                let first = layout[vi].0;
                let t_batch = std::time::Instant::now();
                let slices = if let Some(scan) = fused_scan.as_mut() {
                    debug_assert_eq!(first, 0);
                    debug_assert_eq!(held, n_recovery);
                    let slices = recovery_slices(
                        &slots,
                        block_size,
                        n_slices,
                        first,
                        held,
                        READ_BUDGET,
                        Some(scan),
                    )?;
                    let finished = fused_scan.take().expect("the fused scan was present");
                    fused_res = Some(finished.finish(&members[0]).map(|s| vec![s]));
                    slices
                } else {
                    recovery_slices(&slots, block_size, n_slices, first, held, READ_BUDGET, None)?
                };
                if timing {
                    tracing::info!(
                        target: "repair-timing",
                        "create recovery batch {first}+{held}: {:.2?} (total {:.2?})",
                        t_batch.elapsed(),
                        t0.elapsed()
                    );
                }
                // Volumes of one batch are sealed and written across
                // threads: each is its own packet stream over its own
                // slice range, and serially the 111 MB of a 10% set over
                // 1 GiB cost ~170 ms of a 1.1 s create (measured 2 Sep
                // 2026, M3 Ultra) - the MD5 seal of every recovery packet
                // is the larger half of that.
                let names: Vec<String> = layout[vi..vj]
                    .iter()
                    .map(|&(vfirst, count)| format!("{base}.vol{vfirst:03}+{count:02}.par2"))
                    .collect();
                let mut written: Vec<Option<Result<CriticalPatch, Par2GenError>>> =
                    (0..names.len()).map(|_| None).collect();
                std::thread::scope(|wsc| {
                    for ((&(vfirst, count), name), slot) in
                        layout[vi..vj].iter().zip(&names).zip(written.iter_mut())
                    {
                        let critical = &critical_shape;
                        let slices = &slices;
                        let set_id = &set_id;
                        let cidx = cidx.as_ref();
                        wsc.spawn(move || {
                            let path = dir.join(name);
                            let result = (|| -> std::io::Result<CriticalPatch> {
                                let file = std::fs::File::create(&path)?;
                                // Fine-sliced sets feed many 4 KiB packets, so
                                // coalesce their small writes; a large slice
                                // bypasses the buffer and streams straight out
                                // of the accumulator with no volume-sized copy.
                                let mut writer = std::io::BufWriter::with_capacity(1 << 20, file);
                                let Some(cidx) = cidx else {
                                    std::io::Write::write_all(&mut writer, critical)?;
                                    for i in 0..count {
                                        let e = vfirst + i;
                                        let slice = crate::gf16::words_as_bytes(&slices[e - first]);
                                        write_recovery_packet(
                                            &mut writer,
                                            set_id,
                                            e as u32,
                                            slice,
                                        )?;
                                    }
                                    std::io::Write::flush(&mut writer)?;
                                    return Ok(CriticalPatch::Head);
                                };
                                // par2cmdline's shape: a recovery packet, then
                                // however many critical packets the schedule
                                // owes at that point, and the Creator once at
                                // the end. Offsets are recorded as they are
                                // written, so the backfill patches exactly what
                                // this loop laid down.
                                let after = interleave_schedule(count, cidx.cycle.len());
                                let mut offsets = Vec::with_capacity(after.iter().sum::<usize>());
                                let mut pos = 0u64;
                                let mut turn = 0usize;
                                for (i, owed) in after.iter().enumerate() {
                                    let e = vfirst + i;
                                    let slice = crate::gf16::words_as_bytes(&slices[e - first]);
                                    write_recovery_packet(&mut writer, set_id, e as u32, slice)?;
                                    pos += 68 + slice.len() as u64;
                                    for _ in 0..*owed {
                                        let (o, l) = cidx.cycle[turn % cidx.cycle.len()];
                                        std::io::Write::write_all(
                                            &mut writer,
                                            &critical[o..o + l],
                                        )?;
                                        offsets.push(pos);
                                        pos += l as u64;
                                        turn += 1;
                                    }
                                }
                                let (o, l) = cidx.creator;
                                std::io::Write::write_all(&mut writer, &critical[o..o + l])?;
                                std::io::Write::flush(&mut writer)?;
                                Ok(CriticalPatch::Interleaved(offsets))
                            })();
                            *slot = Some(result.map_err(io(&path)));
                        });
                    }
                });
                for (name, w) in names.into_iter().zip(written) {
                    let patch = w.expect("volume writer filled its slot")?;
                    out.push((name, patch));
                }
                vi = vj;
            }
            Ok(())
        };
        let r = body();
        if let Some(h) = h {
            scan_res = h.join().expect("par2gen scan worker panicked");
        }
        r
    });
    let mut scanned = match fused_res {
        Some(r) => r?,
        None => scan_res?,
    };
    batches?;
    scanned.sort_by_key(|s| id_order(&s.file_id));
    if timing {
        tracing::info!(target: "repair-timing", "create scan + fold: {:.2?}", t0.elapsed());
    }
    let (real_set_id, critical) = critical_packets(&scanned, block_size);
    // Same ids, lengths and names in the same order, so the same Main
    // body, the same set id, and a critical block of the same length:
    // the placeholder's shape is what every file was sized for.
    if real_set_id != set_id || critical.len() != critical_shape.len() {
        return Err(Par2GenError::Other(
            "member identity changed between the head scan and the hash scan - a file was \
             modified while the set was being built"
                .into(),
        ));
    }
    // Backfill: the real critical block over the placeholder - at the
    // front of the index and of every `Head` volume, and at each
    // recorded packet offset of an interleaved one. The placeholder and
    // the real block hold the same packets at the same lengths (the
    // check above is what makes that true), so a recorded offset still
    // names the packet it named when it was written.
    for (name, patch) in &out {
        let path = dir.join(name);
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .map_err(io(&path))?;
        match patch {
            CriticalPatch::Head => {
                crate::disk::write_all_at(&f, &critical, 0).map_err(io(&path))?;
            }
            CriticalPatch::Interleaved(offsets) => {
                let cidx = cidx.as_ref().expect("an interleaved file had an index");
                for (k, &at) in offsets.iter().enumerate() {
                    let (o, l) = cidx.cycle[k % cidx.cycle.len()];
                    crate::disk::write_all_at(&f, &critical[o..o + l], at).map_err(io(&path))?;
                }
            }
        }
    }
    Ok(out.into_iter().map(|(name, _)| name).collect())
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

    let creator = pad4(format!("nzbfast {}", env!("CARGO_PKG_VERSION")).into_bytes());
    // Pre-size the whole critical block: on a file-heavy set this is tens of
    // thousands of packets, and growing the buffer per packet copied it again
    // and again.
    let member_bytes: usize = scanned
        .iter()
        .map(|s| {
            64 + 56
                + s.name_padded.len()
                + if s.blocks.is_empty() {
                    0
                } else {
                    64 + 16 + s.blocks.len() * 20
                }
        })
        .sum();
    let expected_len = 64 + main_body.len() + member_bytes + 64 + creator.len();
    let mut critical = Vec::with_capacity(expected_len);
    append_packet(
        &mut critical,
        &set_id,
        TYPE_MAIN,
        main_body.len(),
        |packet| {
            packet.extend_from_slice(&main_body);
        },
    );
    // EVERY FileDesc, THEN every IFSC - not each member's pair together.
    //
    // The spec fixes no order and every reader takes the packets it
    // finds, so both layouts are valid and this one is chosen for one
    // reason: it is par2cmdline's, and it is the last thing between a
    // set written here and a set BYTE-IDENTICAL to the reference's over
    // the same input. With the file-id fixes above it, a `parfast`
    // create now reproduces par2cmdline-turbo's bytes exactly but for
    // the Creator packet, which names the writer by design
    // (`crates/parfast/tests/integration/creator_packet.rs`
    // is that claim, checked against the reference on every run that has
    // one). Interleaving cost nothing and bought nothing; this costs
    // nothing and buys the drop-in claim.
    for s in scanned {
        append_packet(
            &mut critical,
            &set_id,
            TYPE_FILEDESC,
            56 + s.name_padded.len(),
            |packet| {
                packet.extend_from_slice(&s.file_id);
                packet.extend_from_slice(&s.md5_whole);
                packet.extend_from_slice(&s.md5_16k);
                packet.extend_from_slice(&s.length.to_le_bytes());
                packet.extend_from_slice(&s.name_padded);
            },
        );
    }
    for s in scanned {
        // A 0-byte member has no slices, so it gets no IFSC packet - the
        // shape par2cmdline refuses to emit at all. Its FileDesc alone is
        // what names the placeholder on the way out.
        if s.blocks.is_empty() {
            continue;
        }
        append_packet(
            &mut critical,
            &set_id,
            TYPE_IFSC,
            16 + s.blocks.len() * 20,
            |packet| {
                packet.extend_from_slice(&s.file_id);
                for (m, c) in &s.blocks {
                    packet.extend_from_slice(m);
                    packet.extend_from_slice(&c.to_le_bytes());
                }
            },
        );
    }
    append_packet(
        &mut critical,
        &set_id,
        TYPE_CREATOR,
        creator.len(),
        |packet| {
            packet.extend_from_slice(&creator);
        },
    );
    debug_assert_eq!(critical.len(), expected_len);
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
/// A read-only private mapping of one member, for the transform to
/// read the payload in place: the page cache is the resident copy and
/// the kernel's to reclaim, so no retention budget applies and the
/// whole payload is ONE transform window. Unix only; elsewhere the
/// creator keeps the copied windows.
#[cfg(unix)]
struct MappedMember {
    ptr: *const u8,
    len: usize,
}

#[cfg(unix)]
impl MappedMember {
    fn open(path: &Path, len: u64) -> std::io::Result<Option<MappedMember>> {
        use std::os::unix::io::AsRawFd;
        if len == 0 {
            return Ok(None);
        }
        let f = std::fs::File::open(path)?;
        let len =
            usize::try_from(len).map_err(|_| std::io::Error::other("member too large to map"))?;
        // SAFETY: a fresh read-only private mapping of `len` bytes of an
        // open file we own; checked for MAP_FAILED below; unmapped in
        // Drop with the same length. The file is only ever read through
        // it while the mapping lives.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                f.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Some(MappedMember {
            ptr: ptr as *const u8,
            len,
        }))
    }
}

#[cfg(unix)]
impl Drop for MappedMember {
    fn drop(&mut self) {
        // SAFETY: the pointer and length are exactly what mmap returned.
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.len);
        }
    }
}

// SAFETY: the mapping is read-only and immutable for its lifetime; the
// transform's workers only read through it.
#[cfg(unix)]
unsafe impl Send for MappedMember {}
// SAFETY: as above - shared read-only access.
#[cfg(unix)]
unsafe impl Sync for MappedMember {}

/// Advance the whole-file/head chains and produce the per-block products from
/// the exact arena the recovery fold is reading. Block products use two narrow
/// lanes while the one ordered whole-file chain runs on this caller.
fn scan_fused_window(
    scan: &mut FusedScan,
    window: &[(usize, u64, usize)],
    arena: &[u8],
    bs: usize,
) {
    debug_assert!(window.iter().all(|&(mi, _, _)| mi == 0));
    let mut hashes = vec![([0u8; 16], 0u32); window.len()];
    // One whole-file MD5 chain already consumes this window on the caller.
    // Two block lanes are enough to keep the independent per-block MD5+CRC
    // work below that serial floor; a machine-wide pool here would nest under
    // the fold's own full pool and be recreated once per read window.
    let workers = 2.min(window.len());
    let per = window.len().div_ceil(workers);
    std::thread::scope(|sc| {
        for (hashes, bytes) in hashes
            .chunks_mut(per)
            .zip(arena.chunks(per.saturating_mul(bs)))
        {
            sc.spawn(move || {
                for (hash, block) in hashes.iter_mut().zip(bytes.chunks_exact(bs)) {
                    *hash = (Md5::digest(block).into(), crc32fast::hash(block));
                }
            });
        }
        for (&(_, _off, want), block) in window.iter().zip(arena.chunks_exact(bs)) {
            scan.whole.update(&block[..want]);
            if scan.head_left > 0 {
                let take = scan.head_left.min(want);
                scan.head.update(&block[..take]);
                scan.head_left -= take;
            }
        }
    });
    scan.blocks.extend_from_slice(&hashes);
}

fn recovery_slices(
    scanned: &[(PathBuf, u64)],
    block_size: u64,
    n_slices: usize,
    first: usize,
    count: usize,
    read_budget: u64,
    mut fused_scan: Option<&mut FusedScan>,
) -> Result<Vec<Vec<u16>>, Par2GenError> {
    let words = (block_size / 2) as usize;
    let logs = crate::par2repair::input_base_logs(n_slices)
        .map_err(|e| Par2GenError::Other(format!("assigning RS constants: {e}")))?;
    let mut acc: Vec<Vec<u16>> = vec![vec![0u16; words]; count];

    let bs = block_size as usize;
    let per_read = ((read_budget / block_size).max(1) as usize).min(n_slices);
    let mut arena = vec![0u8; per_read * bs];
    // The global slice list: (member, byte offset, want) in input-slice
    // order, so an arena-full is a contiguous window of it and the base
    // log of arena slot `k` is `logs[window_start + k]`.
    let mut plan: Vec<(usize, u64, usize)> = Vec::with_capacity(n_slices);
    for (mi, &(_, length)) in scanned.iter().enumerate() {
        let mut off = 0u64;
        while off < length {
            let want = (length - off).min(block_size) as usize;
            plan.push((mi, off, want));
            off += want as u64;
        }
    }
    debug_assert_eq!(plan.len(), n_slices);
    // Readers fan out over the window exactly as the repair feed does
    // (contiguous runs per reader, positional reads, one handle per
    // member per reader): the read used to be one thread's BufReader
    // walking the payload between folds, and on a 1 GiB set that was
    // ~300 ms of every pass against a fold of ~120 ms (measured 2 Sep
    // 2026, M3 Ultra, page-cached payload).
    let readers = crate::mem::cpu_workers().clamp(1, 8);
    // One window of the plan into `dst`, across readers.
    let read_window = |w0: usize,
                       w1: usize,
                       dst: &mut [u8],
                       pinned: Option<&std::fs::File>|
     -> Result<(), Par2GenError> {
        let window = &plan[w0..w1];
        let chunk = window.len().div_ceil(readers).max(1);
        let mut results: Vec<Result<(), Par2GenError>> = Vec::new();
        std::thread::scope(|sc| {
            let handles: Vec<_> = window
                .chunks(chunk)
                .zip(dst.chunks_mut(chunk * bs))
                .map(|(jobs, slots)| {
                    sc.spawn(move || -> Result<(), Par2GenError> {
                        let mut open: Option<(usize, std::fs::File)> = None;
                        for (k, &(mi, off, want)) in jobs.iter().enumerate() {
                            // A fused pass reads through the descriptor it
                            // pinned before the fold, so its snapshot is the
                            // one the checksums are taken over.
                            let f = if let Some(file) = pinned {
                                debug_assert_eq!(mi, 0);
                                file
                            } else {
                                if open.as_ref().is_none_or(|(o, _)| *o != mi) {
                                    let path = &scanned[mi].0;
                                    open = Some((mi, std::fs::File::open(path).map_err(io(path))?));
                                }
                                &open.as_ref().expect("just opened").1
                            };
                            let slot = &mut slots[k * bs..][..bs];
                            crate::disk::read_exact_at(f, &mut slot[..want], off)
                                .map_err(io(&scanned[mi].0))?;
                            // The tail block takes part in the arithmetic
                            // zero-padded, exactly as its checksum was
                            // taken - a repair that reconstructs it gets
                            // the padding back and truncates. Padded rather
                            // than handed over short, though the fold takes
                            // either: a full-width source stays on the fused
                            // kernel where a short one drops to the
                            // remainder path.
                            slot[want..].fill(0);
                        }
                        Ok(())
                    })
                })
                .collect();
            results = handles
                .into_iter()
                .map(|h| h.join().expect("par2gen reader panicked"))
                .collect();
        });
        for r in results {
            r?;
        }
        Ok(())
    };

    // The NTT, for the shapes the repair dispatcher admits it on. A
    // recovery slice IS syndrome row `e` over every input, so the
    // output-pruned transform the repair runs (`par2ntt`) produces rows
    // `first..first+count` directly, in O(n log n) against the fold's
    // O(n x count): measured 2 Sep 2026 on the M3 Ultra, the 64 KiB /
    // 16384-input / 1639-row shape folds in 3.1 s at the kernel's peak
    // (566 GB/s) and transforms in well under one.
    //
    // Creation has no verify-and-retry behind it the way a repair does -
    // a wrong recovery set is written and shipped - so the transform's
    // result is CHECKED before it is trusted: one row is re-folded over
    // the resident corpus (a 1-row fold, milliseconds) and compared word
    // for word; any difference throws the whole transform away and the
    // fold below recomputes every row. `NZBFAST_NTT=0` forces the fold.
    let needed = first + count;

    // The transform is linear in its inputs, so it runs over resident
    // WINDOWS of the payload with the outputs XORed together: a window
    // is what the retention budget allows (min(4 GiB, RAM/4) less the
    // workers' arenas), never the whole payload. That is what admits a
    // 23 GB member - 63 s on the fold against ParPar's 37 (2 Sep 2026,
    // M3 Ultra) - and it is what keeps the OOM guard exactly where it
    // was. The transform's per-window cost is measured in the audit
    // record (section 13): a window of NTT_WINDOW_MIN slices still
    // beats the fold at the row counts the outer gate admits, and a
    // payload that cannot fill one stays on the fold.

    // The fused caller deliberately enters only the copied fold path: an NTT
    // consumes stripe-wise source columns and cannot share a sequential hash
    // traversal without reading the mapping again.
    let ntt_window = create_ntt_window(bs, n_slices, first, count);
    let ntt_admitted = fused_scan.is_none() && ntt_window.is_some();
    let ntt_window = ntt_window.unwrap_or(0);
    // Mapped single window (unix): every full block is read straight
    // out of the members' mappings, only the members' tail blocks are
    // copied (zero-padded) into a side arena, and that arena is the one
    // thing bounded by the budget - a set of many small members is all
    // tails, and falls to the copied windows below. Measured 2 Sep 2026
    // (M3 Ultra, 23.4 GB member, 1,117 rows): seven copied windows of
    // 1,822 slices transformed in 25-37 s; the per-window cost is
    // dominated by the per-output combine stages, so one window is the
    // shape to be in.
    #[cfg(unix)]
    if ntt_admitted && !std::env::var_os("NZBFAST_PAR2GEN_MAP").is_some_and(|v| v == "0") {
        let tails = plan.iter().filter(|&&(_, _, want)| want != bs).count();
        let pad_ok = tails.saturating_mul(bs) <= ntt_window.saturating_mul(bs);
        if pad_ok {
            let t_ntt = std::time::Instant::now();
            let mut maps: Vec<Option<MappedMember>> = Vec::with_capacity(scanned.len());
            let mut map_err = None;
            for (path, length) in scanned {
                match MappedMember::open(path, *length) {
                    Ok(m) => maps.push(m),
                    Err(e) => {
                        map_err = Some(e);
                        break;
                    }
                }
            }
            if map_err.is_none() {
                let mut pad = vec![0u8; tails * bs];
                let mut table: Vec<*const u8> = Vec::with_capacity(n_slices);
                let mut pi = 0usize;
                for &(mi, off, want) in &plan {
                    if want == bs {
                        // SAFETY: `off + bs <= length` for a full block, and
                        // the mapping covers `length` bytes.
                        table.push(unsafe {
                            maps[mi].as_ref().expect("mapped").ptr.add(off as usize)
                        });
                    } else {
                        let slot = &mut pad[pi * bs..][..bs];
                        // SAFETY: `off + want <= length`; the mapping covers
                        // `length` bytes.
                        let src = unsafe {
                            std::slice::from_raw_parts(
                                maps[mi].as_ref().expect("mapped").ptr.add(off as usize),
                                want,
                            )
                        };
                        slot[..want].copy_from_slice(src);
                        table.push(slot.as_ptr());
                        pi += 1;
                    }
                }
                let present: Vec<(u32, crate::par2ntt::SrcId)> = logs
                    .iter()
                    .enumerate()
                    .map(|(i, &l)| (l, i as crate::par2ntt::SrcId))
                    .collect();
                if let Ok(ntt) = crate::par2ntt::FlatPlan::build(&present, needed) {
                    let (w, threads) = crate::par2repair::ntt_stripe_geometry(bs);
                    let stripes = words.div_ceil(w);
                    struct Rows(Vec<*mut u16>);
                    // SAFETY: raw pointers into the accumulator rows; workers
                    // write disjoint column ranges only (one stripe per
                    // atomic claim), so sharing them across the scope's
                    // threads races nothing.
                    unsafe impl Send for Rows {}
                    // SAFETY: as above.
                    unsafe impl Sync for Rows {}
                    struct Table(Vec<*const u8>);
                    // SAFETY: read-only pointers into immutable mappings and
                    // the pad arena, neither mutated while the scope's
                    // workers read them.
                    unsafe impl Send for Table {}
                    // SAFETY: as above.
                    unsafe impl Sync for Table {}
                    let rows = Rows(acc.iter_mut().map(|r| r.as_mut_ptr()).collect());
                    let table = Table(table);
                    let next = std::sync::atomic::AtomicUsize::new(0);
                    std::thread::scope(|sc| {
                        for _ in 0..threads {
                            let ntt = &ntt;
                            let rows = &rows;
                            let table = &table;
                            let next = &next;
                            sc.spawn(move || {
                                let mut scratch = ntt.new_scratch(w);
                                let mut out = vec![0u16; ntt.needed * w];
                                loop {
                                    let c = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    if c >= stripes {
                                        break;
                                    }
                                    let len = w.min(words - c * w);
                                    // SAFETY: every table entry is readable
                                    // for `bs` bytes (full blocks inside a
                                    // mapping, tails inside the pad arena),
                                    // and c*w*2 + 2*len <= bs - transform's
                                    // src_of contract.
                                    let src_of = |id: crate::par2ntt::SrcId| unsafe {
                                        table.0[id as usize].add(c * w * 2)
                                    };
                                    ntt.transform(&src_of, len, &mut scratch, &mut out);
                                    for (j, &row) in rows.0.iter().enumerate() {
                                        let e = first + j;
                                        // SAFETY: row j is `words` long and
                                        // c*w + len <= words; stripe c is
                                        // this worker's alone.
                                        let dst = unsafe {
                                            std::slice::from_raw_parts_mut(row.add(c * w), len)
                                        };
                                        dst.copy_from_slice(&out[e * len..(e + 1) * len]);
                                    }
                                }
                            });
                        }
                    });
                    // The check: row `first` again, by the fold, over the
                    // same sources.
                    let mut probe = vec![vec![0u16; words]];
                    // SAFETY: every table entry is readable for `bs` bytes
                    // (see above) and nothing writes through them.
                    let srcs: Vec<&[u8]> = table
                        .0
                        .iter()
                        .map(|&p| unsafe { std::slice::from_raw_parts(p, bs) })
                        .collect();
                    crate::par2repair::linalg::fold_parallel(&mut probe, &srcs, &|_, i| {
                        crate::gf16::pow2(logs[i] as u64 * first as u64 % crate::gf16::ORDER as u64)
                    });
                    drop(srcs);
                    if probe[0] == acc[0] {
                        if std::env::var_os("NZBFAST_NTT_PROFILE").is_some() {
                            let r = crate::par2ntt::FlatPlan::profile_report();
                            tracing::info!(
                                target: "repair-timing",
                                "ntt profile (inclusive thread-seconds): depth0 {:.2} depth1 {:.2} depth2 {:.2} leaves {:.2}",
                                r[0], r[1], r[2], r[3]
                            );
                        }
                        if std::env::var_os("NZBFAST_REPAIR_TIMING").is_some() {
                            tracing::info!(
                                target: "repair-timing",
                                "create ntt rows {first}+{count} (n={n_slices}, mapped, {tails} tail(s) padded, W={w}, threads={threads}, probe ok): {:.2?}",
                                t_ntt.elapsed()
                            );
                        }
                        drop(maps);
                        return Ok(acc);
                    }
                    tracing::warn!(
                        target: "repair-timing",
                        "create ntt rows {first}+{count} (mapped): probe row DISAGREES with the fold - recomputing every row by the fold"
                    );
                    for row in acc.iter_mut() {
                        row.fill(0);
                    }
                    drop(maps);
                    // Straight to the fold: a disagreeing transform is not
                    // retried through the windows.
                    let mut w0 = 0usize;
                    while w0 < n_slices {
                        let w1 = (w0 + per_read).min(n_slices);
                        let window = &plan[w0..w1];
                        read_window(w0, w1, &mut arena[..window.len() * bs], None)?;
                        let held: Vec<u32> = logs[w0..w1].to_vec();
                        fold_batch(&mut acc, &arena[..window.len() * bs], bs, &held, first);
                        w0 = w1;
                    }
                    return Ok(acc);
                }
            }
            // Mapping failed or the plan is unbuildable: the copied
            // windows below take it.
        }
    }
    if ntt_admitted {
        let t_ntt = std::time::Instant::now();
        let (w, threads) = crate::par2repair::ntt_stripe_geometry(bs);
        let stripes = words.div_ceil(w);
        let mut corpus = vec![0u8; ntt_window * bs];
        // The check: row `first` again, by the fold, over the same
        // windows, accumulated the same way.
        let mut probe = vec![vec![0u16; words]];
        let mut ok = true;
        let mut windows = 0usize;
        let mut w0 = 0usize;
        while w0 < n_slices {
            let w1 = (w0 + ntt_window).min(n_slices);
            let wn = w1 - w0;
            read_window(w0, w1, &mut corpus[..wn * bs], None)?;
            let present: Vec<(u32, crate::par2ntt::SrcId)> = logs[w0..w1]
                .iter()
                .enumerate()
                .map(|(i, &l)| (l, i as crate::par2ntt::SrcId))
                .collect();
            let Ok(ntt) = crate::par2ntt::FlatPlan::build(&present, needed) else {
                ok = false;
                break;
            };
            struct Rows(Vec<*mut u16>);
            // SAFETY: raw pointers into the accumulator rows; workers
            // write disjoint column ranges only (one stripe per atomic
            // claim), so sharing them across the scope's threads races
            // nothing.
            unsafe impl Send for Rows {}
            // SAFETY: as above - every write is confined to the claiming
            // worker's stripe columns.
            unsafe impl Sync for Rows {}
            let rows = Rows(acc.iter_mut().map(|r| r.as_mut_ptr()).collect());
            let corpus_ref = &corpus;
            let next = std::sync::atomic::AtomicUsize::new(0);
            std::thread::scope(|sc| {
                for _ in 0..threads {
                    let ntt = &ntt;
                    let rows = &rows;
                    let next = &next;
                    sc.spawn(move || {
                        let mut scratch = ntt.new_scratch(w);
                        let mut out = vec![0u16; ntt.needed * w];
                        loop {
                            let c = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            if c >= stripes {
                                break;
                            }
                            let len = w.min(words - c * w);
                            // SAFETY: slot `id` holds a full block of
                            // `bs` bytes in `corpus`, and c*w*2 + 2*len
                            // <= bs because len = w.min(words - c*w) -
                            // transform's src_of contract.
                            let src_of = |id: crate::par2ntt::SrcId| unsafe {
                                corpus_ref.as_ptr().add(id as usize * bs + c * w * 2)
                            };
                            ntt.transform(&src_of, len, &mut scratch, &mut out);
                            for (j, &row) in rows.0.iter().enumerate() {
                                let e = first + j;
                                // SAFETY: row j is `words` long and c*w +
                                // len <= words; stripe c is this worker's
                                // alone, so no other thread touches these
                                // columns.
                                let dst =
                                    unsafe { std::slice::from_raw_parts_mut(row.add(c * w), len) };
                                for (d, o) in dst.iter_mut().zip(&out[e * len..(e + 1) * len]) {
                                    *d ^= *o;
                                }
                            }
                        }
                    });
                }
            });
            let srcs: Vec<&[u8]> = (0..wn).map(|i| &corpus[i * bs..][..bs]).collect();
            crate::par2repair::linalg::fold_parallel(&mut probe, &srcs, &|_, i| {
                crate::gf16::pow2(logs[w0 + i] as u64 * first as u64 % crate::gf16::ORDER as u64)
            });
            windows += 1;
            w0 = w1;
        }
        drop(corpus);
        if ok && probe[0] == acc[0] {
            if std::env::var_os("NZBFAST_REPAIR_TIMING").is_some() {
                tracing::info!(
                    target: "repair-timing",
                    "create ntt rows {first}+{count} (n={n_slices}, {windows} window(s) of {ntt_window}, W={w}, threads={threads}, probe ok): {:.2?}",
                    t_ntt.elapsed()
                );
            }
            return Ok(acc);
        }
        tracing::warn!(
            target: "repair-timing",
            "create ntt rows {first}+{count}: {} - recomputing every row by the fold",
            if ok { "probe row DISAGREES with the fold" } else { "plan unbuildable for a window" }
        );
        for row in acc.iter_mut() {
            row.fill(0);
        }
    }

    let mut w0 = 0usize;
    while w0 < n_slices {
        let w1 = (w0 + per_read).min(n_slices);
        let window = &plan[w0..w1];
        let pinned = fused_scan.as_deref().map(|scan| &scan.file);
        read_window(w0, w1, &mut arena[..window.len() * bs], pinned)?;
        let held: Vec<u32> = logs[w0..w1].to_vec();
        if let Some(scan) = fused_scan.as_deref_mut() {
            std::thread::scope(|sc| {
                let fold = sc.spawn(|| {
                    fold_batch(&mut acc, &arena[..window.len() * bs], bs, &held, first);
                });
                scan_fused_window(scan, window, &arena[..window.len() * bs], bs);
                fold.join().expect("par2gen fused fold worker panicked");
            });
        } else {
            fold_batch(&mut acc, &arena[..window.len() * bs], bs, &held, first);
        }
        w0 = w1;
    }
    Ok(acc)
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
