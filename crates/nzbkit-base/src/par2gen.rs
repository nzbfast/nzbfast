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

use crate::par2::{
    MAX_BLOCK_SIZE, TYPE_COMMASCI, TYPE_COMMUNI, TYPE_FILEDESC, TYPE_IFSC, TYPE_MAIN, TYPE_RECVSLIC,
};

/// The create's progress sink, cancel gate and the trail a cancel
/// unlinks - the repair's `par2repair::control` machinery, faced for
/// this side. Added 12 Sep 2026 (claim `par2gen-create-control`).
pub mod control;
mod duplicates;
/// The two transform arms of `recovery_slices` - split out on 9 Sep
/// 2026 for the 500-line function ceiling.
mod ntt;
#[doc(hidden)] // `pub` only for its test doors; the creator's items stay `pub(super)`.
pub mod ntt_range;
mod packets;
/// The single read pass over the members and the create admission that
/// bounds it - split out on 9 Sep 2026 for the 4,000-line file ceiling.
mod scan;
mod stripe_first;
/// The batch volume writer and the critical-block backfill - split out
/// on 9 Sep 2026 for the 500-line function ceiling.
mod volwrite;

/// Census door onto [`duplicates::enabled`] (see `par2seams`).
pub(crate) fn seam_duplicates(bs: usize, rows: usize, sources: usize) -> bool {
    duplicates::enabled(bs, rows, sources)
}
use control::{CreateControl, CreatePhase, CreateTrail};
use packets::{append_packet, prepare_recovery_seals, write_recovery_packet};
// Glob rather than a list: the scan module is a lift of a contiguous
// 1,270-line block out of this file, and every name in it kept the
// unqualified spelling its call sites (here, in the sibling modules and
// in `par2gen_tests.rs`) already used.
use scan::*;

/// Packet type of the Creator packet - free-form ASCII body naming the
/// program that built the set. Not in `par2.rs`'s list because nothing
/// on the READ side needs it (the parser skips it), so it lives with
/// the only code that writes one.
const TYPE_CREATOR: &[u8; 16] = b"PAR 2.0\0Creator\0";

/// The PAR2 spec's own input-slice ceiling: 32768 naturals below 65535
/// are coprime to it, and each input slice needs its own constant.
///
/// Public because a CALLER has to be able to ask the question before it
/// builds a set: the engine refuses above this and tells the user to raise
/// the block size, and parfast's `legal_block_size` does that for them
/// rather than passing the refusal on. `par2repair` carries the same
/// ceiling for the read side.
pub const MAX_INPUT_SLICES: usize = 32768;

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
    /// A caller raised its [`control::CreateControl`]'s cancel while
    /// the create was running.
    ///
    /// THE PROMISE, which is why this is its own variant rather than
    /// an `Other`: a cancelled create leaves NOTHING. The index and
    /// every volume this run wrote have been removed before this error
    /// reaches the caller, because the volumes are written to their
    /// final names with the critical packets patched in last, so a
    /// half-written set is a set that names no member and verifies
    /// against nothing. A set this run was EXTENDING (`-f` onto an
    /// existing one) keeps every file it already had - the trail a cancel
    /// unlinks is a record of what this run CREATED, not a glob over
    /// the directory (`control::CreateTrail`).
    #[error("the recovery set was cancelled; every file it wrote has been removed")]
    Cancelled,
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

/// The direct fold's read window in bytes: [`READ_BUDGET`] unless
/// `NZBFAST_CREATE_READ_BUDGET` (bytes, >= 1 MiB) says otherwise. A
/// research knob for the create-pipeline lane (5 Sep 2026): every
/// window's fold walks all `count` accumulators once, so a bigger window
/// is fewer passes over them.
/// The read window sized against the accumulators it is folded into:
/// every window's fold walks ALL of them, so a window a quarter of their
/// size bounds that traffic at four passes over the accumulators per pass
/// over the payload. [`READ_BUDGET`] is the floor, 512 MiB the cap.
/// Measured 5 Sep 2026 (the fused-multi handoff): ten 1 GiB members at
/// 4 MiB slices, 256 rows - 161 windows of 16 blocks walked the 1 GiB
/// accumulator set 161 times, 322 GB of traffic on a 1 GiB-of-arithmetic
/// fold. At the 1 GiB / 1 MiB shape the accumulators are 103 MiB and the
/// window stays at the floor (64 to 512 MiB measured flat there).
fn create_read_budget_for(accum_bytes: u64) -> u64 {
    static B: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    let knob = *B.get_or_init(|| {
        std::env::var("NZBFAST_CREATE_READ_BUDGET")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&b| b >= 1 << 20)
    });
    knob.unwrap_or_else(|| (accum_bytes / 4).clamp(READ_BUDGET, 512 << 20))
}

/// Reader threads per window: under read-ahead (below) ONE on Windows
/// and two elsewhere, else the machine's workers capped at eight;
/// `NZBFAST_CREATE_READERS` (1..=64) overrides either.
///
/// Measured on the i5-10600KF (6c/12t, Windows, 5 Sep 2026, the
/// create-pipeline handoff rounds B-D), 1 GiB / 1 MiB / 103 rows: the
/// page-cache copy costs ~2 CPU-seconds per GiB across eight readers
/// (3.7 GB/s aggregate against 2.9 for one thread), so eight readers
/// running under the fold slow it by exactly what they hide - batch
/// 1.40-1.45 s with read-ahead on eight or four readers against
/// 1.42-1.48 without. One reader copies the GiB in ~0.37 s, well under
/// the ~1.1 s fold, and hides it for nothing: 1.37-1.41. Two readers
/// the same. On the M3 Ultra, where eight readers copy the GiB in
/// 55-73 ms, one reader under read-ahead reads slightly worse than the
/// serial loop (batch 389-428 vs 374-396 ms) and two, four or eight
/// are flat with it (378-410), so the non-Windows default is two.
fn create_readers(under_fold: bool) -> usize {
    static N: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
    let knob = *N.get_or_init(|| {
        std::env::var("NZBFAST_CREATE_READERS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&n| (1..=64).contains(&n))
    });
    // Under read-ahead Windows wants ONE reader (the page-cache copy is
    // the cost there and readers contend for it; i5-10600KF, 5 Sep 2026).
    // Off Windows the count stays at the fold's own: the 2 this arm
    // first shipped with was never measured on unix and cost the M3
    // Ultra 1.1 s on a 10 GiB / 4 MiB create (9.26-9.35 s vs 8.05-8.21
    // with eight, measured 5 Sep 2026).
    knob.unwrap_or_else(|| {
        if under_fold && cfg!(windows) {
            1
        } else {
            crate::mem::cpu_workers().clamp(1, 8)
        }
    })
}

/// Read window k+1 into a second arena while window k folds - on unless
/// `NZBFAST_CREATE_OVERLAP=0`. Measured with the reader count above; the
/// fused single-member scan keeps the serial loop (it hashes the window
/// it just read through the descriptor it pinned).
fn create_overlap_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("NZBFAST_CREATE_OVERLAP").is_none_or(|v| v != "0"))
}

/// Fold pacing (13 Sep 2026), ON by default; `NZBFAST_CREATE_FOLD_PACING=0`
/// is the A/B arm. A fused create is bound by the whole-file MD5 chain
/// (one serial thread) and its fold overlaps that chain window by window;
/// wherever the fold finishes well inside the chain, its extra workers
/// buy nothing and, on a box without cores to spare, the OS shares the
/// chain's core with them. The pacer measures both per window and
/// narrows the fold to the width that still keeps pace. Measured on an
/// 8-vCPU Zen 4 VM, 8.86 GB one file at 5%: 13.26 s at eight workers
/// against 11.91 at four with everything else equal - see `paced_width`.
fn create_fold_pacing_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("NZBFAST_CREATE_FOLD_PACING").is_none_or(|v| v != "0"))
}

/// The fold width the next window should run at, given that this window
/// folded in `fold` on `width` workers while the chain took `chain`.
///
/// The target is a fold at ~80% of the chain: short enough that a slow
/// window does not poke past the chain and lengthen the wall, long
/// enough that the workers freed are real. The step is proportional
/// (fold time is near enough 1/width over the band this walks) so eight
/// workers reach four in one or two windows, and a fold that has crept
/// within 90% of the chain snaps back to the full width at once - the
/// asymmetry is deliberate: over-shedding costs wall, under-shedding
/// costs only the gain. Floor of 2 so the fold never becomes the pole
/// on a two-core box by this hand; ceiling `max`, the published width.
fn paced_width(
    width: usize,
    max: usize,
    fold: std::time::Duration,
    chain: std::time::Duration,
) -> usize {
    let max = max.max(1);
    if chain.is_zero() || fold.is_zero() {
        return width.clamp(1, max);
    }
    // Integer nanoseconds throughout, so the 90% and 70% edges are exact
    // (90 ms over 100 ms is 0.8999.. as an f64 and missed the snap-back
    // in the first cut of the test below).
    let (fold, chain) = (fold.as_nanos(), chain.as_nanos());
    if fold * 10 >= chain * 9 {
        return max;
    }
    if fold * 10 >= chain * 7 {
        return width.clamp(1, max);
    }
    // Under 70%: the fold has slack. Aim it at 80% of the chain -
    // ceil(width * fold / (0.8 * chain)).
    let want = (width as u128 * fold * 10).div_ceil(chain * 8) as usize;
    want.clamp(2.min(max), max).min(width)
}

/// Blocks in the FIRST read-ahead window: the fold cannot start until it
/// lands, and a whole 64 MiB window on one reader is 120-170 ms of
/// exposed startup (round D). Eight blocks start the fold after a few
/// ms; the reader then runs full windows ahead.
const FIRST_WINDOW_BLOCKS: usize = 8;

/// `NZBFAST_CREATE_PREPACK=1`: readers pack each block into the planar
/// layout as it lands (`gf16::prepack_planar_in_place`) and the direct
/// fold consumes it packed, so the split the tiled fold repeats per row
/// group happens once per block. Off by default until measured (the
/// create-pipeline lane, 5 Sep 2026).
fn create_prepack_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("NZBFAST_CREATE_PREPACK").is_some_and(|v| v == "1"))
}

/// Research knob (`NZBFAST_CREATE_WS_LOCK=1`, Windows): raise the
/// process working-set minimum to cover the accumulators and the read
/// arenas, then lock the accumulator rows. The suspect (the lane-chains
/// handoff, 5 Sep 2026): on a ten-member 10 GiB create at 4 MiB slices
/// the kernel time fell ~125 ms per fold window removed, which is what a
/// soft-fault pass over a 1 GiB accumulator set costs - as if the memory
/// manager trimmed the rows between windows while the page cache churned
/// through 10 GiB of reads. Off the knob, nothing here runs.
fn pin_accumulators(acc: &[Vec<u16>], accum_bytes: u64) {
    if !std::env::var_os("NZBFAST_CREATE_WS_LOCK").is_some_and(|v| v == "1") {
        return;
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Memory::VirtualLock;
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, SetProcessWorkingSetSize};
        let min = accum_bytes
            .saturating_add(read_arena_claim(accum_bytes))
            .saturating_add(256 << 20) as usize;
        let max = min.saturating_add(2 << 30);
        // SAFETY: plain calls on the current process handle with sizes in
        // bytes; results are advisory here and ignored.
        unsafe {
            let ok = SetProcessWorkingSetSize(GetCurrentProcess(), min, max);
            let mut locked = 0usize;
            if ok != 0 {
                for row in acc {
                    if VirtualLock(row.as_ptr() as *const std::ffi::c_void, row.len() * 2) != 0 {
                        locked += 1;
                    }
                }
            }
            if std::env::var_os("NZBFAST_REPAIR_TIMING").is_some() {
                tracing::info!(
                    target: "repair-timing",
                    "create ws-lock: SetProcessWorkingSetSize({min}, {max}) {}, {locked}/{} rows locked",
                    if ok != 0 { "ok" } else { "failed" },
                    acc.len()
                );
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (acc, accum_bytes);
    }
}

/// Bytes the read arenas claim from the gauge: one window, two with
/// read-ahead.
fn read_arena_claim(accum_bytes: u64) -> u64 {
    create_read_budget_for(accum_bytes).saturating_mul(if create_overlap_enabled() { 2 } else { 1 })
}

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

/// Null-pad to the next multiple of 4. A FileDesc name is stored
/// exactly this way, which is why `par2.rs` trims trailing NULs when it
/// reads one back.
fn pad4(mut v: Vec<u8>) -> Vec<u8> {
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
    v
}

/// The longest comment this engine will write into a set, in bytes of
/// UTF-8.
///
/// A ceiling rather than a taste. The comment rides in the CRITICAL
/// BLOCK, and the critical block is the one thing in a PAR2 set that is
/// written over and over: once per file under [`CriticalLayout::Head`],
/// and `bit_length(slices)` times per volume under
/// [`CriticalLayout::Interleaved`]. So a comment pasted out of a file is
/// multiplied by the volume count before it reaches the disk and by it
/// again on the wire, and on a file-light set the critical block is
/// already the larger half of what a volume weighs. 16 KiB is far past
/// anything a human types into a comment field and far short of a size
/// that can move what a volume costs.
pub const MAX_COMMENT_BYTES: usize = 16 * 1024;

/// The comment a create was given, checked once at the door.
///
/// PUBLIC so a preview pane can say "the create will refuse this"
/// BEFORE the create runs, off this predicate rather than off a second
/// reading of the rule. [`create_into_exact_with_comment`] calls it for
/// itself, so a caller that skips it is refused all the same.
///
/// # The refusals are the reader's acceptance rule, spelled the other
/// way round
///
/// `par2::packet::clean_comment` refuses a comment carrying any control
/// character but newline, carriage return and tab, because a comment is
/// the one field of a PAR2 set whose content an attacker chooses freely
/// and which lands in front of a human unaltered - an ESC there is an
/// escape sequence in the terminal `parfast` prints to. Writing one this
/// engine would then refuse to read back would make a round trip through
/// its own format lossy, which is worse than either half alone, so the
/// two rules are one rule and
/// `every_comment_this_engine_writes_reads_back` is the claim.
///
/// An EMPTY comment is not written at all rather than refused: the door
/// takes `Option<&str>` and "" is the absence of a comment, which is
/// what a UI with an untouched Comment field sends.
pub fn check_comment(comment: &str) -> Result<(), Par2GenError> {
    if comment.len() > MAX_COMMENT_BYTES {
        return Err(Par2GenError::Other(format!(
            "comment is {} bytes, over the {MAX_COMMENT_BYTES}-byte limit for a PAR2 text packet",
            comment.len()
        )));
    }
    if let Some(c) = comment
        .chars()
        .find(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return Err(Par2GenError::Other(format!(
            "comment carries the control character {:?}, which this engine refuses to write \
             because it refuses to read one back - newline, carriage return and tab are the \
             three it allows",
            c
        )));
    }
    Ok(())
}

/// The ONE text packet this engine writes for a comment: its type and
/// its 4-aligned body.
///
/// # One packet, chosen by content - which is `unicode: "auto"`
///
/// The spec has two comment packets and a producer may write either or
/// both. An ASCII comment gets the ASCII packet alone, because that is
/// the packet every reader on record understands and a Unicode copy of
/// the same characters buys nothing for twice the bytes in every volume.
/// A comment with anything above U+007F gets the Unicode packet alone,
/// because the alternative is inventing a lossy ASCII rendering of a
/// comment the user actually wrote - and a transliterated comment beside
/// the real one is exactly the shape `parse_unifilen`'s own note
/// describes going wrong for filenames.
///
/// That policy is `unicode: "auto"` in `pf_capabilities`, and it is the
/// only honest value while it is the only policy implemented. A `never`
/// / `always` switch belongs on this function and nowhere else (plan
/// 4.2 item 4).
///
/// The Unicode packet's leading 16 bytes are the MD5 of the analogous
/// ASCII packet's body "if it exists". It never does here, by the
/// paragraph above, so the field is the spec's own zeros.
fn comment_packet(comment: &str) -> (&'static [u8; 16], Vec<u8>) {
    if comment.is_ascii() {
        return (TYPE_COMMASCI, pad4(comment.as_bytes().to_vec()));
    }
    let mut body = Vec::with_capacity(16 + comment.len() * 2);
    body.extend_from_slice(&[0u8; 16]);
    for unit in comment.encode_utf16() {
        body.extend_from_slice(&unit.to_le_bytes());
    }
    (TYPE_COMMUNI, pad4(body))
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

/// One file a create would write, as [`plan_files`] answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedFile {
    /// The name on disk, in the ENGINE's own `vol{first:03}+{count:02}`
    /// spelling. par2cmdline's widths - and the spec's own
    /// `vol<first>-<last>` form - are a RENAME afterwards, so a caller
    /// that shows the names a user will see maps this list through
    /// `parfast::create::final_volume_names`, which is the one rule
    /// `parfast::create::rename_volumes` applies to the files.
    pub name: String,
    /// The exponent of this volume's first recovery slice. Zero, and
    /// meaningless, for the index file.
    pub first_exponent: usize,
    /// Recovery slices in this file. Zero for the index file, which
    /// carries the critical block and no parity.
    pub blocks: usize,
    /// The file's length in bytes.
    pub bytes: u64,
}

/// What [`create_into_exact`] WOULD write for this payload and plan,
/// without reading a source byte or writing a file.
///
/// `members` is `(name, length)` per member, in the order they would be
/// passed to the create. The answer is exact for the index file and for
/// every volume: the critical block is BUILT here (over a placeholder
/// whose packet lengths are the real ones - only the digests differ,
/// and a digest is a fixed 16 bytes), the recovery packet is its
/// 68-byte head plus one slice, and the interleaved layout's repetition
/// is `interleave_schedule`'s own rule read once rather than restated.
///
/// THE ONE THING IT CANNOT PROMISE is the volume COUNT under a memory
/// cap. `volume_layout` widens a plan whose volumes would not fit the
/// accumulator budget, and that budget depends on what else is
/// creating at the same moment (`CreateAdmission`). This reads the
/// budget as it stands with nothing else in flight, which is what a
/// preview pane in an idle app is looking at; a create that starts
/// while another is running may write more, smaller volumes than the
/// preview showed. Say so where the number is presented.
///
/// This exists because the alternative - a caller adding up packet
/// headers for itself - is a second copy of the format, and the first
/// thing such a copy does is disagree with the writer about a set
/// nobody can re-create to check.
pub fn plan_files(
    members: &[(String, u64)],
    base: &str,
    block_size: u64,
    n_recovery: usize,
    plan: CreatePlan,
) -> Vec<PlannedFile> {
    plan_files_with_comment(members, base, block_size, n_recovery, plan, None)
}

/// [`plan_files`] for a create that will carry a comment.
///
/// A second door for the same reason [`create_into_exact_with_comment`]
/// is one: the comment cannot ride on `CreatePlan`, which is `Copy` with
/// no lifetimes. Pass the SAME comment the create will be given - a
/// comment packet is bytes in the critical block and the critical block
/// is in every file this answers for, so a preview that omits it
/// under-reports the index and every volume.
pub fn plan_files_with_comment(
    members: &[(String, u64)],
    base: &str,
    block_size: u64,
    n_recovery: usize,
    plan: CreatePlan,
    comment: Option<&str>,
) -> Vec<PlannedFile> {
    // A comment the create would REFUSE is priced as no comment at all.
    // This function answers a preview pane and has no error channel; the
    // create keeps the refusal, which is where a user can be told about
    // it, and the two agree about every comment that is actually
    // writable.
    let comment = comment.filter(|c| !c.is_empty() && check_comment(c).is_ok());
    let block_size = block_size.max(4);
    let placeholder: Vec<Scanned> = members
        .iter()
        .map(|(name, length)| Scanned {
            name_padded: pad4(name.as_bytes().to_vec()),
            file_id: [0u8; 16],
            md5_whole: [0u8; 16],
            md5_16k: [0u8; 16],
            length: *length,
            blocks: vec![([0u8; 16], 0u32); length.div_ceil(block_size) as usize],
        })
        .collect();
    let (_set_id, critical) = critical_packets(&placeholder, block_size, comment);
    let index = PlannedFile {
        name: format!("{base}.par2"),
        first_exponent: 0,
        blocks: 0,
        bytes: critical.len() as u64,
    };
    let mut out = vec![index];
    if n_recovery == 0 {
        return out;
    }
    let cidx = critical_index(&critical);
    // The Creator packet rides once per file and takes no part in the
    // cycle; everything else is repeated `copies` times.
    let creator_bytes = cidx.creator.1 as u64;
    let cycle_bytes = critical.len() as u64 - creator_bytes;

    let per_batch = (accum_budget() / block_size).max(1) as usize;
    let per_vol = plan
        .max_blocks_per_volume
        .map_or(per_batch, |l| per_batch.min(l.max(1)));
    for (first, count) in volume_layout(n_recovery, per_vol, plan.volumes, plan.first_exponent) {
        let recovery_bytes = count as u64 * (68 + block_size);
        let critical_bytes = match plan.critical {
            CriticalLayout::Head => critical.len() as u64,
            // `interleave_schedule`'s own copy count: the BIT LENGTH of
            // the slice count, so a volume is logarithmically more
            // redundant and not proportionally so.
            CriticalLayout::Interleaved => {
                let copies = (usize::BITS - count.leading_zeros()) as u64;
                copies * cycle_bytes + creator_bytes
            }
        };
        out.push(PlannedFile {
            name: format!("{base}.vol{first:03}+{count:02}.par2"),
            first_exponent: first,
            blocks: count,
            bytes: recovery_bytes + critical_bytes,
        });
    }
    out
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
    /// Final metadata was written initially; no backfill needed.
    Complete,
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
    create_into_inner(
        dir,
        members,
        base,
        spec,
        None,
        CreatePlan::ENGINE,
        None,
        &CreateControl::default(),
    )
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
    create_into_exact_with_comment(dir, members, base, block_size, recovery_blocks, plan, None)
}

/// [`create_into_exact`] with the set's COMMENT - the spec's optional
/// `CommASCI` / `CommUni` text packet, which MultiPar, QuickPar and
/// MacPAR all show and which nothing wrote here before 12 Sep 2026.
///
/// # Why a second door and not a field on `CreatePlan`
///
/// [`CreatePlan`] is `Copy` with no lifetimes, and every engine caller
/// names `CreatePlan::ENGINE` as a const. A `&str` on it would put a
/// lifetime on all of them and a `String` would take the `Copy` away;
/// either is a breaking change at every call site in the workspace for a
/// field none of them sets. The layout knobs on `CreatePlan` are also
/// genuinely one KIND of thing - how the bytes are split up - and a
/// comment is not one of them.
///
/// # `None` writes what this engine has always written
///
/// `None`, and an empty comment, write NO text packet, and the set is
/// byte-identical to what [`create_into_exact`] writes for the same
/// inputs. That is not tidiness: the critical block's LENGTH is what a
/// volume's byte size is built from, and four e2e fixtures poison or
/// band a volume by its byte count, so an unconditional extra packet
/// would move every set nzbfast posts. `no_comment_is_byte_identical_to_
/// the_plain_create` is that claim.
///
/// The comment is refused rather than sanitized where it carries a
/// control character or runs past [`MAX_COMMENT_BYTES`] - see
/// [`check_comment`], which is the write half of the parser's own
/// acceptance rule.
pub fn create_into_exact_with_comment(
    dir: &Path,
    members: &[Member],
    base: &str,
    block_size: Option<u64>,
    recovery_blocks: usize,
    plan: CreatePlan,
    comment: Option<&str>,
) -> Result<Vec<String>, Par2GenError> {
    create_into_exact_controlled(
        dir,
        members,
        base,
        block_size,
        recovery_blocks,
        plan,
        comment,
        &CreateControl::default(),
    )
}

/// [`create_into_exact_with_comment`] with a
/// [`control::CreateControl`]: the create's progress out, and the
/// caller's cancel in.
///
/// # Why an eighth parameter and not a field on `CreatePlan`
///
/// The same reason the comment got its own door (above): `CreatePlan`
/// is `Copy` with no lifetimes and every engine caller names
/// `CreatePlan::ENGINE` as a const. A control is also not a LAYOUT
/// choice - it decides nothing about the bytes, and two runs with and
/// without one write byte-identical sets, which
/// `a_watched_create_writes_the_same_set_as_an_unwatched_one` pins.
///
/// # What a cancel leaves
///
/// Nothing: see [`Par2GenError::Cancelled`]. A create is the one
/// direction where stopping halfway cannot leave the payload alone -
/// it is WRITING the set - so the cancel path removes the index and
/// every volume this run wrote, and a set being extended keeps all of
/// its own.
///
/// Every existing door delegates here with an inert control, and an
/// inert control is one `Option` branch per already-chunked loop; the
/// A/B that says so is
/// `research/PAR2GEN-CREATE-CONTROL-AB-2026-09-12.md`.
#[allow(clippy::too_many_arguments)]
pub fn create_into_exact_controlled(
    dir: &Path,
    members: &[Member],
    base: &str,
    block_size: Option<u64>,
    recovery_blocks: usize,
    plan: CreatePlan,
    comment: Option<&str>,
    control: &CreateControl,
) -> Result<Vec<String>, Par2GenError> {
    let spec = Par2Spec {
        redundancy_pct: 0,
        block_size,
    };
    let comment = comment.filter(|c| !c.is_empty());
    if let Some(c) = comment {
        check_comment(c)?;
    }
    create_into_inner(
        dir,
        members,
        base,
        &spec,
        Some(recovery_blocks),
        plan,
        comment,
        control,
    )
}
/// The create's input refusals, out of `create_into_inner` so that
/// function stays under the size gate: member count and base name, the
/// exponent range (the field is 16 bits and the generator's order is
/// 65535, so an exponent at or past it is a different, wrong slice -
/// refused rather than wrapped, which would emit duplicate blocks) and
/// duplicate member names (two FileDesc packets with one name give a
/// reader two equally good answers for a slot, and the file id derives
/// from the name).
fn check_create_inputs(
    members: &[Member],
    base: &str,
    exponent_end: Option<(usize, usize)>,
) -> Result<(), Par2GenError> {
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
    if let Some((first, last)) = exponent_end {
        return Err(Par2GenError::Other(format!(
            "recovery exponents {first}..{last} run past the PAR2 limit of 65535"
        )));
    }
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
    Ok(())
}

/// `Some((first, last))` when the recovery exponents would run past
/// 65535, for [`check_create_inputs`].
///
/// `pub` since 12 Sep 2026, for the same reason
/// `parfast::create::volume_ceiling` is: a Create PANE has to be able to say
/// that a create would be REFUSED before a human presses the button, and the
/// only honest way to say it is to ask the predicate the refusal is made of.
/// `parfast_session::planner::preview` reads this, so the pane's warning and
/// the engine's error cannot drift apart - the alternative was a second copy
/// of `> 65535` in the preview, which is a spec rule restated in a place
/// nothing would re-derive it.
pub fn spec_exponent_end(
    first_exponent: usize,
    exact_recovery: Option<usize>,
) -> Option<(usize, usize)> {
    first_exponent
        .checked_add(exact_recovery.unwrap_or(0))
        .filter(|&n| n > 65535)
        .map(|last| (first_exponent, last))
}

/// The balanced packet-checksum seals for one recovery batch, or None
/// when `NZBFAST_PAR2GEN_SEAL=off` keeps the per-volume sealing. ON by
/// default since 5 Sep 2026 (the review's lead): same binary, mirrored - M3
/// Ultra 1 MiB create 0.466 -> 0.420 s, 64 KiB 0.571 -> 0.540;
/// i5-10600KF 1 MiB 1.34 -> 1.27, 64 KiB flat. `lanes` (the default)
/// rides the eight-lane MD5 where it exists and is scalar elsewhere;
/// `scalar` forces that.
fn recovery_seals(set_id: &[u8; 16], first: usize, slices: &[Vec<u16>]) -> Option<Vec<[u8; 16]>> {
    let seal_mode = std::env::var("NZBFAST_PAR2GEN_SEAL")
        .ok()
        .unwrap_or_else(|| "lanes".to_string());
    match seal_mode.as_str() {
        "scalar" | "lanes" => {
            let st = std::time::Instant::now();
            let d = prepare_recovery_seals(set_id, first, slices, seal_mode == "lanes");
            if std::env::var_os("NZBFAST_REPAIR_TIMING").is_some() {
                tracing::info!(
                    target: "repair-timing",
                    "create seals: mode={seal_mode} rows={} in {:?}",
                    d.len(),
                    st.elapsed()
                );
            }
            Some(d)
        }
        _ => None,
    }
}

/// The one implementation, plus the CANCEL's one promise: a create that
/// was called off leaves nothing behind.
///
/// The unlink is here and not at any of the sites that write, because
/// only here is it known that the whole run is over - a batch that
/// wrote its volumes and then took a cancel in the NEXT batch must have
/// its own removed too, which is the multi-pass case
/// `a_cancel_in_a_later_pass_removes_the_earlier_passes_volumes` pins.
/// Only [`Par2GenError::Cancelled`] triggers it: a create that failed
/// for any other reason (a member that changed under it, a full disk)
/// leaves what it left, exactly as it always has, because that is a
/// diagnosis and not a user's decision.
#[allow(clippy::too_many_arguments)]
fn create_into_inner(
    dir: &Path,
    members: &[Member],
    base: &str,
    spec: &Par2Spec,
    exact_recovery: Option<usize>,
    plan: CreatePlan,
    comment: Option<&str>,
    control: &CreateControl,
) -> Result<Vec<String>, Par2GenError> {
    let control = control.or_env_arm();
    let trail = CreateTrail::default();
    let r = create_body(
        dir,
        members,
        base,
        spec,
        exact_recovery,
        plan,
        comment,
        &control,
        &trail,
    );
    if matches!(r, Err(Par2GenError::Cancelled)) {
        trail.unlink_all(dir);
    }
    r
}

/// [`create_into_inner`]'s body: everything between the input refusals
/// and the finished list of names. Split from it on 12 Sep 2026 only so
/// the cancel's unlink has one place to happen, by any exit.
#[allow(clippy::too_many_arguments)]
fn create_body(
    dir: &Path,
    members: &[Member],
    base: &str,
    spec: &Par2Spec,
    exact_recovery: Option<usize>,
    plan: CreatePlan,
    comment: Option<&str>,
    control: &CreateControl,
    trail: &CreateTrail,
) -> Result<Vec<String>, Par2GenError> {
    check_create_inputs(
        members,
        base,
        spec_exponent_end(plan.first_exponent, exact_recovery),
    )?;

    // `NZBFAST_REPAIR_TIMING=1` prints the create's phase split on the
    // repair path's own key, so the two engines are read the same way.
    let timing = std::env::var_os("NZBFAST_REPAIR_TIMING").is_some();
    let t0 = std::time::Instant::now();
    let _prep = ntt_range::PrepSpan::start("create");

    // Recovery needs the head digest early to put input slices in file-id
    // order while the full hashes run beside the fold. Index-only creation has
    // no fold to overlap and can defer that digest to the one full scan, so it
    // reads lengths alone. Either way this is the ONE prepass: the metadata
    // loop, the head loop and the scan's own stat used to be three.
    let wants_recovery = exact_recovery.map_or(spec.redundancy_pct != 0, |n| n != 0);
    let mut heads = if !wants_recovery {
        None
    } else {
        Some(scan_heads(members, control)?)
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
        control.begin(CreatePhase::Verify, total);
        let mut scanned = scan_all(members, &lengths, block_size, admission.scan_pool, control)?;
        control.finish(CreatePhase::Verify);
        scanned.sort_by_key(|s| id_order(&s.file_id));
        let (_, critical) = critical_packets(&scanned, block_size, comment);
        let index = format!("{base}.par2");
        // The same last poll the recovery path takes below: a cancel
        // raised while the scan's last member was hashing must not be
        // answered with a finished index.
        control.check()?;
        // Noted BEFORE the write: a cancel that lands between the two
        // must still find the file if the write got as far as creating
        // it. `remove_file` on a name that is not there is a no-op.
        trail.note(&index);
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
    let (set_id, critical_shape) = critical_packets(&placeholder, block_size, comment);
    let index = format!("{base}.par2");
    let mut out: Vec<(String, CriticalPatch)> = vec![(index.clone(), CriticalPatch::Head)];
    trail.note(&index);
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
    let eligible_shape = source_fusion_shape_admitted(members.len(), n_recovery, per_batch, block_size)
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
    let create_ntt_admitted = eligible_shape
        && ntt_range::create_ntt_window(block_size as usize, n_slices, 0, n_recovery).is_some();
    // Keep high-row folds on their established scan lane even when a tight
    // NTT retention budget refuses the transform. At 8,193 x 1 MiB and 328
    // rows, lane B measured broad fusion saving the extra read and 7.7% RSS
    // for only 1.1% of wall while adding 3.0% of cycles; the low-row band
    // below the crossover is the conservative win.
    let fuse_admitted =
        eligible_shape && !create_ntt_admitted && source_fusion_rows_admitted(n_slices, n_recovery);
    let mut fused_scan = if fuse_admitted {
        FusedScan::open_all(&heads, members, block_size)?
    } else {
        None
    };
    // THE ARM, named rather than inferred. Fusion decides which of the
    // create's three routes runs and it used to leave no mark of its
    // own: a reader had to work back from whether the TRANSFORM ran
    // (`ntt_admitted` in `recovery_slices` is `fused_scan.is_none() &&
    // ..`), which is an inference through code that is not about
    // fusion. Two wrong mechanisms were proposed for one measured
    // create on 12 Sep 2026 partly on the strength of it. One line, at
    // the decision, under the timing knob every other create marker is
    // already behind.
    //
    // It names the FUSION decision and the two gates that made it, and
    // deliberately does not claim anything about the transform.
    // `create_ntt_admitted` is not "the NTT runs": it is "this shape is
    // one the transform would take, so fusion stands down for it", and
    // it is false on every multi-member unix create - including the
    // 36-member one that then took the transform in `recovery_slices`
    // off its own, WIDER gate. Reported under the name it earns, so a
    // reader cannot make this line say the thing the old inference
    // wrongly said. Whether the transform ran is the `create ntt rows`
    // line's to answer, and it prints only when it did.
    if timing {
        tracing::info!(
            target: "repair-timing",
            "create arms: n={n_slices} rows={n_recovery} batches={} fused={} (fusable shape={eligible_shape}, fusion displaced by the transform={create_ntt_admitted})",
            stripe_first::batches(&layout, per_batch),
            fused_scan.is_some()
        );
    }
    let mut fused_res: Option<Result<Vec<Scanned>, Par2GenError>> = None;
    let mut scan_res: Result<Vec<Scanned>, Par2GenError> = Ok(Vec::new());
    // The two phases that span the WHOLE create, sized once here.
    //
    // `Verify` is the member hashing, which on the fused arm is done by
    // the fold's own reader and reports nothing - that arm reads the
    // payload once and `Fold` is the whole of it (module doc,
    // `control`). `Write` is every recovery slice of the set, so a
    // multi-pass create's write bar walks up across its passes instead
    // of restarting at each; `Fold` is the one that re-sizes per batch,
    // inside `recovery_slices`.
    if fused_scan.is_none() {
        control.begin(CreatePhase::Verify, total);
    }
    control.begin(CreatePhase::Write, n_recovery as u64 * block_size);
    // Early FileDesc/IFSC metadata into the recovery volumes, ON by default
    // since 5 Sep 2026 (the review's lead): i5-10600KF 1 MiB create 1.34 -> 1.27 s
    // and 64 KiB 2.13 -> 2.08 (the backfill writes cost more where the
    // page-cache copy does), M3 Ultra flat; `NZBFAST_CREATE_EARLY_METADATA=0`
    // is the placeholder backfill, the A/B arm.
    let early_metadata = std::env::var("NZBFAST_CREATE_EARLY_METADATA").as_deref() != Ok("0");
    let mut ready_critical: Option<Vec<u8>> = None;
    let batches: Result<(), Par2GenError> = std::thread::scope(|sc| {
        let mut h = if fused_scan.is_none() {
            Some(sc.spawn(|| {
                let mut scanned =
                    scan_all(members, &lengths, block_size, admission.scan_pool, control)?;
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
            // Several batches on the transform: one pass for every row
            // instead of a transform per batch (see `stripe_first`); a
            // disagreeing check falls through to the batches below.
            if let Some(volumes) = stripe_first::try_run(
                control,
                trail,
                &slots,
                block_size as usize,
                n_slices,
                plan.first_exponent,
                n_recovery,
                &layout,
                per_batch,
                fused_scan.is_some(),
                cidx.as_ref(),
                dir,
                base,
                &set_id,
                ready_critical.as_ref(),
                &critical_shape,
            )? {
                out.extend(volumes);
                return Ok(());
            }
            // Group whole volumes into batches that share one pass over
            // the payload: a batch costs `slices * block_size` of
            // accumulator, and one volume already fits by construction.
            let mut vi = 0usize;
            while vi < layout.len() {
                // A batch boundary: the driver thread, holding nothing
                // (the accumulators of the last batch are gone, the
                // next batch's are not allocated), which is where a
                // PAUSE is allowed to park - see `control::PauseGate`.
                control.gate()?;
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
                        create_read_budget_for(held as u64 * block_size),
                        Some(scan),
                        control,
                    )?;
                    let finished = fused_scan.take().expect("the fused scan was present");
                    fused_res = Some(finished.finish_all(members));
                    slices
                } else {
                    recovery_slices(
                        &slots,
                        block_size,
                        n_slices,
                        first,
                        held,
                        create_read_budget_for(held as u64 * block_size),
                        None,
                        control,
                    )?
                };
                if timing {
                    tracing::info!(
                        target: "repair-timing",
                        "create recovery batch {first}+{held}: {:.2?} (total {:.2?})",
                        t_batch.elapsed(),
                        t0.elapsed()
                    );
                }
                // Both routes can already have final hashes: the independent
                // scanner may have finished, and the fused reader finishes its
                // hash states before returning this recovery batch. Never wait.
                if early_metadata && ready_critical.is_none() {
                    if h.as_ref().is_some_and(|h| h.is_finished()) {
                        scan_res = h
                            .take()
                            .unwrap()
                            .join()
                            .expect("par2gen scan worker panicked");
                    }
                    let scanned = match fused_res.as_mut() {
                        Some(Ok(scanned)) => Some(scanned),
                        _ => scan_res.as_mut().ok().filter(|s| !s.is_empty()),
                    };
                    if let Some(scanned) = scanned {
                        scanned.sort_by_key(|s| id_order(&s.file_id));
                        let (real_id, critical) = critical_packets(scanned, block_size, comment);
                        if real_id != set_id || critical.len() != critical_shape.len() {
                            return Err(Par2GenError::Other(
                                "member identity changed before volume write".into(),
                            ));
                        }
                        ready_critical = Some(critical);
                        if std::env::var_os("NZBFAST_CREATE_METADATA_TRACE").is_some() {
                            eprintln!("EARLY_CRITICAL_READY first={first} rows={held}");
                        }
                    }
                }
                out.extend(volwrite::write_batch(volwrite::BatchVolumes {
                    control,
                    trail,
                    dir,
                    base,
                    layout: &layout[vi..vj],
                    set_id: &set_id,
                    first,
                    slices: &slices,
                    ready_critical: ready_critical.as_deref(),
                    critical_shape: &critical_shape,
                    cidx: cidx.as_ref(),
                })?);
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
    // Both spanning phases land on full here rather than at their last
    // batch: the scan thread and the last volume writer have joined by
    // now, so this is the first point at which either is really over.
    control.finish(CreatePhase::Verify);
    control.finish(CreatePhase::Write);
    scanned.sort_by_key(|s| id_order(&s.file_id));
    if timing {
        tracing::info!(target: "repair-timing", "create scan + fold: {:.2?}", t0.elapsed());
    }
    let (real_set_id, critical) = match ready_critical {
        Some(critical) => (set_id, critical),
        None => critical_packets(&scanned, block_size, comment),
    };
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
    // THE LAST POLL, and the one that makes the promise uniform. Every
    // volume of a one-batch create is spawned before the first of them
    // finishes, so a cancel raised while they are being written can
    // reach no per-volume poll: without this check the create would
    // backfill, return the names and leave a complete set behind a
    // cancel the caller had already pressed. It is also the honest
    // place to stop - the volumes still carry the PLACEHOLDER critical
    // block until the backfill below lands, so up to this line the set
    // on disk is not a set.
    control.check()?;
    volwrite::backfill_critical(dir, &out, &critical, cidx.as_ref())?;
    Ok(out.into_iter().map(|(name, _)| name).collect())
}

/// The Main / FileDesc / IFSC / Creator block that every file in the set
/// repeats, and the set id it is sealed under. Repeating it is what
/// makes a set whose index article was lost still nameable from its
/// volumes (the `a_damaged_par2_index_still_names_the_post_from_its_
/// volumes` row), and it is what par2cmdline does.
fn critical_packets(
    scanned: &[Scanned],
    block_size: u64,
    comment: Option<&str>,
) -> ([u8; 16], Vec<u8>) {
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
    // The optional Text packet, where one was asked for. It joins the
    // block like any other packet and needs no case of its own anywhere
    // below: `critical_index` WALKS the finished block rather than being
    // handed offsets, so it falls into the interleave cycle on its own,
    // and `plan_files` prices the cycle by the block's own length.
    let comment = comment.map(comment_packet);
    let comment_bytes = comment.as_ref().map_or(0, |(_, body)| 64 + body.len());
    let expected_len = 64 + main_body.len() + comment_bytes + member_bytes + 64 + creator.len();
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
    // Directly after Main, so a reader that has only the head of a
    // truncated volume has the set and then what it is about. The spec
    // fixes no order and par2cmdline writes no comment packet at all, so
    // there is no reference shape to match here the way the FileDesc /
    // IFSC split below matches one.
    if let Some((ptype, body)) = &comment {
        append_packet(&mut critical, &set_id, ptype, body.len(), |packet| {
            packet.extend_from_slice(body);
        });
    }
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

/// Recovery row `e`'s coefficient for the source whose RS log is `log`:
/// `g_i^e`. The multiply happens in u64 before the reduction, so a large
/// exponent times a large log cannot wrap.
///
/// At module scope rather than inline at the four folds that want it:
/// spelling it out at each cost `recovery_slices` its 500-line function
/// ceiling once the folds grew their `memgauge` argument, and one
/// spelling of the creator's coefficient is worth more than four anyway.
fn row_coeff(log: u32, e: usize) -> u16 {
    crate::gf16::pow2(log as u64 * e as u64 % crate::gf16::ORDER as u64)
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
///   (block, exponent) - 512 field multiplies at the time, a subset walk
///   over a 1 KB working set since 11 Sep 2026 - when the only thing it
///   ever asked of that table was `xor_mul_into`, the fold.
///   [`crate::gf16::FoldTable`] is the same fold at a 128 B basis XOR, and
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
/// A read-only mapping of one member: the page cache is the resident
/// copy and the kernel's to reclaim, so no retention budget applies,
/// the whole payload is ONE transform window, and - since 5 Sep 2026 -
/// the scan's chains and the direct fold read through it too instead
/// of copying the payload out of the cache (on Windows that copy is
/// ~1 kernel-CPU-second per GiB per pass, and the creator made three:
/// the mapped-inputs handoff). Unix `mmap`, Windows
/// `CreateFileMapping`/`MapViewOfFile`; `NZBFAST_PAR2GEN_MAP=0` keeps
/// the copied paths everywhere.
///
/// A member truncated underneath a live mapping faults the reader
/// (SIGBUS / EXCEPTION_IN_PAGE_ERROR) rather than returning short, on
/// both platforms; the transform has carried that since 2 Sep 2026 and
/// the scan and fold now share it. Growth is harmless (the mapping is
/// `len` bytes, taken at open).
pub(crate) struct MappedMember {
    ptr: *const u8,
    len: usize,
    #[cfg(windows)]
    mapping: windows_sys::Win32::Foundation::HANDLE,
    #[cfg(windows)]
    _file: std::fs::File,
}

impl MappedMember {
    /// A read-only mapping of exactly `len` bytes of `path`, or `None`
    /// for an empty member.
    ///
    /// **`len` is the caller's HEAD-SCAN length, re-stat'd here.**
    /// `MappedPlan::open` never re-stats and indexes in at once, so a
    /// member that shrank made `bytes()` a `from_raw_parts` past the
    /// mapping - on Windows the section is created 0/0, the CURRENT
    /// size, so the slice ran off it outright. `scan_at_length` refuses
    /// this on the path it guards; the transform map does not.
    #[cfg(unix)]
    pub(crate) fn open(path: &Path, len: u64) -> std::io::Result<Option<MappedMember>> {
        use std::os::unix::io::AsRawFd;
        if len == 0 {
            return Ok(None);
        }
        let f = std::fs::File::open(path)?;
        if f.metadata()?.len() != len {
            return Err(std::io::Error::other("stale member length"));
        }
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

    /// See the `unix` arm above for why `len` is re-stat'd here.
    #[cfg(windows)]
    pub(crate) fn open(path: &Path, len: u64) -> std::io::Result<Option<MappedMember>> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::Memory::{
            CreateFileMappingW, FILE_MAP_READ, MapViewOfFile, PAGE_READONLY,
        };
        if len == 0 {
            return Ok(None);
        }
        let f = std::fs::File::open(path)?;
        if f.metadata()?.len() != len {
            return Err(std::io::Error::other("stale member length"));
        }
        let len =
            usize::try_from(len).map_err(|_| std::io::Error::other("member too large to map"))?;
        // SAFETY: a read-only section over the whole file (0/0 = current
        // size) on a handle we own; null names, no security attributes;
        // checked for null below and closed in Drop.
        let mapping = unsafe {
            CreateFileMappingW(
                f.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE,
                std::ptr::null(),
                PAGE_READONLY,
                0,
                0,
                std::ptr::null(),
            )
        };
        if mapping.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: a read-only view of the whole section just created;
        // checked for null; unmapped in Drop.
        let view = unsafe { MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0) };
        if view.Value.is_null() {
            let e = std::io::Error::last_os_error();
            // SAFETY: the section handle is ours and unused past here.
            unsafe { windows_sys::Win32::Foundation::CloseHandle(mapping) };
            return Err(e);
        }
        Ok(Some(MappedMember {
            ptr: view.Value as *const u8,
            len,
            mapping,
            _file: f,
        }))
    }

    /// The member's bytes.
    pub(crate) fn bytes(&self) -> &[u8] {
        // SAFETY: `ptr` is a live read-only mapping of exactly `len`
        // bytes for as long as `self` lives, and nothing writes it.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    /// Ask the kernel to populate the pages ahead of the readers: on
    /// Windows one `PrefetchVirtualMemory` call maps the cached pages in
    /// bulk where touching them would take a soft fault per 4 KiB page;
    /// on unix `madvise(WILLNEED)`. Best effort, errors ignored.
    ///
    /// `pub(crate)` since 10 Sep 2026 for the packet catalog's scan of a
    /// mapped volume (`par2repair::catalog::scan_one`), which was faulting
    /// a cold 1 GiB volume in one page at a time - see there.
    pub(crate) fn prefetch(&self) {
        // Research knob: `NZBFAST_PAR2GEN_MAP_PREFETCH=0` skips the hint.
        if std::env::var_os("NZBFAST_PAR2GEN_MAP_PREFETCH").is_some_and(|v| v == "0") {
            return;
        }
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Memory::{
                PrefetchVirtualMemory, WIN32_MEMORY_RANGE_ENTRY,
            };
            use windows_sys::Win32::System::Threading::GetCurrentProcess;
            let range = WIN32_MEMORY_RANGE_ENTRY {
                VirtualAddress: self.ptr as *mut std::ffi::c_void,
                NumberOfBytes: self.len,
            };
            // SAFETY: one range descriptor covering exactly this mapping;
            // the call is advisory and its result is ignored.
            unsafe {
                PrefetchVirtualMemory(GetCurrentProcess(), 1, &range, 0);
            }
        }
        #[cfg(unix)]
        {
            // SAFETY: advisory call over exactly this mapping; ignored.
            unsafe {
                libc::madvise(self.ptr as *mut libc::c_void, self.len, libc::MADV_WILLNEED);
            }
        }
    }
}

impl Drop for MappedMember {
    fn drop(&mut self) {
        #[cfg(unix)]
        // SAFETY: the pointer and length are exactly what mmap returned.
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.len);
        }
        #[cfg(windows)]
        // SAFETY: the view and section handle are exactly what open
        // created, unmapped and closed once, here.
        unsafe {
            let view = windows_sys::Win32::System::Memory::MEMORY_MAPPED_VIEW_ADDRESS {
                Value: self.ptr as *mut std::ffi::c_void,
            };
            windows_sys::Win32::System::Memory::UnmapViewOfFile(view);
            windows_sys::Win32::Foundation::CloseHandle(self.mapping);
        }
    }
}

// SAFETY: the mapping is read-only and immutable for its lifetime; the
// workers only read through it.
unsafe impl Send for MappedMember {}
// SAFETY: as above - shared read-only access.
unsafe impl Sync for MappedMember {}

/// Which payload reads go through a mapping. `NZBFAST_PAR2GEN_MAP=0`:
/// none, every read on the copied paths. Unset: the TRANSFORM reads its
/// corpus mapped (unix since 2 Sep 2026, Windows since 5 Sep) and the
/// scan and the direct fold keep their reads. `all`: the scan and the
/// direct fold read the mapping too.
///
/// `all` is the measured negative that shaped the default (the
/// mapped-inputs handoff, rounds L-M, i5-10600KF and M3 Ultra, 5 Sep
/// 2026): on the 1 MiB create it takes 0.5-1.0 s of kernel time OUT of
/// the process and still costs 0.05-0.10 s of WALL, on both boxes, with
/// or without the populate hint - soft faults taken inside twelve scan
/// lanes and six fold workers serialise where a read's copy did not.
/// The transform's stripe-wise walk does not pay that: 64 KiB create
/// 3.47-3.69 s mapped against 3.53-3.71 copied on the i5, 0.3 s less
/// kernel time.
fn map_inputs_enabled() -> bool {
    !ntt_range::map_off_pinned() && map_mode() != MapMode::Off
}

/// Whether the scan and the direct fold read mapped members (see
/// [`map_inputs_enabled`]): only under `NZBFAST_PAR2GEN_MAP=all`.
fn map_scan_and_fold_enabled() -> bool {
    map_mode() == MapMode::All
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MapMode {
    Off,
    Transform,
    All,
}

fn map_mode() -> MapMode {
    static MODE: std::sync::OnceLock<MapMode> = std::sync::OnceLock::new();
    *MODE.get_or_init(
        || match std::env::var("NZBFAST_PAR2GEN_MAP").ok().as_deref() {
            Some("0") => MapMode::Off,
            Some("all") => MapMode::All,
            _ => MapMode::Transform,
        },
    )
}

/// Every member of a plan mapped, with each block addressable: full
/// blocks point into the mappings, tail blocks are copied zero-padded
/// into `pad`. None when a member cannot be mapped (the caller keeps
/// its copied path) or the tails alone would exceed `pad_cap` bytes.
struct MappedPlan {
    /// Held for the table's lifetime, never read directly.
    _maps: Vec<Option<MappedMember>>,
    /// As above: the tail slots the table points into.
    _pad: Vec<u8>,
    table: Vec<*const u8>,
    tails: usize,
}

// SAFETY: read-only pointers into immutable mappings and the pad
// arena, neither mutated while workers read them.
unsafe impl Send for MappedPlan {}
// SAFETY: as above.
unsafe impl Sync for MappedPlan {}

impl MappedPlan {
    fn open(
        scanned: &[(PathBuf, u64)],
        plan: &[(usize, u64, usize)],
        bs: usize,
        pad_cap: usize,
    ) -> Option<MappedPlan> {
        let tails = plan.iter().filter(|&&(_, _, want)| want != bs).count();
        if tails.saturating_mul(bs) > pad_cap {
            return None;
        }
        let mut maps: Vec<Option<MappedMember>> = Vec::with_capacity(scanned.len());
        for (path, length) in scanned {
            match MappedMember::open(path, *length) {
                Ok(m) => maps.push(m),
                Err(_) => return None,
            }
        }
        for m in maps.iter().flatten() {
            m.prefetch();
        }
        let mut pad = vec![0u8; tails * bs];
        let mut table: Vec<*const u8> = Vec::with_capacity(plan.len());
        let mut pi = 0usize;
        for &(mi, off, want) in plan {
            let m = maps[mi].as_ref()?;
            let off = usize::try_from(off).ok()?;
            if want == bs {
                // A full block lies inside the mapping (`off + bs <=
                // length`, the plan's contract).
                table.push(m.bytes().get(off..off + bs)?.as_ptr());
            } else {
                let slot = &mut pad[pi * bs..][..bs];
                slot[..want].copy_from_slice(m.bytes().get(off..off + want)?);
                table.push(slot.as_ptr());
                pi += 1;
            }
        }
        Some(MappedPlan {
            _maps: maps,
            _pad: pad,
            table,
            tails,
        })
    }

    /// Block `i` as a slice of `bs` bytes.
    fn block(&self, i: usize, bs: usize) -> &[u8] {
        // SAFETY: every table entry is readable for `bs` bytes (a full
        // block inside a mapping, or a pad slot) for as long as the maps
        // and pad live, which is `self`'s lifetime.
        unsafe { std::slice::from_raw_parts(self.table[i], bs) }
    }
}

/// Per-block (MD5, CRC32) for the `n` blocks of a window arena, eight
/// MD5 chains per `md5_many` pass. The arena already holds every block
/// zero-padded to `bs` (the reader pads tails), which is the block the
/// spec hashes.
fn digest_window(arena: &[u8], n: usize, bs: usize) -> Vec<([u8; 16], u32)> {
    let blocks: Vec<&[u8]> = (0..n).map(|k| &arena[k * bs..(k + 1) * bs]).collect();
    let digests = crate::md5fast::multi::md5_many(&blocks);
    digests
        .into_iter()
        .zip(&blocks)
        .map(|(d, b)| (d, crc32fast::hash(b)))
        .collect()
}

/// Advance every member's whole-file and head chain over one window of
/// the arena the fold is reading, and file the window's block digests.
/// With `lanes`, the window is lane-interleaved (see [`interleave_plan`]):
/// each block carries its lane, a run of ascending lanes is one row, and
/// a row is one lockstep step of the eight chains - a member's last block
/// finalises its lane. Without lanes (a slice size that is not a
/// multiple of 64) the members' scalar chains run one at a time. The
/// chains are the create's one serial cost; this runs beside the fold.
fn scan_fused_window(
    state: &mut [FusedMemberState],
    lanes: &mut Option<crate::md5fast::multi::Md5Lanes>,
    window: &[(usize, u64, usize)],
    lane_of: &[u8],
    arena: &[u8],
    bs: usize,
    digests: Vec<([u8; 16], u32)>,
) {
    debug_assert_eq!(digests.len(), window.len());
    let lengths: Vec<u64> = state.iter().map(|st| st.stamp.length).collect();
    let mut row: [&[u8]; 8] = [&[]; 8];
    let mut row_last: [Option<usize>; 8] = [None; 8];
    let mut row_has = false;
    let mut prev_lane = usize::MAX;
    for (k, ((&(mi, off, want), block), digest)) in window
        .iter()
        .zip(arena.chunks_exact(bs))
        .zip(digests)
        .enumerate()
    {
        let st = &mut state[mi];
        if st.head_left > 0 {
            let take = st.head_left.min(want);
            st.head.update(&block[..take]);
            st.head_left -= take;
        }
        st.blocks.push(digest);
        let Some(l) = lanes.as_mut() else {
            st.whole.update(&block[..want]);
            continue;
        };
        let lane = lane_of[k] as usize;
        if row_has && lane <= prev_lane {
            l.update(row);
            for (j, last) in row_last.iter_mut().enumerate() {
                if let Some(m) = last.take() {
                    state[m].whole_digest = Some(l.finalize(j));
                }
            }
            row = [&[]; 8];
        }
        row[lane] = &block[..want];
        row_has = true;
        prev_lane = lane;
        if off + want as u64 >= lengths[mi] {
            row_last[lane] = Some(mi);
        }
    }
    if row_has && let Some(l) = lanes.as_mut() {
        l.update(row);
        for (j, last) in row_last.iter_mut().enumerate() {
            if let Some(m) = last.take() {
                state[m].whole_digest = Some(l.finalize(j));
            }
        }
    }
}

/// The plan in lane order for the fused pass: eight members at a time,
/// one block of each per round, a member taking over a lane as the one
/// before it ends. Returns the reordered plan, the ORIGINAL slice index of
/// each position (the base log belongs to the slice, not the position)
/// and each position's lane.
fn interleave_plan(
    plan: &[(usize, u64, usize)],
) -> (Vec<(usize, u64, usize)>, Vec<usize>, Vec<u8>) {
    // Per member: the range of plan positions (member-major, contiguous).
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for (k, &(mi, _, _)) in plan.iter().enumerate() {
        if ranges.len() <= mi {
            ranges.resize(mi + 1, (k, k));
        }
        if ranges[mi].0 == ranges[mi].1 {
            ranges[mi] = (k, k);
        }
        ranges[mi].1 = k + 1;
    }
    let mut out = Vec::with_capacity(plan.len());
    let mut slice_of = Vec::with_capacity(plan.len());
    let mut lane_of = Vec::with_capacity(plan.len());
    let mut lane_member: [Option<usize>; 8] = [None; 8];
    let mut lane_pos = [0usize; 8];
    let mut next = 0usize;
    let mut take_next = |lane_member: &mut Option<usize>, lane_pos: &mut usize| {
        *lane_member = None;
        while next < ranges.len() {
            let m = next;
            next += 1;
            if ranges[m].1 > ranges[m].0 {
                *lane_member = Some(m);
                *lane_pos = ranges[m].0;
                return;
            }
        }
    };
    for j in 0..8 {
        take_next(&mut lane_member[j], &mut lane_pos[j]);
    }
    loop {
        let mut any = false;
        for j in 0..8 {
            let Some(m) = lane_member[j] else { continue };
            any = true;
            let k = lane_pos[j];
            out.push(plan[k]);
            slice_of.push(k);
            lane_of.push(j as u8);
            lane_pos[j] += 1;
            if lane_pos[j] >= ranges[m].1 {
                take_next(&mut lane_member[j], &mut lane_pos[j]);
            }
        }
        if !any {
            break;
        }
    }
    debug_assert_eq!(out.len(), plan.len());
    (out, slice_of, lane_of)
}

#[allow(clippy::too_many_arguments)]
fn recovery_slices(
    scanned: &[(PathBuf, u64)],
    block_size: u64,
    n_slices: usize,
    first: usize,
    count: usize,
    read_budget: u64,
    fused_scan: Option<&mut FusedScan>,
    control: &CreateControl,
) -> Result<Vec<Vec<u16>>, Par2GenError> {
    // This batch's fold, in bytes of input block fed. Re-entered per
    // batch, which re-sizes the phase - see `RepairPhase`'s own note
    // about a phase a caller may be told about more than once.
    control.begin(CreatePhase::Fold, n_slices as u64 * block_size);
    let words = (block_size / 2) as usize;
    let logs = crate::par2repair::input_base_logs(n_slices)
        .map_err(|e| Par2GenError::Other(format!("assigning RS constants: {e}")))?;
    let mut acc: Vec<Vec<u16>> = vec![vec![0u16; words]; count];
    pin_accumulators(&acc, count as u64 * block_size);

    let bs = block_size as usize;
    let per_read = ((read_budget / block_size).max(1) as usize).min(n_slices);
    // Mutated before the window loop only by the unix mapped path's
    // fold fallback, so the Windows build sees no mutation until the
    // arena moves into `FoldWindows`.
    #[cfg_attr(not(unix), allow(unused_mut))]
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
    // The fused pass with lanes walks the plan eight members at a time;
    // everything else keeps the member-major order (the transform's
    // window and mapped paths index `plan` positionally against `logs`).
    let (plan, slice_of, lane_of) = if fused_scan.as_ref().is_some_and(|f| f.lanes.is_some()) {
        interleave_plan(&plan)
    } else {
        let n = plan.len();
        (plan, (0..n).collect(), vec![0u8; n])
    };
    // Readers fan out over the window exactly as the repair feed does
    // (contiguous runs per reader, positional reads, one handle per
    // member per reader): the read used to be one thread's BufReader
    // walking the payload between folds, and on a 1 GiB set that was
    // ~300 ms of every pass against a fold of ~120 ms (measured 2 Sep
    // 2026, M3 Ultra, page-cached payload).
    // One window of the plan into `dst`, across `readers` threads.
    // `pack`: planar-pack each block as it lands (direct fold only; the
    // transform and the fused scan read the interleaved bytes).
    let read_window = |w0: usize,
                       w1: usize,
                       dst: &mut [u8],
                       pinned: Option<&[std::fs::File]>,
                       pack: bool,
                       readers: usize|
     -> Result<(), Par2GenError> {
        let window = &plan[w0..w1];
        let chunk = window.len().div_ceil(readers).max(1);
        let mut results: Vec<Result<(), Par2GenError>> = Vec::new();
        let trace_scope =
            w0 == 0 && std::env::var_os("NZBFAST_CREATE_READ_TRACE").is_some_and(|v| v == "1");
        let t_scope = std::time::Instant::now();
        std::thread::scope(|sc| {
            let handles: Vec<_> = window
                .chunks(chunk)
                .zip(dst.chunks_mut(chunk * bs))
                .map(|(jobs, slots)| {
                    sc.spawn(move || -> Result<(), Par2GenError> {
                        let mut open: Option<(usize, std::fs::File)> = None;
                        // Research trace (`NZBFAST_CREATE_READ_TRACE=1`): per
                        // open and per block wall for the first window.
                        let trace = w0 == 0
                            && std::env::var_os("NZBFAST_CREATE_READ_TRACE").is_some_and(|v| v == "1");
                        for (k, &(mi, off, want)) in jobs.iter().enumerate() {
                            let t_blk = std::time::Instant::now();
                            // A fused pass reads through the descriptor it
                            // pinned before the fold, so its snapshot is the
                            // one the checksums are taken over.
                            let f = if let Some(files) = pinned {
                                &files[mi]
                            } else {
                                if open.as_ref().is_none_or(|(o, _)| *o != mi) {
                                    let path = &scanned[mi].0;
                                    let t_open = std::time::Instant::now();
                                    open = Some((mi, std::fs::File::open(path).map_err(io(path))?));
                                    if trace {
                                        tracing::info!(target: "repair-timing", "read-trace open member {mi}: {:.2?}", t_open.elapsed());
                                    }
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
                            if pack {
                                assert!(crate::gf16::prepack_planar_in_place(slot));
                            }
                            if trace {
                                tracing::info!(target: "repair-timing", "read-trace block {k} (member {mi} off {off}): {:.2?}", t_blk.elapsed());
                            }
                        }
                        Ok(())
                    })
                })
                .collect();
            if trace_scope {
                tracing::info!(target: "repair-timing", "read-trace spawned {} reader(s) at {:.2?}", handles.len(), t_scope.elapsed());
            }
            results = handles
                .into_iter()
                .map(|h| h.join().expect("par2gen reader panicked"))
                .collect();
            if trace_scope {
                tracing::info!(target: "repair-timing", "read-trace joined at {:.2?}", t_scope.elapsed());
            }
        });
        if trace_scope {
            tracing::info!(target: "repair-timing", "read-trace scope done at {:.2?}", t_scope.elapsed());
        }
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
    let ntt_window = ntt_range::create_ntt_window(bs, n_slices, first, count);
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
    let arms = ntt::NttArms {
        control,
        read_window: &read_window,
        scanned,
        plan: &plan,
        logs: &logs,
        bs,
        words,
        n_slices,
        first,
        count,
        ntt_window,
        per_read,
    };
    if ntt_admitted && map_inputs_enabled() && ntt::mapped_attempt(&arms, &mut acc, &mut arena)? {
        control.finish(CreatePhase::Fold);
        return Ok(acc);
    }
    if ntt_admitted && ntt::windowed_attempt(&arms, &mut acc)? {
        control.finish(CreatePhase::Fold);
        return Ok(acc);
    }

    // Read-ahead (knob): window k+1 lands in a second arena on its own
    // reader fan-out while window k folds on the main thread, so the
    // read's wall hides under the fold's. Only on the plain path - the
    // fused scan pins one descriptor and hashes the window it just read.
    let prepack = create_prepack_enabled()
        && fused_scan.is_none()
        && crate::par2repair::linalg::prepacked_fold_admissible(words, count);
    // The fold straight off the mappings: no read pass at all, the
    // page cache is the source. Windows of 256 slices per fold call (the
    // window budget measured flat from 64 to 512 MiB on the i5, so the
    // call shape is the one the fold bench likes). The fused scan keeps
    // its copied arena (it hashes the window it just read), and a plan
    // that packs its sources needs them in an arena to pack.
    if map_scan_and_fold_enabled()
        && fused_scan.is_none()
        && !prepack
        && let Some(mp) = MappedPlan::open(scanned, &plan, bs, per_read * bs)
    {
        {
            let t0 = std::time::Instant::now();
            const MAP_FOLD_WINDOW: usize = 256;
            let mut w0 = 0usize;
            while w0 < n_slices {
                let w1 = (w0 + MAP_FOLD_WINDOW).min(n_slices);
                let srcs: Vec<&[u8]> = (w0..w1).map(|i| mp.block(i, bs)).collect();
                let held = &logs[w0..w1];
                let c = |j: usize, i: usize| row_coeff(held[i], first + j);
                crate::par2repair::linalg::fold_parallel(&mut acc, &srcs, &c, None);
                control.step(CreatePhase::Fold, (w1 - w0) as u64 * bs as u64);
                w0 = w1;
                // Between two fold windows on the driver thread with
                // nothing held: a park site, and the cancel's grain on
                // this arm.
                control.gate()?;
            }
            if std::env::var_os("NZBFAST_REPAIR_TIMING").is_some() {
                tracing::info!(
                    target: "repair-timing",
                    "create direct fold (mapped, {n_slices} slices in windows of {MAP_FOLD_WINDOW}, {} tail(s) padded): {:.2?}",
                    mp.tails,
                    t0.elapsed()
                );
            }
            drop(mp);
            control.finish(CreatePhase::Fold);
            return Ok(acc);
        }
    }
    fold_windows(FoldWindows {
        control,
        read_window: &read_window,
        logs: &logs,
        acc: &mut acc,
        arena,
        per_read,
        bs,
        n_slices,
        first,
        prepack,
        fused_scan,
        plan: &plan,
        slice_of: &slice_of,
        lane_of: &lane_of,
    })?;
    control.finish(CreatePhase::Fold);
    Ok(acc)
}

/// The direct fold's window loop, split out of [`recovery_slices`] for
/// the size gate: everything it needs from there, by reference.
struct FoldWindows<'a> {
    control: &'a CreateControl,
    read_window: &'a (
            dyn Fn(
        usize,
        usize,
        &mut [u8],
        Option<&[std::fs::File]>,
        bool,
        usize,
    ) -> Result<(), Par2GenError>
                + Sync
        ),
    logs: &'a [u32],
    acc: &'a mut [Vec<u16>],
    arena: Vec<u8>,
    per_read: usize,
    bs: usize,
    n_slices: usize,
    first: usize,
    prepack: bool,
    fused_scan: Option<&'a mut FusedScan>,
    plan: &'a [(usize, u64, usize)],
    /// Plan position -> original slice index (identity unless the plan
    /// is lane-interleaved), and -> lane.
    slice_of: &'a [usize],
    lane_of: &'a [u8],
}

/// Walk the plan window by window - read, fold - either with the next
/// window read ahead on its own reader (the default) or serially (the
/// fused single-member scan, or `NZBFAST_CREATE_OVERLAP=0`).
fn fold_windows(w: FoldWindows<'_>) -> Result<(), Par2GenError> {
    let FoldWindows {
        control,
        read_window,
        logs,
        acc,
        mut arena,
        per_read,
        bs,
        n_slices,
        first,
        prepack,
        mut fused_scan,
        plan,
        slice_of,
        lane_of,
    } = w;
    // Pack-once (knob): the planar split happens on the reader thread,
    // once per block, instead of once per row group in the tiled fold.
    // Only where the planar kernel is the selected one and every block is
    // whole (the readers zero-pad tails to `bs`) - `prepack` carries
    // that decision in.
    let timing = std::env::var_os("NZBFAST_REPAIR_TIMING").is_some();
    let mut t_read = std::time::Duration::ZERO;
    let mut t_fold = std::time::Duration::ZERO;
    let mut windows = 0usize;
    // Fold pacing state (see `create_fold_pacing_enabled`): the width the
    // fold runs at, its ceiling, and the trajectory for the timing line.
    let pace_max = crate::mem::cpu_workers().max(1);
    let mut pace_width = pace_max;
    let mut pace_min_seen = pace_max;
    let mut pace_moves = 0usize;
    // The chain's and the fold's own summed time, against the windows'
    // wall: what the timing line reports so a gap between the chain
    // thread's work and the wall it is supposed to be is a number.
    let mut t_chain_sum = std::time::Duration::ZERO;
    let mut t_fold_sum = std::time::Duration::ZERO;
    if create_overlap_enabled() && n_slices > per_read {
        // With a fused scan the reader also digests the window it just
        // read (eight MD5 chains per pass, then the CRCs - ~20 ms per
        // 64 MiB on an i5-10600KF against its ~22 ms read), and a third
        // thread advances the members' whole-file chains over the window
        // the fold is on (~67 ms per 64 MiB there, the create's one
        // serial cost, now beside the ~65 ms fold instead of ahead of
        // it). The payload is read ONCE.
        let fused = fused_scan.as_deref_mut();
        let (pinned, mut fused_state) = match fused {
            Some(scan) => (
                Some(scan.files.as_slice()),
                Some((&mut scan.state, &mut scan.lanes)),
            ),
            None => (None, None),
        };
        let prepack = prepack && pinned.is_none();
        // Only a fused create has a chain to pace against; the cap is
        // held for the loop and cleared by `Drop` on every exit.
        let pacing = fused_state.is_some() && create_fold_pacing_enabled();
        let pace_cap = pacing.then(|| crate::mem::FoldWidthCap::publish(pace_width));
        let mut ahead = vec![0u8; per_read * bs];
        let mut w0 = 0usize;
        let mut w1 = per_read.min(FIRST_WINDOW_BLOCKS).min(n_slices);
        let t0 = std::time::Instant::now();
        let readers = create_readers(true);
        read_window(
            w0,
            w1,
            &mut arena[..(w1 - w0) * bs],
            pinned,
            prepack,
            readers,
        )?;
        let mut digests = pinned.map(|_| digest_window(&arena[..(w1 - w0) * bs], w1 - w0, bs));
        t_read += t0.elapsed();
        while w0 < n_slices {
            // THE GRAIN, and the whole of what this arm pays: one
            // relaxed load per READ WINDOW (`per_read` blocks against
            // the read budget - at the 1 MiB / 64 MiB default, 64
            // blocks), on the driver thread between two windows with
            // nothing held. A park site by `PauseGate`'s rule: the
            // window's own scope is entered below and joined before the
            // loop turns.
            control.gate()?;
            let held: Vec<u32> = slice_of[w0..w1].iter().map(|&k| logs[k]).collect();
            let n0 = w1;
            let n1 = (n0 + per_read).min(n_slices);
            let t0 = std::time::Instant::now();
            let this_digests = digests.take();
            let (read_ahead, next_digests) = std::thread::scope(|sc| {
                let reader = (n0 < n_slices).then(|| {
                    sc.spawn(|| -> Result<Option<Vec<([u8; 16], u32)>>, Par2GenError> {
                        read_window(
                            n0,
                            n1,
                            &mut ahead[..(n1 - n0) * bs],
                            pinned,
                            prepack,
                            readers,
                        )?;
                        Ok(pinned.map(|_| digest_window(&ahead[..(n1 - n0) * bs], n1 - n0, bs)))
                    })
                });
                // Digests already belong to this immutable fused window.
                // Preparation has fixed-capacity stack metadata and no new
                // read/hash pass; the whole-file chains consume their original
                // digests and bytes unchanged alongside the fold.
                let duplicate_plan = if duplicates::enabled(bs, acc.len(), held.len()) {
                    this_digests.as_deref().and_then(|d| {
                        duplicates::prepare(
                            &arena[..(w1 - w0) * bs],
                            bs,
                            &held,
                            first,
                            acc.len(),
                            d,
                        )
                    })
                } else {
                    None
                };
                let chains = fused_state.as_mut().map(|(state, lanes)| {
                    let d = this_digests.expect("a fused window carries its digests");
                    let window = &plan[w0..w1];
                    let lanes_here = &lane_of[w0..w1];
                    let bytes = &arena[..(w1 - w0) * bs];
                    let state: &mut Vec<FusedMemberState> = state;
                    let lanes: &mut Option<crate::md5fast::multi::Md5Lanes> = lanes;
                    sc.spawn(move || {
                        let t_chain = std::time::Instant::now();
                        scan_fused_window(state, lanes, window, lanes_here, bytes, bs, d);
                        t_chain.elapsed()
                    })
                });
                let t_fold_w = std::time::Instant::now();
                if let Some(plan) = duplicate_plan {
                    plan.fold(acc, &arena[..(w1 - w0) * bs]);
                } else {
                    fold_batch(acc, &arena[..(w1 - w0) * bs], bs, &held, first, prepack);
                }
                let fold_took = t_fold_w.elapsed();
                t_fold_sum += fold_took;
                let chain_took =
                    chains.map(|h| h.join().expect("par2gen fused chain worker panicked"));
                t_chain_sum += chain_took.unwrap_or_default();
                if let (Some(cap), Some(chain_took)) = (pace_cap.as_ref(), chain_took) {
                    let next = paced_width(pace_width, pace_max, fold_took, chain_took);
                    if next != pace_width {
                        pace_width = next;
                        pace_moves += 1;
                        pace_min_seen = pace_min_seen.min(next);
                        cap.set(next);
                    }
                }
                match reader.map(|h| h.join().expect("par2gen read-ahead reader panicked")) {
                    Some(Ok(d)) => (None, d),
                    Some(Err(e)) => (Some(e), None),
                    None => (None, None),
                }
            });
            t_fold += t0.elapsed();
            windows += 1;
            control.step(CreatePhase::Fold, (w1 - w0) as u64 * bs as u64);
            if let Some(e) = read_ahead {
                return Err(e);
            }
            digests = next_digests;
            std::mem::swap(&mut arena, &mut ahead);
            w0 = n0;
            w1 = n1;
        }
        if timing {
            tracing::info!(
                target: "repair-timing",
                "create direct fold ({windows} windows of {per_read}, read-ahead{}{}): first read {:.2?}, fold+read {:.2?} (fold alone {:.2?}, chain alone {:.2?}){}",
                if prepack { ", prepacked" } else { "" },
                if pinned.is_some() { ", fused scan" } else { "" },
                t_read,
                t_fold,
                t_fold_sum,
                t_chain_sum,
                if pace_cap.is_some() {
                    format!(
                        "; fold paced {pace_max} -> {pace_width} workers (min {pace_min_seen}, {pace_moves} move(s))"
                    )
                } else {
                    String::new()
                }
            );
        }
        drop(pace_cap);
        return Ok(());
    }

    let mut w0 = 0usize;
    while w0 < n_slices {
        control.gate()?;
        let w1 = (w0 + per_read).min(n_slices);
        let window = &plan[w0..w1];
        let pinned = fused_scan.as_deref().map(|scan| scan.files.as_slice());
        let t0 = std::time::Instant::now();
        read_window(
            w0,
            w1,
            &mut arena[..window.len() * bs],
            pinned,
            prepack,
            create_readers(false),
        )?;
        t_read += t0.elapsed();
        let held: Vec<u32> = slice_of[w0..w1].iter().map(|&k| logs[k]).collect();
        let t0 = std::time::Instant::now();
        if let Some(scan) = fused_scan.as_deref_mut() {
            std::thread::scope(|sc| {
                let fold = sc.spawn(|| {
                    fold_batch(acc, &arena[..window.len() * bs], bs, &held, first, false);
                });
                let digests = digest_window(&arena[..window.len() * bs], window.len(), bs);
                scan_fused_window(
                    &mut scan.state,
                    &mut scan.lanes,
                    window,
                    &lane_of[w0..w1],
                    &arena[..window.len() * bs],
                    bs,
                    digests,
                );
                fold.join().expect("par2gen fused fold worker panicked");
            });
        } else {
            fold_batch(acc, &arena[..window.len() * bs], bs, &held, first, prepack);
        }
        t_fold += t0.elapsed();
        windows += 1;
        control.step(CreatePhase::Fold, (w1 - w0) as u64 * bs as u64);
        w0 = w1;
    }
    if timing {
        tracing::info!(
            target: "repair-timing",
            "create direct fold ({windows} windows of {per_read}{}): read {:.2?}, fold {:.2?}",
            if prepack { ", prepacked" } else { "" },
            t_read,
            t_fold
        );
    }
    Ok(())
}

/// Fold one arena-full of input blocks into every accumulator.
///
/// `held[i]` is the base log k_i of the block at `arena[i * bs..]`, and
/// accumulator `j` carries exponent `first + j`, so the coefficient is
/// g_i^e = 2^(k_i * e mod 65535) - the same constant the repair side
/// derives for the same slice off the same
/// [`crate::par2repair::input_base_logs`] sequence.
fn fold_batch(
    acc: &mut [Vec<u16>],
    arena: &[u8],
    bs: usize,
    held: &[u32],
    first: usize,
    prepacked: bool,
) {
    let srcs: Vec<&[u8]> = (0..held.len()).map(|i| &arena[i * bs..][..bs]).collect();
    let coeff = |j: usize, i: usize| row_coeff(held[i], first + j);
    // `None`: the creator has no `Sub` of its own, and charging its
    // folds as "PAR2 reconstruction working set" would be a lie in
    // the one instrument that exists to keep terms attributed.
    if prepacked {
        crate::par2repair::linalg::fold_parallel_prepacked(acc, &srcs, &coeff, None);
    } else {
        crate::par2repair::linalg::fold_parallel(acc, &srcs, &coeff, None);
    }
}

#[cfg(test)]
#[path = "par2gen_tests.rs"]
mod tests;

#[cfg(test)]
mod seal_tests {
    use super::*;
    #[test]
    fn prepared_seals_match_packets_for_tails_and_partial_lanes() {
        let id = [73u8; 16];
        for words in [0, 2, 12, 14, 16, 30, 32, 64, 32768] {
            for count in [1, 7, 8, 9, 17] {
                let rows: Vec<Vec<u16>> = (0..count)
                    .map(|r| {
                        (0..words)
                            .map(|w| (r * 137 + w * 379 + 11) as u16)
                            .collect()
                    })
                    .collect();
                for lanes in [false, true] {
                    let seals = prepare_recovery_seals(&id, 65500, &rows, lanes);
                    for (j, row) in rows.iter().enumerate() {
                        let bytes = crate::gf16::words_as_bytes(row);
                        let mut a = Vec::new();
                        let mut b = Vec::new();
                        write_recovery_packet(&mut a, &id, (65500 + j) as u32, bytes, None)
                            .unwrap();
                        write_recovery_packet(
                            &mut b,
                            &id,
                            (65500 + j) as u32,
                            bytes,
                            Some(&seals[j]),
                        )
                        .unwrap();
                        assert_eq!(a, b, "words={words} rows={count} lanes={lanes}");
                        assert_eq!(&a[16..32], &<[u8; 16]>::from(Md5::digest(&a[32..])));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod fold_pacing_tests {
    use super::paced_width;
    use std::time::Duration;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn a_fold_with_slack_sheds_workers_toward_eighty_percent_of_the_chain() {
        // Fold at 40% of the chain on 8 workers: aim for 0.8 -> 8*0.4/0.8 = 4.
        assert_eq!(paced_width(8, 8, ms(40), ms(100)), 4);
        // On 32 workers a 20% fold aims at 8.
        assert_eq!(paced_width(32, 32, ms(20), ms(100)), 8);
        // Never below two, never above what it had.
        assert_eq!(paced_width(2, 8, ms(1), ms(100)), 2);
        assert_eq!(paced_width(4, 8, ms(1), ms(100)), 2);
    }

    #[test]
    fn a_fold_near_the_chain_holds_and_one_past_ninety_percent_snaps_back() {
        assert_eq!(paced_width(4, 8, ms(75), ms(100)), 4);
        assert_eq!(paced_width(4, 8, ms(89), ms(100)), 4);
        assert_eq!(paced_width(4, 8, ms(90), ms(100)), 8);
        assert_eq!(paced_width(4, 8, ms(130), ms(100)), 8);
    }

    #[test]
    fn degenerate_timings_leave_the_width_alone() {
        assert_eq!(paced_width(6, 8, Duration::ZERO, ms(100)), 6);
        assert_eq!(paced_width(6, 8, ms(50), Duration::ZERO), 6);
        assert_eq!(paced_width(6, 0, ms(50), ms(100)), 1);
    }
}
