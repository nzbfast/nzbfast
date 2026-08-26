//! Live in-stream PAR2 verification (design: M2 - the one-pass pipeline).
//!
//! Decoded article buffers are hashed against the PAR2 block checksums
//! *while the download runs*, so verification finishes with the last
//! article and clean sets never trigger a post-download verify pass.
//!
//! Design:
//! - The par2 main packet is scheduled first; [`LiveVerifier`] starts in
//!   `Waiting` and is [`activate`](LiveVerifier::activate)d mid-download as
//!   soon as its packets parse. Until then articles just record their
//!   yEnc name and capture the first 16 KiB (for obfuscation matching).
//! - NZB slots are matched to PAR2 files lazily - by exact/sanitized name
//!   first, then by md5-16k (obfuscated posts lie in subjects but not in
//!   their bytes).
//! - Blocks fully contained in one decoded span are hashed straight from
//!   the decode buffer - zero copies, no disk involvement. Blocks that
//!   straddle article boundaries accumulate in bounded per-file partial
//!   buffers (at most one boundary block per adjacent-article pair is ever
//!   alive; a cap converts pathological orderings into read-back work
//!   instead of unbounded memory).
//! - Anything not verified in-stream (spans decoded before activation,
//!   partials whose neighbor article never arrived, missing articles) is
//!   settled by [`finish_slot`](LiveVerifier::finish_slot) with targeted
//!   `pread`s of exactly those blocks - usually straight from page cache,
//!   and usually zero blocks on the happy path.
//!
//! Hashing happens *outside* the per-slot lock: `on_data` claims work under
//! the lock, hashes lock-free, then records results. MD5 is the throughput
//! floor (~0.6 GB/s/core), so concurrent decode workers must not serialize.
//! [`set_fast_verify`](LiveVerifier::set_fast_verify) lifts that floor by
//! claiming in-stream blocks on the IFSC CRC32 alone (TODO §10) - settle
//! read-back and the no-IFSC whole-file check always keep full MD5.

use crate::sync::{MutexExt, RwLockExt};
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex, RwLock};

use md5::{Digest, Md5};

use crate::par2::{BlockCheck, Par2Error, Par2Set};

/// Default GLOBAL cap on bytes held in partial (boundary) block buffers,
/// across ALL slots, used when NOTHING published a process budget. Beyond
/// it, new partials are abandoned to the settle read-back path instead of
/// allocated. This must be global: a per-file cap multiplied by hundreds
/// of volume slots was the linear RSS term measured on big jobs
/// (5 GB @ 87 GB → 25.8 GB @ 190 GB). Overridden by the MemBudget slice
/// (`with_partials_cap`), and by [`default_partials_cap`] whenever an
/// entry point sized the process.
const PARTIAL_BYTES_DEFAULT_CAP: usize = 256 * 1024 * 1024;
/// Floor under any partials cap, however it was chosen. One block's
/// boundary buffer has to fit or the verifier spills every partial it
/// ever sees and the in-stream lane degrades to pure read-back.
const PARTIAL_BYTES_CAP_FLOOR: usize = 1 << 20;

/// The cap a freshly-built [`LiveVerifier::new`] starts with: the
/// published budget's 30% slice if an entry point sized this process,
/// else the flat [`PARTIAL_BYTES_DEFAULT_CAP`] (TODO 265).
///
/// The sibling of the extractor's `default_holds_cap` (TODO 260), fixed
/// for symmetry rather than for a live bug: as of 23 Aug 2026 the only
/// production `LiveVerifier` is built by `crates/nzbfast/src/get/vrig.rs`,
/// which already passes `budget.partials_cap()`, and every
/// `LiveVerifier::new` in the tree is a test or a test rig. The trap is
/// latent, and it is the same one: `set_process_budget` is read
/// IMPLICITLY by the repair paths, `rar_read_options` and the LZMA gauge,
/// so it looks like the way to size a pipeline, and a rig that pins
/// 256 MiB and then builds a bare verifier would silently buffer against
/// a figure it never chose. That exact shape cost a measurement day on
/// the extractor tier (TODO 209 / 256), where it was written up as an
/// untracked allocation wanting a new budget tier. It was neither.
///
/// Reading [`crate::mem::published_budget`] rather than
/// [`crate::mem::process_budget`] is the whole design, verbatim from
/// TODO 260. `process_budget` falls back to `MemBudget::auto` - RAM/4,
/// clamped to [256 MiB, 16 GiB] - so a default routed through it would
/// hand a 4 GB CI runner a 307 MiB cap and this dev box a 4.8 GiB one,
/// and every partials-sensitive test would spill or not according to the
/// host it ran on. Nothing publishes a budget in a unit test, so `None`
/// keeps the whole existing suite byte-identical to the flat 256 MiB it
/// was written against, while every real entry point (`serve`, the CLI's
/// `run`, `embedded_init`) and any rig that says `set_process_budget`
/// gets the honest slice.
fn default_partials_cap() -> usize {
    crate::mem::published_budget()
        .map(|b| b.partials_cap())
        .unwrap_or(PARTIAL_BYTES_DEFAULT_CAP)
        .max(PARTIAL_BYTES_CAP_FLOOR)
}

/// First-16-KiB capture used for md5_16k matching of obfuscated posts.
const HEAD_LEN: usize = 16384;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockState {
    /// Not yet verified (in-stream hashing hasn't covered it).
    Pending,
    Ok,
    Bad,
}

/// §94 B: the verified-block watermark the chase decode gates on.
///
/// Invariant it exists to enforce: **the chase decode may only consume
/// bytes the PAR2 set has vouched for** - then a repair can never
/// rewrite consumed bytes (repairs only target Bad blocks, and a gated
/// decode never consumed a Bad or Pending block), and the frontier's
/// `"repair rewrote chased bytes"` demote becomes structurally
/// unreachable instead of being the outcome.
///
/// One cell per slot in VOLUME-offset space. `None` = ungated (no set,
/// slot unclaimed, or the gate is switched off) and reads as
/// `u64::MAX`; a claim engages the cell at 0 and verification advances
/// it monotonically. `u64::MAX` after engagement means "every block
/// verified" - the tail past the last block needs no gate.
///
/// Waiters poll with a bounded timeout instead of pairing this condvar
/// with the frontier's: a gate-blocked reader must still observe
/// buffer aborts and demotes, which notify the frontier's own condvar
/// (the pool-deadlock rule - an Err must never hang a waiter).
pub struct VerifyGate {
    marks: Mutex<Vec<Option<u64>>>,
    cv: Condvar,
}

impl VerifyGate {
    pub fn new(n_slots: usize) -> Arc<VerifyGate> {
        Arc::new(VerifyGate {
            marks: Mutex::new(vec![None; n_slots]),
            cv: Condvar::new(),
        })
    }

    /// The slot's current watermark; ungated slots read as `u64::MAX`.
    ///
    /// A slot past the cells this gate was sized for is ungated too. The
    /// root extractor mints slots the NZB never had (`alloc_slot` from
    /// the mapped repair, for a wholly-missing volume rebuilt in full
    /// from parity), and the gate is sized at the NZB's slot count. The
    /// bytes such a slot holds came out of the PAR2 repair, so they are
    /// vouched by construction; before this tolerance the chase worker
    /// panicked on the index (gated e2e matrix, 22 Aug 2026:
    /// `compressed_set_wholly_missing_volume_joins_chase_one_pass`).
    pub fn watermark(&self, slot: usize) -> u64 {
        self.cell(slot).unwrap_or(u64::MAX)
    }

    /// The cell, or `None` past the sized range (see [`watermark`]).
    ///
    /// [`watermark`]: VerifyGate::watermark
    fn cell(&self, slot: usize) -> Option<u64> {
        self.marks.lock_ok().get(slot).copied().flatten()
    }

    /// The watermark only if the verifier has ENGAGED this slot (claimed
    /// it while the set was active): `None` is "nothing vouched for
    /// yet", where [`watermark`] would answer `u64::MAX`. The dropping
    /// trim asks this, because it must not read an unclaimed slot as
    /// fully verified (bug sweep 22 Aug 2026).
    ///
    /// [`watermark`]: VerifyGate::watermark
    pub fn engaged_mark(&self, slot: usize) -> Option<u64> {
        self.cell(slot)
    }

    /// A claim engaged the gate for this slot: from here on the decode
    /// waits for verification. Idempotent; never lowers an existing mark.
    pub(crate) fn engage(&self, slot: usize) {
        let mut m = self.marks.lock_ok();
        if m.len() <= slot {
            m.resize(slot + 1, None);
        }
        if m[slot].is_none() {
            m[slot] = Some(0);
            drop(m);
            self.cv.notify_all();
        }
    }

    /// Monotonic advance (a lower value than the current one is a stale
    /// racer and is dropped).
    pub(crate) fn advance(&self, slot: usize, bytes: u64) {
        let mut m = self.marks.lock_ok();
        if m.len() <= slot {
            m.resize(slot + 1, None);
        }
        let cur = m[slot].unwrap_or(0);
        if bytes > cur || m[slot].is_none() {
            m[slot] = Some(bytes.max(cur));
            drop(m);
            self.cv.notify_all();
        }
    }

    /// Park until the slot's watermark covers `offset`, or `timeout`
    /// passes (callers loop and re-check their own abort conditions -
    /// the bounded wait is what keeps an abort from stranding a
    /// gate-blocked reader).
    pub fn wait_past(&self, slot: usize, offset: u64, timeout: std::time::Duration) {
        let mark = |m: &Vec<Option<u64>>| m.get(slot).copied().flatten().unwrap_or(u64::MAX);
        let m = self.marks.lock_ok();
        if mark(&m) > offset {
            return;
        }
        let _ = self
            .cv
            .wait_timeout_while(m, timeout, |m| mark(m) <= offset);
    }

    /// Park until ANY mark advances, or `timeout` passes. What a
    /// [`ChaseGate`] that derives its limit from several slots (a
    /// routed child's, row 27) waits on: it cannot name one slot, so
    /// it wakes on every advance and recomputes.
    pub fn wait_any(&self, timeout: std::time::Duration) {
        let m = self.marks.lock_ok();
        let _ = self.cv.wait_timeout(m, timeout);
    }

    /// Every engaged slot is now fully vouched for. Called once a
    /// mapped repair has proved the whole set (it re-reads every file
    /// of the set through the view it wrote through - whole-file MD5
    /// for the files it rebuilt into, per-block CRC32 for the rest):
    /// the Bad blocks it rebuilt are Ok now, but the verifier's block
    /// states were taken before the repair and never move again, so
    /// without this a decode parked at a repaired block would wait
    /// until finish released it (row 27, 22 Aug 2026). Unengaged slots
    /// stay unengaged: an advance would turn "nothing vouched for" into
    /// "everything vouched for" in [`engaged_mark`]'s eyes.
    ///
    /// [`engaged_mark`]: VerifyGate::engaged_mark
    pub fn release_all(&self) {
        let mut m = self.marks.lock_ok();
        for cell in m.iter_mut() {
            if cell.is_some() {
                *cell = Some(u64::MAX);
            }
        }
        drop(m);
        self.cv.notify_all();
    }
}

/// What a chase frontier buffer waits on (§94 B): the offset below
/// which its volume's bytes are PAR2-vouched. The root's buffers key
/// straight into [`VerifyGate`] by slot ([`SlotGate`]); a routed child's
/// bytes come from several parent volumes, so its gate translates
/// through the routing map (`extract::ChildGate`). The buffer only ever
/// asks two things of it: the limit now, and a bounded park for it to
/// move.
pub trait ChaseGate: Send + Sync {
    /// Bytes at or past this offset must not reach the decode. `u64::MAX`
    /// = nothing is withheld.
    fn watermark(&self) -> u64;
    /// Park until the limit may have moved past `offset`, or `timeout`
    /// passes. Spurious wakes are fine: the caller re-reads
    /// [`watermark`](ChaseGate::watermark) and loops.
    fn wait_past(&self, offset: u64, timeout: std::time::Duration);
}

/// [`ChaseGate`] for a root-level slot: the [`VerifyGate`] cell itself.
pub struct SlotGate {
    pub gate: Arc<VerifyGate>,
    pub slot: usize,
}

impl ChaseGate for SlotGate {
    fn watermark(&self) -> u64 {
        self.gate.watermark(self.slot)
    }

    fn wait_past(&self, offset: u64, timeout: std::time::Duration) {
        self.gate.wait_past(self.slot, offset, timeout);
    }
}

/// A boundary block accumulating bytes from more than one article.
struct Partial {
    /// Real bytes of this block (final block may be shorter than block_size).
    buf: Vec<u8>,
    /// Filled intervals within `buf`, sorted + merged.
    filled: Vec<(usize, usize)>,
}

impl Partial {
    fn new(len: usize) -> Partial {
        Partial {
            buf: vec![0; len],
            filled: Vec::with_capacity(2),
        }
    }

    fn fill(&mut self, at: usize, bytes: &[u8]) {
        self.buf[at..at + bytes.len()].copy_from_slice(bytes);
        let (mut s, mut e) = (at, at + bytes.len());
        // Merge into the sorted interval list.
        let mut merged = Vec::with_capacity(self.filled.len() + 1);
        for &(fs, fe) in &self.filled {
            if fe < s || fs > e {
                merged.push((fs, fe));
            } else {
                s = s.min(fs);
                e = e.max(fe);
            }
        }
        merged.push((s, e));
        merged.sort_unstable();
        self.filled = merged;
    }

    fn complete(&self) -> bool {
        self.filled == [(0, self.buf.len())]
    }
}

/// B1: a boundary block held as per-fragment CRC32s instead of bytes.
/// CRC32 composes over concatenation (`crc32_combine`), so fragments can
/// arrive in any order and merge whenever neighbors touch - ~24 bytes per
/// fragment against a block-sized buffer. Only valid when the block will
/// be claimed on CRC alone (fast/lean verify - the default); full-MD5
/// mode keeps byte buffers because MD5 cannot be composed.
///
/// This erases the partials RSS term entirely in default mode - the term
/// that grew linearly on big jobs (25.8 GB at 190 GB pre-cap) and that at
/// the 256 MB MemBudget floor forced constant spill → settle read-back on
/// exactly the boxes with the slowest disks. When the PAR2 block size
/// exceeds the article size, EVERY block straddles articles and the old
/// buffers approached a full copy of the in-flight file.
struct CrcParts {
    /// (start, end, crc32 of that range) - sorted, non-overlapping,
    /// adjacent entries eagerly merged.
    parts: Vec<(usize, usize, u32)>,
}

impl CrcParts {
    fn new() -> CrcParts {
        CrcParts {
            parts: Vec::with_capacity(2),
        }
    }

    /// Merge a fragment. Returns false on overlap with an existing part -
    /// impossible for decoder-fresh spans (each article is fed once), so
    /// the caller treats it as "this block can't be tracked losslessly"
    /// and abandons the block to settle read-back.
    fn insert(&mut self, s: usize, e: usize, crc: u32) -> bool {
        let at = self.parts.partition_point(|&(ps, _, _)| ps < s);
        if at > 0 && self.parts[at - 1].1 > s {
            return false;
        }
        if at < self.parts.len() && self.parts[at].0 < e {
            return false;
        }
        self.parts.insert(at, (s, e, crc));
        // Merge with the right neighbor, then the left (order matters for
        // index stability; combine() appends the RIGHT part's crc).
        if at + 1 < self.parts.len() && self.parts[at].1 == self.parts[at + 1].0 {
            let (rs, re, rc) = self.parts.remove(at + 1);
            let _ = rs;
            let p = &mut self.parts[at];
            p.2 = crate::yenc_simd::crc32_combine(p.2, rc, (re - p.1) as u64);
            p.1 = re;
        }
        if at > 0 && self.parts[at - 1].1 == self.parts[at].0 {
            let (_, e2, c2) = self.parts.remove(at);
            let p = &mut self.parts[at - 1];
            p.2 = crate::yenc_simd::crc32_combine(p.2, c2, (e2 - p.1) as u64);
            p.1 = e2;
        }
        true
    }

    /// CRC of the whole block's real bytes once every fragment landed.
    fn complete(&self, blen: usize) -> Option<u32> {
        match self.parts.as_slice() {
            [(0, e, crc)] if *e == blen => Some(*crc),
            _ => None,
        }
    }
}

/// A boundary block in flight: bytes (full-MD5 mode) or fragment CRCs
/// (fast/lean mode).
enum PartialBuf {
    Bytes(Partial),
    Crc(CrcParts),
}

/// How the backfill pass must re-feed one slot's pre-activation spans -
/// the public half of [`Src`], returned by
/// [`LiveVerifier::take_pre_spans`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PreSpanSrc {
    /// This run decoded every span and each may claim as strongly as a
    /// fresh one - the pcrc32 passed, or lean mode owns the weaker
    /// contract. Feed via [`LiveVerifier::on_data_backfill`].
    Backfill,
    /// Crash resume seeded some, or a span arrived with no wire CRC
    /// behind it - feed via [`LiveVerifier::on_data_from_disk`].
    Disk,
}

/// Where a span came from - decides claim strength (see on_data_inner).
#[derive(Clone, Copy, PartialEq)]
enum Src {
    /// Decoder-fresh, article CRC passed.
    Fresh,
    /// Decoder-fresh, article CRC deliberately skipped (lean mode).
    Lean,
    /// Re-read from disk in THIS run, of bytes this process decoded with a
    /// passing yEnc pcrc32 (the M15b backfill of pre-activation spans).
    /// Claims exactly as strongly as `Fresh`: same two CRC32 layers, and
    /// under fast verify a fresh span's disk copy is never checked either.
    /// [`LiveVerifier::take_pre_spans`] is the gate that keeps that true -
    /// a slot whose pre-activation spans were not all wire-CRC'd is routed
    /// to `Disk` instead (unless lean owns them).
    Rehash,
    /// Read back from disk with nothing in this run vouching for the bytes
    /// (settle, crash resume) - never claims CRC-only.
    Disk,
}

struct SlotState {
    /// yEnc-header name (authoritative once seen; NZB subjects lie).
    name: Option<String>,
    /// `name`'s lookup keys (ASCII-lowercased, sanitized), computed once on
    /// first `try_match` - the name never changes after it is set, and an
    /// unmatched slot re-matches on every article.
    name_keys: Option<(String, String)>,
    /// First min(16 KiB, file) bytes for md5_16k matching - articles arrive
    /// out of order, so this fills interval-wise like a boundary block.
    head: Option<Partial>,
    /// yEnc-declared file size (caps head capture for small files).
    file_size: u64,
    /// Index into the active set's `files` once matched.
    file: Option<usize>,
    /// One entry per PAR2 block once matched.
    blocks: Vec<BlockState>,
    partials: HashMap<usize, PartialBuf>,
    /// Bytes held by `PartialBuf::Bytes` entries only - CRC entries are
    /// ~free and exempt from the global partials budget.
    partial_bytes: usize,
    /// Spans decoded before PAR2 activation (offset, len) - metadata only.
    /// The backfill pass re-feeds them from disk once the set is live, so
    /// settle read-back shrinks toward zero (M15b).
    pre_spans: Vec<(u64, u32)>,
    /// Some of `pre_spans` were seeded by crash resume (or otherwise came
    /// off disk), so nothing in this run vouches for those bytes at all -
    /// the whole slot's backfill drops to the full-MD5 disk path rather
    /// than trying to tell the two apart.
    resume_seeded: bool,
    /// Some of `pre_spans` were decoded without a wire CRC covering them (a
    /// pcrc-absent article, or lean's skipped article CRCs). Same reason as
    /// `resume_seeded` - offsets are all `pre_spans` hold, so the backfill
    /// re-feeds a slot under ONE source - but lean may still claim these
    /// CRC-only, so the two flags stay apart (see `take_pre_spans`).
    pre_unvouched: bool,
    /// Matching was attempted and failed permanently (name + head both
    /// exhausted) - avoids rescanning every article.
    unmatchable: bool,
    /// Blocks verified in-stream (for the zero-read-back accounting).
    live_ok: u64,
    live_bad: u64,
    /// §94 B: count of leading contiguous Ok blocks, maintained
    /// incrementally so watermark publication is O(advance), not
    /// O(blocks) per span.
    ok_prefix: usize,
}

enum Plan {
    /// Par2 main not yet parsed; slots record names/heads only.
    Waiting,
    Active(Active),
    /// No PAR2 in this NZB - verification off.
    Off,
}

struct Active {
    set: Arc<Par2Set>,
    /// file idx → slot that claimed it (one slot per PAR2 file). Its own
    /// mutex: matching happens while holding a slot lock, and two slots
    /// must not race a claim.
    claimed: Mutex<Vec<Option<usize>>>,
    /// Name lookups built once at activation so `try_match` consults short
    /// candidate lists under the claimed mutex instead of scanning (and
    /// re-sanitizing) every descriptor per call - the mutex serializes all
    /// decode threads, and unmatched slots retry on every article. Values
    /// are descriptor indexes in FileDesc order, so "first candidate" and
    /// duplicate-name precedence stay byte-identical to a linear scan.
    /// Exact byte-equal matches are found inside their fold bucket (byte
    /// equality implies ASCII-case equality, so no third map is needed).
    by_fold: HashMap<String, Vec<usize>>,
    by_sanitized: HashMap<String, Vec<usize>>,
}

impl Active {
    fn new(set: Arc<Par2Set>) -> Active {
        let claimed = Mutex::new(vec![None; set.files.len()]);
        let mut by_fold: HashMap<String, Vec<usize>> = HashMap::new();
        let mut by_sanitized: HashMap<String, Vec<usize>> = HashMap::new();
        for (fi, f) in set.files.iter().enumerate() {
            by_fold
                .entry(f.name.to_ascii_lowercase())
                .or_default()
                .push(fi);
            by_sanitized
                .entry(crate::disk::sanitize_filename(&f.name))
                .or_default()
                .push(fi);
        }
        Active {
            set,
            claimed,
            by_fold,
            by_sanitized,
        }
    }
}

/// Result of settling one slot at completion time.
#[derive(Debug)]
pub struct SlotReport {
    pub par2_name: Option<String>,
    pub total_blocks: usize,
    pub bad_blocks: Vec<usize>,
    /// Blocks verified in-stream from decode buffers.
    pub live_blocks: u64,
    /// Blocks that needed the read-back fallback.
    pub readback_blocks: u64,
    /// File length per PAR2 (0 if unmatched).
    pub length: u64,
}

impl SlotReport {
    pub fn all_ok(&self) -> bool {
        self.par2_name.is_some() && self.bad_blocks.is_empty()
    }
}

// ---- Instrument-first: yEnc verified-CRC reuse geometry ----
//
// The SIMD yEnc decoder already computes a VERIFIED whole-article CRC32
// (`yenc_simd::DecodeIntegrity::verified_article_crc`) and hands it to the
// download workers, which spend it on RAR STORE composition and then drop
// it. Under fast verify a full PAR2 block is claimed on its own CRC32
// alone - so an article whose bytes ARE exactly one block could be claimed
// on the CRC the decoder already computed, saving one CRC32 pass over
// every such byte.
//
// That reuse is sound ONLY for an article that is exactly one UNTRIMMED,
// BLOCK-ALIGNED, FULL PAR2 block, fed from a decoder-fresh span
// (`Src::Fresh` - the only source holding a wire CRC at feed time) while
// fast verify is on. A file's SHORT last block counts as full: the IFSC
// CRC32 is taken over the block zero-padded to `block_size`, and
// `crc32_zeros` extends a CRC over that padding in O(log n) rather than
// hashing it - which is exactly where a reuse would splice in. Whether real posts have that geometry is an empirical
// question and nothing here can reason it out: article size and PAR2 block
// size are chosen independently by whoever posted the set. So this counts
// it rather than guessing, and changes NOTHING about what gets hashed -
// the decision to implement the reuse waits on the numbers.
//
// The denominator is spans that REACH block mapping: an active plan, a
// slot matched to a PAR2 file, and that file carrying IFSC blocks. An
// article that never gets that far could not have benefited whatever its
// geometry, so counting it would only dilute the ratio.
//
// One caveat the geometry deliberately does not model: the bare-LF scalar
// decode fallback reports `crc_checked` with no VALUE, so a small slice of
// geometrically-qualifying articles would still have to hash. That is a
// decoder-path term, not a geometry one, and an implementation would
// measure it separately.

/// The four relaxed tallies behind [`CrcReuseGeometry`]. One instance
/// rides each [`LiveVerifier`] (the per-job answer, printed at the end of
/// a run) and one is process-global (the cumulative answer the daemon
/// stats API surfaces).
#[derive(Default)]
struct GeomTally {
    spans: std::sync::atomic::AtomicU64,
    bytes: std::sync::atomic::AtomicU64,
    qualifying: std::sync::atomic::AtomicU64,
    qualifying_bytes: std::sync::atomic::AtomicU64,
}

impl GeomTally {
    const fn new() -> GeomTally {
        use std::sync::atomic::AtomicU64;
        GeomTally {
            spans: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            qualifying: AtomicU64::new(0),
            qualifying_bytes: AtomicU64::new(0),
        }
    }

    fn note(&self, len: usize, qualifies: bool) {
        use std::sync::atomic::Ordering;
        self.spans.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(len as u64, Ordering::Relaxed);
        if qualifies {
            self.qualifying.fetch_add(1, Ordering::Relaxed);
            self.qualifying_bytes
                .fetch_add(len as u64, Ordering::Relaxed);
        }
    }

    fn snapshot(&self) -> CrcReuseGeometry {
        use std::sync::atomic::Ordering;
        CrcReuseGeometry {
            spans: self.spans.load(Ordering::Relaxed),
            spans_bytes: self.bytes.load(Ordering::Relaxed),
            qualifying: self.qualifying.load(Ordering::Relaxed),
            qualifying_bytes: self.qualifying_bytes.load(Ordering::Relaxed),
        }
    }
}

/// Process-lifetime reuse geometry - see [`crc_reuse_geometry_total`].
static CRC_REUSE_GEOMETRY: GeomTally = GeomTally::new();

/// A snapshot of the verified-CRC reuse geometry census (see the section
/// note above). The question it answers is the byte ratio: what share of
/// the bytes fast verify CRC32s would a reuse implementation stop hashing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CrcReuseGeometry {
    /// Article spans that reached PAR2 block mapping.
    pub spans: u64,
    /// Their bytes, after the clamp to the PAR2-declared file length.
    pub spans_bytes: u64,
    /// Of those spans, the ones that are exactly one untrimmed,
    /// block-aligned, full PAR2 block from a decoder-fresh source with
    /// fast verify on - the geometry the decoder's CRC is reusable for.
    pub qualifying: u64,
    /// Their bytes - the share that reuse would stop hashing.
    pub qualifying_bytes: u64,
}

/// Cumulative (process-lifetime) verified-CRC reuse geometry. Surfaced by
/// the daemon stats API; a single run's own numbers come from
/// [`LiveVerifier::crc_reuse_geometry`].
pub fn crc_reuse_geometry_total() -> CrcReuseGeometry {
    CRC_REUSE_GEOMETRY.snapshot()
}

/// Reset the process-global tally to zero. Test-only: the counter is
/// process-global, so a test asserting exact counts must isolate first.
#[doc(hidden)]
pub fn reset_crc_reuse_geometry_total() {
    use std::sync::atomic::Ordering;
    for c in [
        &CRC_REUSE_GEOMETRY.spans,
        &CRC_REUSE_GEOMETRY.bytes,
        &CRC_REUSE_GEOMETRY.qualifying,
        &CRC_REUSE_GEOMETRY.qualifying_bytes,
    ] {
        c.store(0, Ordering::Relaxed);
    }
}

pub struct LiveVerifier {
    plan: RwLock<Plan>,
    slots: Vec<Mutex<SlotState>>,
    /// §94 B: watermark handle the chase decode gates on; None unless the
    /// run wired one (attached, and its WAIT env-gated, in get/vrig.rs).
    gate: Mutex<Option<Arc<VerifyGate>>>,
    /// Run-wide counters for the dashboard's verify lane (M14h).
    live_ok_total: std::sync::atomic::AtomicU64,
    live_bad_total: std::sync::atomic::AtomicU64,
    /// M15 global partial-buffer accounting (bytes, across all slots).
    partials_cap: usize,
    partials_used: std::sync::atomic::AtomicUsize,
    partials_peak: std::sync::atomic::AtomicUsize,
    /// Blocks pushed to settle read-back because the budget was full.
    partials_spilled: std::sync::atomic::AtomicU64,
    /// Fast verify (TODO §10): claim in-stream blocks on the IFSC CRC32
    /// alone, skipping the MD5 pass - MD5 is the compute floor
    /// (~0.8 GB/s/core vs 10+ for hw CRC), and every in-stream span
    /// already passed its yEnc pcrc32 in the decoder. Settle read-back
    /// and the no-IFSC whole-file check keep full MD5 hashing either way.
    fast: std::sync::atomic::AtomicBool,
    /// M32 lean mode: CRC-only claims allowed for untrusted spans too
    /// (article CRCs are being skipped upstream). See [`Self::set_lean`].
    lean: std::sync::atomic::AtomicBool,
    /// THIS run's verified-CRC reuse geometry census (see [`GeomTally`]).
    /// Every bump here also bumps the process-global twin.
    geom: GeomTally,
}

impl LiveVerifier {
    pub fn new(n_slots: usize) -> LiveVerifier {
        Self::with_partials_cap(n_slots, default_partials_cap())
    }

    /// M15: cap partial-block memory at `cap` bytes GLOBALLY (a MemBudget
    /// slice). Overflow degrades to settle read-back, never fails.
    pub fn with_partials_cap(n_slots: usize, cap: usize) -> LiveVerifier {
        LiveVerifier {
            plan: RwLock::new(Plan::Waiting),
            live_ok_total: Default::default(),
            live_bad_total: Default::default(),
            partials_cap: cap.max(PARTIAL_BYTES_CAP_FLOOR),
            partials_used: Default::default(),
            partials_peak: Default::default(),
            partials_spilled: Default::default(),
            fast: Default::default(),
            lean: Default::default(),
            geom: Default::default(),
            gate: Mutex::new(None),
            slots: (0..n_slots)
                .map(|_| Mutex::new(SlotState::empty()))
                .collect(),
        }
    }

    /// §94 B: hand this verifier the watermark handle to publish through.
    /// Wire before articles flow; slots claimed afterwards engage their
    /// cell at claim time, and every block transition advances it.
    pub fn set_gate(&self, gate: Arc<VerifyGate>) {
        *self.gate.lock_ok() = Some(gate);
    }

    /// §94 B: advance the slot's published watermark off its contiguous
    /// Ok-block prefix. Called under the slot lock after any block
    /// transition; O(newly-contiguous blocks) thanks to `ok_prefix`.
    /// A fully-verified slot publishes `u64::MAX` - the tail past the
    /// last block (and the whole file once every block claims) needs no
    /// gate.
    fn gate_publish(&self, slot: usize, s: &mut SlotState, block_size: usize) {
        if s.file.is_none() {
            return;
        }
        let Some(g) = self.gate.lock_ok().clone() else {
            return;
        };
        while s.ok_prefix < s.blocks.len() && s.blocks[s.ok_prefix] == BlockState::Ok {
            s.ok_prefix += 1;
        }
        let bytes = if s.ok_prefix == s.blocks.len() {
            u64::MAX
        } else {
            s.ok_prefix as u64 * block_size as u64
        };
        g.advance(slot, bytes);
    }

    /// Declare that no PAR2 set will ever arrive (NZB has none).
    pub fn set_off(&self) {
        *self.plan.write_ok() = Plan::Off;
    }

    /// Enable/disable fast verify (CRC32-only in-stream claims). Flip
    /// before articles flow; blocks already claimed keep their verdict.
    pub fn set_fast_verify(&self, on: bool) {
        self.fast.store(on, std::sync::atomic::Ordering::Relaxed);
    }

    /// M32 "lean" mode (opt-in, slow-CPU boost): CRC-only claims are
    /// allowed even for spans the decoder did NOT vouch for - the
    /// caller is skipping article CRCs on PAR2-covered slots, so the
    /// block CRC32 is the single in-stream integrity layer. Settle
    /// read-back and repair remain the final authority. Only
    /// meaningful with fast verify on.
    pub fn set_lean(&self, on: bool) {
        self.lean.store(on, std::sync::atomic::Ordering::Relaxed);
    }

    /// Seed a slot's name when no article will ever flow through it (crash
    /// resume: fully-completed slots refetch nothing, but matching still
    /// needs a name). A later yEnc name would win only if none is set -
    /// call this exclusively for slots with zero pending articles.
    pub fn set_name_hint(&self, slot: usize, name: &str) {
        let mut s = self.slots[slot].lock_ok();
        if s.name.is_none() && !name.is_empty() {
            s.name = Some(name.to_string());
        }
    }

    /// Parse + adopt the recovery set. Call once, when the par2 main
    /// file(s) finish downloading. Returns the parsed set for the caller's
    /// own use (repair planning, reporting).
    pub fn activate(&self, inputs: &[&[u8]]) -> Result<Arc<Par2Set>, Par2Error> {
        let set = Arc::new(pick_set(inputs)?);
        // Memory-floor gauge (instrument-first): the retained per-block
        // verification tables. 20 B of BlockCheck per IFSC block (rounded
        // to 24 for Vec/padding) - proportional to set size over block
        // size, so a pathological small-block set shows up here.
        let blocks: u64 = set.files.iter().map(|f| f.blocks.len() as u64).sum();
        crate::memgauge::set_at_least(crate::memgauge::Sub::VerifierMeta, blocks * 24);
        *self.plan.write_ok() = Plan::Active(Active::new(set.clone()));
        Ok(set)
    }

    /// M32 perf: true when this slot's bytes will be FULLY verified
    /// without the article CRC - the set is active, the slot is matched
    /// to a PAR2 file, and fast verify is OFF (every claim is full
    /// block MD5). Callers may then skip the yEnc pcrc32 pass, feeding
    /// spans as untrusted. Under fast verify this must stay false: the
    /// CRC-only claim's justification IS the passed pcrc32.
    pub fn delegates_integrity(&self, slot: usize) -> bool {
        // Fast mode blocks delegation - UNLESS lean mode explicitly
        // opted into single-CRC32 in-stream integrity.
        if self.fast.load(std::sync::atomic::Ordering::Relaxed)
            && !self.lean.load(std::sync::atomic::Ordering::Relaxed)
        {
            return false;
        }
        if !matches!(&*self.plan.read_ok(), Plan::Active(_)) {
            return false;
        }
        self.slots[slot].lock_ok().file.is_some()
    }

    /// Has an ACTIVE set claimed this slot as one of its files?
    ///
    /// The same question [`Self::delegates_integrity`] asks, without its
    /// fast/lean verify conditions - those are about whether the article
    /// CRC may be skipped, which is a different matter from whether the
    /// set speaks for these bytes. Completion accounting needs the plain
    /// form: a slot the set covers has its bytes proven (or rebuilt) by
    /// the set, so this run's own write-coverage map is not the witness
    /// to consult about it. Name matching alone cannot answer it - an
    /// obfuscated post's slot hint is a hash, and the set's FileDesc
    /// carries the real name.
    pub fn slot_in_set(&self, slot: usize) -> bool {
        matches!(&*self.plan.read_ok(), Plan::Active(_))
            && self.slots[slot].lock_ok().file.is_some()
    }

    pub fn set(&self) -> Option<Arc<Par2Set>> {
        match &*self.plan.read_ok() {
            Plan::Active(a) => Some(a.set.clone()),
            _ => None,
        }
    }

    /// Feed one decoded article span. `name`/`file_size` come from the yEnc
    /// header; `offset` is the file offset of `data`. Call after the bytes
    /// are written (read-back must be able to see them). ONLY for
    /// decoder-fresh spans (the yEnc pcrc32 just passed): fast verify may
    /// claim their blocks CRC-only. Bytes re-read from disk go through
    /// [`on_data_backfill`](Self::on_data_backfill) (this run's own
    /// pre-activation spans) or
    /// [`on_data_from_disk`](Self::on_data_from_disk) (everything else).
    pub fn on_data(&self, slot: usize, name: &str, file_size: u64, offset: u64, data: &[u8]) {
        self.on_data_inner(slot, name, file_size, offset, data, Src::Fresh);
    }

    /// [`on_data`](Self::on_data) for spans whose bytes came back off disk
    /// with nothing in this run vouching for them (settle read-back,
    /// crash-resume seeds). They always take the full MD5+CRC block check -
    /// fast verify never thins the resume path's protection.
    pub fn on_data_from_disk(
        &self,
        slot: usize,
        name: &str,
        file_size: u64,
        offset: u64,
        data: &[u8],
    ) {
        self.on_data_inner(slot, name, file_size, offset, data, Src::Disk);
    }

    /// M15b backfill: a span re-read from disk in THIS run, recorded as a
    /// pre-activation span while the plan was `Waiting` (by
    /// [`on_data`](Self::on_data), or by
    /// [`on_data_unverified`](Self::on_data_unverified) in lean mode).
    /// Trust equals a fresh span's - the wire CRC layer happened, and fast
    /// verify already claims fresh blocks without ever reading their disk
    /// copy - so boundary fragments compose as CRC parts (B1) instead of
    /// forcing block-sized byte buffers. Feeding these through
    /// [`on_data_from_disk`](Self::on_data_from_disk) instead re-created
    /// the exact partials-RSS term B1 removed: with a PAR2 block bigger
    /// than the partials budget every backfilled block spilled straight
    /// back to settle read-back.
    ///
    /// Only for spans this run produced: crash-resume seeds stay on the
    /// disk path. Whether a pcrc-absent article may ride here is lean
    /// mode's call, not this function's - lean owns that trade, and
    /// [`take_pre_spans`](Self::take_pre_spans) is the single gate that
    /// decides it. Call this only with the source `take_pre_spans` handed
    /// back; it is what tells the routes apart.
    pub fn on_data_backfill(
        &self,
        slot: usize,
        name: &str,
        file_size: u64,
        offset: u64,
        data: &[u8],
    ) {
        self.on_data_inner(slot, name, file_size, offset, data, Src::Rehash);
    }

    /// A decoder-fresh span no wire CRC covered: the article CRC was
    /// deliberately skipped (delegation under lean), or the article
    /// carried no pcrc32 at all. Distinct from
    /// [`Self::on_data_from_disk`] so settle read-backs keep their
    /// full-MD5 contract while lean spans may claim CRC-only. Only lean
    /// unlocks that claim - a pcrc-absent article takes full MD5 in
    /// default fast mode, live and through the backfill alike.
    pub fn on_data_unverified(
        &self,
        slot: usize,
        name: &str,
        file_size: u64,
        offset: u64,
        data: &[u8],
    ) {
        self.on_data_inner(slot, name, file_size, offset, data, Src::Lean);
    }

    fn on_data_inner(
        &self,
        slot: usize,
        name: &str,
        file_size: u64,
        offset: u64,
        data: &[u8],
        src: Src,
    ) {
        let plan = self.plan.read_ok();
        let mut s = self.slots[slot].lock_ok();

        if s.name.is_none() && !name.is_empty() {
            s.name = Some(name.to_string());
        }
        if s.file_size == 0 {
            s.file_size = file_size;
        }

        let active = match &*plan {
            Plan::Active(a) => a,
            Plan::Off => return,
            Plan::Waiting => {
                s.capture_head(offset, data);
                // Record how weakly the span may be claimed once the M15b
                // backfill re-feeds it: `pre_spans` are offsets only, so
                // the whole slot comes back under one source. Without this
                // the round trip through disk LAUNDERS trust - a
                // pcrc-absent article (Src::Lean in default fast mode,
                // denied a CRC-only claim below) would return as
                // Src::Rehash and be claimed on the block CRC32 alone.
                match src {
                    Src::Fresh | Src::Rehash => {}
                    Src::Lean => s.pre_unvouched = true,
                    // Nothing in this run vouches at all: same standing as
                    // a crash-resume seed.
                    Src::Disk => s.resume_seeded = true,
                }
                s.pre_spans.push((offset, data.len() as u32));
                return;
            }
        };

        if s.file.is_none() {
            s.capture_head(offset, data);
            if s.unmatchable || !s.try_match(slot, active) {
                return;
            }
            // §94 B: a fresh claim engages the gate - from here the chase
            // decode for this slot waits on verification.
            if let Some(g) = self.gate.lock_ok().clone() {
                g.engage(slot);
            }
        }

        let fi = s.file.unwrap();
        let file = &active.set.files[fi];
        let bs = active.set.block_size as usize;
        if file.blocks.is_empty() || bs == 0 {
            return; // no IFSC - finish_slot settles via whole-file MD5
        }

        // Clamp the span to the PAR2 length (yEnc padding beyond it is noise).
        let raw_len = data.len();
        let len = (data.len() as u64).min(file.length.saturating_sub(offset)) as usize;
        if len == 0 {
            return;
        }
        let data = &data[..len];
        // FILE COORDINATES ARE u64, EVERY ONE OF THEM. This whole block
        // used to compute in `usize`, which is 32 bits on the armv7 beta
        // target: an article at 5 GiB became a span at 1 GiB, and the
        // blocks it claimed were hashed against the wrong region of the
        // file entirely. Disk writes go through `pwrite` at u64 offsets,
        // so the real bytes stayed where they were - a high block could
        // be marked Ok from a region 4 GiB below it, `settle` would then
        // see `damage == 0`, and repair would never run over bytes that
        // were never verified. Only the offsets INTO `data` narrow to
        // `usize`, and those are bounded by one article.
        let span = offset..offset + len as u64;
        let bs64 = bs as u64;
        // Instrument-first census, no behaviour: could this article have
        // been claimed on the CRC32 its decoder already verified? See the
        // reuse-geometry section note above [`LiveVerifier`].
        self.note_reuse_geometry(src, raw_len, &span, bs, file.length);

        // Claim work under the lock, hash outside it. Fast/lean spans
        // (decided below, same condition as the check fn) route boundary
        // blocks through CRC-parts (B1): no bytes are held, so nothing
        // counts against the partials budget and no spill can happen.
        // Src::Lean reaches here in two cases: lean mode is on (its documented
        // single-CRC32 contract), OR the article carried no pcrc32 in default
        // fast mode (main.rs routes crc_checked=false to Src::Lean). The latter
        // must NOT make a CRC-only claim - with no wire CRC to vouch for it a
        // single block CRC32 would be its only integrity, half the two-CRC
        // guarantee fast mode promises. Gate Lean on lean actually being on so
        // a pcrc-absent article falls to full MD5 (both claim and check below).
        // Src::Rehash rides with Fresh: same run, only a round trip through
        // our own writer in between. Its pcrc32 passed too, EXCEPT where
        // lean mode routed a pcrc-absent article here - lean makes that
        // trade knowingly, and take_pre_spans is where it is made.
        let crc_claims = self.fast.load(std::sync::atomic::Ordering::Relaxed)
            && (matches!(src, Src::Fresh | Src::Rehash)
                || (matches!(src, Src::Lean)
                    && self.lean.load(std::sync::atomic::Ordering::Relaxed)));
        let first_block = (span.start / bs64) as usize;
        let last_block = ((span.end - 1) / bs64) as usize;
        let mut full: Vec<usize> = Vec::new(); // hash straight from `data`
        let mut ready: Vec<(usize, Vec<u8>)> = Vec::new(); // completed byte partials
        let mut crc_jobs: Vec<(usize, u64, u64)> = Vec::new(); // (bi, os, oe)
        for bi in first_block..=last_block.min(file.blocks.len() - 1) {
            if s.blocks[bi] != BlockState::Pending {
                continue;
            }
            let bstart = bi as u64 * bs64;
            let blen = block_len(file.length, bs, bi);
            let bend = bstart + blen as u64;
            if span.start <= bstart && bend <= span.end {
                full.push(bi);
                continue;
            }
            // Boundary block: track the overlapping fragment. Still file
            // coordinates; every use below subtracts a base first, and
            // the difference is bounded by one block or one article.
            let os = span.start.max(bstart);
            let oe = span.end.min(bend);
            match s.partials.get_mut(&bi) {
                Some(PartialBuf::Crc(_)) if !crc_claims => {
                    // Mixed trust: this fragment has no wire CRC vouching
                    // for it (a disk read-back, or a pcrc-absent article in
                    // default fast mode), and the parts already held are
                    // CRCs, not bytes - so a composed block CRC32 would be
                    // this block's ONLY integrity layer. Gate on crc_claims
                    // rather than Src::Disk alone: whatever makes a span
                    // unable to claim CRC-only makes it unable to lend its
                    // bytes to someone else's CRC-only claim.
                    // Abandon to settle read-back (which always full-MD5s).
                    s.partials.remove(&bi);
                    self.partials_spilled
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                Some(PartialBuf::Crc(_)) => crc_jobs.push((bi, os, oe)),
                Some(PartialBuf::Bytes(p)) => {
                    // Byte-mode block (created under full-MD5 or by a disk
                    // span): keep filling bytes whatever this span's mode.
                    p.fill(
                        (os - bstart) as usize,
                        &data[(os - span.start) as usize..(oe - span.start) as usize],
                    );
                    if p.complete() {
                        let Some(PartialBuf::Bytes(p)) = s.partials.remove(&bi) else {
                            unreachable!()
                        };
                        s.partial_bytes -= p.buf.len();
                        self.partials_used
                            .fetch_sub(p.buf.len(), std::sync::atomic::Ordering::Relaxed);
                        ready.push((bi, p.buf));
                    }
                }
                None if crc_claims => {
                    s.partials.insert(bi, PartialBuf::Crc(CrcParts::new()));
                    crc_jobs.push((bi, os, oe));
                }
                None => {
                    // GLOBAL budget check (M15): the sum across every slot
                    // stays under the cap, whatever the volume count.
                    // Reserve-then-check so concurrent slots can't both
                    // pass a load() and overshoot the cap together.
                    use std::sync::atomic::Ordering;
                    let prev = self.partials_used.fetch_add(blen, Ordering::Relaxed);
                    if prev + blen > self.partials_cap {
                        self.partials_used.fetch_sub(blen, Ordering::Relaxed);
                        self.partials_spilled.fetch_add(1, Ordering::Relaxed);
                        continue; // leave Pending → read-back at finish
                    }
                    self.partials_peak.fetch_max(prev + blen, Ordering::Relaxed);
                    s.partial_bytes += blen;
                    let mut p = Partial::new(blen);
                    p.fill(
                        (os - bstart) as usize,
                        &data[(os - span.start) as usize..(oe - span.start) as usize],
                    );
                    // A single span can't complete a boundary block it
                    // just created (some other article owns the rest).
                    s.partials.insert(bi, PartialBuf::Bytes(p));
                }
            }
        }
        let set = active.set.clone();
        drop(s);
        drop(plan);

        // Lock-free hashing. Fast verify applies only to trusted spans -
        // ones straight out of a decoder that already enforced the yEnc
        // pcrc32, so the CRC-only claim keeps two independent CRC32
        // layers. Disk-fed spans (backfill, crash-resume) always hash in
        // full: no wire CRC vouches for them.
        // Fresh spans: pcrc passed, CRC-only claim justified. Lean
        // spans: the caller opted into single-CRC32 in-stream integrity
        // (only sent when lean is on). Disk spans (settle read-back)
        // ALWAYS full-MD5 - lean does not weaken that contract.
        // (`crc_claims` above is the same condition - boundary fragments
        // of such spans were queued as CRC jobs.)
        let check = if crc_claims {
            check_block_crc
        } else {
            check_block
        };
        let file = &set.files[fi];
        let mut results: Vec<(usize, bool)> = Vec::with_capacity(full.len() + ready.len());
        for bi in full {
            let bstart = bi as u64 * bs64;
            let blen = block_len(file.length, bs, bi);
            let rel = (bstart - span.start) as usize;
            let ok = check(&file.blocks[bi], bs, &data[rel..rel + blen]);
            results.push((bi, ok));
        }
        // Completed byte partials ALWAYS take full MD5, regardless of what
        // THIS span may claim. A byte partial exists only because some
        // fragment of the block arrived without a wire CRC (the `None` arm
        // allocates bytes exactly when `crc_claims` is false), and the span
        // that happens to finish a block says nothing about the ones that
        // started it - a disk-fed fragment completed by a fresh article
        // would otherwise be claimed on the block CRC32 alone.
        for (bi, buf) in ready {
            let ok = check_block(&file.blocks[bi], bs, &buf);
            results.push((bi, ok));
        }
        // B1: fragment CRCs, also outside the lock (hardware CRC is fast,
        // but a block-sized fragment is still real work at 2 cores).
        let crc_frags: Vec<(usize, u64, u64, u32)> = crc_jobs
            .into_iter()
            .map(|(bi, os, oe)| {
                let crc =
                    crc32fast::hash(&data[(os - span.start) as usize..(oe - span.start) as usize]);
                (bi, os, oe, crc)
            })
            .collect();

        if !results.is_empty() || !crc_frags.is_empty() {
            use std::sync::atomic::Ordering;
            let mut s = self.slots[slot].lock_ok();
            let record = |s: &mut SlotState, bi: usize, ok: bool| {
                if s.blocks[bi] == BlockState::Pending {
                    s.blocks[bi] = if ok { BlockState::Ok } else { BlockState::Bad };
                    if ok {
                        s.live_ok += 1;
                        self.live_ok_total.fetch_add(1, Ordering::Relaxed);
                    } else {
                        s.live_bad += 1;
                        self.live_bad_total.fetch_add(1, Ordering::Relaxed);
                    }
                }
            };
            for (bi, ok) in results {
                record(&mut s, bi, ok);
            }
            for (bi, os, oe, crc) in crc_frags {
                if s.blocks[bi] != BlockState::Pending {
                    // Raced: another span (one containing the whole block)
                    // already settled it - drop the stale partial. It can
                    // be a BYTE partial by now (a mixed-trust span drops
                    // the CRC parts and the next fragment allocates bytes
                    // for the same block), and those carry a budget
                    // charge: dropping one without returning it holds
                    // headroom for memory that is gone until the slot
                    // finishes, which is a spill nobody needed.
                    if let Some(PartialBuf::Bytes(p)) = s.partials.remove(&bi) {
                        s.partial_bytes -= p.buf.len();
                        self.partials_used.fetch_sub(p.buf.len(), Ordering::Relaxed);
                    }
                    continue;
                }
                let Some(PartialBuf::Crc(parts)) = s.partials.get_mut(&bi) else {
                    continue; // vanished (mixed-trust abandon) - stays Pending
                };
                let bstart = bi as u64 * bs64;
                if !parts.insert((os - bstart) as usize, (oe - bstart) as usize, crc) {
                    // Overlapping re-feed - can't compose CRCs losslessly.
                    s.partials.remove(&bi);
                    self.partials_spilled.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let blen = block_len(file.length, bs, bi);
                if let Some(crc_data) = parts.complete(blen) {
                    // IFSC checksums cover the block zero-padded to bs.
                    let final_crc = if blen < bs {
                        crate::yenc_simd::crc32_zeros(crc_data, (bs - blen) as u64)
                    } else {
                        crc_data
                    };
                    s.partials.remove(&bi);
                    record(&mut s, bi, final_crc == file.blocks[bi].crc32);
                }
            }
            // §94 B: every claim above may have extended the contiguous
            // Ok prefix - publish before the slot lock drops so a gated
            // chase parked at the old watermark wakes.
            self.gate_publish(slot, &mut s, bs);
        }
    }

    /// Crash resume: register spans a previous run already persisted (and
    /// the journal restored) as pre-activation spans. The M15b backfill
    /// then reads them from disk once the set activates and verifies
    /// their blocks against the PAR2 block map - restored bytes are
    /// trusted only after they hash clean (settle read-back backstops
    /// anything the backfill couldn't reach).
    pub fn seed_pre_spans(&self, slot: usize, spans: &[(u64, u64)]) {
        let mut s = self.slots[slot].lock_ok();
        s.resume_seeded = true;
        for &(off, len) in spans {
            let (mut off, mut len) = (off, len);
            while len > 0 {
                let n = len.min(u32::MAX as u64);
                s.pre_spans.push((off, n as u32));
                off += n;
                len -= n;
            }
        }
    }

    /// Drain the spans a slot decoded before activation (coalesced,
    /// sorted) for the backfill pass, with the source the re-read bytes
    /// must be fed under: [`PreSpanSrc::Backfill`] when this run decoded
    /// every one of them under a passing pcrc32, [`PreSpanSrc::Disk`] when
    /// crash resume seeded any (see [`Self::seed_pre_spans`]) or any span
    /// came in with no wire CRC covering it.
    ///
    /// Lean is the one mode that keeps unvouched spans on the backfill
    /// route: it is exactly the mode where a span the decoder did not
    /// vouch for may still be claimed CRC-only, so the disk round trip
    /// hands back no more trust than the span had live.
    pub fn take_pre_spans(&self, slot: usize) -> (Vec<(u64, u64)>, PreSpanSrc) {
        let mut s = self.slots[slot].lock_ok();
        let lean = self.lean.load(std::sync::atomic::Ordering::Relaxed);
        let how = if s.resume_seeded || (s.pre_unvouched && !lean) {
            PreSpanSrc::Disk
        } else {
            PreSpanSrc::Backfill
        };
        let mut spans = std::mem::take(&mut s.pre_spans);
        drop(s);
        spans.sort_unstable();
        let mut out: Vec<(u64, u64)> = Vec::new();
        for (off, len) in spans {
            let (off, len) = (off, len as u64);
            match out.last_mut() {
                Some((_, e)) if off <= *e && off + len > *e => *e = off + len,
                Some((_, e)) if off + len <= *e => {}
                _ => out.push((off, off + len)),
            }
        }
        (out.into_iter().map(|(s, e)| (s, e - s)).collect(), how)
    }

    /// Record one mapped span against the verified-CRC reuse geometry
    /// census - the per-run tally and the process-global one together.
    ///
    /// `raw_len` is the span BEFORE the clamp to the PAR2-declared file
    /// length: a clamped (trimmed) article's verified CRC covers bytes the
    /// block does not, so it is not reusable however well the rest lines
    /// up. `Src::Fresh` is the only source with a wire CRC in hand at feed
    /// time - `Src::Rehash` claims just as strongly but its bytes came
    /// back off disk, with the article CRC long gone.
    fn note_reuse_geometry(
        &self,
        src: Src,
        raw_len: usize,
        span: &std::ops::Range<u64>,
        bs: usize,
        file_length: u64,
    ) {
        let len = (span.end - span.start) as usize;
        let qualifies = src == Src::Fresh
            && self.fast.load(std::sync::atomic::Ordering::Relaxed)
            && len == raw_len
            && span.start.is_multiple_of(bs as u64)
            && len == block_len(file_length, bs, (span.start / bs as u64) as usize);
        self.geom.note(len, qualifies);
        CRC_REUSE_GEOMETRY.note(len, qualifies);
    }

    /// THIS run's verified-CRC reuse geometry (see [`CrcReuseGeometry`]).
    /// The cumulative twin is [`crc_reuse_geometry_total`].
    pub fn crc_reuse_geometry(&self) -> CrcReuseGeometry {
        self.geom.snapshot()
    }

    /// This verifier's EFFECTIVE partial-buffer cap: what
    /// [`Self::with_partials_cap`] was handed (or [`default_partials_cap`]
    /// for a bare [`Self::new`]), floored. The figure a memory rig should
    /// print beside the peak from [`Self::partials_stats`], so a run that
    /// never got the production cap says so out loud - the single line
    /// that would have caught the TODO 209 misreading on sight (TODO 265).
    pub fn partials_cap(&self) -> usize {
        self.partials_cap
    }

    /// (peak partial-buffer bytes, blocks spilled to read-back) - the
    /// end-of-run memory summary (M15).
    pub fn partials_stats(&self) -> (usize, u64) {
        use std::sync::atomic::Ordering;
        (
            self.partials_peak.load(Ordering::Relaxed),
            self.partials_spilled.load(Ordering::Relaxed),
        )
    }

    /// (blocks verified in-stream so far, of which bad) - dashboard gauge.
    pub fn live_counts(&self) -> (u64, u64) {
        use std::sync::atomic::Ordering;
        (
            self.live_ok_total.load(Ordering::Relaxed)
                + self.live_bad_total.load(Ordering::Relaxed),
            self.live_bad_total.load(Ordering::Relaxed),
        )
    }

    /// Settle a slot when all its articles are terminal: read back every
    /// still-pending block from `path` (None if no file was ever created)
    /// and return the verdict. Returns None when no PAR2 file matched this
    /// slot (nothing to verify against).
    pub fn finish_slot(&self, slot: usize, path: Option<&Path>) -> Option<SlotReport> {
        match path {
            Some(p) => self.finish_slot_from(slot, ReadAt::Path(p)),
            None => self.finish_slot_from(slot, ReadAt::Missing),
        }
    }

    /// [`finish_slot`](Self::finish_slot) with a generic byte source - for
    /// direct-extracted RAR volumes the "file" is reconstructed on demand
    /// (header stash + extracted-file pread) instead of read from disk.
    pub fn finish_slot_from(&self, slot: usize, src: ReadAt<'_>) -> Option<SlotReport> {
        let plan = self.plan.read_ok();
        let active = match &*plan {
            Plan::Active(a) => a,
            _ => return None,
        };
        let mut s = self.slots[slot].lock_ok();
        // Last-chance match (e.g. every article of the slot arrived before
        // activation, so on_data never ran while Active).
        if s.file.is_none()
            && !s.unmatchable
            && s.try_match(slot, active)
            && let Some(g) = self.gate.lock_ok().clone()
        {
            g.engage(slot);
        }
        let fi = s.file?;
        let file = &active.set.files[fi];
        let bs = active.set.block_size as usize;

        // Drop leftover partials - their blocks read back below. Return
        // their bytes to the global budget (M15).
        s.partials.clear();
        self.partials_used
            .fetch_sub(s.partial_bytes, std::sync::atomic::Ordering::Relaxed);
        s.partial_bytes = 0;

        let mut bad: Vec<usize> = Vec::new();
        let mut readback = 0u64;

        if file.blocks.is_empty() {
            // No IFSC: whole-file MD5 is the only check.
            let ok = src_md5(&src, file.length).is_ok_and(|md5| md5 == file.md5);
            // §94 B: this slot's gate was ENGAGED at claim time (on_data
            // and the last-chance match above both engage), and a
            // no-IFSC slot has no block stream to advance it - so its
            // watermark sat at 0 forever, and any RAR/7z frontier reader
            // waiting on it blocked until chase_finish joined the worker
            // and the job hung (Codex sweep 3 Aug M6). The whole-file
            // MD5 IS this slot's verdict, and it has now been taken, so
            // the gate is released either way: a hung worker is
            // unbounded, while a chase fed damaged bytes fails its own
            // CRC and demotes to the disk ladder, which is bounded. The
            // damage itself is not swallowed - it rides the bad_blocks
            // report below, exactly as an IFSC slot's would.
            if let Some(g) = self.gate.lock_ok().clone() {
                g.advance(slot, u64::MAX);
            }
            if !ok {
                tracing::warn!(
                    target: "verify",
                    "{}: whole-file MD5 failed (no IFSC blocks) - \
                     releasing the chase gate; the chase will demote",
                    file.name
                );
            }
            return Some(SlotReport {
                par2_name: Some(file.name.clone()),
                total_blocks: 0,
                bad_blocks: if ok { Vec::new() } else { vec![0] },
                live_blocks: 0,
                readback_blocks: 1,
                length: file.length,
            });
        }

        let pending: Vec<usize> = s
            .blocks
            .iter()
            .enumerate()
            .filter(|(_, st)| **st == BlockState::Pending)
            .map(|(i, _)| i)
            .collect();
        if !pending.is_empty() {
            let f = match &src {
                ReadAt::Path(p) => std::fs::File::open(p).ok(),
                _ => None,
            };
            // One block-sized buffer per slot was `block_size` resident, and
            // the caller settles slots on up to 12 threads: the accepted wire
            // block size runs to 256 MiB, so a small, valid PAR2 metadata set
            // naming a dozen targets with one pending block each asked for
            // ~3 GiB at once. Bounded above 8 MiB, where the block is read
            // and hashed in chunks instead (`read_block_chunked`); at or
            // below it - every real-world set - the single-buffer path with
            // its CRC-before-MD5 short circuit is unchanged.
            const READBACK_CHUNK: usize = 8 << 20;
            let mut buf = vec![0u8; bs.min(READBACK_CHUNK)];
            for bi in pending {
                readback += 1;
                let blen = block_len(file.length, bs, bi);
                let ok = if bs <= READBACK_CHUNK {
                    let got = match (&src, &f) {
                        (ReadAt::Path(_), Some(f)) => {
                            crate::disk::read_exact_at(f, &mut buf[..blen], bi as u64 * bs as u64)
                                .is_ok()
                        }
                        (ReadAt::Reader(r), _) => {
                            r(bi as u64 * bs as u64, &mut buf[..blen]).is_ok()
                        }
                        _ => false,
                    };
                    got && check_block(&file.blocks[bi], bs, &buf[..blen])
                } else {
                    read_block_chunked(&src, f.as_ref(), bi as u64 * bs as u64, blen, &mut buf)
                        .is_some_and(|check| check.finish(&file.blocks[bi], bs))
                };
                s.blocks[bi] = if ok { BlockState::Ok } else { BlockState::Bad };
            }
            // §94 B: settle read-back claims advance the watermark too.
            self.gate_publish(slot, &mut s, bs);
        }
        for (bi, st) in s.blocks.iter().enumerate() {
            if *st == BlockState::Bad {
                bad.push(bi);
            }
        }
        Some(SlotReport {
            par2_name: Some(file.name.clone()),
            total_blocks: file.blocks.len(),
            bad_blocks: bad,
            live_blocks: s.live_ok + s.live_bad,
            readback_blocks: readback,
            length: file.length,
        })
    }

    /// PAR2 files no slot claimed (files entirely absent from the NZB or
    /// whose every article vanished before a name could be learned).
    pub fn unclaimed_files(&self) -> Vec<String> {
        match &*self.plan.read_ok() {
            Plan::Active(a) => a
                .claimed
                .lock_ok()
                .iter()
                .enumerate()
                .filter(|(_, c)| c.is_none())
                .map(|(i, _)| a.set.files[i].name.clone())
                .collect(),
            _ => Vec::new(),
        }
    }
}

impl SlotState {
    fn empty() -> SlotState {
        SlotState {
            name: None,
            name_keys: None,
            head: None,
            file_size: 0,
            file: None,
            blocks: Vec::new(),
            partials: HashMap::new(),
            partial_bytes: 0,
            pre_spans: Vec::new(),
            resume_seeded: false,
            pre_unvouched: false,
            unmatchable: false,
            live_ok: 0,
            live_bad: 0,
            ok_prefix: 0,
        }
    }

    fn head_want(&self) -> usize {
        if self.file_size > 0 {
            // Clamp in u64 BEFORE narrowing: `self.file_size as usize`
            // truncates a >4 GiB file on a 32-bit target, so a 4 GiB + 10
            // byte file asked for a 10-byte head.
            self.file_size.min(HEAD_LEN as u64) as usize
        } else {
            HEAD_LEN
        }
    }

    fn capture_head(&mut self, offset: u64, data: &[u8]) {
        let want = self.head_want();
        // In u64: `offset as usize` wrapped on a 32-bit target, so an
        // article at 4 GiB + 16 read as offset 16 and its bytes were
        // captured as the head of the file.
        if want == 0 || offset >= want as u64 {
            return;
        }
        let head = self.head.get_or_insert_with(|| Partial::new(want));
        if head.buf.len() != want {
            // file_size learned after the first capture changed `want`;
            // restart (rare, only when the very first article lacked a size).
            *head = Partial::new(want);
        }
        if head.complete() {
            return;
        }
        // Proven < `want` (a few KiB) by the guard above, so this narrows
        // on every target.
        let off = offset as usize;
        let end = (off + data.len()).min(want);
        if end > off {
            head.fill(off, &data[..end - off]);
        }
    }

    /// Try to claim a PAR2 file for this slot. Name match first, md5-16k
    /// second. Requires `self.file.is_none()`.
    fn try_match(&mut self, slot: usize, active: &Active) -> bool {
        let files = &active.set.files;
        let mut claimed = active.claimed.lock_ok();

        let mut name_ambiguous = false;
        if let Some(name) = &self.name {
            // EXACT first, across the whole set, before any approximate
            // tier is allowed to claim. One first-hit loop over the
            // three match classes let an approximate claim consume a
            // FileDesc whose exact owner had not arrived yet: with
            // slots A.txt and a.txt on a case-sensitive filesystem and
            // FileDesc order [a.txt, A.txt], whichever slot matched
            // first claimed the OTHER file's descriptor case-
            // insensitively and both ended crossed - each verifying,
            // repairing and publishing under the other's name, up to
            // and including one rename unlinking the other's inode
            // (Codex sweep 13 Aug R1).
            let (fold, sname) = self.name_keys.get_or_insert_with(|| {
                (
                    name.to_ascii_lowercase(),
                    crate::disk::sanitize_filename(name),
                )
            });
            let folded: &[usize] = active.by_fold.get(fold.as_str()).map_or(&[], |v| v);
            let sanit: &[usize] = active.by_sanitized.get(sname.as_str()).map_or(&[], |v| v);
            let exact = folded
                .iter()
                .copied()
                .find(|&fi| claimed[fi].is_none() && files[fi].name == **name);
            let hit = exact.or_else(|| {
                // Approximate (case-folded or sanitized) only when it is
                // UNIQUE among the unclaimed descriptors. Two candidates
                // is ambiguity, not a choice for FileDesc order to make:
                // leave the slot unclaimed and let the md5-16k fallback
                // below settle it by content. The two sorted candidate
                // lists are merge-walked with dedup so a descriptor
                // matching both keys counts once, in FileDesc order -
                // identical answers to the pre-index linear drain
                // (`try_match_linear`, kept below as the test oracle).
                let (mut i, mut j) = (0usize, 0usize);
                let mut first = None;
                while i < folded.len() || j < sanit.len() {
                    let fi;
                    if i < folded.len() && (j >= sanit.len() || folded[i] <= sanit[j]) {
                        fi = folded[i];
                        i += 1;
                        if j < sanit.len() && sanit[j] == fi {
                            j += 1;
                        }
                    } else {
                        fi = sanit[j];
                        j += 1;
                    }
                    if claimed[fi].is_none() {
                        if first.is_none() {
                            first = Some(fi);
                        } else {
                            name_ambiguous = true;
                            first = None;
                            break;
                        }
                    }
                }
                first
            });
            if let Some(fi) = hit {
                claimed[fi] = Some(slot);
                self.file = Some(fi);
                self.blocks = vec![BlockState::Pending; files[fi].blocks.len()];
                return true;
            }
        }
        // md5-16k fallback (obfuscated names).
        let want = self.head_want();
        if want > 0
            && self
                .head
                .as_ref()
                .is_some_and(|h| h.buf.len() == want && h.complete())
        {
            let head_md5: [u8; 16] = Md5::digest(&self.head.as_ref().unwrap().buf).into();
            for (fi, f) in files.iter().enumerate() {
                if claimed[fi].is_some() || f.length.min(HEAD_LEN as u64) != want as u64 {
                    continue;
                }
                if f.md5_16k == head_md5 {
                    claimed[fi] = Some(slot);
                    self.file = Some(fi);
                    self.blocks = vec![BlockState::Pending; f.blocks.len()];
                    return true;
                }
            }
            // Head is complete and matched nothing: if the name also failed,
            // this slot will never match (nfo/sfv/sample files). NOT when the
            // name tier declined on ambiguity - those candidates are real, and
            // a later claim by the twin slot makes the approximate match
            // unique. Latching here froze the slot forever and downgraded a
            // patchable file to wholly-missing (found by the 14 Aug sweep).
            if self.name.is_some() && !name_ambiguous {
                self.unmatchable = true;
            }
        }
        false
    }

    /// The pre-B6 linear matcher, byte-for-byte: full descriptor scans and
    /// per-candidate `sanitize_filename` calls. NOT called in production -
    /// kept as the oracle for the differential tests and as the baseline
    /// leg of [`bench_match`], so any drift between the indexed tiers and
    /// the original semantics fails a test instead of crossing a claim.
    fn try_match_linear(&mut self, slot: usize, active: &Active) -> bool {
        let files = &active.set.files;
        let mut claimed = active.claimed.lock_ok();

        let mut name_ambiguous = false;
        if let Some(name) = &self.name {
            let sname = crate::disk::sanitize_filename(name);
            let exact = files
                .iter()
                .enumerate()
                .find(|(fi, f)| claimed[*fi].is_none() && f.name == **name)
                .map(|(fi, _)| fi);
            let hit = exact.or_else(|| {
                let mut it = files.iter().enumerate().filter(|(fi, f)| {
                    claimed[*fi].is_none()
                        && (f.name.eq_ignore_ascii_case(name)
                            || crate::disk::sanitize_filename(&f.name) == sname)
                });
                let first = it.next();
                if it.next().is_none() {
                    first.map(|(fi, _)| fi)
                } else {
                    name_ambiguous = true;
                    None
                }
            });
            if let Some(fi) = hit {
                claimed[fi] = Some(slot);
                self.file = Some(fi);
                self.blocks = vec![BlockState::Pending; files[fi].blocks.len()];
                return true;
            }
        }
        let want = self.head_want();
        if want > 0
            && self
                .head
                .as_ref()
                .is_some_and(|h| h.buf.len() == want && h.complete())
        {
            let head_md5: [u8; 16] = Md5::digest(&self.head.as_ref().unwrap().buf).into();
            for (fi, f) in files.iter().enumerate() {
                if claimed[fi].is_some() || f.length.min(HEAD_LEN as u64) != want as u64 {
                    continue;
                }
                if f.md5_16k == head_md5 {
                    claimed[fi] = Some(slot);
                    self.file = Some(fi);
                    self.blocks = vec![BlockState::Pending; f.blocks.len()];
                    return true;
                }
            }
            if self.name.is_some() && !name_ambiguous {
                self.unmatchable = true;
            }
        }
        false
    }
}

/// Matcher microbench hook (`examples/live_match_bench.rs`) - drives the
/// match tiers the way `on_data` hits them: `calls` attempts round-robin
/// over one slot per probe name, against a fresh claim table for `set`
/// (map build included, as activation pays it). `indexed` picks the
/// production pre-index matcher or the pre-B6 linear reference. Returns
/// how many probes ended claimed, so the harness can assert both paths
/// agree and the work is not optimized away.
#[doc(hidden)]
pub fn bench_match(
    set: &Arc<Par2Set>,
    probe_names: &[String],
    calls: usize,
    indexed: bool,
) -> usize {
    let active = Active::new(set.clone());
    let mut slots: Vec<SlotState> = probe_names
        .iter()
        .map(|n| {
            let mut s = SlotState::empty();
            if !n.is_empty() {
                s.name = Some(n.clone());
            }
            s
        })
        .collect();
    for c in 0..calls {
        let i = c % slots.len();
        let s = &mut slots[i];
        if s.file.is_none() && !s.unmatchable {
            if indexed {
                s.try_match(i, &active);
            } else {
                s.try_match_linear(i, &active);
            }
        }
    }
    slots.iter().filter(|s| s.file.is_some()).count()
}

/// Real (unpadded) length of block `bi` of a `length`-byte file.
fn block_len(length: u64, bs: usize, bi: usize) -> usize {
    // Multiply in u64, and CLAMP before narrowing. Both halves were
    // 32-bit wraps: `(bi * bs) as u64` cast after a `usize` multiply, so
    // every block past 4 GiB reported the start of a block 4 GiB lower;
    // and `(length - start) as usize` truncated a >4 GiB remainder
    // BEFORE `.min(bs)`, so a mid-file block of a huge file could report
    // a short length. See the file-coordinate note in `add_span`.
    let start = bi as u64 * bs as u64;
    (length - start.min(length)).min(bs as u64) as usize
}

/// Hash `bytes` (the real bytes of one block, zero-padded to `block_size`
/// per spec) and compare with the IFSC checksums. MD5 + CRC32 must both
/// match - identical semantics to `par2::verify_file_blocks`. CRC32 runs
/// first: hardware CRC is ~13× faster than MD5, so a mismatching (damaged)
/// block never pays for the MD5 pass.
pub fn check_block(check: &BlockCheck, block_size: usize, bytes: &[u8]) -> bool {
    if !check_block_crc(check, block_size, bytes) {
        return false;
    }
    let mut md5 = Md5::new();
    md5.update(bytes);
    pad_to(block_size, bytes.len(), |z| md5.update(z));
    <[u8; 16]>::from(md5.finalize()) == check.md5
}

/// CRC32-only block check - the fast-verify hot path. The caller must only
/// use this for bytes that already carry an independent integrity check
/// (in-stream spans passed their yEnc pcrc32 in the decoder); a false
/// accept then requires corruption that survives two independent CRC32s
/// over differently-aligned spans.
pub fn check_block_crc(check: &BlockCheck, block_size: usize, bytes: &[u8]) -> bool {
    debug_assert!(bytes.len() <= block_size);
    let mut crc = crc32fast::Hasher::new();
    crc.update(bytes);
    // O(log n) through the padding rather than hashing it, exactly as
    // `StreamedBlock::finish` does. Saturating so a caller that broke
    // the assert above pays a wrong answer, not a wrapped length.
    // (The MD5 half of `check_block` keeps the real zero bytes - MD5
    // has no zero-extension trick.)
    crate::yenc_simd::crc32_zeros(
        crc.finalize(),
        (block_size.saturating_sub(bytes.len())) as u64,
    ) == check.crc32
}

/// [`check_block`] fed in pieces, for a block too big to hold at once.
///
/// Both digests run together, so the CRC-before-MD5 short circuit is gone -
/// which is why the caller only uses this above the chunking threshold, where
/// holding the whole block is the larger cost by far.
struct StreamedBlock {
    crc: crc32fast::Hasher,
    md5: Md5,
    len: usize,
}

impl StreamedBlock {
    fn new() -> Self {
        Self {
            crc: crc32fast::Hasher::new(),
            md5: Md5::new(),
            len: 0,
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        self.crc.update(bytes);
        self.md5.update(bytes);
        self.len += bytes.len();
    }

    /// Pad to `block_size` per spec and compare both digests.
    fn finish(mut self, check: &BlockCheck, block_size: usize) -> bool {
        // O(log n) through the padding rather than hashing it: the padding on
        // a 256 MiB block is itself most of a block.
        if crate::yenc_simd::crc32_zeros(self.crc.finalize(), (block_size - self.len) as u64)
            != check.crc32
        {
            return false;
        }
        pad_to(block_size, self.len, |z| self.md5.update(z));
        <[u8; 16]>::from(self.md5.finalize()) == check.md5
    }
}

/// Read one block through `buf` in `buf.len()` pieces, hashing as it goes.
/// `None` if any read failed - a block that cannot be read is damage.
fn read_block_chunked(
    src: &ReadAt<'_>,
    file: Option<&std::fs::File>,
    base: u64,
    blen: usize,
    buf: &mut [u8],
) -> Option<StreamedBlock> {
    let mut check = StreamedBlock::new();
    let mut done = 0usize;
    while done < blen {
        let n = (blen - done).min(buf.len());
        let ok = match (src, file) {
            (ReadAt::Path(_), Some(f)) => {
                crate::disk::read_exact_at(f, &mut buf[..n], base + done as u64).is_ok()
            }
            (ReadAt::Reader(r), _) => r(base + done as u64, &mut buf[..n]).is_ok(),
            _ => false,
        };
        if !ok {
            return None;
        }
        check.update(&buf[..n]);
        done += n;
    }
    Some(check)
}

/// Feed `block_size - len` zero-padding bytes to a hasher, chunk-wise.
fn pad_to(block_size: usize, len: usize, mut update: impl FnMut(&[u8])) {
    const ZEROS: [u8; 4096] = [0; 4096];
    let mut rem = block_size - len;
    while rem > 0 {
        let n = rem.min(ZEROS.len());
        update(&ZEROS[..n]);
        rem -= n;
    }
}

/// A source of file bytes for read-back settling.
pub enum ReadAt<'a> {
    /// No backing data at all (file never created).
    Missing,
    /// An ordinary file on disk.
    Path(&'a Path),
    /// Reconstructed bytes (direct-extracted volumes): read `buf.len()`
    /// bytes at the given offset.
    Reader(&'a (dyn Fn(u64, &mut [u8]) -> io::Result<()> + Sync)),
}

/// Streaming whole-file MD5 (for IFSC-less sets).
fn src_md5(src: &ReadAt<'_>, expect_len: u64) -> io::Result<[u8; 16]> {
    let mut md5 = Md5::new();
    match src {
        ReadAt::Missing => Err(io::Error::new(io::ErrorKind::NotFound, "no data")),
        ReadAt::Path(path) => {
            use std::io::Read;
            let mut f = std::fs::File::open(path)?;
            if f.metadata()?.len() != expect_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "length mismatch",
                ));
            }
            let mut buf = vec![0u8; 1 << 20];
            loop {
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                md5.update(&buf[..n]);
            }
            Ok(md5.finalize().into())
        }
        ReadAt::Reader(r) => {
            let mut buf = vec![0u8; 1 << 20];
            let mut off = 0u64;
            while off < expect_len {
                // Clamp in u64 before narrowing: on a 32-bit target
                // `(expect_len - off) as usize` truncates, and a
                // remainder that is an exact multiple of 4 GiB narrows to
                // ZERO - a read of nothing, no progress, and this loop
                // never ends.
                let n = (expect_len - off).min(buf.len() as u64) as usize;
                r(off, &mut buf[..n])?;
                md5.update(&buf[..n]);
                off += n as u64;
            }
            Ok(md5.finalize().into())
        }
    }
}

/// Parse par2 inputs into one set. If the inputs mix recovery sets (an NZB
/// carrying several releases), fall back to parsing each input alone and
/// keep the set describing the most files.
pub fn pick_set(inputs: &[&[u8]]) -> Result<Par2Set, Par2Error> {
    match Par2Set::parse(inputs) {
        Ok(set) => Ok(set),
        Err(Par2Error::MixedRecoverySets) => inputs
            .iter()
            .filter_map(|i| Par2Set::parse(&[i]).ok())
            .max_by_key(|s| s.files.len())
            .ok_or(Par2Error::NoMainPacket),
        Err(e) => Err(e),
    }
}

/// Files/blocks needed for repair planning, computed from slot reports.
#[derive(Debug, Default)]
pub struct DamageSummary {
    pub(crate) bad_blocks: usize,
    pub(crate) damaged_files: Vec<String>,
}

pub fn summarize_damage<'a>(reports: impl Iterator<Item = &'a SlotReport>) -> DamageSummary {
    let mut d = DamageSummary::default();
    for r in reports {
        if !r.bad_blocks.is_empty() {
            d.bad_blocks += r.bad_blocks.len();
            if let Some(n) = &r.par2_name {
                d.damaged_files.push(n.clone());
            }
        }
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A slot the gate was never sized for is UNGATED, not a panic:
    /// the mapped repair mints root slots past the NZB's count for a
    /// wholly-missing volume it rebuilds from parity (gated e2e matrix,
    /// 22 Aug 2026). Engaging one grows the gate instead.
    #[test]
    fn verify_gate_tolerates_slots_past_its_size() {
        let g = VerifyGate::new(2);
        assert_eq!(g.watermark(5), u64::MAX);
        assert_eq!(g.engaged_mark(5), None);
        g.wait_past(5, 100, std::time::Duration::from_millis(1));
        g.engage(5);
        assert_eq!(g.watermark(5), 0);
        g.advance(7, 40);
        assert_eq!(g.engaged_mark(7), Some(40));
        assert_eq!(g.engaged_mark(6), None);
        assert_eq!(g.watermark(1), u64::MAX);
    }

    /// §94 B VerifyGate contract: ungated reads as MAX, a claim engages
    /// at 0, advances are monotonic (a stale racer can never lower the
    /// mark), and wait_past returns immediately once covered.
    #[test]
    fn verify_gate_engage_advance_monotonic() {
        let g = VerifyGate::new(2);
        assert_eq!(g.watermark(0), u64::MAX, "ungated = MAX");
        g.engage(0);
        assert_eq!(g.watermark(0), 0, "engaged at zero");
        assert_eq!(g.watermark(1), u64::MAX, "other slots untouched");
        g.advance(0, 4096);
        assert_eq!(g.watermark(0), 4096);
        g.advance(0, 1024); // stale racer
        assert_eq!(g.watermark(0), 4096, "advance is monotonic");
        g.engage(0); // idempotent, never lowers
        assert_eq!(g.watermark(0), 4096);
        g.advance(0, u64::MAX);
        assert_eq!(g.watermark(0), u64::MAX, "fully verified ungates");
        // Covered: returns without blocking.
        g.wait_past(0, 0, std::time::Duration::from_secs(5));
        // Uncovered: bounded by the timeout, not hung.
        g.engage(1);
        let t0 = std::time::Instant::now();
        g.wait_past(1, 100, std::time::Duration::from_millis(50));
        assert!(t0.elapsed() < std::time::Duration::from_secs(2));
    }

    /// Pre-activation spans are re-fed by the M15b backfill under ONE
    /// source per slot, so a span no wire CRC covered must not come back
    /// as a fresh-strength `Rehash` claim - the disk round trip would
    /// otherwise hand a pcrc-absent article a CRC32-only verdict.
    #[test]
    fn unvouched_pre_spans_take_the_disk_backfill() {
        let data = [7u8; 4096];
        let v = LiveVerifier::new(3);
        v.set_fast_verify(true);

        // Every span wire-CRC'd: the CRC-parts backfill route stands.
        v.on_data(0, "a.bin", 8192, 0, &data);
        v.on_data(0, "a.bin", 8192, 4096, &data);
        assert_eq!(v.take_pre_spans(0).1, PreSpanSrc::Backfill);

        // One pcrc-absent article taints the slot in default fast mode.
        v.on_data(1, "b.bin", 8192, 0, &data);
        v.on_data_unverified(1, "b.bin", 8192, 4096, &data);
        assert_eq!(v.take_pre_spans(1).1, PreSpanSrc::Disk);

        // Lean owns the weaker contract, so its own spans keep the route.
        v.set_lean(true);
        v.on_data_unverified(2, "c.bin", 8192, 0, &data);
        assert_eq!(v.take_pre_spans(2).1, PreSpanSrc::Backfill);
    }

    // ===== Par2Set fixtures: real serialized packets, parsed by the =====
    // ===== same code the wire feeds, so activate() is exercised too. =====

    /// Wrap a body in a valid packet (magic, length, body MD5) - the same
    /// shape par2.rs's own tests build. Header is 64 bytes per spec.
    fn pkt(set_id: [u8; 16], ptype: &[u8; 16], body: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(crate::par2::MAGIC);
        p.extend_from_slice(&(64 + body.len() as u64).to_le_bytes());
        p.extend_from_slice(&[0u8; 16]); // md5 patched below
        p.extend_from_slice(&set_id);
        p.extend_from_slice(ptype);
        p.extend_from_slice(body);
        let md5: [u8; 16] = Md5::digest(&p[32..]).into();
        p[16..32].copy_from_slice(&md5);
        p
    }

    fn fid(i: usize) -> [u8; 16] {
        let mut f = [0u8; 16];
        f[0] = i as u8 + 1;
        f
    }

    /// Serialized single-set PAR2 metadata describing `files`. With
    /// `ifsc` false every file lands on the whole-file-MD5 path.
    fn par2_meta(
        set_id: [u8; 16],
        block_size: usize,
        files: &[(&str, &[u8])],
        ifsc: bool,
    ) -> Vec<u8> {
        use crate::par2::{TYPE_FILEDESC, TYPE_IFSC, TYPE_MAIN};
        let mut main = Vec::new();
        main.extend_from_slice(&(block_size as u64).to_le_bytes());
        main.extend_from_slice(&(files.len() as u32).to_le_bytes());
        for i in 0..files.len() {
            main.extend_from_slice(&fid(i));
        }
        let mut out = pkt(set_id, TYPE_MAIN, &main);
        for (i, (name, data)) in files.iter().enumerate() {
            let mut desc = Vec::new();
            desc.extend_from_slice(&fid(i));
            desc.extend_from_slice(&<[u8; 16]>::from(Md5::digest(data)));
            let head = &data[..data.len().min(HEAD_LEN)];
            desc.extend_from_slice(&<[u8; 16]>::from(Md5::digest(head)));
            desc.extend_from_slice(&(data.len() as u64).to_le_bytes());
            let mut nb = name.as_bytes().to_vec();
            while nb.len() % 4 != 0 {
                nb.push(0);
            }
            desc.extend_from_slice(&nb);
            out.extend(pkt(set_id, TYPE_FILEDESC, &desc));
            if ifsc {
                let mut body = fid(i).to_vec();
                for chunk in data.chunks(block_size) {
                    let mut md5 = Md5::new();
                    md5.update(chunk);
                    pad_to(block_size, chunk.len(), |z| md5.update(z));
                    body.extend_from_slice(&<[u8; 16]>::from(md5.finalize()));
                    let mut crc = crc32fast::Hasher::new();
                    crc.update(chunk);
                    pad_to(block_size, chunk.len(), |z| crc.update(z));
                    body.extend_from_slice(&crc.finalize().to_le_bytes());
                }
                out.extend(pkt(set_id, TYPE_IFSC, &body));
            }
        }
        out
    }

    /// A single-file set whose file is DECLARED huge without any of its
    /// bytes existing: real IFSC entries for every block, but only the
    /// one named in `real` carries the checksums of `data` (the rest are
    /// zeroed and never checked). The only way to exercise a PAR2 offset
    /// past `u32::MAX` in a unit test - `par2_meta` hashes the file it is
    /// given, and a 4 GiB fixture is not a unit test.
    fn par2_meta_declared(
        set_id: [u8; 16],
        block_size: usize,
        name: &str,
        length: u64,
        real: usize,
        data: &[u8],
    ) -> Vec<u8> {
        use crate::par2::{TYPE_FILEDESC, TYPE_IFSC, TYPE_MAIN};
        let mut main = Vec::new();
        main.extend_from_slice(&(block_size as u64).to_le_bytes());
        main.extend_from_slice(&1u32.to_le_bytes());
        main.extend_from_slice(&fid(0));
        let mut out = pkt(set_id, TYPE_MAIN, &main);

        let mut desc = Vec::new();
        desc.extend_from_slice(&fid(0));
        desc.extend_from_slice(&[0u8; 16]); // whole-file MD5: never settled here
        desc.extend_from_slice(&[0u8; 16]); // md5-16k: matched by NAME
        desc.extend_from_slice(&length.to_le_bytes());
        let mut nb = name.as_bytes().to_vec();
        while !nb.len().is_multiple_of(4) {
            nb.push(0);
        }
        desc.extend_from_slice(&nb);
        out.extend(pkt(set_id, TYPE_FILEDESC, &desc));

        let blocks = length.div_ceil(block_size as u64) as usize;
        let mut body = fid(0).to_vec();
        for bi in 0..blocks {
            if bi == real {
                let mut md5 = Md5::new();
                md5.update(data);
                pad_to(block_size, data.len(), |z| md5.update(z));
                body.extend_from_slice(&<[u8; 16]>::from(md5.finalize()));
                let mut crc = crc32fast::Hasher::new();
                crc.update(data);
                pad_to(block_size, data.len(), |z| crc.update(z));
                body.extend_from_slice(&crc.finalize().to_le_bytes());
            } else {
                body.extend_from_slice(&[0u8; 20]);
            }
        }
        out.extend(pkt(set_id, TYPE_IFSC, &body));
        out
    }

    /// A PAR2 offset past `u32::MAX` claims the block it really names.
    ///
    /// Nothing on a 64-bit host can regress this - the test exists for
    /// the linux-armv7 beta, where nightly runs the suite under qemu and
    /// `usize` is 32 bits. Before the fix `add_span` computed the whole
    /// span, every block start and every fragment bound in `usize`, so
    /// this article at exactly 4 GiB became a span at offset 0: block
    /// 4096 stayed Pending and a boundary fragment of block 0 was
    /// claimed from bytes belonging four gigabytes away. Writes go out at
    /// u64 `pwrite` offsets, so the real bytes never moved - the verdict
    /// did, and `settle` then saw no damage to repair.
    #[test]
    fn a_span_past_four_gibibytes_claims_the_block_it_names() {
        const BS: usize = 1 << 20;
        const LEN: u64 = (1u64 << 32) + 4096;
        let tail = data_of(4096, 3);
        let last = (LEN.div_ceil(BS as u64) - 1) as usize;
        assert_eq!(last, 4096, "the block a 32-bit multiply cannot reach");

        let v = LiveVerifier::new(1);
        let meta = par2_meta_declared([9u8; 16], BS, "huge.bin", LEN, last, &tail);
        let set = v.activate(&[meta.as_slice()]).expect("fixture parses");
        assert_eq!(set.files[0].blocks.len(), last + 1);

        v.on_data(0, "huge.bin", LEN, 1u64 << 32, &tail);
        assert_eq!(
            v.live_counts(),
            (1, 0),
            "the last block hashes clean from its own bytes"
        );
        let (peak, spilled) = v.partials_stats();
        assert_eq!(
            (peak, spilled),
            (0, 0),
            "and nothing was held as a fragment of some other block"
        );
    }

    /// The head capture is in file coordinates too: an article at 4 GiB +
    /// 16 is not the head of the file. `offset as usize` wrapped it to 16
    /// on a 32-bit target and captured those bytes as the first sixteen
    /// of the file, which is what `md5_16k` matching then judged.
    #[test]
    fn the_head_capture_ignores_an_article_past_four_gibibytes() {
        const BS: usize = 1 << 20;
        const LEN: u64 = (1u64 << 32) + 4096;
        let tail = data_of(4096, 4);
        let last = (LEN.div_ceil(BS as u64) - 1) as usize;
        let v = LiveVerifier::new(1);
        let meta = par2_meta_declared([9u8; 16], BS, "huge.bin", LEN, last, &tail);
        v.activate(&[meta.as_slice()]).expect("fixture parses");
        // Before activation matters not at all here: capture_head runs on
        // every span, and this one is far past the head either way.
        v.on_data(0, "huge.bin", LEN, (1u64 << 32) + 16, &tail);
        assert!(
            v.slots[0].lock_ok().head.is_none(),
            "no head buffer was opened for a span past the head"
        );
    }

    fn data_of(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    fn active_verifier(files: &[(&str, &[u8])], bs: usize) -> (LiveVerifier, Arc<Par2Set>) {
        let v = LiveVerifier::new(files.len());
        let meta = par2_meta([9u8; 16], bs, files, true);
        let set = v.activate(&[meta.as_slice()]).expect("fixture parses");
        (v, set)
    }

    /// The happy path: whole-file spans arrive after activation, every
    /// block hashes from the decode buffer, settle reads back nothing.
    #[test]
    fn in_stream_verify_whole_spans() {
        let data = data_of(2048 + 100, 1); // 3 blocks, short last
        let (v, set) = active_verifier(&[("a.bin", &data)], 1024);
        assert_eq!(set.block_size, 1024);
        assert_eq!(set.files[0].blocks.len(), 3);
        assert!(v.set().is_some());

        assert!(!v.slot_in_set(0), "unmatched slot is not in the set");
        v.on_data(0, "a.bin", data.len() as u64, 0, &data);
        assert!(v.slot_in_set(0));
        assert!(
            v.delegates_integrity(0),
            "matched + full-MD5 mode delegates"
        );
        v.set_fast_verify(true);
        assert!(!v.delegates_integrity(0), "fast mode blocks delegation");
        v.set_lean(true);
        assert!(v.delegates_integrity(0), "lean opts back in");
        v.set_fast_verify(false);
        v.set_lean(false);

        let (live, bad) = v.live_counts();
        assert_eq!((live, bad), (3, 0));
        let r = v.finish_slot(0, None).expect("matched slot reports");
        assert!(r.all_ok(), "{r:?}");
        assert_eq!(r.par2_name.as_deref(), Some("a.bin"));
        assert_eq!(r.total_blocks, 3);
        assert_eq!(r.live_blocks, 3);
        assert_eq!(r.readback_blocks, 0);
        assert_eq!(r.length, data.len() as u64);
        assert!(v.unclaimed_files().is_empty());
        let (peak, spilled) = v.partials_stats();
        assert_eq!((peak, spilled), (0, 0));
    }

    /// The instrument-first reuse-geometry census counts what it claims:
    /// only a decoder-fresh span under fast verify that is exactly one
    /// untrimmed, block-aligned PAR2 block. Everything else is a span
    /// seen and nothing more.
    ///
    /// The short FINAL block still qualifies - its padded IFSC CRC32
    /// follows from the article's own by zero-extension (`crc32_zeros`),
    /// which is where the reuse would splice in, not a second hash.
    #[test]
    fn crc_reuse_geometry_counts_exact_blocks_only() {
        let data = data_of(2048 + 100, 5); // blocks of 1024 / 1024 / 100
        let (v, _set) = active_verifier(&[("a.bin", &data)], 1024);
        v.set_fast_verify(true);

        // Exactly block 0, untrimmed, decoder-fresh: the geometry in
        // question, and the only thing that may ever count.
        v.on_data(0, "a.bin", data.len() as u64, 0, &data[..1024]);
        let g = v.crc_reuse_geometry();
        assert_eq!((g.spans, g.qualifying), (1, 1), "{g:?}");
        assert_eq!((g.spans_bytes, g.qualifying_bytes), (1024, 1024), "{g:?}");

        // The short last block qualifies too (see the note above).
        v.on_data(0, "a.bin", data.len() as u64, 2048, &data[2048..]);
        assert_eq!(v.crc_reuse_geometry().qualifying, 2);

        // Aligned to no block boundary: two half-blocks, neither whole.
        v.on_data(0, "a.bin", data.len() as u64, 512, &data[512..1536]);
        // Half a block: block-aligned, but the CRC covers half the bytes.
        v.on_data(0, "a.bin", data.len() as u64, 1024, &data[1024..1536]);
        // yEnc padding past the PAR2 length: the clamp trims the span, so
        // the article's CRC covers bytes the block does not.
        let overrun = data_of(200, 6);
        v.on_data(0, "a.bin", data.len() as u64, 2048, &overrun);
        // A span with no wire CRC behind it has no CRC to reuse.
        v.on_data_unverified(0, "a.bin", data.len() as u64, 0, &data[..1024]);
        // And under full MD5 there is no CRC-only claim to shortcut.
        v.set_fast_verify(false);
        v.on_data(0, "a.bin", data.len() as u64, 0, &data[..1024]);

        let g = v.crc_reuse_geometry();
        assert_eq!(g.qualifying, 2, "a disqualified span was counted: {g:?}");
        assert_eq!(g.spans, 7, "every mapped span is seen: {g:?}");
        assert_eq!(g.qualifying_bytes, 1024 + 100, "{g:?}");
        // The process-global twin takes every bump this run made, and
        // whatever the rest of the suite made - a lower bound, since the
        // unit suite runs its tests as threads of one process.
        assert!(crc_reuse_geometry_total().spans >= g.spans);
    }

    /// Boundary blocks under full-MD5 mode accumulate byte partials; the
    /// completing span routes them through the full-MD5 check, and the
    /// budget accounting returns to zero.
    #[test]
    fn boundary_blocks_byte_partials() {
        let data = data_of(2048, 2);
        let (v, _set) = active_verifier(&[("a.bin", &data)], 1024);
        v.on_data(0, "a.bin", 2048, 0, &data[..700]);
        let (peak, _) = v.partials_stats();
        assert_eq!(peak, 1024, "one boundary block's bytes are held");
        v.on_data(0, "a.bin", 2048, 700, &data[700..]);
        let r = v.finish_slot(0, None).unwrap();
        assert!(r.all_ok(), "{r:?}");
        assert_eq!(r.live_blocks, 2, "both blocks claimed in-stream");
        assert_eq!(r.readback_blocks, 0);
    }

    /// Fast verify routes boundary fragments through CRC parts (B1): no
    /// bytes held, the short last block zero-pads via crc32_zeros, and
    /// out-of-order fragments still compose.
    #[test]
    fn fast_verify_crc_parts_compose() {
        let data = data_of(2048 + 100, 3); // short last block
        let (v, _set) = active_verifier(&[("a.bin", &data)], 1024);
        v.set_fast_verify(true);
        // Out of order, straddling every block boundary.
        v.on_data(0, "a.bin", 2148, 1100, &data[1100..]);
        v.on_data(0, "a.bin", 2148, 0, &data[..700]);
        v.on_data(0, "a.bin", 2148, 700, &data[700..1100]);
        let (peak, spilled) = v.partials_stats();
        assert_eq!((peak, spilled), (0, 0), "CRC parts hold no bytes");
        let r = v.finish_slot(0, None).unwrap();
        assert!(r.all_ok(), "{r:?}");
        assert_eq!(r.live_blocks, 3);
        assert_eq!(r.readback_blocks, 0);
    }

    /// A corrupted span claims Bad in-stream, and the report names the
    /// block. summarize_damage folds it into the repair plan's view.
    #[test]
    fn corrupt_block_reported() {
        let data = data_of(3072, 4);
        let (v, _set) = active_verifier(&[("a.bin", &data)], 1024);
        let mut wrong = data.clone();
        wrong[1500] ^= 0xFF; // damage block 1 only
        v.on_data(0, "a.bin", 3072, 0, &wrong);
        let (live, bad) = v.live_counts();
        assert_eq!((live, bad), (3, 1));
        let r = v.finish_slot(0, None).unwrap();
        assert!(!r.all_ok());
        assert_eq!(r.bad_blocks, vec![1]);
        let d = summarize_damage(std::iter::once(&r));
        assert_eq!(d.bad_blocks, 1);
        assert_eq!(d.damaged_files, vec!["a.bin".to_string()]);
    }

    /// M15 budget: a boundary block bigger than the global cap is never
    /// allocated - it spills to settle read-back, which full-MD5s it off
    /// disk. Also the plain finish_slot(path) read-back route.
    #[test]
    fn partials_budget_spills_to_readback() {
        let bs = 2 << 20; // 2 MiB blocks against the 1 MiB cap floor
        let data = data_of(2 * bs, 5);
        let v = LiveVerifier::with_partials_cap(1, 1);
        let meta = par2_meta([9u8; 16], bs, &[("a.bin", &data)], true);
        v.activate(&[meta.as_slice()]).unwrap();
        v.on_data(0, "a.bin", data.len() as u64, 0, &data[..1 << 20]);
        let (peak, spilled) = v.partials_stats();
        assert_eq!(peak, 0, "over-budget block was never allocated");
        assert_eq!(spilled, 1);

        let dir = std::env::temp_dir().join(format!("nzbkit-live-spill-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("a.bin");
        std::fs::write(&path, &data).unwrap();
        let r = v.finish_slot(0, Some(&path)).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(r.all_ok(), "{r:?}");
        assert_eq!(r.readback_blocks, 2, "both blocks settled off disk");
        assert_eq!(r.live_blocks, 0);
    }

    /// A block bigger than the 8 MiB read-back chunk takes the streamed
    /// path (chunked read, composed CRC padding, then MD5) - and agrees
    /// with the single-buffer verdict.
    #[test]
    fn oversized_block_readback_is_chunked() {
        let bs = 16 << 20;
        let data = data_of(9 << 20, 6); // one 9 MiB block, 7 MiB padding
        let v = LiveVerifier::new(1);
        let meta = par2_meta([9u8; 16], bs, &[("big.bin", &data)], true);
        v.activate(&[meta.as_slice()]).unwrap();
        v.set_name_hint(0, "big.bin");
        let ok = v
            .finish_slot_from(
                0,
                ReadAt::Reader(&|off, buf| {
                    let off = off as usize;
                    buf.copy_from_slice(&data[off..off + buf.len()]);
                    Ok(())
                }),
            )
            .unwrap();
        assert!(ok.all_ok(), "{ok:?}");
        assert_eq!(ok.readback_blocks, 1);

        // The same block with one corrupt byte fails the streamed check.
        let mut wrong = data.clone();
        wrong[8 << 20] ^= 1;
        let v2 = LiveVerifier::new(1);
        v2.activate(&[meta.as_slice()]).unwrap();
        v2.set_name_hint(0, "big.bin");
        let bad = v2
            .finish_slot_from(
                0,
                ReadAt::Reader(&|off, buf| {
                    let off = off as usize;
                    buf.copy_from_slice(&wrong[off..off + buf.len()]);
                    Ok(())
                }),
            )
            .unwrap();
        assert_eq!(bad.bad_blocks, vec![0]);
    }

    /// Pre-activation spans: heads are captured while Waiting, the spans
    /// coalesce (overlaps merged, contained spans dropped), and the
    /// backfill re-feed verifies them without settle read-back.
    #[test]
    fn pre_activation_backfill_roundtrip() {
        let data = data_of(2048, 7);
        let v = LiveVerifier::new(1);
        v.on_data(0, "a.bin", 2048, 0, &data[..800]);
        v.on_data(0, "a.bin", 2048, 600, &data[600..1400]); // overlap
        v.on_data(0, "a.bin", 2048, 700, &data[700..900]); // contained
        v.on_data(0, "a.bin", 2048, 1400, &data[1400..]);
        let meta = par2_meta([9u8; 16], 1024, &[("a.bin", &data)], true);
        v.activate(&[meta.as_slice()]).unwrap();
        let (spans, how) = v.take_pre_spans(0);
        assert_eq!(how, PreSpanSrc::Backfill);
        assert_eq!(spans, vec![(0, 2048)], "coalesced to one span");
        for &(off, len) in &spans {
            let (off, len) = (off as usize, len as usize);
            v.on_data_backfill(0, "a.bin", 2048, off as u64, &data[off..off + len]);
        }
        let r = v.finish_slot(0, None).unwrap();
        assert!(r.all_ok(), "{r:?}");
        assert_eq!(r.readback_blocks, 0, "backfill left nothing to settle");
    }

    /// Crash-resume seeds split at the u32 boundary and force the whole
    /// slot onto the Disk backfill route.
    #[test]
    fn resume_seeds_split_and_route_to_disk() {
        let v = LiveVerifier::new(1);
        let big = (u32::MAX as u64) + 10;
        v.seed_pre_spans(0, &[(0, big), (big + 100, 50)]);
        let (spans, how) = v.take_pre_spans(0);
        assert_eq!(how, PreSpanSrc::Disk);
        assert_eq!(spans, vec![(0, big), (big + 100, 50)]);
    }

    /// Obfuscated posts: the yEnc name lies (or is absent), and the slot
    /// still claims its PAR2 file through the md5-16k of its head.
    #[test]
    fn md5_16k_matches_obfuscated_slot() {
        let data = data_of(3000, 8); // < 16 KiB: head is the whole file
        let (v, _set) = active_verifier(&[("real-name.bin", &data)], 1024);
        v.on_data(0, "jibberish123", 3000, 0, &data);
        assert!(v.slot_in_set(0), "claimed via md5-16k despite the name");
        let r = v.finish_slot(0, None).unwrap();
        assert!(r.all_ok(), "{r:?}");
        assert_eq!(r.par2_name.as_deref(), Some("real-name.bin"));
    }

    /// Codex sweep 13 Aug R1: slots differing only by case must never
    /// cross-claim each other's descriptors. With FileDesc order
    /// [a.txt, A.txt] the first slot to match used to take the OTHER
    /// file's descriptor case-insensitively (one first-hit loop over
    /// exact and approximate classes), and the second slot then claimed
    /// what was left - both crossed, each verifying and publishing
    /// under the other's name.
    #[test]
    fn same_name_different_case_slots_never_cross_claim() {
        let a = data_of(3000, 21);
        let b = data_of(3000, 22);
        // Adversarial descriptor order: the lowercase twin first.
        let (v, _set) = active_verifier(&[("a.txt", &a), ("A.txt", &b)], 1024);
        // The uppercase slot arrives first.
        v.on_data(0, "A.txt", 3000, 0, &b);
        v.on_data(1, "a.txt", 3000, 0, &a);
        let r0 = v.finish_slot(0, None).unwrap();
        let r1 = v.finish_slot(1, None).unwrap();
        assert_eq!(r0.par2_name.as_deref(), Some("A.txt"), "crossed claim");
        assert_eq!(r1.par2_name.as_deref(), Some("a.txt"), "crossed claim");
        assert!(r0.all_ok() && r1.all_ok(), "{r0:?} {r1:?}");
    }

    /// ...and when the name tier is genuinely AMBIGUOUS - one slot
    /// whose sanitized name matches two descriptors - FileDesc order
    /// must not pick the winner. The name tier declines and the
    /// md5-16k tier settles it by content.
    #[test]
    fn ambiguous_sanitized_names_settle_by_content_not_desc_order() {
        let a = data_of(3000, 23);
        let b = data_of(3000, 24);
        // Both descriptor names sanitize to "a_b.txt".
        let (v, _set) = active_verifier(&[("a/b.txt", &a), ("a\\b.txt", &b)], 1024);
        v.on_data(0, "a_b.txt", 3000, 0, &b);
        let r = v.finish_slot(0, None).unwrap();
        assert_eq!(
            r.par2_name.as_deref(),
            Some("a\\b.txt"),
            "content, not descriptor order, must decide the ambiguous claim"
        );
        assert!(r.all_ok(), "{r:?}");
    }

    /// 14 Aug sweep: an AMBIGUOUS name decline must not latch the slot
    /// unmatchable. Slot 0's sanitized name matches two descriptors and
    /// its head matches neither (damage inside the first 16k), so both
    /// tiers decline - but the candidates are real, and once the twin
    /// slot claims its descriptor by exact name the ambiguity resolves
    /// to unique. The latch froze the slot forever and downgraded a
    /// patchable file to wholly-missing.
    #[test]
    fn ambiguous_decline_stays_retryable_until_twin_resolves_it() {
        let a = data_of(3000, 25);
        let b = data_of(3000, 26);
        let corrupt = data_of(3000, 27); // head matches neither descriptor
        let (v, _set) = active_verifier(&[("a/b.txt", &a), ("a\\b.txt", &b)], 1024);
        // Slot 0: ambiguous name, corrupt head - both tiers decline.
        v.on_data(0, "a_b.txt", 3000, 0, &corrupt);
        assert!(!v.slot_in_set(0), "nothing claimable yet");
        // Slot 1 claims a/b.txt by exact name, making slot 0's
        // approximate match unique.
        v.on_data(1, "a/b.txt", 3000, 0, &a);
        assert!(v.slot_in_set(1));
        // Slot 0's next span retries the match and must now claim.
        v.on_data(0, "a_b.txt", 3000, 0, &corrupt);
        assert!(
            v.slot_in_set(0),
            "ambiguity resolved by the twin's claim - the slot must not stay latched unmatchable"
        );
    }

    /// A slot whose name AND head both match nothing (nfo/sfv/sample)
    /// goes unmatchable, stops rescanning, reports None - and its PAR2
    /// files stay on the unclaimed list.
    #[test]
    fn unmatchable_slot_reports_none() {
        let data = data_of(2048, 9);
        let stranger = data_of(2048, 10);
        let (v, _set) = active_verifier(&[("a.bin", &data)], 1024);
        v.on_data(0, "not-in-set.nfo", 2048, 0, &stranger);
        assert!(!v.slot_in_set(0));
        assert!(!v.delegates_integrity(0));
        v.on_data(0, "not-in-set.nfo", 2048, 0, &stranger); // early-out path
        assert!(v.finish_slot(0, None).is_none());
        assert_eq!(v.unclaimed_files(), vec!["a.bin".to_string()]);
    }

    /// No IFSC packet: the slot settles on the whole-file MD5, engaged
    /// gates release either way, and a mismatch reads as one bad block.
    #[test]
    fn no_ifsc_settles_on_whole_file_md5() {
        let data = data_of(5000, 11);
        let v = LiveVerifier::new(2);
        let g = VerifyGate::new(2);
        v.set_gate(g.clone());
        let meta = par2_meta([9u8; 16], 1024, &[("a.bin", &data)], false);
        v.activate(&[meta.as_slice()]).unwrap();
        // A span arriving on a matched no-IFSC slot is a no-op (no block
        // map to claim against), but it does claim the file.
        v.on_data(0, "a.bin", 5000, 0, &data);
        assert_eq!(g.watermark(0), 0, "claim engaged the gate");
        let ok = v
            .finish_slot_from(
                0,
                ReadAt::Reader(&|off, buf| {
                    let off = off as usize;
                    buf.copy_from_slice(&data[off..off + buf.len()]);
                    Ok(())
                }),
            )
            .unwrap();
        assert!(ok.all_ok(), "{ok:?}");
        assert_eq!(ok.total_blocks, 0);
        assert_eq!(g.watermark(0), u64::MAX, "no-IFSC settle releases the gate");

        // Missing source: the whole-file check cannot pass, and the
        // verdict is damage rather than a hang.
        let v2 = LiveVerifier::new(1);
        v2.activate(&[meta.as_slice()]).unwrap();
        v2.set_name_hint(0, "a.bin");
        let bad = v2.finish_slot(0, None).unwrap();
        assert_eq!(bad.bad_blocks, vec![0]);
        assert!(!bad.all_ok());
    }

    /// §94 B: the published watermark tracks the contiguous Ok prefix -
    /// an out-of-order claim publishes nothing until the prefix catches
    /// up, and a fully verified slot publishes MAX.
    #[test]
    fn gate_watermark_tracks_ok_prefix() {
        let data = data_of(3072, 12);
        let (v, _set) = active_verifier(&[("a.bin", &data)], 1024);
        let g = VerifyGate::new(1);
        v.set_gate(g.clone());
        v.on_data(0, "a.bin", 3072, 2048, &data[2048..]); // block 2 first
        assert_eq!(g.watermark(0), 0, "no contiguous prefix yet");
        v.on_data(0, "a.bin", 3072, 0, &data[..1024]);
        assert_eq!(g.watermark(0), 1024, "prefix = block 0");
        v.on_data(0, "a.bin", 3072, 1024, &data[1024..2048]);
        assert_eq!(g.watermark(0), u64::MAX, "every block verified");
    }

    /// Mixed trust on a CRC-parts block: a fragment that cannot claim
    /// CRC-only (settle/disk source) may not lend bytes to someone
    /// else's CRC-only claim - the block abandons to read-back.
    #[test]
    fn mixed_trust_abandons_crc_partial() {
        let data = data_of(2048, 13);
        let (v, _set) = active_verifier(&[("a.bin", &data)], 1024);
        v.set_fast_verify(true);
        v.on_data(0, "a.bin", 2048, 0, &data[..700]); // CRC fragment
        v.on_data_from_disk(0, "a.bin", 2048, 700, &data[700..1024]);
        let (_, spilled) = v.partials_stats();
        assert_eq!(spilled, 1, "the CRC partial was abandoned");
        // The rest arrives whole; block 1 claims, block 0 reads back.
        v.on_data(0, "a.bin", 2048, 1024, &data[1024..]);
        let dir = std::env::temp_dir().join(format!("nzbkit-live-mixed-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("a.bin");
        std::fs::write(&path, &data).unwrap();
        let r = v.finish_slot(0, Some(&path)).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(r.all_ok(), "{r:?}");
        assert_eq!(r.readback_blocks, 1);
    }

    /// An overlapping re-feed cannot compose CRCs losslessly - the block
    /// abandons rather than guessing, then a whole-block span claims it.
    #[test]
    fn overlapping_crc_refeed_abandons_then_recovers() {
        let data = data_of(2048, 14);
        let (v, _set) = active_verifier(&[("a.bin", &data)], 1024);
        v.set_fast_verify(true);
        v.on_data(0, "a.bin", 2048, 0, &data[..700]);
        v.on_data(0, "a.bin", 2048, 0, &data[..700]); // exact overlap
        let (_, spilled) = v.partials_stats();
        assert_eq!(spilled, 1);
        v.on_data(0, "a.bin", 2048, 0, &data[..1024]); // whole block 0
        v.on_data(0, "a.bin", 2048, 1024, &data[1024..]);
        let r = v.finish_slot(0, None).unwrap();
        assert!(r.all_ok(), "{r:?}");
    }

    /// set_off: spans are dropped, no set, no reports - and Waiting
    /// (never activated) reports None the same way.
    #[test]
    fn off_and_waiting_report_nothing() {
        let v = LiveVerifier::new(1);
        assert!(v.finish_slot(0, None).is_none(), "Waiting reports None");
        assert!(v.set().is_none());
        v.set_off();
        v.on_data(0, "a.bin", 100, 0, &[0u8; 100]);
        assert!(v.finish_slot(0, None).is_none());
        assert!(!v.slot_in_set(0));
        assert!(!v.delegates_integrity(0));
        assert!(v.unclaimed_files().is_empty());
    }

    /// set_name_hint seeds a name for a slot no article will flow
    /// through, and finish_slot's last-chance match claims on it.
    #[test]
    fn name_hint_enables_last_chance_match() {
        let data = data_of(2048, 15);
        let (v, _set) = active_verifier(&[("a.bin", &data)], 1024);
        v.set_name_hint(0, "a.bin");
        v.set_name_hint(0, "loser.bin"); // first hint wins
        let dir = std::env::temp_dir().join(format!("nzbkit-live-hint-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("a.bin");
        std::fs::write(&path, &data).unwrap();
        let r = v.finish_slot(0, Some(&path)).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(r.all_ok(), "{r:?}");
        assert_eq!(r.readback_blocks, 2, "every block settled off disk");
        assert_eq!(r.live_blocks, 0);
    }

    /// A head restarted by a late-learned file size still md5-16k
    /// matches: the first article carried no size, the second did.
    #[test]
    fn head_restarts_when_size_learned_late() {
        let data = data_of(1000, 16);
        let v = LiveVerifier::new(1);
        v.on_data(0, "", 0, 0, &data[..500]); // size unknown: 16 KiB head
        v.on_data(0, "", 1000, 0, &data[..500]); // size learned: restart
        v.on_data(0, "", 1000, 500, &data[500..]);
        let meta = par2_meta([9u8; 16], 1024, &[("real.bin", &data)], true);
        v.activate(&[meta.as_slice()]).unwrap();
        // Backfill re-feed completes the head and matches via md5-16k.
        let (spans, how) = v.take_pre_spans(0);
        assert_eq!(how, PreSpanSrc::Backfill);
        for &(off, len) in &spans {
            let (off, len) = (off as usize, len as usize);
            v.on_data_backfill(0, "", 1000, off as u64, &data[off..off + len]);
        }
        let r = v.finish_slot(0, None).unwrap();
        assert!(r.all_ok(), "{r:?}");
        assert_eq!(r.par2_name.as_deref(), Some("real.bin"));
    }

    /// pick_set: mixed recovery sets fall back to the input describing
    /// the most files; pure garbage stays an error.
    #[test]
    fn pick_set_prefers_larger_of_mixed() {
        let a = data_of(1024, 17);
        let b = data_of(1024, 18);
        let one = par2_meta([1u8; 16], 1024, &[("solo.bin", &a)], true);
        let two = par2_meta([2u8; 16], 1024, &[("x.bin", &a), ("y.bin", &b)], true);
        let set = pick_set(&[one.as_slice(), two.as_slice()]).expect("fallback picks one set");
        assert_eq!(set.files.len(), 2);
        assert_eq!(set.recovery_set_id, [2u8; 16]);
        assert!(matches!(
            pick_set(&[b"not a par2 at all".as_slice()]),
            Err(Par2Error::NoMainPacket)
        ));
        // activate() surfaces parse failures without adopting a plan.
        let v = LiveVerifier::new(1);
        assert!(v.activate(&[b"garbage".as_slice()]).is_err());
        assert!(v.set().is_none());
    }

    /// Two slots, two files: claims don't collide, and per-slot verdicts
    /// stay independent.
    #[test]
    fn two_slots_claim_distinct_files() {
        let a = data_of(2048, 19);
        let b = data_of(1500, 20);
        let (v, _set) = active_verifier(&[("a.bin", &a), ("b.bin", &b)], 1024);
        v.on_data(1, "b.bin", 1500, 0, &b);
        v.on_data(0, "a.bin", 2048, 0, &a);
        let ra = v.finish_slot(0, None).unwrap();
        let rb = v.finish_slot(1, None).unwrap();
        assert_eq!(ra.par2_name.as_deref(), Some("a.bin"));
        assert_eq!(rb.par2_name.as_deref(), Some("b.bin"));
        assert!(ra.all_ok() && rb.all_ok());
        assert!(v.unclaimed_files().is_empty());
    }

    // ===== B6 differential: the indexed matcher vs the pre-B6 linear =====
    // ===== drain. Same scripted sequence through both, every visible  =====
    // ===== outcome must agree at every step.                          =====

    /// One matcher step: optionally learn a name (the `on_data` rule: only
    /// if none yet, only if non-empty), optionally feed head bytes from
    /// offset 0 with a declared file size, then attempt a match under the
    /// caller guards (skip if claimed or latched unmatchable).
    type Step<'a> = (usize, Option<&'a str>, Option<(&'a [u8], u64)>);

    fn mk_active(files: &[(&str, &[u8])], bs: usize) -> Active {
        let v = LiveVerifier::new(0);
        let meta = par2_meta([7u8; 16], bs, files, true);
        Active::new(v.activate(&[meta.as_slice()]).expect("fixture parses"))
    }

    #[expect(clippy::type_complexity)]
    fn run_world(
        files: &[(&str, &[u8])],
        steps: &[Step],
        indexed: bool,
    ) -> (Vec<Option<usize>>, Vec<(Option<usize>, bool)>, Vec<bool>) {
        let active = mk_active(files, 512);
        let nslots = steps.iter().map(|s| s.0 + 1).max().unwrap_or(0);
        let mut slots: Vec<SlotState> = (0..nslots).map(|_| SlotState::empty()).collect();
        let mut rets = Vec::new();
        for &(si, name, head) in steps {
            let s = &mut slots[si];
            if let Some(n) = name
                && s.name.is_none()
                && !n.is_empty()
            {
                s.name = Some(n.to_string());
            }
            if let Some((bytes, size)) = head {
                if s.file_size == 0 {
                    s.file_size = size;
                }
                s.capture_head(0, bytes);
            }
            let r = if s.file.is_some() || s.unmatchable {
                false
            } else if indexed {
                s.try_match(si, &active)
            } else {
                s.try_match_linear(si, &active)
            };
            rets.push(r);
        }
        let claimed = active.claimed.lock_ok().clone();
        let state = slots.iter().map(|s| (s.file, s.unmatchable)).collect();
        (claimed, state, rets)
    }

    fn assert_matchers_agree(files: &[(&str, &[u8])], steps: &[Step]) {
        let a = run_world(files, steps, true);
        let b = run_world(files, steps, false);
        assert_eq!(
            a,
            b,
            "indexed vs linear diverged; files {:?} steps {:?}",
            files.iter().map(|f| f.0).collect::<Vec<_>>(),
            steps
                .iter()
                .map(|(s, n, h)| (*s, *n, h.map(|(b, sz)| (b.len(), sz))))
                .collect::<Vec<_>>()
        );
    }

    /// The Codex-R1 case-cross shape plus duplicates: exact must beat
    /// approximate in both impls whichever arrival order, and duplicate
    /// names must claim in FileDesc order.
    #[test]
    fn differential_exact_precedence_and_duplicates() {
        let d: Vec<Vec<u8>> = (0..4).map(|i| data_of(700, i as u8 + 40)).collect();
        let files: &[(&str, &[u8])] = &[
            ("a.txt", &d[0]),
            ("A.txt", &d[1]),
            ("dup.bin", &d[2]),
            ("dup.bin", &d[3]),
        ];
        for order in [[0usize, 1, 2, 3], [3, 2, 1, 0], [1, 0, 3, 2]] {
            let names = ["A.txt", "a.txt", "dup.bin", "dup.bin"];
            let steps: Vec<Step> = order.iter().map(|&s| (s, Some(names[s]), None)).collect();
            assert_matchers_agree(files, &steps);
        }
    }

    /// Ambiguity must stay retryable identically: a slot whose name folds
    /// onto two descriptors (one via case, one via sanitize) claims nothing
    /// and never latches, then claims once a twin's exact match removes the
    /// other candidate.
    #[test]
    fn differential_ambiguity_across_both_key_classes() {
        let d: Vec<Vec<u8>> = (0..2).map(|i| data_of(600, i as u8 + 50)).collect();
        // "ab.txt." matches "AB.TXT." case-folded and "ab.txt" sanitized.
        let files: &[(&str, &[u8])] = &[("AB.TXT.", &d[0]), ("ab.txt", &d[1])];
        let junk = data_of(600, 99);
        let steps: &[Step] = &[
            // Ambiguous, complete head that md5-matches nothing: no claim,
            // and the latch must NOT set (retryable ambiguity).
            (0, Some("ab.txt."), Some((&junk, 600))),
            (1, Some("AB.TXT."), None), // exact claims descriptor 0
            (0, None, None),            // retry: now unique via sanitize
        ];
        assert_matchers_agree(files, steps);
    }

    /// Sanitize-tier variants (separators, trims) and the md5-16k
    /// fallback + unmatchable latch, same answers from both impls.
    #[test]
    fn differential_sanitize_and_md5_paths() {
        let d: Vec<Vec<u8>> = (0..3).map(|i| data_of(900, i as u8 + 60)).collect();
        let files: &[(&str, &[u8])] = &[("al/pha.bin", &d[0]), ("beta.bin", &d[1]), ("x", &d[2])];
        let junk = data_of(900, 98);
        let steps: &[Step] = &[
            (0, Some("al_pha.bin"), None),               // sanitize-only hit
            (1, Some(" beta.bin"), None),                // leading space, sanitize hit
            (2, Some("obfuscated"), Some((&d[2], 900))), // md5-16k claim
            (3, Some("junk.nfo"), Some((&junk, 900))),   // full miss: latch
            (3, None, None),                             // latched: caller skips
            (4, Some(""), Some((&junk, 900))),           // nameless: md5 miss, NO latch
            (4, None, None),
        ];
        assert_matchers_agree(files, steps);
    }

    /// Seeded fuzz over name-variant pools (case flips, separators,
    /// trailing dots, duplicates, empties) and random step orders, with
    /// occasional matching or junk heads - every world pair must agree.
    #[test]
    fn differential_fuzz_variant_pools() {
        let mut rng = 0x9e3779b97f4a7c15u64;
        let mut next = move || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        let pool = [
            "alpha.bin",
            "Alpha.bin",
            "ALPHA.BIN",
            "alpha.bin.",
            " alpha.bin",
            "al/pha.bin",
            "al_pha.bin",
            "beta.bin",
            "beta.nfo",
            "..",
            "",
        ];
        let data: Vec<Vec<u8>> = (0..pool.len())
            .map(|i| data_of(400 + i * 37, i as u8))
            .collect();
        let junk = data_of(4096, 250);
        for _ in 0..300 {
            let nf = 2 + (next() % 7) as usize;
            let files: Vec<(&str, &[u8])> = (0..nf)
                .map(|_| {
                    let p = (next() % pool.len() as u64) as usize;
                    // Descriptor names must be non-empty to survive parsing;
                    // fall back to a fixed name for the "" pool entry.
                    let name = if pool[p].is_empty() { "x" } else { pool[p] };
                    (name, data[p].as_slice())
                })
                .collect();
            let mut steps: Vec<Step> = Vec::new();
            for _ in 0..24 {
                let slot = (next() % 8) as usize;
                let name = if next() % 4 == 0 {
                    None
                } else {
                    Some(pool[(next() % pool.len() as u64) as usize])
                };
                let head = match next() % 5 {
                    0 => {
                        let (_, d) = files[(next() % nf as u64) as usize];
                        Some((d, d.len() as u64))
                    }
                    1 => Some((junk.as_slice(), junk.len() as u64)),
                    _ => None,
                };
                steps.push((slot, name, head));
            }
            assert_matchers_agree(&files, &steps);
        }
    }
}
