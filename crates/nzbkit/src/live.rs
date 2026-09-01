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
use std::collections::{HashMap, HashSet};
use std::io;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex, RwLock};

use md5::{Digest, Md5};

use crate::par2::{BlockCheck, Par2Error, Par2File, Par2Set};

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
    /// `head`'s MD5, once the head is complete. Cached because an
    /// unmatched slot re-matches on EVERY article, and a slot whose name
    /// the content denies stays unmatched for the rest of the run - see
    /// [`SlotState::head_key`]. Reset wherever `head` is restarted.
    head_md5: Option<[u8; 16]>,
    /// yEnc-declared file size (caps head capture for small files).
    file_size: u64,
    /// Index into the active set's `files` once matched. BOUND is not
    /// CLAIMED: see `confirmed`.
    file: Option<usize>,
    /// Does this slot hold the CLAIM on `file` (`active.claimed[file] ==
    /// this slot`), or is the binding still only a name's nomination?
    ///
    /// A name is poster-controlled, so a slot bound on the name alone is
    /// bound TENTATIVELY: it verifies its blocks against the nominated
    /// descriptor exactly as a claim would - which is what keeps
    /// out-of-order arrival at zero read-back - but it takes no claim, so
    /// it locks nobody out and the descriptor's real owner can still
    /// claim it on content. The first block that verifies Ok IS the
    /// content proof, and promotes the binding to a claim
    /// ([`LiveVerifier::promote_binding`]); a binding that never earns one
    /// is settled at finish by [`SlotState::settle_binding`].
    confirmed: bool,
    /// A denied nomination has been re-judged and NO descriptor in the
    /// set carries this slot's head - so no later claim can produce one,
    /// and [`LiveVerifier::rejudge_binding`] need not scan the set again
    /// on every remaining article. Latched only for the empty answer:
    /// two candidates today can become one unique rival tomorrow, which
    /// is exactly the case that must stay live.
    head_rival_ruled_out: bool,
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
    ///
    /// `Some(g)` carries the [`Active::adopted_gen`] the refusal was reached
    /// under, because the refusal is a statement ABOUT a descriptor
    /// population and means nothing once that population is a
    /// different one. Read through [`SlotState::refused`], never
    /// directly, at every site that GATES a match on it - the raw
    /// `is_some()` answers "was a verdict ever reached", which is a
    /// different question and the one `slot_undecided` asks.
    unmatchable: Option<u64>,
    /// Blocks verified in-stream (for the zero-read-back accounting).
    live_ok: u64,
    live_bad: u64,
    /// §94 B: count of leading contiguous Ok blocks, maintained
    /// incrementally so watermark publication is O(advance), not
    /// O(blocks) per span.
    ok_prefix: usize,
    /// M4-69: at least one IFSC entry of this slot's descriptor was
    /// caught saying two different things about ONE block's bytes - the
    /// CRC32 matched and the MD5 did not. Latched, never cleared.
    ///
    /// It costs nothing to notice: [`check_block`] runs the CRC first
    /// and only reaches the MD5 once the CRC has matched, so the pair
    /// that disagrees is the one pair already fully computed. On any
    /// well-formed set it never fires - the two digests cover the same
    /// bytes, so an honest entry cannot disagree with itself, and a
    /// damaged block fails the CRC and never consults the MD5 (a chance
    /// CRC32 hit on damaged bytes is 2^-32).
    ///
    /// What it arms is the escalation in [`LiveVerifier::finish_slot_from`]:
    /// an entry that contradicts itself is not evidence of damage, it is
    /// an unusable entry, and the bytes it fails to describe are covered
    /// by the FileDesc whole-file MD5 - which is the strongest evidence
    /// the settled file admits.
    ///
    /// IT CANNOT LATCH ON THE MIRROR SHAPE, and that is a refusal rather
    /// than an oversight: a lying CRC32 beside an honest MD5 fails the
    /// CRC, so no MD5 is ever reached and nothing has disagreed with
    /// itself. Detecting it costs an MD5 pass over damaged blocks -
    /// priced and refused at [`BlockVerdict::Damaged`]. The escalation's
    /// third trigger, every block of a file bad, covers what that leaves
    /// at a cost bounded by what it prevents; see `finish_slot_from`.
    ifsc_self_contradicted: bool,
}

enum Plan {
    /// Par2 main not yet parsed; slots record names/heads only.
    Waiting,
    Active(Active),
    /// No PAR2 in this NZB - verification off.
    Off,
}

/// Every recovery set the post carries, adopted together.
///
/// TODO 311 / GH #63: a post may ship one recovery set PER FILE - the
/// reporter's had eighteen tracks, eighteen `.par2` index files, one set
/// each. `pick_set` kept the largest and dropped the other seventeen in
/// silence, so seventeen tracks were never verified and the job reported
/// clean; a damaged one among them had no repair path at all and the run
/// failed it as "outside the PAR2 set" with its own parity sitting on
/// disk unused (measured, `tests/e2e_multiset`).
///
/// The sets are held as a LIST and never merged into one synthetic set.
/// A merged set cannot be right: `block_size` and `recovery_set_id` are
/// per set, a recovery slice belongs to its own set's Reed-Solomon
/// geometry, and `par2repair::recovery_slice_locators` filters slices BY
/// set id - so a merge would have to carry the mapping anyway, and would
/// additionally have to be taken apart again to feed repair, which wants
/// exactly one whole `Par2Set` at a time.
///
/// Slots address files through a FLAT index across the whole list
/// (`SlotState::file`), so every site that used to say
/// `set.files[fi]`/`set.block_size` now says [`Active::file`] /
/// [`Active::block_size`] and nothing else about matching changes -
/// candidate order, duplicate-name precedence and the claim mutex are
/// all as they were, with the population widened from one set's files to
/// every set's.
struct Active {
    sets: Vec<Arc<Par2Set>>,
    /// Flat file index → (set index, file index within that set). The
    /// flat index is what `SlotState::file`, `claimed`, `by_fold` and
    /// `by_sanitized` all speak.
    index: Vec<(usize, usize)>,
    /// flat file idx → slot that claimed it (one slot per PAR2 file). Its
    /// own mutex: matching happens while holding a slot lock, and two
    /// slots must not race a claim.
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
    /// How many times the adopted set list has GROWN, counted from 0.
    ///
    /// A slot's permanent refusal ([`SlotState::unmatchable`]) is a
    /// statement ABOUT a descriptor population - "hashed whole, this
    /// head matched nothing here" - so it means nothing once that
    /// population is a different one. `extended` bumps this exactly
    /// when a set id nothing had adopted is appended, and
    /// [`SlotState::refused`] compares it, which is what re-opens a
    /// latched slot for the tiers a second activation put descriptors
    /// in front of. See `extended` for why a re-activation that adds
    /// nothing must NOT bump it.
    adopted_gen: u64,
}

impl Active {
    fn new(sets: Vec<Arc<Par2Set>>) -> Active {
        let mut index: Vec<(usize, usize)> = Vec::new();
        let mut by_fold: HashMap<String, Vec<usize>> = HashMap::new();
        let mut by_sanitized: HashMap<String, Vec<usize>> = HashMap::new();
        for (si, set) in sets.iter().enumerate() {
            for (fi, f) in set.files.iter().enumerate() {
                let flat = index.len();
                index.push((si, fi));
                by_fold
                    .entry(f.name.to_ascii_lowercase())
                    .or_default()
                    .push(flat);
                by_sanitized
                    .entry(crate::disk::sanitize_out_name(&f.name))
                    .or_default()
                    .push(flat);
            }
        }
        let claimed = Mutex::new(vec![None; index.len()]);
        Active {
            sets,
            index,
            claimed,
            by_fold,
            by_sanitized,
            adopted_gen: 0,
        }
    }

    /// This `Active` plus every set in `extra` whose recovery set id is
    /// not already live, with existing flat indices and their claims
    /// preserved. See [`LiveVerifier::activate`] for why a second
    /// activation must extend rather than replace.
    fn extended(&self, extra: &[Arc<Par2Set>]) -> Active {
        let mut sets = self.sets.clone();
        for s in extra {
            if !sets.iter().any(|x| x.recovery_set_id == s.recovery_set_id) {
                sets.push(s.clone());
            }
        }
        let grew = sets.len() > self.sets.len();
        let mut out = Active::new(sets);
        // The generation moves ONLY when a set id nothing had adopted
        // was appended, and both halves of that are load-bearing.
        //
        // It has to move at all because `SlotState::unmatchable` is a
        // refusal reached against the descriptors live at the time, and
        // this is the moment that population stops being the one the
        // refusal was about - the same argument `capture_head` already
        // makes for a head that GREW, with the other operand moving.
        // Left unbumped, a slot whose only descriptor arrives in a
        // deferred set never claims however intact its bytes are:
        // `finish_slot` skips the whole-file and named tiers for it, so
        // it stays in `missing_files` and is charged WHOLLY MISSING to
        // whichever set names it, sending a repair to rebuild a file
        // that is byte-perfect on disk. Measured 31 Aug 2026 on a
        // two-set post - "verified 0 file(s)" over a file present and
        // byte-exact in `out_dir`.
        //
        // And it must NOT move when nothing was appended, which is the
        // ordinary re-activation: this function DISCARDS an already-live
        // set deliberately - see the note above, and `LiveVerifier`'s
        // own `activate` - so a bump there would re-open every latched slot
        // on a post that learned nothing, and each one costs a
        // whole-file read in `try_match_whole` at settle. Nothing new
        // to match against is not a reason to match again.
        out.adopted_gen = if grew {
            self.adopted_gen + 1
        } else {
            self.adopted_gen
        };
        // The prefix is the same sets in the same order with the same
        // files, so flat index N still names the same descriptor.
        let old = self.claimed.lock_ok();
        let mut new = out.claimed.lock_ok();
        debug_assert!(
            new.len() >= old.len(),
            "extending a set list may only append"
        );
        new[..old.len()].copy_from_slice(&old);
        drop(new);
        drop(old);
        out
    }

    /// The descriptor behind a flat file index.
    fn file(&self, flat: usize) -> &Par2File {
        let (si, fi) = self.index[flat];
        &self.sets[si].files[fi]
    }

    /// The block size of the set that flat index belongs to. PER SET,
    /// not per job: #63's post carried 716800 for every set, and nothing
    /// obliges a poster to be that consistent.
    fn block_size(&self, flat: usize) -> u64 {
        self.sets[self.index[flat].0].block_size
    }

    /// Every adopted file in flat-index order: sets in `sets` order,
    /// files in FileDesc order within each. That order is what
    /// duplicate-name precedence and "first candidate" mean, so the
    /// matchers walk it rather than one set's `files`.
    fn files(&self) -> impl Iterator<Item = (usize, &Par2File)> {
        self.index
            .iter()
            .enumerate()
            .map(|(flat, &(si, fi))| (flat, &self.sets[si].files[fi]))
    }

    /// A flat index split into (owning set, that set's own file index).
    /// The hashing pass below the lock holds the `Arc<Par2Set>` rather
    /// than a borrow of `Active`, so it needs the SET-LOCAL index to
    /// address `Par2Set::files` - the flat one only means anything to
    /// `Active`.
    fn split(&self, flat: usize) -> (usize, usize) {
        self.index[flat]
    }

    /// Which set a flat file index belongs to. Settle needs it to
    /// attribute a slot's damage to the set whose parity can heal it.
    fn set_of(&self, flat: usize) -> usize {
        self.index[flat].0
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
    pub fn activate(&self, inputs: &[&[u8]]) -> Result<Vec<Arc<Par2Set>>, Par2Error> {
        let sets: Vec<Arc<Par2Set>> = pick_sets(inputs)?.into_iter().map(Arc::new).collect();
        // Memory-floor gauge (instrument-first): the retained per-block
        // verification tables. 20 B of BlockCheck per IFSC block (rounded
        // to 24 for Vec/padding) - proportional to set size over block
        // size, so a pathological small-block set shows up here.
        //
        // Summed over EVERY adopted set since TODO 311, and that is not
        // a new cost so much as the cost this gauge always meant to
        // report: a file's IFSC list is sized by its own length, so N
        // one-file sets carry the same total as one set naming the same
        // N files at the same block size. The pathological shape the
        // gauge exists to surface (tiny blocks over a large post) is
        // unchanged, and a post large enough to matter is still small
        // here - 100 GB at #63's 716800 is ~140k blocks, 3.4 MB of
        // table.
        let blocks: u64 = sets
            .iter()
            .flat_map(|s| s.files.iter())
            .map(|f| f.blocks.len() as u64)
            .sum();
        crate::memgauge::set_at_least(crate::memgauge::Sub::VerifierMeta, blocks * 24);
        // W4-15: MERGE, never replace. A post carrying two recovery sets
        // reaches this TWICE - the in-stream sniff elects one bootstrap
        // volume for the whole job, so the second set is activated later,
        // from the bytes its deferred volumes already have on disk
        // (`get::settle::activate_deferred_sets`).
        // Replacing built a fresh `Active` with an empty `claimed`
        // vector and a fresh flat index, so every slot already bound
        // kept a `file` index into the OLD table: its claim vanished,
        // its descriptor read as unclaimed, and the same member was
        // charged BOTH as damaged (the stale binding's blocks) and as
        // wholly missing (the unclaimed descriptor) - 24 blocks of
        // demand on a 4-block loss.
        //
        // Sets already live keep their position, so every flat index
        // that exists stays pointing at the descriptor it pointed at,
        // and `claimed` is carried across; only genuinely new set ids
        // are appended, at the end. Re-parsing an already-live set is
        // DISCARDED rather than swapped in for the same reason - the
        // bound slots' block vectors were sized from the live copy.
        let mut plan = self.plan.write_ok();
        let merged = match &*plan {
            Plan::Active(a) => a.extended(&sets),
            _ => Active::new(sets),
        };
        let all = merged.sets.clone();
        *plan = Plan::Active(merged);
        Ok(all)
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
    ///
    /// BOUND, which after settle is the same thing as CLAIMED: a
    /// name-only binding ([`SlotState::confirmed`]) is either promoted or
    /// dropped by `finish_slot`, so no slot reaches a caller of this
    /// still holding one. Mid-run it answers about the binding, which is
    /// what the pre-nomination code answered too.
    pub fn slot_in_set(&self, slot: usize) -> bool {
        matches!(&*self.plan.read_ok(), Plan::Active(_))
            && self.slots[slot].lock_ok().file.is_some()
    }

    /// Did the matcher never reach a VERDICT for this slot - neither a
    /// claim nor the permanent refusal?
    ///
    /// [`Self::slot_in_set`] answers "did it claim". This is the third
    /// state, and the reason it needs a name of its own is that the two
    /// look identical from outside and mean opposite things. A slot that
    /// claimed nothing has either been JUDGED - name tiers tried, the
    /// md5-16k head hashed, nothing matched, `unmatchable` latched - or
    /// never been in a position to be judged at all, because the head
    /// never completed. `head_want()` is min(16 KiB, declared length), so
    /// losing ANY article covering the first 16k leaves the md5-16k tier
    /// with nothing to hash, the latch unset, and the slot silently
    /// undecided for the rest of the run.
    ///
    /// Settle's obfuscated-alias reconciliation is the caller: it pairs a
    /// slot that never claimed a FileDesc against a set member parity
    /// rebuilt whole, and used to admit only a slot that arrived NOTHING
    /// on the reasoning that a slot which wrote bytes had a yEnc name to
    /// claim with and did not. That reasoning holds only where the
    /// matcher DECIDED; this is how that caller tells the two apart.
    ///
    /// True is never on its own evidence of anything - it says the
    /// matcher has no opinion, so the caller still owes its own proof
    /// (settle's is the set having rebuilt and MD5-proved the member,
    /// plus a declared-size band). `false` when no set is active: with no
    /// set there is no matcher and so no verdict to be missing.
    pub fn slot_undecided(&self, slot: usize) -> bool {
        if !matches!(&*self.plan.read_ok(), Plan::Active(_)) {
            return false;
        }
        let s = self.slots[slot].lock_ok();
        // The RAW latch and not `refused`, deliberately. This asks
        // whether a verdict was ever reached, not whether it is still
        // about the population now live, and by the time the only
        // caller runs every latch is current: `get::settle` activates
        // any deferred set BEFORE `settle_slots`, and `finish_slot`
        // re-runs the tiers for a slot whose refusal that activation
        // staled and re-latches it at the new generation. Reading
        // `refused` here would instead report a slot the matcher HAS
        // judged as one it has no opinion on, which is the one thing
        // this predicate's own doc says it must not do.
        s.file.is_none() && s.unmatchable.is_none()
    }

    /// Every adopted recovery set, in the order [`pick_sets`] fixed
    /// (largest first, ties by set id). Empty when no set is active.
    ///
    /// There is deliberately no `set()` singular any more: TODO 311's
    /// defect was four call sites each holding one set and each silently
    /// meaning "the post's set". A caller that genuinely wants ONE - the
    /// damage projection needs a block size to state a figure in blocks
    /// at all - takes `sets().first()` and says why at the site.
    pub fn sets(&self) -> Vec<Arc<Par2Set>> {
        match &*self.plan.read_ok() {
            Plan::Active(a) => a.sets.clone(),
            _ => Vec::new(),
        }
    }

    /// Live bad blocks so far, charged to the set whose parity can heal
    /// them - indexed the way [`Self::sets`] is, empty when no set is
    /// active.
    ///
    /// [`live_counts`](Self::live_counts) answers the JOB's total, which
    /// is the right figure for a dashboard gauge and the wrong one for a
    /// margin. The §146 tail give-up and the par-race both price a trade
    /// per set - set 3's parity rebuilds set 3's damage and nothing
    /// else - so charging a set the whole post's bad-block count on a
    /// per-file-set post inflates every set's ceiling by its siblings'
    /// damage and the margin never clears. Same predicate settle charges
    /// its own damage with, [`slot_set`](Self::slot_set), so the two
    /// cannot drift.
    ///
    /// A slot no set claimed contributes to nothing: its blocks are
    /// outside every adopted set, so no parity on hand rebuilds them.
    pub fn live_bad_by_set(&self) -> Vec<u64> {
        let plan = self.plan.read_ok();
        let Plan::Active(a) = &*plan else {
            return Vec::new();
        };
        let mut out = vec![0u64; a.sets.len()];
        for slot in &self.slots {
            let s = slot.lock_ok();
            if let Some(fi) = s.file {
                out[a.set_of(fi)] += s.live_bad;
            }
        }
        out
    }

    /// Which adopted set claimed this slot's file, as an index into
    /// [`Self::sets`]. `None` when no set is active or the slot matched
    /// nothing.
    ///
    /// Settle needs it to charge a slot's bad blocks to the set whose
    /// parity can heal them: on a per-file-set post every set has its own
    /// recovery volumes, so "how much damage is there" is a question per
    /// set and never per job.
    pub fn slot_set(&self, slot: usize) -> Option<usize> {
        match &*self.plan.read_ok() {
            Plan::Active(a) => self.slots[slot].lock_ok().file.map(|fi| a.set_of(fi)),
            _ => None,
        }
    }

    /// Sets OTHER than this slot's owning one that describe the SAME
    /// file, with `bad` restated in each one's own block geometry:
    /// `(set index, damaged block count there)`.
    ///
    /// W4-15. Damage is charged per SET because repair is per set, and a
    /// slot has exactly one owning descriptor - so where two overlapping
    /// sets name one member, the set that did NOT win the binding
    /// charged zero and never spent the parity it was holding. Measured:
    /// two active sets over one damaged 200 KB member, the weak one
    /// (1 recovery block) owning it and the strong one (8) sitting idle,
    /// and the job failed with `2 block(s) damaged, only 1 recovery
    /// block(s) on disk` while five usable volumes lay on disk beside
    /// it. Which set owns the slot is decided by the in-stream arrival
    /// race; which set can HEAL it is not, so the damage is told to
    /// both and whichever has the parity repairs.
    ///
    /// Identity is `(length, md5_16k, whole-file md5)` - the same test
    /// `try_match` uses to tell one file described twice from two files
    /// sharing a head. Block indices are mapped through BYTE RANGES
    /// rather than rescaled, because the two sets rarely share a block
    /// size (10000 against 10004 in the fixture) and a count scaled by
    /// a ratio is not a count of anything.
    pub fn slot_twin_damage(&self, slot: usize, bad: &[usize]) -> Vec<(usize, usize)> {
        let plan = self.plan.read_ok();
        let Plan::Active(a) = &*plan else {
            return Vec::new();
        };
        let Some(flat) = self.slots[slot].lock_ok().file else {
            return Vec::new();
        };
        if bad.is_empty() {
            return Vec::new();
        }
        let owner = a.set_of(flat);
        let f = a.file(flat);
        let obs = a.block_size(flat).max(1);
        let mut out = Vec::new();
        for (si, set) in a.sets.iter().enumerate() {
            if si == owner {
                continue;
            }
            let Some(t) = set
                .files
                .iter()
                .find(|g| g.length == f.length && g.md5 == f.md5 && g.md5_16k == f.md5_16k)
            else {
                continue;
            };
            let tbs = set.block_size.max(1);
            let mut touched: HashSet<u64> = HashSet::new();
            for &b in bad {
                let start = (b as u64).saturating_mul(obs);
                let end = start.saturating_add(obs).min(t.length);
                if start >= end {
                    continue;
                }
                for k in (start / tbs)..=((end - 1) / tbs) {
                    touched.insert(k);
                }
            }
            if !touched.is_empty() {
                out.push((si, touched.len()));
            }
        }
        out
    }

    /// [`slot_set`](Self::slot_set) for every slot in one pass, under one
    /// plan lock - `None` per slot exactly where the singular answers it.
    ///
    /// The tail give-up re-decides five times a second and needs the
    /// attribution of every slot each tick; asking one at a time retakes
    /// the plan read lock per slot for an answer that cannot change
    /// between two of them.
    pub fn slot_sets(&self) -> Vec<Option<usize>> {
        let plan = self.plan.read_ok();
        let Plan::Active(a) = &*plan else {
            return vec![None; self.slots.len()];
        };
        self.slots
            .iter()
            .map(|s| s.lock_ok().file.map(|fi| a.set_of(fi)))
            .collect()
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
        // W4-11: the yEnc `size=` is a PER-ARTICLE declaration of the
        // WHOLE file's length, so an N-part post carries N copies of it
        // and nothing makes them agree. Latching the first nonzero copy
        // let ARRIVAL ORDER pick which one is authoritative: on a 120 KB
        // obfuscated post one article declaring `size=8192`, decoded
        // first, set `head_want` to 8192, so `head_key` hashed 8 KiB
        // where the FileDesc's md5_16k covers 16 KiB, the slot never
        // bound by content, and an intact file was priced `file missing
        // entirely` - its bytes recovered only by a full-file adoption
        // plus a 2000-block rebuild.
        //
        // A declaration is a claim; the bytes in hand are proof. This
        // span occupies `offset .. offset + len`, which is the article's
        // OWN `=ypart` range (the decoder refuses a part whose payload
        // and range disagree), so a `size=` below it is the same article
        // contradicting itself and is raised rather than believed. Never
        // lowered, and never raised above what some article really
        // carries, so this is a floor on the truth and not a second
        // guess at it - and it is monotone, which is what lets
        // `capture_head` grow rather than restart below.
        let seen_end = offset.saturating_add(data.len() as u64);
        if s.file_size == 0 {
            s.file_size = file_size;
        }
        // Only ever CORRECTS a declaration, never manufactures one:
        // zero means "no article has declared a length", and its
        // `head_want` is the full 16 KiB - the safe answer. Promoting
        // that zero to one span's end would SHRINK the head instead,
        // which is the very defect above. The backfill and disk feeds
        // pass `file_size: 0` for exactly this reason.
        if s.file_size != 0 && s.file_size < seen_end {
            s.file_size = seen_end;
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

        // The head fills for the whole run, bound or not. It stopped at
        // the claim once, which was invisible while a claim was final:
        // now that a name-only binding can be dropped at finish, the slot
        // that is re-matched then needs the head it would otherwise have
        // stopped collecting on its first article.
        s.capture_head(offset, data);
        // The article carrying a file's first 16 KiB may land at any
        // point, and until it does a NAME is all a slot has to bind on.
        // So a tentative binding is re-judged the moment the head
        // completes - which is what makes the crossed-name answer
        // independent of arrival order rather than merely usually right.
        if s.file.is_some() && !s.confirmed {
            self.rejudge_binding(slot, &mut s, active);
        }
        if s.file.is_none() {
            if s.refused(active) || !s.try_match(slot, active, true) {
                return;
            }
            // §94 B: a fresh claim engages the gate - from here the chase
            // decode for this slot waits on verification. A TENTATIVE
            // binding engages too: engaging is the conservative side (it
            // makes the chase wait), and dropping the binding at finish
            // releases it.
            if let Some(g) = self.gate.lock_ok().clone() {
                g.engage(slot);
            }
        }

        let fi = s.file.unwrap();
        let file = active.file(fi);
        let bs = active.block_size(fi) as usize;
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
        let (set_ix, local_fi) = active.split(fi);
        let set = active.sets[set_ix].clone();
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
        // M4-69: three-valued, so a self-contradicting IFSC entry is
        // told apart from damage. The CRC-only arm can never report one -
        // it never reaches the MD5 - which is exactly right: a CRC-only
        // claim is not evidence about the pair.
        let check: fn(&BlockCheck, usize, &[u8]) -> BlockVerdict = if crc_claims {
            check_block_crc_verdict
        } else {
            check_block_verdict
        };
        let file = &set.files[local_fi];
        let mut results: Vec<(usize, BlockVerdict)> = Vec::with_capacity(full.len() + ready.len());
        for bi in full {
            let bstart = bi as u64 * bs64;
            let blen = block_len(file.length, bs, bi);
            let rel = (bstart - span.start) as usize;
            results.push((bi, check(&file.blocks[bi], bs, &data[rel..rel + blen])));
        }
        // Completed byte partials ALWAYS take full MD5, regardless of what
        // THIS span may claim. A byte partial exists only because some
        // fragment of the block arrived without a wire CRC (the `None` arm
        // allocates bytes exactly when `crc_claims` is false), and the span
        // that happens to finish a block says nothing about the ones that
        // started it - a disk-fed fragment completed by a fresh article
        // would otherwise be claimed on the block CRC32 alone.
        for (bi, buf) in ready {
            results.push((bi, check_block_verdict(&file.blocks[bi], bs, &buf)));
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
            for (bi, v) in results {
                // The BLOCK verdict is unchanged - a contradicted entry
                // still fails the block, which is the safe direction. What
                // the latch changes is what settle does about it (M4-69).
                s.ifsc_self_contradicted |= v == BlockVerdict::Contradicted;
                record(&mut s, bi, v == BlockVerdict::Ok);
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
                    record(&mut s, bi, file.blocks[bi].crc_matches(final_crc));
                }
            }
            // §94 B: every claim above may have extended the contiguous
            // Ok prefix - publish before the slot lock drops so a gated
            // chase parked at the old watermark wakes.
            self.gate_publish(slot, &mut s, bs);
            let earned = !s.confirmed && s.live_ok > 0;
            drop(s);
            if earned {
                self.promote_binding(slot);
            }
        }
    }

    /// An Ok block is content proof, and the first one turns a name's
    /// tentative nomination into a claim ([`SlotState::confirmed`]).
    ///
    /// Its own function, taking the plan and then the slot, because that
    /// is the order `on_data_inner` takes them in and the promotion is
    /// decided at the foot of the span path where the plan lock has been
    /// released for hashing. Taking it back under the slot lock there
    /// would invert the order against every other caller.
    ///
    /// A descriptor the real owner claimed by content in the meantime
    /// simply drops the binding: two slots may nominate the same
    /// descriptor precisely because a nomination locks nobody out.
    fn promote_binding(&self, slot: usize) {
        let plan = self.plan.read_ok();
        let Plan::Active(active) = &*plan else {
            return;
        };
        let mut s = self.slots[slot].lock_ok();
        let Some(fi) = s.file else {
            return;
        };
        if s.confirmed || s.live_ok == 0 {
            return;
        }
        let mut claimed = active.claimed.lock_ok();
        if claimed[fi].is_none() {
            claimed[fi] = Some(slot);
            s.confirmed = true;
            return;
        }
        drop(claimed);
        self.forget_binding(&mut s);
    }

    /// Re-judge a tentative binding once the head has completed.
    ///
    /// The binding is DROPPED only when the head both denies the
    /// nominated descriptor AND names another one outright - a unique
    /// unclaimed md5-16k match. Denial alone is not enough and must not
    /// be: a truthfully-named member damaged inside its own first
    /// 16 KiB denies exactly the same way, and dropping that one would
    /// cost it its in-stream verification and price a repairable file as
    /// wholly missing. What is left after this is the case with no rival
    /// at all, which `settle_binding` settles at finish on the whole
    /// file.
    ///
    /// The blocks verified under the old binding go with it: they were
    /// judged against the wrong descriptor. They are read back at
    /// finish, which is the right price for a slot whose name lied.
    fn rejudge_binding(&self, slot: usize, s: &mut SlotState, active: &Active) {
        let Some(fi) = s.file else {
            return;
        };
        if s.head_rival_ruled_out {
            return;
        }
        let Some(key) = s.head_key() else {
            return;
        };
        let want = s.head_want();
        if head_says(active.file(fi), want, key) != HeadSays::Deny {
            return;
        }
        let (rival, seen) = {
            let claimed = active.claimed.lock_ok();
            let (mut hit, mut seen) = (None, 0usize);
            for (gi, g) in active.files() {
                if gi == fi || claimed[gi].is_some() {
                    continue;
                }
                if head_says(g, want, key) == HeadSays::Confirm {
                    seen += 1;
                    hit = if seen == 1 { Some(gi) } else { None };
                }
            }
            (hit, seen)
        };
        let Some(_) = rival else {
            s.head_rival_ruled_out = seen == 0;
            return;
        };
        self.forget_binding(s);
        s.try_match(slot, active, true);
    }

    /// [`SlotState::unbind`] plus the global wind-back it owes.
    fn forget_binding(&self, s: &mut SlotState) {
        use std::sync::atomic::Ordering;
        let (ok, bad, held) = s.unbind();
        self.live_ok_total.fetch_sub(ok, Ordering::Relaxed);
        self.live_bad_total.fetch_sub(bad, Ordering::Relaxed);
        self.partials_used.fetch_sub(held, Ordering::Relaxed);
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

    /// Drop every in-stream Ok verdict for a slot back to Pending so the
    /// next [`finish_slot`] re-hashes those blocks from the bytes actually
    /// on disk. Settle calls this for a slot whose writer saw an
    /// overlapping write ([`crate::extract::Extractor::slot_had_rewrite`]):
    /// an in-stream Ok proves the bytes that WERE hashed, not the bytes on
    /// disk now, and a maliciously-duplicated article can overwrite a
    /// verified block after it was marked Ok. Re-hashing from disk is the
    /// authority in that case - a legitimate identical duplicate re-hashes
    /// clean, a conflicting one is caught as damage. Bad verdicts are left
    /// as-is (already scheduled for read-back/repair).
    pub fn force_readback(&self, slot: usize) {
        let mut s = self.slots[slot].lock_ok();
        // Reset EVERY settled verdict, Ok and Bad alike: the final bytes on
        // disk are whichever write landed last, so an earlier Ok may now be
        // garbage and an earlier Bad may now be the good copy. Re-hashing
        // the whole slot from disk is the only authority once a range was
        // written twice - it recovers the good-copy-last case and catches
        // the garbage-last case, deterministically.
        for st in s.blocks.iter_mut() {
            *st = BlockState::Pending;
        }
        s.ok_prefix = 0;
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
        // A binding the NAME alone made earns its claim here, on content,
        // or is dropped - and a drop puts the slot back through the whole
        // ladder below with the file now available.
        let dropped = s.file.is_some() && !s.confirmed && !s.settle_binding(slot, active, &src);
        if dropped {
            self.forget_binding(&mut s);
        }
        // Last-chance match (e.g. every article of the slot arrived before
        // activation, so on_data never ran while Active). The whole-file
        // and named tiers run only here, never in on_data: both need the
        // slot's complete bytes, and finish is the first moment they
        // exist. Order is strongest evidence first - head-confirmed name
        // or unique md5-16k, then whole-file MD5 among identical-head
        // twins, then a name the head denied or never judged, which is
        // the weakest and must not pre-empt either of the others.
        if s.file.is_none()
            && !s.refused(active)
            && (s.try_match(slot, active, false)
                || s.try_match_whole(slot, active, &src)
                || s.try_match_named(slot, active, &src))
            && let Some(g) = self.gate.lock_ok().clone()
        {
            g.engage(slot);
        }
        if s.file.is_none() {
            if dropped && let Some(g) = self.gate.lock_ok().clone() {
                // The dropped binding had engaged the gate and nothing
                // will verify this slot now: release whatever chase is
                // parked on it, the way the no-IFSC verdict does. The
                // chase then demotes to the disk ladder, which is
                // bounded where a parked reader is not.
                g.advance(slot, u64::MAX);
            }
            return None;
        }
        let fi = s.file?;
        let file = active.file(fi);
        let bs = active.block_size(fi) as usize;

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
                let v = if bs <= READBACK_CHUNK {
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
                    if got {
                        check_block_verdict(&file.blocks[bi], bs, &buf[..blen])
                    } else {
                        // Unreadable is damage, never a contradiction:
                        // no digest was compared.
                        BlockVerdict::Damaged
                    }
                } else {
                    read_block_chunked(&src, f.as_ref(), bi as u64 * bs as u64, blen, &mut buf)
                        .map_or(BlockVerdict::Damaged, |c| c.finish(&file.blocks[bi], bs))
                };
                s.ifsc_self_contradicted |= v == BlockVerdict::Contradicted;
                s.blocks[bi] = if v == BlockVerdict::Ok {
                    BlockState::Ok
                } else {
                    BlockState::Bad
                };
            }
            // §94 B: settle read-back claims advance the watermark too.
            self.gate_publish(slot, &mut s, bs);
        }
        for (bi, st) in s.blocks.iter().enumerate() {
            if *st == BlockState::Bad {
                bad.push(bi);
            }
        }
        // TWO reasons a file's block grid cannot settle it, one action.
        // Both were measured on 30 Aug 2026 and both end the same way: no
        // block-level claim may outrank the FileDesc whole-file MD5,
        // which covers every byte of every block, so where it matches the
        // settled file IS the file the set describes.
        //
        // A grid fitted from a SHORT IFSC (`par2::fit_ifsc`) carries
        // slices the set never described. Nothing can satisfy them, so
        // they read Bad forever and the block tier alone would price a
        // byte-perfect file as damaged - and a post with no recovery
        // volumes would then fail a download that is entirely fine. That
        // arm fires only when nothing PROVEN failed: a proven failure has
        // already settled the question and the MD5 could only agree.
        //
        // M4-69 is the other, and its blocks ARE proven, which is why the
        // two conditions are an OR and not one test. An IFSC entry that
        // contradicts ITSELF - the CRC32 matched and the MD5 did not -
        // describes two different blocks and so describes neither; it is
        // an unusable entry rather than a report of damage. Without this a
        // byte-exact post whose block MD5s were forged reported 100%
        // damage and spent a full reconstruct on intact bytes, or failed
        // Unrepairable when the parity fell short. It costs one read of a
        // file already on its way into a repair that reads it anyway, and
        // only ever on a set whose own packets contradict each other:
        // ordinary damage fails the CRC, and the latch needs a CRC that
        // MATCHED.
        //
        // THE THIRD is M4-69's own stated limit, closed 31 Aug 2026 and
        // narrower than the two above BECAUSE IT IS NOT FREE. The mirror
        // shape - honest block MD5s beside a LYING CRC32 - fails every
        // block on the CRC, so nothing latches and no digest disagreed
        // with itself. Measured end to end that day, and worse than the
        // row predicted: with 20% redundancy a byte-exact download is
        // reported `2000/2000 blocks bad` and the JOB FAILS
        // `unrepairable: 2000 blocks needed, only 400 recovery blocks`,
        // in the DEFAULT configuration - in-stream fast verify is
        // CRC32-only, so the lying half is the only half it reads.
        //
        // It fires on the ONE shape whose price is bounded by what it
        // prevents: EVERY block of the file is bad. Acting on that claim
        // is a full-file recovery fetch and reconstruct, or the failure
        // above; one pass over the file to refute it is cheaper than
        // either. On PARTIAL damage the arithmetic inverts - the hash
        // still scales with the FILE while the spend it saves scales
        // with the DAMAGE - which is why this is not "hash any damaged
        // file", and why the mirror stays uncovered there.
        //
        // A COUNT OF BAD BLOCKS AND NOTHING FINER, deliberately. The
        // first cut screened on `live_bad` instead, to hold out a file
        // nothing arrived for, and it was LOAD-DEPENDENT - the partials
        // budget spills under memory pressure, so the trigger stopped
        // firing on a busy box. What it was guarding is unreachable
        // anyway: `settle_binding` drops a binding no content tier
        // earned. Both measurements, and the residue this does pay for,
        // are with the pin in `live/ifsc_contra_tests.rs`.
        //
        // THE READ CANNOT PARK, which matters because this arm makes
        // `src_md5` reachable far more often than the two above did: a
        // mapped or chased slot is read through `Extractor::read_at`,
        // which preads, and never the frontier's
        // `read_covered_blocking`, whose gate an all-bad file would wait
        // on forever. Checked 31 Aug 2026; see the pins.
        //
        // A MISS leaves the block report exactly as it stood - the file
        // really is wrong, and which blocks to rebuild is still the best
        // guess available.
        //
        // Clearing it releases the §94 B chase gate too, for the reason
        // the no-IFSC branch above releases its own: the watermark stops
        // at the first non-Ok block, and here that block is one no
        // evidence will ever advance, so a frontier reader waiting past
        // it would block until `chase_finish` joined the worker. The MD5
        // just proved every byte of this file, so `u64::MAX` is the
        // truth and not a concession.
        if !bad.is_empty()
            && (s.ifsc_self_contradicted
                || bad.iter().all(|&bi| !file.blocks[bi].is_proven())
                || bad.len() == file.blocks.len())
            && src_md5(&src, file.length).is_ok_and(|md5| md5 == file.md5)
        {
            readback += 1;
            if s.ifsc_self_contradicted {
                tracing::warn!(
                    target: "verify",
                    "{}: IFSC entries contradict themselves ({} of {} blocks) and \
                     the whole-file MD5 matches - the file is intact and the block \
                     checksums are not usable",
                    file.name,
                    bad.len(),
                    file.blocks.len()
                );
            } else if bad.len() == file.blocks.len() {
                // Said out loud rather than silently cleared: this arm
                // turns a report of total damage into a clean file, so
                // the run log has to carry why.
                tracing::warn!(
                    target: "verify",
                    "{}: all {} block(s) failed their IFSC checksums and the \
                     whole-file MD5 matches - the file is intact and the block \
                     checksums do not describe it",
                    file.name,
                    file.blocks.len()
                );
            }
            bad.clear();
            for st in s.blocks.iter_mut() {
                *st = BlockState::Ok;
            }
            self.gate_publish(slot, &mut s, bs);
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
    ///
    /// A name some OTHER descriptor DID claim is not unclaimed. That
    /// only arises once several sets are adopted (TODO 311): two sets
    /// naming the same file give two flat entries, a slot can claim just
    /// one of them, and the leftover would otherwise be reported "missing
    /// entirely" and sent to repair to recreate a file already sitting on
    /// disk. The single-set world had one descriptor per name and so
    /// could not express the question; this keeps the answer it gave.
    pub fn unclaimed_files(&self) -> Vec<String> {
        match &*self.plan.read_ok() {
            Plan::Active(a) => {
                let claimed = a.claimed.lock_ok();
                let taken: std::collections::HashSet<&str> = claimed
                    .iter()
                    .enumerate()
                    .filter(|(_, c)| c.is_some())
                    .map(|(i, _)| a.file(i).name.as_str())
                    .collect();
                claimed
                    .iter()
                    .enumerate()
                    .filter(|(i, c)| c.is_none() && !taken.contains(a.file(*i).name.as_str()))
                    .map(|(i, _)| a.file(i).name.clone())
                    .collect()
            }
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
            head_md5: None,
            file_size: 0,
            file: None,
            confirmed: false,
            head_rival_ruled_out: false,
            blocks: Vec::new(),
            partials: HashMap::new(),
            partial_bytes: 0,
            pre_spans: Vec::new(),
            resume_seeded: false,
            pre_unvouched: false,
            unmatchable: None,
            live_ok: 0,
            live_bad: 0,
            ok_prefix: 0,
            ifsc_self_contradicted: false,
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
            // file_size learned after the first capture changed `want`.
            //
            // NEITHER DIRECTION MAY DISCARD A BYTE, and that is one rule
            // rather than two cases: every byte in this buffer was
            // written at the file offset its own article declared, so
            // the buffer is always a true PREFIX of the file and a
            // prefix stays true whatever the length turns out to be.
            // What changes is only how much of it the digest covers.
            if want > head.buf.len() {
                // GROW, never restart, when `want` only got bigger -
                // which since W4-11 is the ordinary case: a later
                // article disproves an under-declared `size=` and the
                // head this slot needs gets longer. The bytes already
                // captured are still the file's FIRST bytes and their
                // intervals still describe them, so discarding them
                // would strand a slot whose offset-0 article has already
                // been consumed and can never be re-fed - the head would
                // then never complete and the content tier would be dead
                // for that slot for the rest of the run.
                head.buf.resize(want, 0);
            } else {
                // M4-94: SHRINK, which the grow arm above cannot reach
                // and which restarted from empty until 31 Aug 2026 -
                // "rare, only when the very first article lacked a
                // size" was the note on it, and that is precisely the
                // shape it broke. `file_size` is monotone once nonzero
                // (W4-11 raises it, never lowers it), so the only way
                // `want` gets SMALLER is the 0 -> nonzero latch: an
                // article omitting `size=` captures its bytes under the
                // full 16 KiB `want`, and the first article to declare a
                // length below that shrinks it. The restart threw those
                // offset-0 bytes away, and the offset-0 article has by
                // then been consumed and can never be re-fed - so the
                // head never completed again, `head_key` stayed `None`
                // for the rest of the run, and the md5-16k tier (the
                // ONLY identity an obfuscated post has) was dead for
                // that slot. Measured on an INTACT 20 KB file whose
                // second article declared 8192: unclaimed, where the
                // same spans with honest sizes claim.
                //
                // Truncation is what the prefix argument above buys:
                // bytes 0..want are already the right bytes, and the
                // intervals are clipped to match. `filled` is sorted and
                // merged, and clipping a sorted merged list to a prefix
                // keeps it sorted and merged, so `complete()` still
                // recognises a filled head as the single span
                // `[(0, want)]`.
                //
                // The head is NOT held at a high-water mark instead:
                // PAR2's `md5_16k` covers the first 16 KiB OR THE WHOLE
                // FILE IF SHORTER, so a genuinely 5000-byte file must
                // hash exactly 5000 bytes. A `want` that refused to
                // shrink would hash 5000 real bytes plus 11384 zeros and
                // match nothing, which trades this defect for a wider
                // one.
                head.truncate(want);
            }
            // The cached digest described the OLD span. Leaving it would
            // let `head_key` answer about bytes this slot no longer holds,
            // and the rival latch is an answer ABOUT that digest.
            self.head_md5 = None;
            self.head_rival_ruled_out = false;
            // ...and so is the permanent refusal, which is the half W4-11
            // turned up. `unmatchable` means "this head, hashed whole,
            // matched no descriptor"; a head that has just got LONGER is
            // not that head, and the digest the refusal was reached on no
            // longer exists. Left latched it froze the slot for the rest
            // of the run - `on_data` returns before matching and
            // `finish_slot` skips the whole-file and named tiers too - so
            // an under-declared `size=` on the article that happened to
            // arrive first was a permanent verdict about a file that was
            // merely described short. Cleared here rather than weakened
            // at the latch site so every slot whose head never changes
            // keeps exactly the behaviour it had.
            self.unmatchable = None;
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

    /// The MD5 of this slot's captured head, once the head is COMPLETE -
    /// the content key every name tier is arbitrated by. `None` means
    /// "no evidence yet", never "no evidence ever": the head fills
    /// interval-wise, so a slot whose first article has not landed
    /// simply has not been judged.
    ///
    /// Cached because an unmatched slot re-matches on every article and a
    /// denied name never becomes matchable, so the digest would otherwise
    /// be recomputed per article for the whole run.
    fn head_key(&mut self) -> Option<[u8; 16]> {
        if self.head_md5.is_some() {
            return self.head_md5;
        }
        let want = self.head_want();
        if want == 0 {
            return None;
        }
        let h = self.head.as_ref()?;
        if h.buf.len() != want || !h.complete() {
            return None;
        }
        self.head_md5 = Some(Md5::digest(&h.buf).into());
        self.head_md5
    }

    /// Is this slot's permanent refusal still ABOUT the descriptors now
    /// live?
    ///
    /// Every site that skips a match tier because the slot "will never
    /// match" asks this rather than reading the field, because a refusal
    /// reached before a second recovery set was adopted is a refusal
    /// about descriptors that are no longer the whole of what there is
    /// to match against. [`Active::adopted_gen`] moves exactly when the
    /// adopted set list grows, so a stale latch re-opens the slot for one
    /// more pass and [`try_match`](Self::try_match) re-latches it at the
    /// current generation if the answer has not changed.
    fn refused(&self, active: &Active) -> bool {
        self.unmatchable == Some(active.adopted_gen)
    }

    /// Try to claim a PAR2 file for this slot. Name NOMINATES, content
    /// FINALIZES; md5-16k second. Requires `self.file.is_none()`.
    ///
    /// A NAME IS A NOMINATION AND NEVER A PROOF (W4-02, 30 Aug 2026).
    /// The exact tier used to `find` the first unclaimed descriptor with
    /// a matching name and claim it on the spot, ahead of every content
    /// tier. yEnc names are attacker- and poster-controlled, so that made
    /// three measured failures out of one seam: two intact payloads whose
    /// yEnc names are CROSSED each claimed the other's descriptor and both
    /// verified 1000/1000 blocks bad, so an intact post died unrepairable
    /// at r=10; two descriptors sharing one exact name with distinct
    /// content were settled by FileDesc order, which is arrival-order
    /// dependent and paid a full phantom repair on the losing run; and an
    /// UNCOVERED file posted honestly under a name the set also uses was
    /// claimed by the set, verified all-bad and failed the whole job.
    ///
    /// So the head key arbitrates every name candidate:
    ///   * exactly one candidate CONFIRMED by the head - claim it;
    ///   * several confirmed (identical heads) - the first, bound
    ///     TENTATIVELY, since a shared 16 KiB head is not a shared file;
    ///   * none confirmed but exactly one INCOMPARABLE (the descriptor's
    ///     `md5_16k` covers a different span than this slot's head, so the
    ///     digests can never be equal and the head is silent about it) -
    ///     claim it, which is the pre-W4-02 answer for that shape;
    ///   * every candidate DENIED - decline, and let the md5-16k tier
    ///     below find the descriptor the content actually names.
    /// A DENIAL NEVER LATCHES `unmatchable`: a truthfully-named file
    /// damaged inside its own first 16 KiB denies too, and
    /// [`try_match_named`](Self::try_match_named) settles that one at
    /// finish on per-block IFSC evidence.
    ///
    /// Nothing here throws the nomination away. What the head has not
    /// settled is bound TENTATIVELY instead (see
    /// [`SlotState::confirmed`]): the first candidate while the head is
    /// still filling, the sole candidate the head denied. The slot
    /// verifies its blocks against it exactly as a claim would, so
    /// out-of-order arrival still costs zero read-back and the ordinary
    /// post is untouched - but it takes no claim, so a crossed pair
    /// locks nothing out and each slot's md5-16k tier still finds the
    /// descriptor its CONTENT names. The first Ok block promotes the
    /// binding to a claim; the head completing RE-JUDGES it
    /// ([`LiveVerifier::rejudge_binding`]), which is what makes the
    /// crossed answer independent of which article landed first; and one
    /// that never earns a promotion is settled at finish by
    /// [`settle_binding`](Self::settle_binding).
    ///
    /// `tentative` is false at finish: by then the whole file is
    /// available, so a nomination is either proved or dropped and there
    /// is nothing left for a provisional binding to wait for.
    fn try_match(&mut self, slot: usize, active: &Active, tentative: bool) -> bool {
        let head_key = self.head_key();
        let mut claimed = active.claimed.lock_ok();

        let mut name_ambiguous = false;
        let mut nominee: Option<usize> = None;
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
                    crate::disk::sanitize_out_name(name),
                )
            });
            let folded: &[usize] = active.by_fold.get(fold.as_str()).map_or(&[], |v| v);
            let sanit: &[usize] = active.by_sanitized.get(sname.as_str()).map_or(&[], |v| v);
            let exact: Vec<usize> = folded
                .iter()
                .copied()
                .filter(|&fi| claimed[fi].is_none() && active.file(fi).name == **name)
                .collect();
            // Approximate (case-folded or sanitized) only when the exact
            // tier produced NO candidate at all, and only when it is
            // UNIQUE among the unclaimed descriptors. Two candidates is
            // ambiguity, not a choice for FileDesc order to make: leave
            // the slot unclaimed and let the md5-16k fallback below
            // settle it by content. The two sorted candidate lists are
            // merge-walked with dedup so a descriptor matching both keys
            // counts once, in FileDesc order - identical answers to the
            // pre-index linear drain (`try_match_linear`, kept below as
            // the test oracle). An exact candidate the head DENIED does
            // not fall through to here: a case-folded name is weaker
            // evidence than the exact one the content just refused, so
            // the content tiers own the slot from that point.
            //
            // `try_match_linear` in live/matchref.rs mirrors this whole
            // tier; the differential tests hold the two to the same
            // answers, `confirmed` included.
            let cands: Vec<usize> = if !exact.is_empty() {
                exact
            } else {
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
                first.into_iter().collect()
            };
            let want = self.head_want();
            let hit = arbitrate_by_head(&cands, active, want, head_key);
            if hit.is_none() && !cands.is_empty() {
                // Confirmed-plural, denied, or waiting on the head: all
                // three are "not yet", never "never" (see the fn note).
                name_ambiguous = true;
                // The tentative nominee, taken below only if the
                // content tiers find nothing better. With NO head yet
                // the first candidate is taken however many there are -
                // that is the pre-nomination answer, and it is safe
                // again because the binding is tentative: the head
                // completing re-judges it (`rejudge_binding`) and moves
                // it to the descriptor the content names, so FileDesc
                // order no longer DECIDES anything (W4-02B). With a head
                // that denied every candidate there is nothing to
                // re-judge, so a sole candidate is the only one worth
                // verifying against.
                nominee = if head_key.is_none() {
                    cands.first().copied()
                } else if cands.len() == 1 {
                    Some(cands[0])
                } else {
                    None
                };
            }
            if let Some((fi, sure)) = hit {
                if sure {
                    claimed[fi] = Some(slot);
                }
                self.file = Some(fi);
                self.confirmed = sure;
                self.blocks = vec![BlockState::Pending; active.file(fi).blocks.len()];
                return true;
            }
        }
        // md5-16k fallback (obfuscated names). UNIQUE among the unclaimed
        // descriptors, same rule as the approximate name tier above: two
        // same-length files sharing an identical first 16 KiB (zero-filled
        // heads - padded VOBs, disk images) both match both descriptors,
        // and taking the first hit made WHICH slot claimed which a
        // worker-thread race (matrix finding F1, measured 29 Aug 2026:
        // crossed ~1 run in 5 on a loaded box; at r=10 the crossed pairing
        // reads every differing block as damage and FAILS an intact post).
        // Declined ambiguity resolves later: a twin's claim makes the
        // remaining candidate unique on retry, and `try_match_whole` at
        // finish settles what is left by whole-file MD5.
        let want = self.head_want();
        let mut head_ambiguous = false;
        if want > 0
            && self
                .head
                .as_ref()
                .is_some_and(|h| h.buf.len() == want && h.complete())
        {
            let head_md5: [u8; 16] = Md5::digest(&self.head.as_ref().unwrap().buf).into();
            let mut hit: Option<usize> = None;
            for (fi, f) in active.files() {
                if claimed[fi].is_some() || f.length.min(HEAD_LEN as u64) != want as u64 {
                    continue;
                }
                if f.md5_16k != head_md5 {
                    continue;
                }
                match hit {
                    None => hit = Some(fi),
                    // W4-15: ONE FILE DESCRIBED BY TWO RECOVERY SETS IS
                    // NOT TWO FILES. The rivalry this tier declines on is
                    // two DIFFERENT files that happen to share a 16 KiB
                    // head - zero-filled heads, padded VOBs - and what
                    // makes them different is the whole-file MD5. Two
                    // descriptors agreeing on the length AND that MD5
                    // describe the same bytes, which is the ordinary
                    // shape of a post carrying two overlapping sets over
                    // one member. Declining there cost the whole row:
                    // with both sets live the payload matched two entries
                    // and neither, the slot stayed unclaimed, and a
                    // 4-block loss on an intact-but-damaged file was
                    // priced WHOLLY MISSING - `try_match_whole` cannot
                    // rescue it either, because a damaged file matches
                    // no candidate's whole-file MD5 at all.
                    //
                    // Safe where claiming a real twin by elimination is
                    // not (see `try_match_whole`'s note): the objection
                    // there is that settle could publish this slot's
                    // bytes under the OTHER file's name, and here the
                    // other descriptor declares the same length and the
                    // same content hash, so there is no other file to be
                    // wrong about.
                    Some(h) if active.file(h).length == f.length && active.file(h).md5 == f.md5 => {
                        continue;
                    }
                    Some(_) => {
                        head_ambiguous = true;
                        hit = None;
                        break;
                    }
                }
            }
            if let Some(fi) = hit {
                claimed[fi] = Some(slot);
                self.file = Some(fi);
                self.confirmed = true;
                self.blocks = vec![BlockState::Pending; active.file(fi).blocks.len()];
                return true;
            }
            // Head is complete and matched nothing: if the name also failed,
            // this slot will never match (nfo/sfv/sample files). NOT when
            // EITHER tier declined on ambiguity - those candidates are real,
            // and a later claim by the twin slot makes the match unique.
            // Latching here froze the slot forever and downgraded a
            // patchable file to wholly-missing (found by the 14 Aug sweep).
            if self.name.is_some() && !name_ambiguous && !head_ambiguous {
                self.unmatchable = Some(active.adopted_gen);
            }
        }
        // Nothing the content vouches for. Bind the name's sole nominee
        // TENTATIVELY so the slot keeps verifying in-stream, and let the
        // blocks say whether the name told the truth.
        if tentative
            && let Some(fi) = nominee
            && claimed[fi].is_none()
        {
            self.file = Some(fi);
            self.confirmed = false;
            self.blocks = vec![BlockState::Pending; active.file(fi).blocks.len()];
            return true;
        }
        false
    }

    /// Drop a tentative binding and everything measured under it,
    /// returning the (ok, bad, partial bytes) it discards.
    ///
    /// The block states, the live counts and the watermark prefix were
    /// all judged against a descriptor this slot turns out not to be, so
    /// none of them means anything now. The PARTIALS have to go with
    /// them and not merely be forgotten: they are keyed by BLOCK INDEX,
    /// and the next descriptor this slot binds has its own block size,
    /// so a surviving entry would be handed to a block it holds no bytes
    /// of. The caller winds the returned figures out of the GLOBAL
    /// counters too - the live gauge would otherwise keep the phantom
    /// damage a lying name produced, and the partials budget would hold
    /// headroom for memory that is gone. Idempotent: a second call
    /// discards nothing.
    fn unbind(&mut self) -> (u64, u64, usize) {
        self.file = None;
        self.confirmed = false;
        self.blocks = Vec::new();
        self.ok_prefix = 0;
        // The latch is a statement about a DESCRIPTOR's entries, so it
        // goes with the binding it was made against (M4-69). Carrying it
        // to the next descriptor would cost a whole-file MD5 the honest
        // set beside it never asked for; it could never make a wrong
        // verdict, since the MD5 comparison is what gates the
        // escalation, only a wasted read.
        self.ifsc_self_contradicted = false;
        self.partials.clear();
        (
            std::mem::take(&mut self.live_ok),
            std::mem::take(&mut self.live_bad),
            std::mem::take(&mut self.partial_bytes),
        )
    }
}

/// What a slot's complete-head digest says about one name candidate.
///
/// `Unknown` is NOT a soft no: the descriptor's `md5_16k` covers
/// `min(16 KiB, its own length)` bytes and the slot's head covers
/// `min(16 KiB, the yEnc-declared size)`, so when those spans differ the
/// two digests can never be equal however right the name is. Comparing
/// them anyway would read "the poster's size header disagrees with the
/// FileDesc" as "this file is an impostor".
#[derive(PartialEq)]
enum HeadSays {
    Confirm,
    Deny,
    Unknown,
}

fn head_says(f: &crate::par2::Par2File, want: usize, key: [u8; 16]) -> HeadSays {
    if f.length.min(HEAD_LEN as u64) != want as u64 {
        HeadSays::Unknown
    } else if f.md5_16k == key {
        HeadSays::Confirm
    } else {
        HeadSays::Deny
    }
}

/// Arbitrate name candidates by the slot's head digest - the shared rule
/// behind both matchers' name tiers, so the indexed and linear drains
/// cannot drift on it. `Some((fi, true))` is a CLAIM, `Some((fi, false))`
/// a tentative binding, and `None` a DECLINE - never "unmatchable":
/// every path to it is resolvable later, by a twin's claim, by the
/// whole-file tier, or by [`SlotState::try_match_named`] at finish.
///
/// `key` is `None` while the head is still filling. The name tier then
/// claims NOTHING - a name is a nomination and the evidence that
/// finalizes it has not arrived. See [`SlotState::try_match`] for the
/// three measured crossings that rule exists for.
///
/// SEVERAL candidates confirming is the duplicate POSTING: one file in
/// two recovery sets, which is what a poster running par2create twice
/// over a directory emits, and the everyday per-file-set shape. Their
/// heads agree because their bytes do, so the first is taken - but
/// TENTATIVELY, because a shared 16 KiB head is not a shared file and
/// the blocks are what tell two of them apart. The first Ok block
/// promotes it in the same call for the duplicate-posting case, and a
/// pairing the blocks refuse is dropped at finish for the whole-file
/// tier to settle (matrix finding F1's rule, reached through a name).
fn arbitrate_by_head(
    cands: &[usize],
    active: &Active,
    want: usize,
    key: Option<[u8; 16]>,
) -> Option<(usize, bool)> {
    let key = key?;
    let mut confirm: Option<usize> = None;
    let mut unknown: Option<usize> = None;
    let (mut n_confirm, mut n_unknown) = (0usize, 0usize);
    for &fi in cands {
        match head_says(active.file(fi), want, key) {
            HeadSays::Confirm => {
                n_confirm += 1;
                confirm.get_or_insert(fi);
            }
            HeadSays::Unknown => {
                n_unknown += 1;
                unknown.get_or_insert(fi);
            }
            HeadSays::Deny => {}
        }
    }
    if n_confirm > 0 {
        return confirm.map(|fi| (fi, n_confirm == 1));
    }
    if n_unknown == 1 {
        return unknown.map(|fi| (fi, true));
    }
    None
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

/// A source of file bytes for read-back settling.
pub enum ReadAt<'a> {
    /// No backing data at all (file never created).
    Missing,
    /// An ordinary file on disk.
    Path(&'a Path),
    /// Reconstructed bytes (direct-extracted volumes): read `buf.len()`
    /// bytes at the given offset.
    ///
    /// CONTRACT, and it is load-bearing rather than a nicety: a range
    /// the source cannot FULLY serve must come back as `Err`. Never a
    /// short read, never zero padding, never a panic. `src_md5` has no
    /// `metadata()` to ask how long a closure is, so it asks by reading
    /// one byte past the descriptor's end - a source that answers `Ok`
    /// there is longer than the descriptor and is not its file (M4-41).
    /// A source that pads instead would fail every healthy slot; one
    /// that panics takes the process with it. `Extractor::read_at` -
    /// the one production reader - returns `nofile()` from every mode
    /// for a range it cannot cover, which is what makes the answer mean
    /// what it says.
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
            // M4-42's sibling, M4-41 (30 Aug 2026): the Path arm above
            // refuses a source whose length is not the descriptor's, and
            // this arm used to hash exactly `expect_len` bytes from
            // offset 0 without ever asking how long the source was - so a
            // FileDesc for a PREFIX of a longer mapped or chased buffer
            // whole-file-MATCHED and the suffix bytes vanished into a
            // file the set then called proved. Direct-extracted and
            // chased slots are precisely the ones that take this arm
            // (`get/settle.rs`: `is_mapped(sidx) || is_chased(sidx)`), so
            // M4-09's Path-slot prefix pair being green said nothing
            // about it.
            //
            // A closure has no `metadata()`, so it is asked the only way
            // a closure can be: read one byte at `expect_len`. A source
            // that SERVES that byte spans more than the descriptor
            // describes and is not that descriptor's file.
            // `Extractor::read_at` refuses any range it cannot fully
            // serve - every mode returns `nofile()` rather than padding -
            // which is what makes the answer mean what it says.
            //
            // IT IS ASKED FIRST, and until X5-21 (31 Aug 2026) it was
            // asked LAST, after the whole file had already been hashed -
            // an ordering change and not a rule change, since the
            // verdict either way is the same. What it is worth is the
            // row: the finish-time tiers ask this once per candidate
            // LENGTH over identical-head twins, so a candidate shorter
            // than the bytes that landed cost a full hash of its
            // declared length before the probe threw the answer away.
            // Measured, 24 such candidates over one 32 KiB slot: 665,113
            // bytes for 32,256 of file, 20.6x, and the multiplier is the
            // same over gigabytes. It is not new work - the same call
            // stood at the foot of this arm - it has only stopped being
            // paid for after the fact.
            let mut past = [0u8; 1];
            if r(expect_len, &mut past).is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "length mismatch",
                ));
            }
            // And the OTHER end of the same question, which the probe
            // above cannot answer alone: it refuses a source LONGER than
            // the descriptor and says nothing about a SHORTER one, so an
            // over-declaring descriptor was paid for by hashing the
            // whole covered prefix and failing at the chunk that crossed
            // the end. One byte at `expect_len - 1` settles it, and the
            // two probes together pin the length EXACTLY before a byte
            // is hashed. Measured, 12 over-declaring candidates over one
            // 2 MiB slot: 38,830,093 bytes for 2,113,536 of file, 18.4x,
            // one byte each afterwards. The reader's own error is
            // propagated rather than replaced (X5-21).
            if expect_len > 0 {
                r(expect_len - 1, &mut past)?;
            }
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

/// Parse par2 inputs into EVERY recovery set they describe.
///
/// The ordinary post is one set and comes back as a one-element list.
/// When the inputs mix set ids they are GROUPED by id and each group is
/// parsed together, so a set's `.volNN+MM` volumes are parsed with their
/// own index and their slices reach `recovery_blocks_seen`.
///
/// This replaced `pick_set`, which parsed each input ALONE and kept
/// `max_by_key(files.len())` - see [`Active`] for what that cost GH
/// #63's reporter. Two things about the old fallback are worth keeping
/// in mind, because both are fixed here rather than merely widened:
/// parsing an input alone gives a volume-only file no Main packet and
/// drops it, and `max_by_key` keeps the LAST maximum, so on a post whose
/// sets are all one file the winner was whichever input happened to be
/// captured last.
///
/// Groups are ordered by descending file count, ties broken by set id.
/// That is DETERMINISTIC where the old tie-break was not - capture order
/// is download order - and it keeps `sets()[0]` the set the old code
/// would have adopted, which is what the surfaces that legitimately want
/// a single representative (the damage projection's block size) still
/// read.
///
/// A group that will not parse is skipped, not fatal: one broken index
/// among eighteen must not cost the other seventeen their verification.
/// The whole call fails only when NO group yields a set.
pub fn pick_sets(inputs: &[&[u8]]) -> Result<Vec<Par2Set>, Par2Error> {
    match Par2Set::parse(inputs) {
        Ok(set) => Ok(vec![set]),
        Err(Par2Error::MixedRecoverySets) => {
            // First-appearance order, so the grouping itself is stable;
            // the sort below is what fixes the final order.
            let mut order: Vec<[u8; 16]> = Vec::new();
            let mut groups: HashMap<[u8; 16], Vec<&[u8]>> = HashMap::new();
            for i in inputs {
                let Some(id) = Par2Set::set_id_of(i) else {
                    continue;
                };
                if !groups.contains_key(&id) {
                    order.push(id);
                }
                groups.entry(id).or_default().push(i);
            }
            let mut sets: Vec<Par2Set> = order
                .iter()
                .filter_map(|id| Par2Set::parse(&groups[id]).ok())
                .collect();
            if sets.is_empty() {
                return Err(Par2Error::NoMainPacket);
            }
            sets.sort_by(|a, b| {
                b.files
                    .len()
                    .cmp(&a.files.len())
                    .then_with(|| a.recovery_set_id.cmp(&b.recovery_set_id))
            });
            Ok(sets)
        }
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

// The finish-time name tier - a nomination proved on content or
// dropped. Split off for the size gate; see the file header.
#[path = "live/nametier.rs"]
mod nametier;

pub use nametier::declared_block_evidence;

// The finish-time TWIN tier - which of several identical-head
// descriptors a slot's bytes are, by whole-file MD5 when the slot is
// intact and by per-block IFSC evidence when it is damaged. Split off
// for the size gate; see the file header.
#[path = "live/twintier.rs"]
mod twintier;

// The matcher's reference drain and its microbench hook - production
// code, and the only production module here that is never on a download
// path. Split off for the size gate; see the file header.
#[path = "live/matchref.rs"]
mod matchref;
pub use matchref::bench_match;

// The boundary-block interval trackers and the merged run store under
// both. Its own file for the reason `live/blockcheck.rs` is: one subject,
// and live.rs is at the size-gate ceiling (TODO 106). X5-18's hybrid
// store and the measurement behind it are in that file's header.
#[path = "live/runs.rs"]
mod runs;
use runs::{CrcParts, Partial, PartialBuf};

// The IFSC block-check primitives - one subject, its own file under the
// size gate (TODO 106). `pub use` because `check_block`,
// `check_block_verdict`, `check_block_crc` and `BlockVerdict` are this
// module's public surface and callers outside the crate name them at
// `live::`; the rest is `pub(super)` and stays inside.
#[path = "live/blockcheck.rs"]
mod blockcheck;
pub use blockcheck::{BlockVerdict, check_block, check_block_crc, check_block_verdict};
use blockcheck::{block_digest, check_block_crc_verdict, read_block_chunked};
// `pad_to` is reached by name from `live/tests.rs`, which builds its
// expected digests exactly as the production path does - that identity
// is the point of the test, so the helper is imported here rather than
// spelled out a second time there.
#[cfg(test)]
use blockcheck::pad_to;

#[cfg(test)]
#[path = "live/tests.rs"]
mod tests;

// The matcher's third state - claimed, refused, or never judged. Its own
// module for the reason `live/tests.rs` is a sibling at all: live.rs and
// that file both grew past comfort on TODO 311, and one subject per file
// is how this tree splits them.
#[cfg(test)]
#[path = "live/verdict_tests.rs"]
mod verdict_tests;

// M4-69: an IFSC entry that contradicts itself about one block, and the
// whole-file MD5 that outranks it. Its own file, one subject per file.
#[cfg(test)]
#[path = "live/ifsc_contra_tests.rs"]
mod ifsc_contra_tests;

// X5-21: what the finish-time whole-file tiers COST the mapped reader,
// asserted as read counts. Its own file, one subject per file.
#[cfg(test)]
#[path = "live/readcount_tests.rs"]
mod readcount_tests;
