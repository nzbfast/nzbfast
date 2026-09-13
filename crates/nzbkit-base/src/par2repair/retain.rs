//! The verify pass keeps what it proved: present blocks packed into feed
//! batches as they are hashed, so the syndrome pass folds them from
//! memory instead of reading every present block a second time.
//!
//! Why: the disk repair reads the whole set twice - once to prove each
//! block (the verify pass, 256 KiB chunks through one MD5 chain per
//! member) and once to feed the fold (`feed_readers` positional reads
//! of every present block). On a Windows page cache the second read is
//! a ~3 GB/s kernel copy, and on the everyday repair - a few blocks
//! damaged in a gigabyte - it IS the feed phase: the fold of three rows
//! over 1 GiB is 27 ms of an i5-10600KF's 185-210 ms `feed+fold+solve`
//! (the next-dial handoff, item 7a, 5 Sep 2026). The bytes were in a
//! buffer on the verify thread a moment earlier. So each verify worker
//! appends the block it is hashing to a packed [`FeedBatch`] as the
//! chunks go by, seals it when the CRC proves it and drops it when the
//! CRC does not, and the driver hands the sealed batches to the fold
//! worker before it reads whatever was NOT retained (blocks past the
//! budget, blocks a clean file's whole-file MD5 vouched for after their
//! CRC disagreed, adopted blocks, blocks of a truncated member hashed
//! on the pool branch).
//!
//! Memory: retention is bounded by the same budget the transform's
//! corpus retention answers to (`fastpar::ntt_budget_within_published`,
//! a quarter of RAM under a 64 GiB ceiling, then clamped to whatever
//! budget an entry point PUBLISHED - `--mem-limit`), reserved a block
//! at a time across the verify workers; past it the sink goes quiet and
//! the feed reads the
//! rest as before. The budget is read once per PROCESS but spent per
//! CORPUS, so two repairs running at once hold two of them - bounded
//! below `RETAIN_MAX_CORPUS_BYTES` each, and no round has instrumented
//! peak RSS. When the transform is admitted after the survey the
//! batches are exactly the corpus it would have retained from the feed
//! reads, so nothing is held twice. `NZBFAST_REPAIR_RETAIN=<bytes>`
//! overrides the budget, `0` turns retention off (the A/B arm).

use super::linalg::FeedBatch;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A sink's assembly batch: sixteen blocks of a usenet-sized set, or
/// one block when blocks are larger than that.
const SINK_BATCH_BYTES: usize = 16 << 20;

/// Every present block the verify pass held on to, across all its
/// workers, with the global block indexes it holds.
pub(super) struct RetainedCorpus {
    base_logs: Vec<u32>,
    block_size: usize,
    budget: usize,
    used: AtomicUsize,
    batches: Mutex<Vec<FeedBatch>>,
    held: Mutex<Vec<bool>>,
}

/// The retention budget in bytes and whether an explicit
/// `NZBFAST_REPAIR_RETAIN` set it. Read once per PROCESS - which is
/// itself one of the reasons the admission census records the decision
/// rather than reconstructing it later, since a reconstruction would
/// have to know what the environment said at first use.
#[derive(Clone, Copy)]
pub(super) struct Policy {
    pub(super) budget: usize,
    /// The knob was present. It overrides the size ceiling below, in
    /// either direction, so this is part of the decision and not
    /// derivable from the budget value.
    pub(super) explicit: bool,
}

/// Both halves are snapshotted TOGETHER at first use. The presence
/// test used to be a fresh `var_os` on every call while the budget was
/// already a `OnceLock`, so a process that set the knob after the first
/// repair would start bypassing the size ceiling while still spending
/// the budget it had cached - two halves of one decision disagreeing.
/// Nothing shipped depends on that; the census would have recorded it
/// as a refusal arm nobody could reproduce.
fn env_policy() -> Policy {
    static B: std::sync::OnceLock<Policy> = std::sync::OnceLock::new();
    *B.get_or_init(|| {
        let raw = std::env::var("NZBFAST_REPAIR_RETAIN").ok();
        Policy {
            budget: raw
                .as_deref()
                .and_then(|v| v.parse::<usize>().ok())
                // The PUBLISHED-budget form, not the raw host one: a
                // `--mem-limit 64M` that held the creator to 64 MiB let
                // this cache retain against RAM/4 instead, so the limit
                // bound one direction of the same job. That is the exact
                // outcome `ntt_budget_within_published` was cut out for
                // on 8 Sep 2026; this call site was the one it missed.
                // Measured on a 256 MiB set with 1 MiB of parity, M3
                // Ultra: `parfast r -m64` peaked at 261.9 MiB RSS before
                // and 69.7 MiB after.
                .unwrap_or_else(super::fastpar::ntt_budget_within_published),
            explicit: raw.is_some(),
        }
    })
}

/// The policy in force. The forced arm below is a TEST seam only: the
/// production budget is a process-wide `OnceLock`, so a test that wants
/// forced-on against forced-off against the default cannot get there
/// through the environment at all.
fn policy() -> Policy {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(p) = *FORCED.lock().unwrap_or_else(|e| e.into_inner()) {
        return p;
    }
    env_policy()
}

/// The forced policy, for the admission census's validation cases.
#[cfg(any(test, feature = "test-support"))]
static FORCED: Mutex<Option<Policy>> = Mutex::new(None);

/// Force the retention policy for the duration of the returned guard.
/// Callers must serialize themselves - `census::testing::record()`
/// holds the process-wide lock the census tests use.
#[cfg(any(test, feature = "test-support"))]
pub fn force_policy(budget: usize, explicit: bool) -> ForcedPolicy {
    *FORCED.lock().unwrap_or_else(|e| e.into_inner()) = Some(Policy { budget, explicit });
    ForcedPolicy
}

/// Restores the environment policy on drop.
#[cfg(any(test, feature = "test-support"))]
pub struct ForcedPolicy;

#[cfg(any(test, feature = "test-support"))]
impl Drop for ForcedPolicy {
    fn drop(&mut self) {
        *FORCED.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

/// The retention admission decision, with everything that decided it.
///
/// The census records THIS, at the moment it is taken and before the
/// paid verify pass runs. Reconstructing it later from set size is
/// failure 5 of `research/PAR2-RETENTION-CALLER-CENSUS-2026-09-08.md`:
/// the budget, the dimensions and the explicit override all decide too,
/// and none of them is recoverable from a log line about blocks.
pub(super) struct Admission {
    /// The corpus, when retention was admitted.
    pub(super) corpus: Option<RetainedCorpus>,
    /// Bytes the corpus would hold if every block were present.
    pub(super) corpus_bytes: u64,
    /// The budget the decision was taken against.
    pub(super) budget: usize,
    /// `NZBFAST_REPAIR_RETAIN` was set.
    pub(super) explicit_override: bool,
    /// Why retention was refused, or `None` when it was admitted. The
    /// ACTUAL arm taken, never a later re-derivation.
    pub(super) refusal: Option<&'static str>,
}

/// [`RetainedCorpus::new`] with the decision reported.
pub(super) fn admit(n_inputs: usize, block_size: usize) -> Admission {
    let p = policy();
    let corpus_bytes = (n_inputs as u64).saturating_mul(block_size as u64);
    let mut a = Admission {
        corpus: None,
        corpus_bytes,
        budget: p.budget,
        explicit_override: p.explicit,
        refusal: None,
    };
    if block_size == 0 {
        a.refusal = Some("zero_block_size");
        return a;
    }
    if n_inputs == 0 {
        a.refusal = Some("zero_inputs");
        return a;
    }
    if p.budget < block_size {
        // Includes the A/B off arm: `NZBFAST_REPAIR_RETAIN=0`.
        a.refusal = Some(if p.explicit && p.budget == 0 {
            "forced_off"
        } else {
            "budget_below_one_block"
        });
        return a;
    }
    if corpus_bytes > RETAIN_MAX_CORPUS_BYTES && !p.explicit {
        a.refusal = Some("over_corpus_ceiling");
        return a;
    }
    let Ok(base_logs) = super::input_base_logs(n_inputs) else {
        a.refusal = Some("no_base_logs");
        return a;
    };
    a.corpus = Some(RetainedCorpus {
        base_logs,
        block_size,
        budget: p.budget,
        used: AtomicUsize::new(0),
        batches: Mutex::new(Vec::new()),
        held: Mutex::new(vec![false; n_inputs]),
    });
    a
}

/// The largest corpus retention takes on by default, in bytes. The
/// verify pass decides before it knows how many blocks are missing, so
/// the corpus size is the only key it has: a 1 GiB set's 3-block repair
/// reads -15% with retention (the second read's kernel copy is what
/// goes), but a 10 GiB set's 12-hole repair on an i5-10600KF read
/// 10.25-11.11 s retaining against 6.74-6.87 without (6 Sep 2026,
/// round AR) - the verify pass 4.0 s against 2.1 holding 10.7 GB of
/// fresh pages, the fold 2.7 s from either source - while the same
/// set's 900-missing transform repair gains only 3% from retention
/// and the M3 Ultra is flat on both shapes. An explicit
/// `NZBFAST_REPAIR_RETAIN=<bytes>` overrides it (that is the budget the
/// corpus is then held to, whatever its size).
///
/// Everything above is a REPAIR leg. The clean leg went unrun until
/// 8 Sep 2026, and it is the expensive one: retention is paid in full
/// before the pass learns there was nothing to repair. Forced on
/// against off, clean `repair_dir` at 1/2/4/10 GiB
/// (`research/PAR2-VERIFY-RETENTION-2026-09-08.md`, 88 non-warmup cells
/// per host): M1 Ultra +8.1 / +10.3 / +12.7 / +13.7%; i5-10600KF
/// +102 / +50 / +141 (inside its own A/A floor, so inconclusive) /
/// +272%; EPYC 9354P +116 / +105 / +101 / +124%. The 4 and 10 GiB
/// columns are that override rather than this default, and the
/// default-vs-off controls there agree within noise, so the ceiling
/// does what it claims - but it BOUNDS the tax below 2 GiB, it does not
/// remove it, and the M3's flatness is not the general case.
///
/// Before moving this constant, read
/// `research/PAR2-RETENTION-CALLER-CENSUS-2026-09-08.md`. Ordinary
/// download settlement never arrives here - `settle.rs` calls
/// `run_set_repair` only once damage is known - so the clean tax falls
/// on the speculative callers: offline extraction, nested and late
/// sets, the disk-repair fallback, the adoption probe and `parfast r`.
/// What prices retention is the damaged fraction of calls AT THIS
/// ENTRY, which nothing has measured; pairing the clean figures above
/// with the repair savings puts break-even near 70% of calls, on
/// mismatched corpora that cannot settle it. The open question is a
/// CALLER-specific default, not an architecture rule - a broad x86
/// exemption would set policy for a hardware family on a caller mix
/// nobody has counted, and would leave the Linux clean tax standing.
const RETAIN_MAX_CORPUS_BYTES: u64 = 2 << 30;

impl RetainedCorpus {
    /// Blocks the verify pass actually held, across every worker.
    pub(super) fn retained_blocks(&self) -> usize {
        self.batches
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|b| b.slices.len())
            .sum()
    }

    /// Bytes the verify pass actually held. Short of a whole block
    /// where a file tail was retained.
    pub(super) fn retained_bytes(&self) -> usize {
        self.batches
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|b| b.len())
            .sum()
    }

    /// One verify worker's sink. Flushes into the corpus on drop.
    pub(super) fn sink(&self) -> RetainSink<'_> {
        RetainSink {
            corpus: self,
            batch: FeedBatch::with_capacity(SINK_BATCH_BYTES.max(self.block_size)),
            cap: SINK_BATCH_BYTES.max(self.block_size),
            open: None,
            held: Vec::new(),
            full: false,
        }
    }

    /// The batches and the held map; the corpus is consumed.
    pub(super) fn take(self) -> (Vec<FeedBatch>, Vec<bool>) {
        let batches = self.batches.into_inner().unwrap_or_else(|e| e.into_inner());
        let held = self.held.into_inner().unwrap_or_else(|e| e.into_inner());
        (batches, held)
    }
}

/// One verify worker's handle: a block is opened when its first bytes
/// are hashed, appended chunk by chunk, and sealed or dropped when its
/// CRC is decided. Blocks arrive in file order on one worker, so the
/// open block is always the tail of this sink's arena.
pub(super) struct RetainSink<'a> {
    corpus: &'a RetainedCorpus,
    batch: FeedBatch,
    cap: usize,
    /// (global block index, arena offset) of the block being assembled.
    open: Option<(usize, usize)>,
    held: Vec<usize>,
    /// The budget refused a reservation: nothing more is retained here.
    full: bool,
}

impl RetainSink<'_> {
    /// Start block `g`, reserving a whole block of budget for it.
    pub(super) fn begin(&mut self, g: usize) {
        debug_assert!(self.open.is_none(), "begin() with a block still open");
        if self.full || g >= self.corpus.base_logs.len() {
            return;
        }
        let bs = self.corpus.block_size;
        let prev = self.corpus.used.fetch_add(bs, Ordering::AcqRel);
        if prev + bs > self.corpus.budget {
            self.corpus.used.fetch_sub(bs, Ordering::AcqRel);
            self.full = true;
            return;
        }
        if self.batch.len() + bs > self.cap && !self.batch.is_empty() {
            self.flush_batch();
        }
        self.open = Some((g, self.batch.len()));
    }

    /// The next bytes of the open block, if one is open.
    pub(super) fn append(&mut self, bytes: &[u8]) {
        if self.open.is_some() {
            self.batch.extend(bytes);
        }
    }

    /// The open block proved present: keep it. Its length may be short
    /// of a block (a file tail); the fold zero-pads.
    pub(super) fn commit(&mut self) {
        if let Some((g, off)) = self.open.take() {
            let len = self.batch.len() - off;
            self.batch.seal(self.corpus.base_logs[g], off);
            self.corpus
                .used
                .fetch_sub(self.corpus.block_size - len, Ordering::AcqRel);
            self.held.push(g);
        }
    }

    /// The open block did not prove: drop its bytes and its reservation.
    pub(super) fn abort(&mut self) {
        if let Some((_, off)) = self.open.take() {
            self.batch.truncate_to(off);
            self.corpus
                .used
                .fetch_sub(self.corpus.block_size, Ordering::AcqRel);
        }
    }

    fn flush_batch(&mut self) {
        if self.batch.is_empty() {
            return;
        }
        let cap = self.cap;
        let done = std::mem::replace(&mut self.batch, FeedBatch::with_capacity(cap));
        self.corpus
            .batches
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(done);
    }
}

impl Drop for RetainSink<'_> {
    fn drop(&mut self) {
        self.abort();
        self.flush_batch();
        if !self.held.is_empty() {
            let mut held = self.corpus.held.lock().unwrap_or_else(|e| e.into_inner());
            for &g in &self.held {
                held[g] = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus(n_inputs: usize, bs: usize, budget: usize) -> RetainedCorpus {
        RetainedCorpus {
            base_logs: super::super::input_base_logs(n_inputs).unwrap(),
            block_size: bs,
            budget,
            used: AtomicUsize::new(0),
            batches: Mutex::new(Vec::new()),
            held: Mutex::new(vec![false; n_inputs]),
        }
    }

    /// Chunked appends, a committed block, an aborted one and a short
    /// tail: the batch holds exactly the committed bytes at their
    /// logs, the held map names them, and the budget is settled.
    #[test]
    fn sink_keeps_committed_blocks_and_drops_aborted_ones() {
        let c = corpus(4, 8, 1 << 20);
        {
            let mut s = c.sink();
            s.begin(0);
            s.append(&[1, 2, 3]);
            s.append(&[4, 5, 6, 7, 8]);
            s.commit();
            s.begin(1);
            s.append(&[9; 8]);
            s.abort();
            s.begin(2);
            s.append(&[7; 8]);
            s.commit();
            s.begin(3);
            s.append(&[5; 3]);
            s.commit();
        }
        assert_eq!(c.used.load(Ordering::Acquire), 8 + 8 + 3);
        let (batches, held) = c.take();
        assert_eq!(held, [true, false, true, true]);
        assert_eq!(batches.len(), 1);
        let b = &batches[0];
        let logs = super::super::input_base_logs(4).unwrap();
        assert_eq!(
            b.slices,
            vec![(logs[0], 0, 8), (logs[2], 8, 8), (logs[3], 16, 3)]
        );
        assert_eq!(
            &b.arena[..],
            &[1, 2, 3, 4, 5, 6, 7, 8, 7, 7, 7, 7, 7, 7, 7, 7, 5, 5, 5]
        );
    }

    /// Past the budget the sink goes quiet for good, and a block open
    /// at drop is not kept.
    #[test]
    fn sink_stops_at_the_budget_and_drops_an_open_block() {
        let c = corpus(6, 8, 20);
        {
            let mut s = c.sink();
            for g in 0..4 {
                s.begin(g);
                s.append(&[g as u8; 8]);
                s.commit();
            }
            // Two fit (16 of 20), the third reservation is refused.
            assert!(s.full);
            s.begin(4);
            s.append(&[4; 8]);
            // Dropped while open.
        }
        let (batches, held) = c.take();
        assert_eq!(held, [true, true, false, false, false, false]);
        assert_eq!(batches.iter().map(|b| b.slices.len()).sum::<usize>(), 2);
    }

    /// A sink's batch turns over at its capacity, on a block boundary.
    #[test]
    fn sink_batches_turn_over_whole_blocks() {
        let c = corpus(64, 1 << 20, 1 << 30);
        let mut s = c.sink();
        s.cap = 2 << 20;
        s.batch = FeedBatch::with_capacity(2 << 20);
        for g in 0..5 {
            s.begin(g);
            s.append(&vec![g as u8; 1 << 20]);
            s.commit();
        }
        drop(s);
        let (batches, held) = c.take();
        assert_eq!(held.iter().filter(|&&h| h).count(), 5);
        assert_eq!(
            batches.iter().map(|b| b.slices.len()).collect::<Vec<_>>(),
            [2, 2, 1]
        );
        for b in &batches {
            for &(_, off, len) in &b.slices {
                assert_eq!(len, 1 << 20);
                let first = b.arena[off];
                assert!(b.arena[off..off + len].iter().all(|&x| x == first));
            }
        }
    }
}
