//! BLAKE2sp-256 as used by RAR 5 file-hash records.
//!
//! Built from eight independent BLAKE2s leaf states (tree mode, per RFC
//! 7693). The eight leaves receive the input round-robin in 64-byte blocks
//! and are completely independent, so a fast implementation compresses all
//! eight side by side rather than one after another. Three kernels live
//! here, and every one of them produces the same digest:
//!
//! - [`simd::SimdHasher`] - `blake2s_simd`'s own blake2sp, whose leaves
//!   read their blocks in place at a stride of eight and compress
//!   eight-wide under AVX2 or four-wide under SSE4.1, selected at run time
//!   with the crate's portable compression as the fallback. The default
//!   off aarch64 (2026-09-03; audit round 25).
//! - [`many::ManyLeaves`] - a four-lane NEON kernel, the aarch64 default.
//!   `blake2s_simd` has no many-way kernel there (`guts::MAX_DEGREE` is 1),
//!   which otherwise left the whole hash on one scalar lane per leaf.
//! - [`portable::PortableLeaves`] - eight independent `blake2s_simd`
//!   states fed on a four-thread team after gathering each leaf's blocks
//!   into a scratch buffer. This was the x86 production path until
//!   2026-09-03 and is kept compiled on every target as the independent
//!   implementation the agreement tests cross-check the other two against.
//!
//! [`LeafSet`] is the interface for the two that really are eight separate
//! leaf states; `simd` owns its whole tree and so stands beside it. Every
//! kernel a target has is held to `blake2s_simd`'s blake2sp - and so to
//! the others - over random inputs and random chunkings.
//!
//! (The `simd` default off aarch64 is an nzbfast-local change, 3 Sep 2026 -
//! re-apply on the next rars re-sync, see vendor/rars/VENDORING.md.)

// The hand-built tree - [`LeafSet`], [`TreeHasher`], and the two kernels
// that implement it - is PRODUCTION only on aarch64, and compiled
// everywhere else only for the tests that cross-check it against the
// many-way kernel. Off aarch64 a production build carries `simd` alone.
#[cfg(target_arch = "aarch64")]
mod many;
#[cfg(any(target_arch = "aarch64", test))]
mod portable;
mod simd;

const OUT_BYTES: usize = 32;
#[cfg(any(target_arch = "aarch64", test))]
const BLOCK_BYTES: usize = 64;
#[cfg(any(target_arch = "aarch64", test))]
const PARALLELISM: usize = 8;
#[cfg(any(target_arch = "aarch64", test))]
const GROUP_BYTES: usize = BLOCK_BYTES * PARALLELISM;
// Below this many buffered bytes, feeding leaves serially beats spawning.
#[cfg(any(target_arch = "aarch64", test))]
const PARALLEL_MIN_BYTES: usize = 512 * 1024;

/// The eight leaf states, fed whole 512-byte groups and finished with the
/// final partial group.
#[cfg(any(target_arch = "aarch64", test))]
pub(crate) trait LeafSet: Clone {
    fn new() -> Self;
    /// `groups.len()` is a multiple of `GROUP_BYTES`; leaf `i` takes block
    /// `i` of every group.
    fn absorb_groups(&mut self, groups: &[u8]);
    /// [`Self::absorb_groups`] over several group-aligned pieces hashed as
    /// if they were concatenated. The default feeds them one at a time,
    /// which is what a kernel whose per-call cost is one thread wants; the
    /// wide leaf team overrides it, because its whole gain is in the batch
    /// size (`portable.rs` has the table).
    fn absorb_group_pieces(&mut self, pieces: &[&[u8]]) {
        for piece in pieces {
            self.absorb_groups(piece);
        }
    }
    /// `tail.len() < GROUP_BYTES`; leaf `i` takes bytes `i * 64..` of it.
    fn finalize(self, tail: &[u8]) -> [[u8; OUT_BYTES]; PARALLELISM];
}

#[cfg(any(target_arch = "aarch64", test))]
fn root_params() -> blake2s_simd::Params {
    let mut params = blake2s_simd::Params::new();
    params
        .hash_length(OUT_BYTES)
        .fanout(PARALLELISM as u8)
        .max_depth(2)
        .max_leaf_length(0)
        .node_offset(0)
        .node_depth(1)
        .inner_hash_length(OUT_BYTES)
        .last_node(true);
    params
}

/// The production hasher: this target's fastest kernel. Both shapes carry
/// the same `new` / `update` / `finalize` surface, so the callers do not
/// know which one they hold.
#[cfg(target_arch = "aarch64")]
pub(crate) type Hasher = TreeHasher<Kernel>;
#[cfg(not(target_arch = "aarch64"))]
pub(crate) type Hasher = simd::SimdHasher;

/// The aarch64 production leaf set, chosen once per process on core count.
///
/// A BLAKE2sp leaf is a serial chain and there are eight of them, so eight
/// workers is the whole of the tree's parallelism and the four-lane NEON
/// kernel - two halves, two threads - can never use more than two cores.
/// Where the cores exist, one leaf per core wins WALL by a wide margin
/// (6.24 against 2.96 GB/s at a 16 MiB batch on a 32-core arm64 desktop,
/// 4.28 against 2.71 at the 1 MiB pieces a stored extract feeds) and costs
/// about twice the CPU per byte. That is the trade this file takes
/// deliberately: wall time is what an extraction is judged on, and CPU
/// spent to shorten it is worth spending as long as the ratio stays
/// anywhere near sane. Below that many cores the NEON kernel is both
/// faster and thriftier - its two threads beat a two-worker team 2.71 to
/// 1.44 - so a small ARM box keeps it.
///
/// WHICH eight-worker team was itself measured: the leaves read their
/// blocks in place rather than gathering them into scratch first, which
/// is worth another 13% at the batch size that matters and 23% at the
/// ceiling. `portable.rs` carries the losing arm and the table.
#[cfg(target_arch = "aarch64")]
#[derive(Clone)]
pub(crate) enum Kernel {
    /// Four leaf lanes per NEON kernel call, two halves on two threads.
    /// Boxed because its eight lane states and two withheld blocks are
    /// 800 bytes against the team's one `Vec`, and the hasher that holds
    /// this enum is built once per member and cloned.
    Neon(Box<many::ManyLeaves>),
    /// One leaf per worker, each reading its blocks in place. Boxed for
    /// the same reason [`Self::Neon`] is - it holds the same lane states.
    Wide(Box<many::ScalarLeafTeam<{ portable::WIDE_THREADS }, true>>),
}

/// Whether this box has a core for every leaf. Read once: the answer
/// cannot change and `available_parallelism` is a syscall.
#[cfg(target_arch = "aarch64")]
fn wide_team_fits() -> bool {
    static FITS: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *FITS.get_or_init(|| {
        std::thread::available_parallelism().is_ok_and(|n| n.get() >= portable::WIDE_THREADS)
    })
}

#[cfg(target_arch = "aarch64")]
impl LeafSet for Kernel {
    fn new() -> Self {
        if wide_team_fits() {
            Self::Wide(Box::new(many::ScalarLeafTeam::new()))
        } else {
            Self::Neon(Box::new(many::ManyLeaves::new()))
        }
    }

    fn absorb_groups(&mut self, groups: &[u8]) {
        match self {
            Self::Neon(leaves) => leaves.absorb_groups(groups),
            Self::Wide(leaves) => leaves.absorb_groups(groups),
        }
    }

    fn absorb_group_pieces(&mut self, pieces: &[&[u8]]) {
        match self {
            Self::Neon(leaves) => leaves.absorb_group_pieces(pieces),
            Self::Wide(leaves) => leaves.absorb_group_pieces(pieces),
        }
    }

    fn finalize(self, tail: &[u8]) -> [[u8; OUT_BYTES]; PARALLELISM] {
        match self {
            Self::Neon(leaves) => leaves.finalize(tail),
            Self::Wide(leaves) => leaves.finalize(tail),
        }
    }
}

#[cfg(any(target_arch = "aarch64", test))]
#[derive(Clone)]
pub(crate) struct TreeHasher<L: LeafSet> {
    leaves: L,
    /// Input buffered until a parallel batch is worthwhile. Always drained
    /// in whole 512-byte groups except at finalization.
    buffer: Vec<u8>,
}

#[cfg(any(target_arch = "aarch64", test))]
impl<L: LeafSet> TreeHasher<L> {
    pub(crate) fn new() -> Self {
        Self {
            leaves: L::new(),
            buffer: Vec::new(),
        }
    }

    pub(crate) fn update(&mut self, input: &[u8]) {
        // Steady state (whole-group-aligned batches from the extract
        // pipelines, empty buffer): hash straight from the caller's slice -
        // no copy of the stream.
        if self.buffer.is_empty() && input.len() >= PARALLEL_MIN_BYTES {
            let whole = input.len() / GROUP_BYTES * GROUP_BYTES;
            self.leaves.absorb_groups(&input[..whole]);
            self.buffer.extend_from_slice(&input[whole..]);
            return;
        }
        self.buffer.extend_from_slice(input);
        if self.buffer.len() >= PARALLEL_MIN_BYTES {
            let whole = self.buffer.len() / GROUP_BYTES * GROUP_BYTES;
            let (groups, remainder) = self.buffer.split_at(whole);
            self.leaves.absorb_groups(groups);
            self.buffer = remainder.to_vec();
        }
    }

    /// [`Self::update`] over several pieces hashed as if concatenated,
    /// handed to the kernel as ONE batch where their shapes allow it.
    ///
    /// The batch size is the whole lever on the wide leaf team: the stored
    /// extract digester holds up to `DIGEST_BATCH` 1 MiB pieces, and
    /// feeding them one at a time costs a third of the rate the same bytes
    /// reach in one call (4.00 against 4.99 GB/s, `portable.rs`). Every
    /// piece but the last has to be a whole number of 512-byte groups for
    /// the leaves to run on across the boundary; a ragged piece in the
    /// middle simply falls back to one update each, which is what the
    /// hasher did before.
    pub(crate) fn update_pieces(&mut self, pieces: &[&[u8]]) {
        let total: usize = pieces.iter().map(|piece| piece.len()).sum();
        let aligned = pieces
            .split_last()
            .is_some_and(|(_, lead)| lead.iter().all(|p| p.len() % GROUP_BYTES == 0));
        if !self.buffer.is_empty() || total < PARALLEL_MIN_BYTES || !aligned {
            for piece in pieces {
                self.update(piece);
            }
            return;
        }
        let (last, lead) = pieces.split_last().expect("checked non-empty above");
        let whole = last.len() / GROUP_BYTES * GROUP_BYTES;
        let mut batch: Vec<&[u8]> = Vec::with_capacity(pieces.len());
        batch.extend_from_slice(lead);
        batch.push(&last[..whole]);
        self.leaves.absorb_group_pieces(&batch);
        self.buffer.extend_from_slice(&last[whole..]);
    }

    pub(crate) fn finalize(mut self) -> [u8; OUT_BYTES] {
        // Drain the remainder: whole groups first, then the partial
        // group's per-leaf slots.
        let buffer = std::mem::take(&mut self.buffer);
        let whole = buffer.len() / GROUP_BYTES * GROUP_BYTES;
        self.leaves.absorb_groups(&buffer[..whole]);
        let leaves = self.leaves.finalize(&buffer[whole..]);

        let mut root = root_params().to_state();
        for leaf in &leaves {
            root.update(leaf);
        }
        let hash = root.finalize();
        let mut out = [0u8; OUT_BYTES];
        out.copy_from_slice(hash.as_bytes());
        out
    }
}

pub(crate) fn hash(input: &[u8]) -> [u8; OUT_BYTES] {
    let mut hasher = Hasher::new();
    hasher.update(input);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "aarch64")]
    use super::many::{ManyLeaves, ScalarLeafTeam};
    use super::portable::{PortableLeaves, WideLeafTeam};
    use super::simd::SimdHasher;
    use super::{hash, Hasher, LeafSet, TreeHasher, GROUP_BYTES, PARALLEL_MIN_BYTES};

    fn reference(input: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(
            blake2s_simd::blake2sp::Params::new()
                .hash_length(32)
                .to_state()
                .update(input)
                .finalize()
                .as_bytes(),
        );
        out
    }

    /// Walk `input` in the cycled `chunks` lengths, handing each piece to
    /// `update`. The chunking is the point: every hasher here buffers, and
    /// has to give the same digest however the stream is cut.
    fn feed_chunks(input: &[u8], chunks: &[usize], mut update: impl FnMut(&[u8])) {
        let mut offset = 0;
        for &len in chunks.iter().cycle() {
            if offset >= input.len() {
                break;
            }
            let end = (offset + len).min(input.len());
            update(&input[offset..end]);
            offset = end;
        }
    }

    /// EVERY kernel this target has, fed `input` in the given chunking,
    /// against `blake2s_simd`'s own blake2sp (and so against each other).
    fn check_kernels(input: &[u8], chunks: &[usize]) {
        fn feed<L: super::LeafSet>(input: &[u8], chunks: &[usize]) -> [u8; 32] {
            let mut hasher = TreeHasher::<L>::new();
            feed_chunks(input, chunks, |piece| hasher.update(piece));
            hasher.finalize()
        }
        fn feed_simd(input: &[u8], chunks: &[usize]) -> [u8; 32] {
            let mut hasher = SimdHasher::new();
            feed_chunks(input, chunks, |piece| hasher.update(piece));
            hasher.finalize()
        }
        let expected = reference(input);
        assert_eq!(
            feed::<PortableLeaves>(input, chunks),
            expected,
            "portable kernel, len {}",
            input.len()
        );
        // The many-way kernel IS the crate's own blake2sp, so this arm
        // holds our streaming wrapper to it rather than cross-checking two
        // independent compressions - the chunk boundaries are what a
        // wrapper gets wrong, and the portable arm above is the
        // independent implementation.
        assert_eq!(
            feed_simd(input, chunks),
            expected,
            "many-way kernel, len {}",
            input.len()
        );
        assert_eq!(
            feed::<WideLeafTeam>(input, chunks),
            expected,
            "wide leaf team, len {}",
            input.len()
        );
        #[cfg(target_arch = "aarch64")]
        assert_eq!(
            feed::<ManyLeaves>(input, chunks),
            expected,
            "NEON kernel, len {}",
            input.len()
        );
        // Both team sizes, and both dispatches: a scope per batch, and
        // workers that outlive it.
        #[cfg(target_arch = "aarch64")]
        for arm in 0..4usize {
            let (threads, pooled) = (if arm < 2 { 4 } else { 8 }, arm % 2 == 1);
            let got = match arm {
                0 => feed::<ScalarLeafTeam<4, false>>(input, chunks),
                1 => feed::<ScalarLeafTeam<4, true>>(input, chunks),
                2 => feed::<ScalarLeafTeam<8, false>>(input, chunks),
                _ => feed::<ScalarLeafTeam<8, true>>(input, chunks),
            };
            assert_eq!(
                got,
                expected,
                "scalar team {threads} pooled {pooled}, len {}",
                input.len()
            );
        }
        // Both arms of the production kernel, whichever this box's core
        // count would have picked.
        #[cfg(target_arch = "aarch64")]
        for (label, mut kernel) in [
            (
                "Kernel::Neon",
                super::Kernel::Neon(Box::new(ManyLeaves::new())),
            ),
            (
                "Kernel::Wide",
                super::Kernel::Wide(Box::new(ScalarLeafTeam::<8, true>::new())),
            ),
        ] {
            let mut hasher = TreeHasher::<super::Kernel>::new();
            // Replace the leaf set so the arm under test is the one fed.
            std::mem::swap(&mut hasher.leaves, &mut kernel);
            feed_chunks(input, chunks, |piece| hasher.update(piece));
            assert_eq!(hasher.finalize(), expected, "{label}, len {}", input.len());
        }
    }

    /// `update_pieces` has to give the digest the same bytes fed one piece
    /// at a time do, over every piece shape the fast path can and cannot
    /// take: group-aligned leading pieces (which it batches), a ragged one
    /// in the middle (which it refuses), a non-empty buffer in front of it,
    /// and a batch under the threshold.
    #[test]
    fn update_pieces_matches_piece_by_piece() {
        let mut rng = XorShift(0x0DDB_A11C_0FFE_E511);
        for round in 0..32 {
            let shapes: Vec<usize> = (0..1 + rng.next() as usize % 5)
                .map(|_| match round % 4 {
                    // Whole groups, over and under the batch threshold.
                    0 => GROUP_BYTES * (1 + rng.next() as usize % 4096),
                    1 => GROUP_BYTES * (1 + rng.next() as usize % 16),
                    // Ragged, so the aligned fast path must decline.
                    _ => 1 + rng.next() as usize % (2 * PARALLEL_MIN_BYTES),
                })
                .collect();
            let total: usize = shapes.iter().sum();
            let input: Vec<u8> = (0..total).map(|_| rng.next() as u8).collect();
            let mut pieces: Vec<&[u8]> = Vec::new();
            let mut rest = input.as_slice();
            for len in &shapes {
                let (head, tail) = rest.split_at(*len);
                pieces.push(head);
                rest = tail;
            }
            // A prefix left in the buffer on some rounds, so the fast path
            // meets a non-empty buffer.
            let prefix = if round % 3 == 0 { 0 } else { 37.min(total) };
            #[cfg(target_arch = "aarch64")]
            let mut batched = TreeHasher::<ScalarLeafTeam<8, true>>::new();
            #[cfg(not(target_arch = "aarch64"))]
            let mut batched = TreeHasher::<WideLeafTeam>::new();
            let mut serial = TreeHasher::<WideLeafTeam>::new();
            let mut gathered = TreeHasher::<WideLeafTeam>::new();
            gathered.update(&input[..prefix]);
            batched.update(&input[..prefix]);
            serial.update(&input[..prefix]);
            batched.update_pieces(&pieces);
            for piece in &pieces {
                serial.update(piece);
            }
            gathered.update_pieces(&pieces);
            let expected = serial.finalize();
            assert_eq!(
                batched.finalize(),
                expected,
                "in place, round {round}, shapes {shapes:?}, prefix {prefix}"
            );
            assert_eq!(
                gathered.finalize(),
                expected,
                "gathered, round {round}, shapes {shapes:?}, prefix {prefix}"
            );
        }
    }

    /// Past [`super::portable::GATHER_MAX_GROUPS`] the team splits one
    /// batch into several dispatches; the digest must not notice.
    #[test]
    fn wide_team_agrees_past_the_gather_cap() {
        let mut rng = XorShift(0x5EED_1234_5678_9ABC);
        let input: Vec<u8> = (0..24 << 20).map(|_| rng.next() as u8).collect();
        let expected = reference(&input);
        #[cfg(target_arch = "aarch64")]
        let arms = 0..2;
        #[cfg(not(target_arch = "aarch64"))]
        let arms = 0..1;
        for arm in arms {
            let one_shot = |input: &[u8]| -> [u8; 32] {
                match arm {
                    0 => {
                        let mut h = TreeHasher::<WideLeafTeam>::new();
                        h.update(input);
                        h.finalize()
                    }
                    #[cfg(target_arch = "aarch64")]
                    _ => {
                        let mut h = TreeHasher::<ScalarLeafTeam<8, true>>::new();
                        h.update(input);
                        h.finalize()
                    }
                    #[cfg(not(target_arch = "aarch64"))]
                    _ => unreachable!(),
                }
            };
            assert_eq!(
                one_shot(&input),
                expected,
                "arm {arm}, one shot past the cap"
            );
            let pieces: Vec<&[u8]> = input.chunks(1 << 20).collect();
            let batched = match arm {
                0 => {
                    let mut h = TreeHasher::<WideLeafTeam>::new();
                    h.update_pieces(&pieces);
                    h.finalize()
                }
                #[cfg(target_arch = "aarch64")]
                _ => {
                    let mut h = TreeHasher::<ScalarLeafTeam<8, true>>::new();
                    h.update_pieces(&pieces);
                    h.finalize()
                }
                #[cfg(not(target_arch = "aarch64"))]
                _ => unreachable!(),
            };
            assert_eq!(batched, expected, "arm {arm}, 1 MiB pieces past the cap");
        }
    }

    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    #[test]
    fn kernels_agree_on_every_small_length() {
        // Every tail shape: which leaves get a partial block, which get
        // nothing, with and without a withheld block behind them.
        let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
        let input: Vec<u8> = (0..3 * GROUP_BYTES).map(|_| rng.next() as u8).collect();
        for len in 0..input.len() {
            check_kernels(&input[..len], &[len.max(1)]);
        }
    }

    #[test]
    fn kernels_agree_on_random_inputs_and_chunkings() {
        let mut rng = XorShift(0x2545_F491_4F6C_DD1D);
        for round in 0..48 {
            let len = if round % 4 == 0 {
                // Around the parallel threshold and group multiples.
                let base = [1usize << 19, 1 << 20, 1 << 21][round % 3];
                base + (rng.next() as usize % (2 * GROUP_BYTES)) - GROUP_BYTES
            } else {
                rng.next() as usize % (3 << 20)
            };
            let input: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            let chunks: Vec<usize> = (0..1 + rng.next() as usize % 6)
                .map(|_| 1 + rng.next() as usize % (700 * 1024))
                .collect();
            check_kernels(&input, &chunks);
        }
    }

    /// Run `body` on a thread of its own and fail if it has not finished
    /// within `secs`. Every lifecycle test below goes through this: the
    /// failure mode being guarded against IS a hang, and a `join` would
    /// simply hang with it rather than reporting.
    #[cfg(target_arch = "aarch64")]
    fn within<R: Send + 'static>(secs: u64, body: impl FnOnce() -> R + Send + 'static) -> R {
        let (done, wait) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = done.send(body());
        });
        wait.recv_timeout(std::time::Duration::from_secs(secs))
            .expect("the leaf team wedged")
    }

    /// Enough whole groups to be worth a team, so the hasher builds one.
    #[cfg(target_arch = "aarch64")]
    fn team_sized_batch() -> Vec<u8> {
        let mut rng = XorShift(0x0BAD_C0DE_1234_5678);
        (0..4 << 20).map(|_| rng.next() as u8).collect()
    }

    /// The team must not outlive the hasher. An extraction can stop
    /// early, so a hasher is routinely dropped mid-stream, and a worker
    /// left parked on the condvar would be a leaked thread per member.
    /// `within` is what makes this a test rather than a hang: the pool's
    /// `Drop` joins, so a worker that missed the shutdown wedges HERE.
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn a_dropped_hasher_leaves_no_worker_behind() {
        within(30, || {
            let input = team_sized_batch();
            for batches in 1..4 {
                let mut hasher = TreeHasher::<ScalarLeafTeam<8, true>>::new();
                for _ in 0..batches {
                    hasher.update(&input);
                }
                assert_eq!(
                    hasher.leaves.live_workers(),
                    7,
                    "the team is one short of a share per leaf"
                );
                // Dropped mid-stream: no `finalize`.
                drop(hasher);
            }
        });
    }

    /// Many batches through ONE team: the generation handshake has to
    /// hand every one of them out, and a worker that missed a wake would
    /// leave the dispatcher waiting forever.
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn one_team_takes_batch_after_batch() {
        let input = team_sized_batch();
        let expected = reference(&input.repeat(64));
        let digest = within(60, move || {
            let mut hasher = TreeHasher::<ScalarLeafTeam<8, true>>::new();
            for _ in 0..64 {
                hasher.update(&input);
            }
            hasher.finalize()
        });
        assert_eq!(digest, expected);
    }

    /// A panicking share must surface on the dispatcher rather than
    /// wedge it: the dispatcher waits for a completion signal, and a
    /// worker that unwound past its signal would never send one.
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn a_worker_panic_reaches_the_dispatcher() {
        use super::many::PANIC_IN_SHARE;
        // Shares 0..7 run on workers; share 7 runs on the dispatching
        // thread, and is covered too because an unwind from THERE would
        // leave the batch's frame while the workers still read it.
        for share in [0usize, 3, 7] {
            let outcome = within(30, move || {
                PANIC_IN_SHARE.with(|cell| cell.set(share));
                let input = team_sized_batch();
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut hasher = TreeHasher::<ScalarLeafTeam<8, true>>::new();
                    hasher.update(&input);
                    hasher.finalize()
                }));
                PANIC_IN_SHARE.with(|cell| cell.set(usize::MAX));
                result
            });
            assert!(outcome.is_err(), "share {share} panicked in silence");
        }
    }

    #[test]
    fn matches_public_blake2sp_vectors() {
        assert_eq!(
            hex(&hash(b"")),
            "dd0e891776933f43c7d032b08a917e25741f8aa9a12c12e1cac8801500f2ca4f"
        );
        assert_eq!(
            hex(&hash(b"abc")),
            "70f75b58f1fecab821db43c88ad84edde5a52600616cd22517b7bb14d440a7d5"
        );
    }

    #[test]
    fn streaming_hasher_matches_one_shot_hash() {
        let input: Vec<u8> = (0..4097).map(|i| (i % 251) as u8).collect();
        let mut hasher = Hasher::new();
        for chunk in input.chunks(37) {
            hasher.update(chunk);
        }
        assert_eq!(hasher.finalize(), hash(&input));
    }

    #[test]
    fn parallel_batches_match_crate_blake2sp() {
        // Large enough to cross the parallel threshold multiple times, with
        // a ragged tail; reference is blake2s_simd's own blake2sp.
        let input: Vec<u8> = (0..3 * 1024 * 1024 + 517)
            .map(|i| (i % 253) as u8)
            .collect();
        let mut hasher = Hasher::new();
        for chunk in input.chunks(96 * 1024 + 13) {
            hasher.update(chunk);
        }
        let parallel = hasher.finalize();

        let reference = blake2s_simd::blake2sp::Params::new()
            .hash_length(32)
            .to_state()
            .update(&input)
            .finalize();
        assert_eq!(parallel.as_slice(), reference.as_bytes());
    }

    /// Timing rig, not a gate. Run with
    /// `cargo test --release -p rars --lib blake2sp::tests::timing -- --ignored --nocapture`.
    ///
    /// Every kernel this target has, one-shot and streamed in the 256 KiB
    /// pieces the extract pipelines feed. On x86 the interesting pair is
    /// `many-way` (one thread, AVX2/SSE4.1 eight-wide) against `portable`
    /// (four threads, a gather copy and a one-instance compression each):
    /// the second can win on WALL by spending four cores, and the producer
    /// stage that carries this hash is in series with a read, so read the
    /// user CPU beside the rate. `BLAKE2SP_BENCH_ONLY=many|simd|portable`
    /// runs ONE variant over 1 GiB so `/usr/bin/time -l` attributes the
    /// process's user CPU to it.
    #[test]
    #[ignore]
    fn timing() {
        use std::time::Instant;
        const SIZE: usize = 64 << 20;
        const ROUNDS: usize = 5;
        let mut rng = XorShift(0x1234_5678_9ABC_DEF1);
        let input: Vec<u8> = (0..SIZE).map(|_| rng.next() as u8).collect();
        let gbps = |seconds: f64| SIZE as f64 / seconds / 1e9;

        let simd_once = |input: &[u8]| {
            let mut hasher = SimdHasher::new();
            hasher.update(input);
            hasher.finalize()
        };
        let portable_once = |input: &[u8]| {
            let mut hasher = TreeHasher::<PortableLeaves>::new();
            hasher.update(input);
            hasher.finalize()
        };
        #[cfg(target_arch = "aarch64")]
        let many_once = |input: &[u8]| {
            let mut hasher = TreeHasher::<ManyLeaves>::new();
            hasher.update(input);
            hasher.finalize()
        };

        if let Ok(only) = std::env::var("BLAKE2SP_BENCH_ONLY") {
            let rounds = (1usize << 30) / SIZE;
            let start = Instant::now();
            let mut digest = [0u8; 32];
            for _ in 0..rounds {
                digest = match only.as_str() {
                    #[cfg(target_arch = "aarch64")]
                    "many" | "neon" => many_once(&input),
                    "simd" => simd_once(&input),
                    "portable" => portable_once(&input),
                    "serial" => reference(&input),
                    other => panic!("unknown variant {other}"),
                };
            }
            assert_eq!(digest, reference(&input));
            println!(
                "{only}: {} MiB in {:.3} s = {:.2} GB/s wall",
                rounds * (SIZE >> 20),
                start.elapsed().as_secs_f64(),
                (rounds * SIZE) as f64 / start.elapsed().as_secs_f64() / 1e9
            );
            return;
        }

        let best = |f: &mut dyn FnMut() -> [u8; 32]| {
            let mut best = f64::MAX;
            for _ in 0..ROUNDS {
                let start = Instant::now();
                let digest = std::hint::black_box(f());
                best = best.min(start.elapsed().as_secs_f64());
                assert_eq!(digest, reference(&input));
            }
            best
        };
        let simd = best(&mut || simd_once(&input));
        let simd_stream = best(&mut || {
            let mut hasher = SimdHasher::new();
            for chunk in input.chunks(256 << 10) {
                hasher.update(chunk);
            }
            hasher.finalize()
        });
        let portable = best(&mut || portable_once(&input));
        let portable_stream = best(&mut || {
            let mut hasher = TreeHasher::<PortableLeaves>::new();
            for chunk in input.chunks(256 << 10) {
                hasher.update(chunk);
            }
            hasher.finalize()
        });
        println!("blake2sp {} MiB, best of {ROUNDS}:", SIZE >> 20);
        #[cfg(target_arch = "aarch64")]
        {
            let many = best(&mut || many_once(&input));
            let many_stream = best(&mut || {
                let mut hasher = TreeHasher::<ManyLeaves>::new();
                for chunk in input.chunks(256 << 10) {
                    hasher.update(chunk);
                }
                hasher.finalize()
            });
            println!(
                "  NEON 4-way kernel     one-shot {:.2} GB/s  256K-chunked {:.2} GB/s",
                gbps(many),
                gbps(many_stream),
            );
        }
        println!(
            "  crate many-way        one-shot {:.2} GB/s  256K-chunked {:.2} GB/s  (1 thread)\n  gathered leaf team    one-shot {:.2} GB/s  256K-chunked {:.2} GB/s  ({} threads)",
            gbps(simd),
            gbps(simd_stream),
            gbps(portable),
            gbps(portable_stream),
            super::portable::HASH_THREADS,
        );
    }

    /// Batch-size matrix for the kernels this target has, the measurement
    /// that chose the aarch64 production leaf set (`portable.rs` carries
    /// the table it produced). Not a gate. Run with
    /// `cargo test --release -p rars --lib blake2sp::tests::timing_matrix -- --ignored --nocapture`,
    /// and `BLAKE2SP_FEED_KIB=<n>` for one feed size rather than the sweep.
    /// Read it on a QUIET box: two identical legs measured 9% apart on the
    /// dev Mac at load 8-20.
    #[test]
    #[ignore]
    fn timing_matrix() {
        use super::portable::LeafTeam;
        use std::time::Instant;
        const SIZE: usize = 256 << 20;
        const ROUNDS: usize = 5;
        let feeds: Vec<usize> = match std::env::var("BLAKE2SP_FEED_KIB") {
            Ok(value) => vec![value.parse::<usize>().expect("KiB") << 10],
            Err(_) => vec![256 << 10, 1 << 20, 4 << 20, 16 << 20, SIZE],
        };
        let mut rng = XorShift(0x1234_5678_9ABC_DEF1);
        let input: Vec<u8> = (0..SIZE).map(|_| rng.next() as u8).collect();
        let expected = reference(&input);
        fn stream<L: LeafSet>(input: &[u8], feed: usize) -> [u8; 32] {
            let mut hasher = TreeHasher::<L>::new();
            for chunk in input.chunks(feed) {
                hasher.update(chunk);
            }
            hasher.finalize()
        }
        let best = |f: &mut dyn FnMut() -> [u8; 32]| {
            let mut wall = f64::MAX;
            for _ in 0..ROUNDS {
                let round = Instant::now();
                let digest = std::hint::black_box(f());
                wall = wall.min(round.elapsed().as_secs_f64());
                assert_eq!(digest, expected);
            }
            SIZE as f64 / wall / 1e9
        };
        println!(
            "blake2sp {} MiB, best of {ROUNDS} GB/s, {} cores:",
            SIZE >> 20,
            std::thread::available_parallelism().map_or(0, |n| n.get()),
        );
        println!(
            "  feed KiB   NEON 2thr   gather 4   gather 8   scalar 4   scalar 8   team 4   team 8"
        );
        for feed in feeds {
            #[cfg(target_arch = "aarch64")]
            let neon = best(&mut || stream::<ManyLeaves>(&input, feed));
            #[cfg(not(target_arch = "aarch64"))]
            let neon = f64::NAN;
            #[cfg(target_arch = "aarch64")]
            let (s4, s8) = (
                best(&mut || stream::<ScalarLeafTeam<4, false>>(&input, feed)),
                best(&mut || stream::<ScalarLeafTeam<8, false>>(&input, feed)),
            );
            // The same two teams, on workers that outlive the batch.
            #[cfg(target_arch = "aarch64")]
            let (p4, p8) = (
                best(&mut || stream::<ScalarLeafTeam<4, true>>(&input, feed)),
                best(&mut || stream::<ScalarLeafTeam<8, true>>(&input, feed)),
            );
            #[cfg(not(target_arch = "aarch64"))]
            let (p4, p8) = (f64::NAN, f64::NAN);
            #[cfg(not(target_arch = "aarch64"))]
            let (s4, s8) = (f64::NAN, f64::NAN);
            println!(
                "  {:>8}   {neon:>9.2}   {:>8.2}   {:>8.2}   {s4:>8.2}   {s8:>8.2}   {p4:>6.2}   {p8:>6.2}",
                feed >> 10,
                best(&mut || stream::<LeafTeam<4>>(&input, feed)),
                best(&mut || stream::<LeafTeam<8>>(&input, feed)),
            );
        }
    }

    /// The crate's `unsafe_code` lint went from `forbid` to `deny` for the
    /// NEON entry in `many.rs` and for nothing else. Keep it that way: that
    /// is the only file in the source tree using the keyword outside a
    /// comment (the per-file `deny` in Cargo.toml already refuses a block
    /// without a local allow; this refuses a second local allow).
    #[test]
    fn unsafe_is_confined_to_the_neon_entry() {
        fn walk(dir: &std::path::Path, keyword: &str, hits: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, keyword, hits);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    let text = std::fs::read_to_string(&path).unwrap();
                    let mut hit = false;
                    for line in text.lines() {
                        let code = line.split("//").next().unwrap_or("");
                        hit |= code
                            .split(|c: char| !c.is_alphanumeric() && c != '_')
                            .any(|word| word == keyword);
                    }
                    if hit {
                        // Normalised to `/`: the assertion below ends_with
                        // "blake2sp/many.rs", and `display()` gives
                        // `blake2sp\many.rs` on Windows.
                        let p = path.display().to_string();
                        hits.push(p.replace(std::path::MAIN_SEPARATOR, "/"));
                    }
                }
            }
        }
        // Spelled in two halves so this test's own text is not a hit.
        let keyword = concat!("un", "safe");
        let mut hits = Vec::new();
        walk(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            keyword,
            &mut hits,
        );
        // Two homes since 6 Sep 2026: the NEON BLAKE2sp entry and the GF16
        // recovery fold kernels (recovery/gf16_fold.rs), whose module
        // header carries the same argument. Three since 16 Sep 2026: the
        // PMULL-folded CRC-32 (crc32/pmull.rs), on the same argument.
        hits.sort();
        assert_eq!(hits.len(), 3, "{keyword} outside its three homes: {hits:?}");
        assert!(
            hits[0].ends_with("crc32/pmull.rs")
                && hits[1].ends_with("blake2sp/many.rs")
                && hits[2].ends_with("recovery/gf16_fold.rs"),
            "an {keyword} block moved: {hits:?}"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }
}
