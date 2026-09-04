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
pub(crate) type Hasher = TreeHasher<many::ManyLeaves>;
#[cfg(not(target_arch = "aarch64"))]
pub(crate) type Hasher = simd::SimdHasher;

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
    use super::many::ManyLeaves;
    use super::portable::PortableLeaves;
    use super::simd::SimdHasher;
    use super::{hash, Hasher, TreeHasher, GROUP_BYTES};

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
        #[cfg(target_arch = "aarch64")]
        assert_eq!(
            feed::<ManyLeaves>(input, chunks),
            expected,
            "NEON kernel, len {}",
            input.len()
        );
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
        assert_eq!(hits.len(), 1, "{keyword} outside the NEON entry: {hits:?}");
        assert!(
            hits[0].ends_with("blake2sp/many.rs"),
            "the one {keyword} block moved: {}",
            hits[0]
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
