//! The one seeded generator every stage draws from.
//!
//! The determinism contract (spec section 9.3) is that the same profile
//! over the same source with the same seed produces a byte-identical
//! layout - the same opaque names, the same message-ids, the same
//! choice of which articles a fault lands on. That holds only if there
//! is exactly ONE source of randomness and every stage is handed it,
//! which is what this type is.
//!
//! **Nothing in this crate may draw from OS entropy.** The two helpers
//! the posting engine offers, `nzbkit::post::random_token` and
//! `message_id`, mint from a nanosecond clock, the pid and a process
//! counter, which is right for a real post (nothing worth
//! fingerprinting) and fatal for an oracle (a rerun of a failing
//! profile would not reproduce the failure). So the generator wraps the
//! `nzbkit::post` helpers that take an rng and re-implements the two
//! that do not - [`Rng::token`] being the first of them, mint for mint.
//!
//! ChaCha8 rather than a small non-cryptographic generator because
//! `rand_chacha`'s stream is reproducible ACROSS PLATFORMS and across
//! `rand` releases: a seeded `StdRng` promises neither, and an oracle
//! whose article selection differs between the dev box and a CI runner
//! would be worse than no oracle at all. That claim was "patch
//! releases" until the rand 0.8 -> 0.10 bump on 3 Sep 2026 measured it
//! over two MAJOR boundaries and found the bytes unmoved; it is pinned
//! now rather than asserted, by
//! `tests::the_seeded_stream_is_frozen_across_rand_releases`.

use rand::rand_core::{Infallible, TryRng};
use rand::{Rng as _, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::profile::Profile;

/// The layout generator's single random source.
///
/// Threaded by `&mut` through every stage rather than cloned, because
/// two stages drawing from two copies of the same stream would produce
/// the same names in both.
#[derive(Debug, Clone)]
pub struct Rng {
    inner: ChaCha8Rng,
}

impl Rng {
    /// Start the stream from an explicit seed.
    pub fn from_seed(seed: u64) -> Self {
        Self {
            inner: ChaCha8Rng::seed_from_u64(seed),
        }
    }

    /// Start the stream from the profile's `[layout] seed`, which is
    /// the only place a seed legitimately comes from in a catalog run.
    pub fn for_profile(p: &Profile) -> Self {
        Self::from_seed(p.layout.seed)
    }

    /// A random opaque name, indistinguishable from one the posting
    /// tool mints.
    ///
    /// `nzbkit::post::random_token` is the first 24 characters of a
    /// message-id local part, which is `sha2` output rendered lowercase
    /// hex: 24 hex characters, 12 bytes of material. Matching that
    /// exactly matters because an opaque name is a shape the client's
    /// identification path reads - a token of a different length or
    /// alphabet would be a layout no posting tool produces, and a test
    /// over it would prove something about nothing.
    pub fn token(&mut self) -> String {
        let mut bytes = [0u8; 12];
        self.inner.fill_bytes(&mut bytes);
        let mut s = String::with_capacity(24);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// Fill a buffer, which is how generated payload bytes are drawn.
    pub fn fill(&mut self, buf: &mut [u8]) {
        self.inner.fill_bytes(buf);
    }

    /// A uniform value in `0..n`. `n == 0` yields 0 rather than
    /// panicking: a fault plan over an empty set is a no-op, not a bug
    /// in the caller.
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        // Rejection sampling, so the result is uniform and, unlike a
        // modulo fold, identical for a given stream position whatever
        // `rand` does to `gen_range` between releases.
        let zone = u64::MAX - (u64::MAX % n) - 1;
        loop {
            let v = self.inner.next_u64();
            if v <= zone {
                return v % n;
            }
        }
    }
}

// So a stage can hand this to any `rand` helper that takes a generator
// (`choose`, `shuffle`) instead of reaching for `rand::rng()`.
//
// `TryRng` and not `rand::Rng`: since rand 0.10 the infallible `Rng`
// trait is BLANKET-implemented for every `TryRng<Error = Infallible>`,
// so `TryRng` is the only one a type can implement and implementing it
// is what grants `Rng`. (Before 0.10 this was `RngCore`, whose
// `try_fill_bytes` returned a `rand::Error` that no longer exists -
// filling is infallible now.)
impl TryRng for Rng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(self.inner.next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(self.inner.next_u64())
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        self.inner.fill_bytes(dest);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Rng;

    /// The determinism contract in its smallest form: one seed, one
    /// stream, whoever asks.
    #[test]
    fn one_seed_gives_one_token_stream() {
        let mut a = Rng::from_seed(1);
        let mut b = Rng::from_seed(1);
        let left: Vec<String> = (0..16).map(|_| a.token()).collect();
        let right: Vec<String> = (0..16).map(|_| b.token()).collect();
        assert_eq!(left, right);
    }

    /// ...and a different seed is a different stream, or the contract
    /// above would also be satisfied by a constant.
    #[test]
    fn a_different_seed_gives_a_different_stream() {
        let mut a = Rng::from_seed(1);
        let mut b = Rng::from_seed(2);
        assert_ne!(a.token(), b.token());
    }

    /// A token has to be minted like `nzbkit::post::random_token`: 24
    /// lowercase hex characters. A generated opaque name that does not
    /// look like a posted one tests the wrong shape.
    #[test]
    fn a_token_matches_the_posting_tools_alphabet_and_length() {
        let mut r = Rng::from_seed(7);
        for _ in 0..64 {
            let t = r.token();
            assert_eq!(t.len(), 24, "token length: {t}");
            assert!(
                t.chars()
                    .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
                "token alphabet: {t}"
            );
        }
        // The real thing, for the same two properties. Not compared for
        // value - it is OS-entropy-shaped and this crate never uses it.
        let real = nzbkit::post::random_token();
        assert_eq!(real.len(), 24);
        assert!(real.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// Successive draws advance the stream. A `token()` that reseeded
    /// per call would pass the equality test above and be useless.
    #[test]
    fn successive_tokens_differ() {
        let mut r = Rng::from_seed(3);
        let a = r.token();
        let b = r.token();
        assert_ne!(a, b);
    }

    /// `below` stays in range, `below(0)` does not panic, and the same
    /// seed picks the same articles - which is what makes a serve-time
    /// fault plan reproducible.
    #[test]
    fn below_is_bounded_and_reproducible() {
        let mut a = Rng::from_seed(11);
        let mut b = Rng::from_seed(11);
        for _ in 0..256 {
            let v = a.below(10);
            assert!(v < 10);
            assert_eq!(v, b.below(10));
        }
        assert_eq!(Rng::from_seed(1).below(0), 0);
    }

    /// THE STREAM ITSELF, FROZEN. Every test above is self-consistent -
    /// it compares this build against this build - so all of them stay
    /// green when a `rand` or `rand_chacha` bump silently moves the
    /// stream, and every generated layout in the catalog changes bytes
    /// underneath a suite that never notices. These are the actual
    /// values, captured on rand 0.8.7 / rand_chacha 0.3.1 and unchanged
    /// on rand 0.10.2 / rand_chacha 0.10.0, which is what the module
    /// doc's cross-release reproducibility claim asserts.
    ///
    /// A future bump that reddens this test has NOT broken the crate -
    /// it has moved the oracle's inputs, which means the catalog's
    /// recorded verdicts were reached over different bytes. Re-derive
    /// the catalog before re-freezing, never re-freeze to get green.
    #[test]
    fn the_seeded_stream_is_frozen_across_rand_releases() {
        // (seed, first four tokens, 16 filled bytes, eight below(97)).
        let expect: [(u64, [&str; 4], &str, [u64; 8]); 3] = [
            (
                1,
                [
                    "b10da48cea4c09676b8e0efc",
                    "d806941465060736032bb898",
                    "420d0863dca72538e5cb1bd5",
                    "53f29f485820e2e9368deab5",
                ],
                "178aff7ee0df09768e48c5b5423f1427",
                [49, 82, 32, 24, 17, 35, 93, 42],
            ),
            (
                7,
                [
                    "bb43d723345365283a299b2e",
                    "d359012b31952445b9704bb4",
                    "e33a3e09b6b70bba88db3712",
                    "5f1cec9926fe99cfa34dff5b",
                ],
                "9bb8f53d9f6343157e0a6f41630f6bd9",
                [27, 13, 80, 7, 33, 31, 38, 27],
            ),
            (
                42,
                [
                    "a15b5d39b5bf90ae88917925",
                    "c63f45f38c53b6c508b7716d",
                    "52671658f9b29aa0b042b6bc",
                    "d849e1499e825da45bb46326",
                ],
                "1413875001bfdb4e8428122a0d9bcacd",
                [7, 89, 70, 14, 71, 7, 57, 30],
            ),
        ];
        for (seed, tokens, filled, below) in expect {
            let mut r = Rng::from_seed(seed);
            for (i, want) in tokens.iter().enumerate() {
                assert_eq!(&r.token(), want, "seed {seed} token {i}");
            }
            let mut buf = [0u8; 16];
            r.fill(&mut buf);
            let got: String = buf.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(got, filled, "seed {seed} fill");
            for (i, want) in below.iter().enumerate() {
                assert_eq!(r.below(97), *want, "seed {seed} below {i}");
            }
        }
    }

    /// Filled bytes are part of the same one stream: the payload a
    /// profile generates is as reproducible as its names.
    #[test]
    fn fill_is_reproducible_and_shares_the_stream() {
        let mut a = Rng::from_seed(5);
        let mut b = Rng::from_seed(5);
        let mut pa = [0u8; 64];
        let mut pb = [0u8; 64];
        a.fill(&mut pa);
        b.fill(&mut pb);
        assert_eq!(pa, pb);
        // Drawing bytes moved the stream, so the next token follows it.
        assert_eq!(a.token(), b.token());
        assert_ne!(a.token(), Rng::from_seed(5).token());
    }
}
