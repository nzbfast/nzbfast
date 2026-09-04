//! Where the writers draw the random bytes their encryption needs.
//!
//! Both RAR generations salt the key derivation, and RAR 5 draws an
//! initialisation vector as well - one for the file data and a fresh one
//! for every encrypted header block. All of it comes from the operating
//! system by default, through `getrandom::fill`, and [`Entropy::Os`] is
//! the only setting a real archive should ever be written with.
//!
//! # Why the other setting exists
//!
//! A generator that builds archive fixtures wants ONE profile plus ONE
//! seed to give ONE layout, on every machine and every run, so a corpus
//! can be rebuilt and compared byte for byte. OS entropy makes that
//! impossible: two runs of the same generator profile emit different
//! salts, so the archives differ in bytes that carry no meaning, and a
//! catalog walk over them fails on noise. [`Entropy::Seeded`] answers
//! exactly that, and nothing else.
//!
//! # How the seeded source reaches the five draw sites
//!
//! [`Entropy`] is a plain `Copy` description carried on the writers'
//! `WriterOptions`, so the choice is visible in the public API where a
//! caller makes it. The writer entry points then install it for the
//! duration of one archive, and the draw sites read it back from there.
//!
//! That indirection is deliberate rather than lazy. The alternative -
//! a source parameter threaded by hand - would have to pass through the
//! whole plan-and-emit machinery between a writer's entry point and its
//! key derivation, and a writer arm added later that forgot the
//! parameter would silently draw from the OS again and break
//! reproducibility with no error anywhere. Installing it once at the
//! entry point means a new arm inherits the setting instead of having to
//! remember it.
//!
//! The install is per thread and strictly scoped: the guard restores
//! whatever was there before, so a nested write (an archive written
//! while another is being written) sees its own setting and gives the
//! outer one back. No writer path in this crate fans work out to another
//! thread - the `parallel` feature reaches the recovery and extraction
//! code, never `rar50::write` or `rar15_40::write` - so a write started
//! on one thread does all of its own drawing. A writer that ever does
//! spawn must install the scope on the threads it spawns, or they will
//! draw from the OS.

use std::cell::RefCell;

use crate::error::{Error, Result};

/// Where a writer draws the salt (and, for RAR 5, the initialisation
/// vectors) that its encryption needs.
///
/// The default is [`Entropy::Os`], and a caller that says nothing keeps
/// it: the bytes an existing caller writes are the bytes it wrote
/// before.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Entropy {
    /// Draw from the operating system, through `getrandom::fill`. The
    /// default, and the only correct setting for an archive anyone will
    /// rely on.
    #[default]
    Os,
    /// Derive every draw from a caller-supplied seed, so one seed and
    /// one set of inputs give a byte-identical archive every time.
    ///
    /// # This weakens the encryption it feeds. Test generation only.
    ///
    /// The salt exists to make two archives written under the same
    /// password derive different keys, and the RAR 5 initialisation
    /// vectors exist to keep two encryptions under one key from lining
    /// up. A seeded source hands all three to anyone who has the seed,
    /// and the seed travels with the generator profile that produced
    /// the archive. An archive written this way must be treated as
    /// having no secrecy at all: a fixture, a corpus member, a test
    /// input.
    ///
    /// Never write an archive a user will rely on with this. There is no
    /// check in this crate that can tell the two apart - the caller
    /// choosing the variant is the whole of the decision.
    Seeded([u8; 32]),
}

/// The seeded state, which unlike [`Entropy`] has to advance.
///
/// Each draw takes the next 32-byte block of `BLAKE2s(key = seed,
/// message = counter)`, so successive draws inside one archive differ -
/// the RAR 5 header IVs in particular must not repeat under one key -
/// while the sequence itself is fixed by the seed.
#[derive(Debug, Clone, Copy)]
struct Seeded {
    seed: [u8; 32],
    counter: u64,
}

impl Seeded {
    fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(32) {
            let block = blake2s_simd::Params::new()
                .hash_length(32)
                .key(&self.seed)
                .hash(&self.counter.to_le_bytes());
            self.counter = self.counter.wrapping_add(1);
            chunk.copy_from_slice(&block.as_bytes()[..chunk.len()]);
        }
    }
}

thread_local! {
    /// The seeded source installed for the write running on this thread,
    /// if any. `None` - the state every thread starts in - means the
    /// draw sites call `getrandom::fill`, which is what they did before
    /// this module existed.
    static INSTALLED: RefCell<Option<Seeded>> = const { RefCell::new(None) };
}

/// Installs an [`Entropy`] choice for as long as it is held, and puts
/// back whatever was installed before when it is dropped.
///
/// A writer entry point takes one of these from its `WriterOptions` and
/// holds it across the whole archive.
#[derive(Debug)]
pub(crate) struct EntropyScope {
    previous: Option<Seeded>,
}

impl EntropyScope {
    pub(crate) fn install(entropy: Entropy) -> Self {
        let next = match entropy {
            Entropy::Os => None,
            Entropy::Seeded(seed) => Some(Seeded { seed, counter: 0 }),
        };
        let previous = INSTALLED.with(|cell| cell.replace(next));
        Self { previous }
    }
}

impl Drop for EntropyScope {
    fn drop(&mut self) {
        let previous = self.previous.take();
        INSTALLED.with(|cell| {
            *cell.borrow_mut() = previous;
        });
    }
}

/// Fills `out` with the write path's random bytes.
///
/// Draws from the seeded source installed on this thread when there is
/// one, and from the operating system otherwise. `whose` names the
/// caller for the error message, exactly as the five draw sites spelled
/// it before this module existed.
pub(crate) fn fill(out: &mut [u8], whose: &'static str) -> Result<()> {
    let seeded = INSTALLED.with(|cell| {
        let mut installed = cell.borrow_mut();
        installed.as_mut().map(|state| state.fill(out)).is_some()
    });
    if seeded {
        return Ok(());
    }
    getrandom::fill(out).map_err(|_| Error::InvalidHeader(whose))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draw(len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        fill(&mut out, "test draw").unwrap();
        out
    }

    #[test]
    fn a_seeded_source_advances_between_draws() {
        // The RAR 5 data path draws a salt and then an IV, and every
        // encrypted header block draws another IV. A source that handed
        // back one constant would still make an archive REPEAT, so the
        // end-to-end reproducibility tests cannot see this: it has to be
        // pinned here. A repeated IV under one key is the real cost.
        let _scope = EntropyScope::install(Entropy::Seeded([0x5a; 32]));
        let first = draw(16);
        let second = draw(16);
        let third = draw(8);
        assert_ne!(first, second);
        assert_ne!(&first[..8], &third[..]);
        assert_ne!(&second[..8], &third[..]);
    }

    #[test]
    fn one_seed_gives_one_sequence() {
        let take = || {
            let _scope = EntropyScope::install(Entropy::Seeded([0x11; 32]));
            (draw(16), draw(16), draw(8))
        };
        assert_eq!(take(), take());

        let other = {
            let _scope = EntropyScope::install(Entropy::Seeded([0x12; 32]));
            (draw(16), draw(16), draw(8))
        };
        assert_ne!(take(), other);
    }

    #[test]
    fn a_draw_longer_than_one_block_does_not_repeat_the_block() {
        let _scope = EntropyScope::install(Entropy::Seeded([0x33; 32]));
        let long = draw(96);
        assert_ne!(&long[0..32], &long[32..64]);
        assert_ne!(&long[32..64], &long[64..96]);
    }

    #[test]
    fn a_scope_puts_back_what_it_replaced() {
        let outer = EntropyScope::install(Entropy::Seeded([0x77; 32]));
        let before = draw(16);
        {
            let _inner = EntropyScope::install(Entropy::Seeded([0x88; 32]));
            let _ = draw(16);
        }
        // The outer sequence carries on from where it was, rather than
        // restarting or inheriting the inner seed.
        let after = draw(16);
        drop(outer);

        let expected = {
            let _scope = EntropyScope::install(Entropy::Seeded([0x77; 32]));
            let first = draw(16);
            assert_eq!(first, before);
            draw(16)
        };
        assert_eq!(after, expected);
    }

    #[test]
    fn dropping_the_scope_returns_the_thread_to_the_os() {
        {
            let _scope = EntropyScope::install(Entropy::Seeded([0x99; 32]));
            let _ = draw(16);
        }
        // Two OS draws of 16 bytes colliding has probability 2^-128.
        assert_ne!(draw(16), draw(16));
    }
}
