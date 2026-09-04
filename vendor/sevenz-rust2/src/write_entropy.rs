//! Where the AES writer options draw the random bytes their encryption
//! needs.
//!
//! A 7z archive encrypted with AES-256 carries a key derivation salt and
//! an initialisation vector, and [`AesEncoderOptions::new`] draws both
//! from the operating system through `getrandom::fill`. That is the only
//! way a real archive should ever be written, and [`Entropy::Os`] is the
//! default this module keeps.
//!
//! [`AesEncoderOptions`]: crate::encoder_options::AesEncoderOptions
//!
//! # Why the other setting exists
//!
//! A generator that builds archive fixtures wants ONE profile plus ONE
//! seed to give ONE archive, on every machine and every run, so a corpus
//! can be rebuilt and compared byte for byte. OS entropy makes that
//! impossible: two runs of the same generator profile emit different
//! salts, so the archives differ in bytes that carry no meaning, and a
//! catalog walk over them fails on noise. [`Entropy::Seeded`] answers
//! exactly that, and nothing else.
//!
//! This is the same design `rars::Entropy` carries for the RAR writers
//! (`vendor/rars/src/write_entropy.rs`), deliberately: `postfast` draws
//! one seed per nesting level and hands it to whichever writer that
//! level selected, so a stack mixing the two formats is reproducible the
//! same way at every level.
//!
//! # How the seeded source reaches the draw sites
//!
//! [`Entropy`] is a plain `Copy` description, and [`EntropyScope`]
//! installs one for as long as it is held. The caller installs it around
//! the whole archive build - the options constructor AND the writer run
//! - and the draw sites read it back from there.
//!
//! The scope rather than a parameter on `AesEncoderOptions::new`, which
//! would be the smaller change: the salt and the IV are two draws today
//! and an upstream bump that adds a third (a per-block IV, say) would
//! take it from the OS in silence and break reproducibility with no
//! error anywhere. A scope means a draw site added later inherits the
//! setting instead of having to remember it.
//!
//! The install is per thread and strictly scoped: the guard restores
//! whatever was there before, so a nested build sees its own setting and
//! gives the outer one back. The writer does its own drawing on the
//! thread that drives it - `set_thread_count` reaches the DECODER, never
//! this path - so a build started on one thread draws on that thread. A
//! writer that ever does spawn must install the scope on the threads it
//! spawns, or they will draw from the OS.
//!
//! # Where this module's tests are
//!
//! In `crates/postfast/src/sevenz.rs`, over this module's public API,
//! and NOT here. This crate is a `[patch.crates-io]` path dependency of
//! the nzbfast workspace rather than a member of it, so `cargo test -p
//! sevenz-rust2` runs nowhere in that repo and a `#[cfg(test)]` module
//! here would be a test set with no runner - the exact trap
//! `vendor/lzma-rust2/README-nzbfast.md` records. The four properties
//! that matter are pinned there by name: successive draws differ, one
//! seed gives one sequence, a scope puts back what it replaced, and the
//! DEFAULT still varies per run.

use std::cell::RefCell;

use sha2::Digest;

/// Where the AES encoder options draw their key derivation salt and
/// their initialisation vector.
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
    /// password derive different keys, and the initialisation vector
    /// exists to keep two encryptions under one key from lining up. A
    /// seeded source hands both to anyone who has the seed, and the seed
    /// travels with the generator profile that produced the archive. An
    /// archive written this way must be treated as having no secrecy at
    /// all: a fixture, a corpus member, a test input.
    ///
    /// Never write an archive a user will rely on with this. There is no
    /// check in this crate that can tell the two apart - the caller
    /// choosing the variant is the whole of the decision.
    Seeded([u8; 32]),
}

/// The seeded state, which unlike [`Entropy`] has to advance.
///
/// Each draw takes the next 32-byte block of `SHA-256(seed || counter)`,
/// so successive draws inside one archive differ - the salt and the IV
/// must not be the same 16 bytes - while the sequence itself is fixed by
/// the seed. SHA-256 rather than the BLAKE2s the RAR half uses because
/// it is already a dependency of this crate's `aes256` feature, and the
/// two only have to be reproducible, never interchangeable.
#[derive(Debug, Clone, Copy)]
struct Seeded {
    seed: [u8; 32],
    counter: u64,
}

impl Seeded {
    fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(32) {
            let mut sha = sha2::Sha256::default();
            sha.update(self.seed);
            sha.update(self.counter.to_le_bytes());
            let block: [u8; 32] = sha.finalize().into();
            self.counter = self.counter.wrapping_add(1);
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
    }
}

thread_local! {
    /// The seeded source installed on this thread, if any. `None` - the
    /// state every thread starts in - means the draw sites call
    /// `getrandom::fill`, which is what they did before this module
    /// existed.
    static INSTALLED: RefCell<Option<Seeded>> = const { RefCell::new(None) };
}

/// Installs an [`Entropy`] choice for as long as it is held, and puts
/// back whatever was installed before when it is dropped.
///
/// Hold one across the whole archive build - the [`AesEncoderOptions`]
/// construction and the `ArchiveWriter` run both - because the salt and
/// the IV are drawn by the options constructor and a later draw site
/// would be inside the writer.
///
/// [`AesEncoderOptions`]: crate::encoder_options::AesEncoderOptions
#[derive(Debug)]
pub struct EntropyScope {
    previous: Option<Seeded>,
}

impl EntropyScope {
    /// Installs `entropy` on this thread until the returned guard drops.
    #[must_use]
    pub fn install(entropy: Entropy) -> Self {
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
/// caller for the panic message, exactly as the two draw sites spelled
/// it before this module existed.
pub(crate) fn fill(out: &mut [u8], whose: &str) {
    let seeded = INSTALLED.with(|cell| {
        let mut installed = cell.borrow_mut();
        installed.as_mut().map(|state| state.fill(out)).is_some()
    });
    if seeded {
        return;
    }
    getrandom::fill(out).unwrap_or_else(|_| panic!("Can't generate {whose}"));
}
