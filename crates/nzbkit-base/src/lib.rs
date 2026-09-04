//! nzbkit-base - everything the rest of the engine stands on.
//!
//! One crate cut out of `nzbkit` on 3 Sep 2026 (the crate-split plan's
//! nzbkit lane 2). It is the 46 modules that `extract`, `pool`,
//! `mediaprobe` and `index` all reach and that reach none of them back:
//! parse an NZB ([`nzb`], [`nzblnk`]), talk NNTP ([`nntp`]), decode yEnc
//! ([`yenc`], [`yenc_simd`]), land bytes ([`disk`], [`mem`]), verify and
//! repair with PAR2 ([`par2`], [`par2repair`], [`par2gen`]), read
//! containers ([`rar`], [`zip`], [`tar`], [`sfx`]), name releases
//! ([`names`], [`release`], [`categories`], [`predb`]) and probe the live
//! set ([`live`]).
//!
//! `crates/nzbkit` is a FACADE over this crate: every module here is
//! re-exported there under its old name, so every `nzbkit::disk::...`
//! path in the workspace - 3,099 of them when this was cut, from eleven
//! source trees including the detached fuzz workspace - resolves with no
//! consumer edit. Nothing in this crate may name `nzbkit`;
//! `tools/modgraph.py --nzbkit --check` refuses the edge.

pub mod audiotag;
pub mod categories;
pub mod config;
pub mod disk;
/// PLAN M31 stage 1: borrow a lost segment's bytes from a duplicate
/// posting, proved block by block against the target's own PAR2 set.
pub mod dupedonor;
/// Role-aware fault selection for the chaos mock (TODO 283): resolve a
/// FILE ROLE - payload, recovery index, volume N - to the ids the
/// `Chaos` knobs apply to. Same status as `mock`: public for the rigs
/// and the test suites, not a real API.
#[doc(hidden)]
pub mod fail;
pub mod faultplan;
/// FF1 format-preserving encryption (NIST SP 800-38G) - the cipher
/// under `yencrypt`'s control-lines half; see its header.
pub mod ff1;
/// GF(2^16) primitives for the PAR2 engines. Not part of the real API:
/// public only so nzbkit's own examples (par2_fold_bench, par2_ntt_bench)
/// can build against it.
#[doc(hidden)]
pub mod gf16;
/// One read of a file's first bytes, however many magic sniffs ask -
/// see the module docs for the eighteen-sniffs-per-file measurement.
pub mod headpeek;
pub mod live;
pub mod livetune;
pub mod logtee;
pub mod lossdoubt;
/// The crate's MD5 hasher. Not part of the real API: public only
/// because [`par2repair::Md5Resume`] names the type, and because
/// nzbkit's own benches build against it.
#[doc(hidden)]
pub mod md5fast;
pub mod media;
pub mod mem;
pub mod memgauge;
pub mod mkv;
/// In-process mock NNTP server. Not part of the real API: public only for
/// tests and examples in other crates (nzbfast's suites, mockserv).
#[doc(hidden)]
pub mod mock;
pub(crate) mod mp4;
pub mod nameprobe;
/// Name grammar for posted release files: the shared stem a whole set
/// reduces to, the volume sort order, and the container-is-the-payload
/// guard. Pure functions over names, reached by `extract`, `index`,
/// `nzbimport` and `release` alike - which is why it sits here rather
/// than inside the extractor, where it was until 3 Sep 2026.
/// `extract` re-exports all six, so `nzbkit::extract::release_stem`
/// still resolves.
pub mod names;
pub mod nntp;
pub mod nzb;
pub mod nzblnk;
pub mod oracle;
pub mod par2;
/// PAR2 creation - the third direction after `par2` (parse/verify) and
/// `par2repair` (reconstruct). Native, so `nzbfast post`'s no-RAR mode
/// can describe a 0-byte member, which par2cmdline skips outright.
pub mod par2gen;
pub(crate) mod par2ntt;
pub mod par2repair;
pub mod pesto;
pub mod predb;
pub mod predb_corr;
pub mod rar;
#[doc(hidden)]
pub mod rarcrypt;
pub mod release;
pub mod sfx;
pub mod shaping;
pub mod sync;
pub mod tar;
pub mod urlauth;
pub mod yenc;
pub mod yenc_simd;
/// yEnc body-layer encryption spike (Tensai75 draft) - see its header.
pub mod yencrypt;
pub mod zip;
pub(crate) mod zipcrypt;

/// Junk scoring for a posted stem - `index::ingest`'s two pure name
/// rules, which `release`'s own test table pins. See the module note.
#[doc(hidden)]
pub mod junk;

// The rename-race harness the occupancy claims are pinned with. It was
// `#[cfg(test)] mod renameclaim;` in `nzbkit` until the nzbkit-base cut,
// and its pins are in `par2repair`'s tests HERE and `journal`'s THERE -
// two crates now, where a `cfg(test)` item is invisible whatever its
// visibility. So it lives at the lower of the two and is gated on
// `test-support` as well; the facade re-imports it under its old name.
// Nothing in it reaches past `std`.
#[cfg(any(test, feature = "test-support"))]
pub mod renameclaim;

// The scratch guard this crate's own unit tests reach for. Its `#[path]`
// include is why the file below it sits under `tests/` - see the module
// note. One copy per crate, the house pattern.
#[cfg(test)]
mod testscratch;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
