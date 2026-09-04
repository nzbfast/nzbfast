//! nzbkit - the nzbfast engine.
//!
//! One crate, one pass: parse an NZB ([`nzb`], [`nzblnk`]), schedule its
//! articles over pooled NNTP connections ([`nntp`], [`pool`], [`warmpool`],
//! [`live`], [`preflight`]), decode yEnc in place ([`yenc`], [`yenc_simd`]),
//! land bytes at their final offsets ([`disk`], [`mem`], [`journal`]), verify
//! and repair with PAR2 ([`par2`], [`par2repair`]), and extract archives in
//! stream ([`extract`], [`rar`], [`zip`]). Around that core: media probing
//! ([`mkv`], [`media`], [`mediaprobe`]), release identification ([`release`], [`oracle`],
//! [`categories`], [`spot`], the IRC pre feed [`predb`]), the built-in
//! indexer ([`index`]), posting
//! ([`post`]), configuration ([`config`]), log capture ([`logtee`]),
//! poison-free locking ([`sync`]), and benchmarking helpers
//! ([`benchserve`], [`sysbench`], [`warmbench`]).
//! Cipher internals (`rarcrypt`, `zipcrypt`), container probing (`mp4`) and
//! the PAR2 NTT engine (`par2ntt`) are crate-private implementation detail.
//!
//! SINCE 3 Sep 2026 THIS IS A FACADE. The 46 modules everything else
//! here reaches are `crates/nzbkit-base` and are re-exported below under
//! their old names, so no `nzbkit::` path anywhere moved. What is still
//! declared in this crate is the four SIBLING layers the plan's lane 3
//! takes out next - `extract` (+ `journal`), `pool` (and its rigs),
//! `mediaprobe`, and `index` (+ `nzbimport`, `spot`) - each of which
//! reaches base and none of which reaches another.

pub use nzbkit_base::audiotag;
pub mod benchserve;
pub use nzbkit_base::categories;
pub use nzbkit_base::config;
/// Population-level precision/recall floors for the pre-feed correlation
/// tiers. Test-only: it asserts calibration, it is not part of the API.
#[cfg(all(test, feature = "indexer"))]
mod corr_calibration;
pub use nzbkit_base::disk;
/// PLAN M31 stage 1: borrow a lost segment's bytes from a duplicate
/// posting, proved block by block against the target's own PAR2 set.
pub use nzbkit_base::dupedonor;
pub mod extract;
/// Role-aware fault selection for the chaos mock (TODO 283): resolve a
/// FILE ROLE - payload, recovery index, volume N - to the ids the
/// `Chaos` knobs apply to. Same status as `mock`: public for the rigs
/// and the test suites, not a real API.
#[doc(hidden)]
pub use nzbkit_base::fail;
pub use nzbkit_base::faultplan;
/// FF1 format-preserving encryption (NIST SP 800-38G) - the cipher
/// under `yencrypt`'s control-lines half; see its header.
pub use nzbkit_base::ff1;
/// GF(2^16) primitives for the PAR2 engines. Not part of the real API:
/// public only so nzbkit's own examples (par2_fold_bench, par2_ntt_bench)
/// can build against it.
#[doc(hidden)]
pub use nzbkit_base::gf16;
pub use nzbkit_base::headpeek;
#[cfg(feature = "indexer")]
pub mod index;
pub mod journal;
pub use nzbkit_base::live;
pub use nzbkit_base::livetune;
pub use nzbkit_base::logtee;
pub use nzbkit_base::lossdoubt;
/// The crate's MD5 hasher. Not part of the real API: public only
/// because [`par2repair::Md5Resume`] names the type, and because
/// nzbkit's own benches build against it.
#[doc(hidden)]
pub use nzbkit_base::md5fast;
pub use nzbkit_base::media;
pub mod mediaprobe;
pub use nzbkit_base::mem;
pub use nzbkit_base::memgauge;
pub use nzbkit_base::mkv;
/// In-process mock NNTP server. Not part of the real API: public only for
/// tests and examples in other crates (nzbfast's suites, mockserv).
#[doc(hidden)]
pub use nzbkit_base::mock;
/// TLS front end for the chaos mock (§129 3b). Same status as `mock`:
/// public for the rigs and the chaos-serve binary, not a real API.
#[doc(hidden)]
pub mod mock_tls;
pub use nzbkit_base::nameprobe;
/// Name grammar for posted release files: the shared stem a whole set
/// reduces to, the volume sort order, and the container-is-the-payload
/// guard. Pure functions over names, reached by `extract`, `index`,
/// `nzbimport` and `release` alike - which is why it sits here rather
/// than inside the extractor, where it was until 3 Sep 2026.
/// `extract` re-exports all six, so `nzbkit::extract::release_stem`
/// still resolves.
pub use nzbkit_base::names;
pub use nzbkit_base::nntp;
pub use nzbkit_base::nzb;
pub mod nzbimport;
pub use nzbkit_base::nzblnk;
pub use nzbkit_base::oracle;
pub use nzbkit_base::par2;
/// PAR2 creation - the third direction after `par2` (parse/verify) and
/// `par2repair` (reconstruct). Native, so `nzbfast post`'s no-RAR mode
/// can describe a 0-byte member, which par2cmdline skips outright.
pub use nzbkit_base::par2gen;
pub use nzbkit_base::par2repair;
pub use nzbkit_base::pesto;
pub mod pool;
pub mod post;
pub use nzbkit_base::predb;
pub use nzbkit_base::predb_corr;
pub mod preflight;
pub use nzbkit_base::rar;
pub(crate) use nzbkit_base::rarcrypt;
pub use nzbkit_base::release;
pub use nzbkit_base::sfx;
pub use nzbkit_base::shaping;
#[cfg(feature = "indexer")]
pub mod spot;
pub use nzbkit_base::sync;
pub mod sysbench;
pub use nzbkit_base::tar;
pub use nzbkit_base::urlauth;
pub mod warmbench;
pub mod warmpool;
pub mod warmreserve;
pub use nzbkit_base::yenc;
pub use nzbkit_base::yenc_simd;
/// yEnc body-layer encryption spike (Tensai75 draft) - see its header.
pub use nzbkit_base::yencrypt;
pub use nzbkit_base::zip;

// `index::ingest` re-exports both halves, so `nzbkit::index::junk_score`
// is unchanged; this binding is what makes `crate::junk` resolve for it.
// GATED because `index` is: a `use` can be unused where a `mod` never
// could, and `unused_imports` says so in a slim build.
#[cfg(feature = "indexer")]
pub(crate) use nzbkit_base::junk;

// The rename-race harness. `#[cfg(test)] mod renameclaim;` while it lived
// here; its pins are in `journal`'s tests AND `par2repair`'s, which are two
// crates since the base cut, so it moved down behind nzbkit-base's
// `test-support` feature. Re-imported under its old name, so every
// `crate::renameclaim::` path is unchanged.
#[cfg(test)]
pub(crate) use nzbkit_base::renameclaim;

#[cfg(test)]
mod testscratch;

// DNS fault families (§129 3a) - `nntp::resolve_tests` until the
// nzbkit-base cut on 3 Sep 2026. Four of its tests drive a fleet through
// `pool::fetch_all_multi`, so it could not go down with `nntp`: `pool` is
// a SIBLING of nzbkit-base, not something under it. It stays a private
// unit test of this crate, which is the only place that sees both halves,
// and reaches `nntp` through the re-export above like any other consumer.
#[cfg(test)]
mod nntp_resolve_tests;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
