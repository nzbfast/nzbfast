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

pub mod audiotag;
pub mod benchserve;
pub mod categories;
pub mod config;
/// Population-level precision/recall floors for the pre-feed correlation
/// tiers. Test-only: it asserts calibration, it is not part of the API.
#[cfg(all(test, feature = "indexer"))]
mod corr_calibration;
pub mod disk;
/// PLAN M31 stage 1: borrow a lost segment's bytes from a duplicate
/// posting, proved block by block against the target's own PAR2 set.
pub mod dupedonor;
pub mod extract;
/// Role-aware fault selection for the chaos mock (TODO 283): resolve a
/// FILE ROLE - payload, recovery index, volume N - to the ids the
/// `Chaos` knobs apply to. Same status as `mock`: public for the rigs
/// and the test suites, not a real API.
#[doc(hidden)]
pub mod fail;
pub mod faultplan;
/// GF(2^16) primitives for the PAR2 engines. Not part of the real API:
/// public only so nzbkit's own examples (par2_fold_bench, par2_ntt_bench)
/// can build against it.
#[doc(hidden)]
pub mod gf16;
#[cfg(feature = "indexer")]
pub mod index;
pub mod journal;
pub mod live;
pub mod livetune;
pub mod logtee;
pub mod media;
pub mod mediaprobe;
pub mod mem;
pub mod memgauge;
pub mod mkv;
/// In-process mock NNTP server. Not part of the real API: public only for
/// tests and examples in other crates (nzbfast's suites, mockserv).
#[doc(hidden)]
pub mod mock;
/// TLS front end for the chaos mock (§129 3b). Same status as `mock`:
/// public for the rigs and the chaos-serve binary, not a real API.
#[doc(hidden)]
pub mod mock_tls;
pub(crate) mod mp4;
pub mod nameprobe;
pub mod nntp;
pub mod nzb;
pub mod nzbimport;
pub mod nzblnk;
pub mod oracle;
pub mod par2;
pub(crate) mod par2ntt;
pub mod par2repair;
pub mod pesto;
pub mod pool;
pub mod post;
pub mod predb;
pub mod predb_corr;
pub mod preflight;
pub mod rar;
pub(crate) mod rarcrypt;
pub mod release;
pub mod sfx;
pub mod shaping;
#[cfg(feature = "indexer")]
pub mod spot;
pub mod sync;
pub mod sysbench;
pub mod tar;
pub mod urlauth;
pub mod warmbench;
pub mod warmpool;
pub mod yenc;
pub mod yenc_simd;
pub mod zip;
pub(crate) mod zipcrypt;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
