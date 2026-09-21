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
//!
//! # The front door
//!
//! The pipeline in three calls: a manifest names the articles, an
//! article decodes to payload, and the payload says where it belongs.
//! There is no reassembly step between them, which is what makes the
//! download one pass.
//!
//! ```
//! use nzbkit_base::{nzb, yenc};
//!
//! let xml = br#"<?xml version="1.0"?>
//! <nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
//!   <file subject="[1/1] &quot;demo.bin&quot; yEnc (1/1)" poster="p" date="1700000000">
//!     <groups><group>alt.binaries.test</group></groups>
//!     <segments><segment bytes="120" number="1">a1@example.com</segment></segments>
//!   </file>
//! </nzb>"#;
//!
//! // 1. The manifest: which articles, in which groups, for which file.
//! let manifest = nzb::Nzb::parse(xml).expect("well-formed NZB");
//! let file = &manifest.files[0];
//! assert_eq!(file.filename_hint(), Some("demo.bin"));
//! assert_eq!(file.groups, ["alt.binaries.test"]);
//! assert_eq!(file.segments[0].message_id, "a1@example.com");
//!
//! // 2. What `BODY <a1@example.com>` returns, minus the wire framing.
//! //    (Here we build one instead of dialling a provider.)
//! let body = yenc::encode("demo.bin", 4, None, 1, &[0, 1, 2, 3]);
//!
//! // 3. Decode. The article carries its own file offset, so the bytes
//! //    go straight to a positioned write wherever they arrive.
//! let article = yenc::decode(&body).expect("a well-formed article");
//! assert_eq!(article.data, [0, 1, 2, 3]);
//! assert_eq!(article.offset(), 0);
//! ```
//!
//! From there: [`par2`] verifies what landed and [`par2repair`] puts
//! back what did not, [`rar`] and [`zip`] read the containers, and
//! [`names`] plus [`release`] turn posted file names into a release.

pub mod audiotag;
pub mod categories;
pub mod config;
#[cfg(feature = "digest-cache")]
pub mod digest_cache;
#[cfg(not(feature = "digest-cache"))]
#[path = "digest_cache_off.rs"]
pub mod digest_cache;
pub mod disk;
pub mod dupedonor;
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
pub mod headpeek;
pub mod live;
pub mod livetune;
pub mod logtee;
pub mod lossdoubt;
#[doc(hidden)]
pub mod md5fast;
pub mod media;
pub mod mem;
pub mod memgauge;
/// Fast `memset` / `memcpy` / `memmove` / `memcmp` / `bcmp` for the static
/// musl downloads, whose zig-linked `compiler_rt` serves byte loops. x86_64
/// and AArch64 have their own shapes; armv7 has none (see the module docs).
/// Not part of the real API: public only so the bins can reach it through
/// [`crate::fast_mem_ops`], which is what actually defines the symbols.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[doc(hidden)]
pub mod memops;
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
pub mod par2seams;
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

// The binary fixtures this crate owns, reachable from the facade above it.
// Same gate as `renameclaim` and for the same reason - a `cfg(test)` item is
// invisible from another crate whatever its visibility - but the motivation
// is publication rather than test layering: `cargo package` includes only
// files below the package root, so an `include_bytes!` written UP THERE and
// pointing down HERE resolves to nothing in the published `.crate`. Forty
// such sites were live on main until 21 Sep 2026.
// `tools/package-escape-gate.py` is what refuses the next one; the module's
// own header is the full story.
#[cfg(any(test, feature = "test-support"))]
pub mod testdata;

// The scratch guard this crate's own unit tests reach for. Its `#[path]`
// include is why the file below it sits under `tests/` - see the module
// note. One copy per crate, the house pattern.
#[cfg(test)]
mod testscratch;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
