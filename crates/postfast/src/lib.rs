//! postfast: posting-layout generator.
//!
//! A layout profile (a TOML document describing how files are named,
//! packaged, split, encoded, protected and degraded when posted to
//! Usenet) goes in; a deterministic `Layout` comes out - the files that
//! would be posted, the article map keyed by Message-ID for
//! `nzbkit::mock::MockServer`, the NZB that recovers them, and the
//! end state the client must reach. The round-trip oracle, a `layouts`
//! test target under nzbfast's tests that chip 04 adds, runs the real
//! binary against every profile in `catalog/`.
//!
//! Design and chip plan: `research/SPEC-POSTING-LAYOUT-TOOLKIT-2026-09-03.md`.
//! This crate was cut by chip 01 of that plan, which owns the workspace
//! wiring and nothing else. Chip 02 added the profile schema and the
//! seeded generator below it, chip 03 the bare-files generator, chip 04
//! the oracle target, chip 05 the recovery plane, chip 06 the container
//! plane, chip 07 the fault planes and chip 10 the encoding and NZB
//! planes. What is left of a plane is refused by name at the stage that
//! owns it, never silently emitted. Chip 15 added [`post`], the posting
//! tool, whose network half is behind the `live-post` feature and off
//! by default: nothing in this crate uploads to a live server.
//!
//! Written public-clean from the first line: `packaging/PUBLIC_MANIFEST`
//! lists `crates` as a whole directory, so this crate ships in the next
//! public export unless it is excluded. No provider hostnames, no real
//! group names beyond `alt.test` / `alt.binaries.test`, no box or
//! account names, in code, comments, profiles or fixtures.

pub mod assemble;
pub mod companion;
pub mod container;
pub mod encode;
pub mod fault;
pub mod layout;
pub mod naming;
pub mod nzb;
pub mod par2patch;
pub mod post;
pub mod profile;
pub mod recovery;
pub mod rng;
pub mod serve;
// The 7z writer arm of the container plane (H1). A module of its own
// rather than more arms inside `container`, which is already 1,200
// lines and whose subject is the PLANE rather than either library.
pub mod sevenz;
pub mod split;
// The zip writer arm of the container plane (H1), beside
// [`sevenz`] and for the same reason: the subject of `container` is
// the PLANE, and each format's library is its own module.
pub mod zip;

pub use container::{Contained, ContainerError};
pub use fault::FaultError;
pub use layout::{Expectation, GenError, Layout, generate, generate_over};
pub use profile::{Contradiction, FORMAT_VERSION, Profile, ProfileError};
pub use recovery::{Recovered, RecoveryError, RecoveryFile};
pub use rng::Rng;
pub use serve::ServeError;
