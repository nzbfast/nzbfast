//! parfast's integration tests, as ONE target.
//!
//! One binary rather than one per file, which is `tools/test-target-gate.py`'s
//! rule and the reason is arithmetic: a separate test target links its own
//! executable on every push, on both CI legs. A module costs nothing.
//!
//! Everything here needs the built `parfast` binary, the reference
//! `par2`, or both, and skips cleanly when they are absent.

/// Ctrl-C is the engine's clean cancel since 12 Sep 2026; this holds
/// what a cancelled run leaves on disk and what it exits with. Unix
/// only for the signal it sends - the Windows console handler is the
/// same forty lines behind the same gate, compiled by windows-clippy.
#[cfg(unix)]
mod cancel;
mod creator_packet;
/// `--digest-cache` through the binary: no store without the flag, one
/// record on first use, a validated hit after, and the same set bytes on
/// every run.
mod digest_cache;
/// The verify tier: the default per-block verdict and `--slow`'s
/// whole-file one answer the same on an honest set, by exit code, stdout
/// and repaired bytes.
mod fast_check;
/// The named `.par2` is junk and its volumes are not: the set the
/// reference repairs off the siblings and parfast used to decline, and
/// the two-set directory the rescue must not reach across.
mod junk_index;
/// `-p` deletes files, and this holds it to deleting only the ones the
/// run made - the 10 Sep 2026 data-loss defect.
mod purge;
/// What SABnzbd's own parser gets out of a repair: the extra-file
/// announcements it turns into renames and deletions, and the order
/// that makes them readable at all.
mod sab_parser;
/// TODO 334: the repair's load prints from the engine's scan report;
/// this holds it byte for byte against the whole-read load it replaced.
mod scan_load;
/// Every test's scratch directory, in one copy: the pid-scoped path
/// that stops two concurrent runs of this binary deleting each other's
/// working directory mid-create (16 Sep 2026).
mod scratch;
/// A set with ONE DOMINANT MEMBER - the shape whose absence from this
/// tree hid an 8.6x verify scheduling defect until 16 Sep 2026. Holds
/// every outer width to the same lines and the same verdicts.
mod skewed_set;
// The whole module is unix-only, not just its one test: it reaches the
// engine fold by making a recovery volume unreadable, which is a
// `PermissionsExt` 0o000 and has no Windows equivalent. Gated on the
// `mod` line rather than the `#[test]`, because a `#[cfg(unix)]` test in
// a compiled module leaves its two helpers with no caller on Windows and
// `-D warnings` refuses the target (windows-clippy red, 10 Sep 2026).
#[cfg(unix)]
mod engine_fold;
