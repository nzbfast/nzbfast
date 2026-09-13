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
/// The verify tier: the default per-block verdict and `--slow`'s
/// whole-file one answer the same on an honest set, by exit code, stdout
/// and repaired bytes.
mod fast_check;
/// `-p` deletes files, and this holds it to deleting only the ones the
/// run made - the 10 Sep 2026 data-loss defect.
mod purge;
/// TODO 334: the repair's load prints from the engine's scan report;
/// this holds it byte for byte against the whole-read load it replaced.
mod scan_load;
// The whole module is unix-only, not just its one test: it reaches the
// engine fold by making a recovery volume unreadable, which is a
// `PermissionsExt` 0o000 and has no Windows equivalent. Gated on the
// `mod` line rather than the `#[test]`, because a `#[cfg(unix)]` test in
// a compiled module leaves its two helpers with no caller on Windows and
// `-D warnings` refuses the target (windows-clippy red, 10 Sep 2026).
#[cfg(unix)]
mod engine_fold;
