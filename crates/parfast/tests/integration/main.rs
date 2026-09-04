//! parfast's integration tests, as ONE target.
//!
//! One binary rather than one per file, which is `tools/test-target-gate.py`'s
//! rule and the reason is arithmetic: a separate test target links its own
//! executable on every push, on both CI legs. A module costs nothing.
//!
//! Everything here needs the built `parfast` binary, the reference
//! `par2`, or both, and skips cleanly when they are absent.

mod creator_packet;
