//! The shared session model behind the parfast desktop apps.
//!
//! One crate, no FFI, so it is unit-tested in ONE PROCESS like every
//! other crate on CLAUDE.md's list - which matters more here than
//! usual, because the engine knobs this crate sets are process-GLOBAL
//! and a per-test process would hide every interaction between them.
//! `crates/parfast-ffi` is the C ABI over this and is a translation
//! layer with no rules of its own.
//!
//! # What lives here and why
//!
//! Everything both apps must AGREE on: what "repairable" means, how
//! padding is computed, what the volume layout is, what the queue does
//! after its last job. A rule that lived in the macOS app would have to
//! be written again in C# and would be wrong in one of them within a
//! week.
//!
//! Nothing here re-implements the engine or the CLI. The selection
//! rules are `parfast::create`'s, the verdict is
//! `parfast::verify::Survey`'s, the purge and the backup-aside are
//! `parfast::verify::purge` and `parfast::repair`'s, and the planned
//! file sizes are `nzbkit::par2gen::plan_files`'. See
//! `research/PLAN-PARFAST-GUI-2026-09-12.md` section 4.1 for the map.

pub mod checksum;
pub mod job;
pub mod pairing;
pub mod planner;
pub mod queue;
pub mod runner;
pub mod settings;
pub mod survey;

pub use job::{JobSnapshot, JobSpec, JobState};
pub use queue::Session;
pub use settings::Settings;
