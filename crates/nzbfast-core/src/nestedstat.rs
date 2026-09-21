//! The nested-archive prevalence tally ON DISK, so it survives a restart.
//!
//! TODO 13 phase 0(b) (shipped 24 Jul 2026) counts every nested archive
//! level the engine processes, by inner type and disposition, so that
//! real-world prevalence data accumulates and can decide whether the
//! remaining nested one-pass work is worth an account. The design's own
//! honest-costs section says "MEASURE FIRST (phase 0)".
//!
//! **It was not accumulating.** The counters are process-global atomics
//! in `nzbkit::extract::shape`, nothing wrote them anywhere, and the only
//! durable copy was the `nested-prevalence:` line in `daemon.log` - which
//! the Mac app rotates when it SPAWNS the daemon, keeping exactly one
//! `.1`, so the window is the last two daemon runs. Measured over the
//! whole surviving window on 20 Sep 2026 (2026-09-16 19:00Z to 09-19
//! 22:53Z, 17 archive jobs): zero `nested-prevalence:` lines of any
//! disposition, and every older rotation already gone. Two months of
//! soaking banked nothing. Written up in
//! `research/NESTED-ONE-PASS-PLAN-2026-09-20.md` section 2, stage 0a.
//!
//! So this module is the banking half: nine `u64`s in a JSON file beside
//! the other daemon state, loaded once at startup into the engine's
//! BASELINE and written back whenever a level is counted.
//!
//! ## Where each half lives, and why the split is here
//!
//! `nzbkit` holds the counters, the baseline and the hook, and opens no
//! file and holds no path - it is a library with no notion of a config
//! directory. This layer owns daemon state (`conntune.json` next door is
//! the same shape: `path_for` / `load` / `save` / a `LOCK` / an atomic
//! write), so it owns the file, the path and the degradation.
//!
//! ## Reading it
//!
//! `GET /api?mode=stats` carries `nested_prevalence`. Its nine top-level
//! keys are now the RUNNING TOTAL - previous runs plus this one - and the
//! `process` and `previous_runs` sub-objects break that back apart, so a
//! reader wanting "since this daemon started" has not lost it and the
//! existing tests, which assert lower-bound deltas within one process,
//! keep asserting the same thing.
//!
//! ## What is deliberately NOT here
//!
//! Reading the data back is a separate item (stage 0b) and needs weeks of
//! accumulation, not a session. And nothing tries to reconstruct history
//! from log rotations: they are gone.

use crate::persist::write_atomic;
use crate::tools::MutexExt;
use nzbkit::extract::NestedPrevalence;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The on-disk shape. A mirror of [`NestedPrevalence`] rather than serde
/// derived on it, for the same reason `conntune::Tuned` lives in this
/// layer: the file format is daemon state, and a field added to the
/// engine's struct should not silently change a file another version
/// reads.
///
/// EVERY field is `#[serde(default)]`, which is what makes a file written
/// by an older build - or truncated to a bare `{}` - load as zeros in the
/// fields it lacks rather than failing the whole parse.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
struct Stored {
    #[serde(default)]
    levels: u64,
    #[serde(default)]
    in_stream: u64,
    #[serde(default)]
    demoted: u64,
    #[serde(default)]
    disk: u64,
    #[serde(default)]
    rar_store: u64,
    #[serde(default)]
    rar_compressed: u64,
    #[serde(default)]
    rar_encrypted: u64,
    #[serde(default)]
    sevenz: u64,
    #[serde(default)]
    other: u64,
}

impl From<NestedPrevalence> for Stored {
    fn from(p: NestedPrevalence) -> Self {
        Self {
            levels: p.levels,
            in_stream: p.in_stream,
            demoted: p.demoted,
            disk: p.disk,
            rar_store: p.rar_store,
            rar_compressed: p.rar_compressed,
            rar_encrypted: p.rar_encrypted,
            sevenz: p.sevenz,
            other: p.other,
        }
    }
}

impl From<Stored> for NestedPrevalence {
    fn from(s: Stored) -> Self {
        Self {
            levels: s.levels,
            in_stream: s.in_stream,
            demoted: s.demoted,
            disk: s.disk,
            rar_store: s.rar_store,
            rar_compressed: s.rar_compressed,
            rar_encrypted: s.rar_encrypted,
            sevenz: s.sevenz,
            other: s.other,
        }
    }
}

pub fn path_for(config: &Path) -> PathBuf {
    config.with_file_name("nested-prevalence.json")
}

/// What previous runs banked. Absent, unreadable, truncated, corrupt or
/// the wrong shape all answer zero.
///
/// This is daemon state and must degrade: a startup must not fail on it
/// and a stats request must not either. There is nothing here worth
/// interrupting a download for - it is an instrument, and a lost tally
/// costs a measurement, not a byte of anybody's payload.
pub fn load(config: &Path) -> NestedPrevalence {
    std::fs::read(path_for(config))
        .ok()
        .and_then(|b| serde_json::from_slice::<Stored>(&b).ok())
        .unwrap_or_default()
        .into()
}

/// Serializes read-modify-write of the file, the same way `conntune`'s
/// does and for the same reason: the sink fires on whatever thread
/// counted a level, and a nested set counts several in a row.
static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Write one snapshot. Best-effort: a failed write must never take down a
/// live daemon.
pub fn save(config: &Path, p: &NestedPrevalence) {
    let _g = LOCK.lock_ok();
    if let Ok(bytes) = serde_json::to_vec_pretty(&Stored::from(*p)) {
        let _ = write_atomic(&path_for(config), &bytes);
    }
}

/// Where [`sink`] writes. Set by [`install`]; `None` means nothing has
/// installed the hook in this process (every CLI run, every test that
/// does not opt in) and the sink is then a no-op.
static CONFIG: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

/// The hook `note_nested_level` calls after each counted level.
///
/// Writes the TOTAL, which is what the next startup loads as its
/// baseline - so a run that counts three levels on top of a banked
/// twelve leaves fifteen on disk, and loading it back is not
/// double-counting.
fn sink() {
    let path = CONFIG.lock_ok().clone();
    if let Some(p) = path {
        save(&p, &nzbkit::extract::nested_prevalence_total());
    }
}

/// Load what previous runs banked and arm the write-back. Called once at
/// daemon startup, before anything can download.
///
/// Banking on the hook rather than on a timer or at shutdown is what
/// makes this correct against a `kill -9`, a power cut and the crash that
/// takes a daemon down mid-job - and it costs nothing, because a nested
/// level is rare (zero in the 17 jobs the surviving log window held).
pub fn install(config: &Path) {
    *CONFIG.lock_ok() = Some(config.to_path_buf());
    nzbkit::extract::set_nested_prevalence_baseline(load(config));
    nzbkit::extract::set_nested_prevalence_sink(sink);
}

#[cfg(test)]
#[path = "nestedstat_tests.rs"]
mod nestedstat_tests;
