//! Scratch-directory guard for this crate's unit tests - a copy of
//! `crates/nzbfast/tests/scratch/mod.rs`, kept in step with it and with
//! the `crates/nzbkit`, `crates/nzbtray`, `crates/nzbfast-core`,
//! `crates/nzbfast-unpack` and `crates/nzbfast-meta` copies.
//!
//! It lives under `tests/` in a crate that has no integration target,
//! which looks odd and is deliberate: `src/testscratch.rs` reaches it by
//! `#[path]`, exactly as the other six crates do, so the seven files stay
//! one file in seven places rather than becoming seven designs. This copy
//! arrived with the `nzbfast-engine` cut (crate-split step 4): `plan`'s
//! route rig and `latesets`/`settle`'s window tests each attach one, and
//! they moved up here with `get`.
//!
//! Every test that puts a `nzbfast-*` directory in the OS temp dir holds
//! one of these for the test's lifetime: the directory is recreated fresh
//! on attach and removed again on drop - the historical leak was ~90k
//! dirs (~360 GB) of scratch in $TMPDIR over five days, and on NTFS a
//! leaked `set_len` reservation is real clusters held for the rest of
//! the run (the §142 red's blast radius). The removal is a plain
//! `remove_dir_all`, never the Trash: routing temp paths through the
//! Trash raced in-flight calls into Finder "-43" dialogs once already.
//!
//! A PANICKING test keeps its tree: the failure someone is about to
//! debug lives in there, and deleting it during unwind destroys the
//! evidence. The kept path is printed to stderr, so it lands in the
//! failing test's captured output.
//!
//! Attaching also sweeps stale scratch entries older than a day, so
//! scratch from crashed or SIGKILLed runs - and the trees kept by failing
//! tests above - still gets reclaimed. That sweep used to run once per
//! test PROCESS, which nextest makes once per test, and it scans the
//! whole OS temp directory; see `claim_sweep` for what that cost and why
//! a stamp now holds it to once an hour across the box.

use std::path::{Path, PathBuf};
use std::sync::Once;
use std::time::{Duration, SystemTime};

/// Age beyond which an unclaimed scratch temp entry is presumed dead.
/// Generous enough that no live run (or concurrent session's run) is ever
/// swept: the longest suites finish in minutes, not days.
const STALE_AFTER: Duration = Duration::from_secs(24 * 60 * 60);

/// How long one completed sweep stands for every process on the box, not
/// just the one that ran it. See `claim_sweep` for why this exists at
/// all. Against `STALE_AFTER`'s 24 h it makes the worst-case life of a
/// dead directory 25 h rather than 24, which nothing depends on.
const SWEEP_EVERY: Duration = Duration::from_secs(60 * 60);

/// The stamp `claim_sweep` writes. It is a FILE and it is rewritten every
/// hour, so it can never be old enough for the sweep to reach it - but it
/// is skipped by name anyway rather than by that reasoning.
const SWEEP_STAMP: &str = "nzbfast-scratch-sweep.stamp";

/// The prefixes a sweep will remove: one per workspace crate that puts
/// scratch in the OS temp dir.
///
/// A scratch directory named anything else is swept by NOBODY, ever, and
/// that is not a theoretical hole - `nzbtray-key-*` (7,808 entries on
/// 31 Aug 2026) and the two `nzb-*rss` families had been exactly that
/// since the day they were written, because the set was `nzbfast-` and
/// `nzbkit-` and nothing else. Name a scratch directory after the crate
/// it belongs to and it is covered; invent a prefix and it is litter
/// forever. Deliberately NOT widened to a bare `nzb`: this box runs
/// `nzbget` for the competitive benchmarks, and sweeping a rival's live
/// temp tree mid-round would be a far worse bug than the one this fixes.
const SWEPT_PREFIXES: &[&str] = &["nzbfast-", "nzbkit-", "nzbtray-"];

/// RAII guard for one test scratch directory.
pub struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    /// Recreate `path` empty and return a guard that removes it on drop.
    ///
    /// The first attach in the process also sweeps day-old siblings left
    /// behind by runs that died without unwinding - at most once an hour
    /// across the whole box, see `claim_sweep`.
    pub fn attach(path: &Path) -> ScratchDir {
        sweep_stale_siblings();
        let _ = std::fs::remove_dir_all(path);
        std::fs::create_dir_all(path).unwrap();
        ScratchDir {
            path: path.to_path_buf(),
        }
    }
}

impl std::ops::Deref for ScratchDir {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.path
    }
}

impl AsRef<Path> for ScratchDir {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("scratch kept for inspection: {}", self.path.display());
            return;
        }
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// True if this process should pay for the full scan below.
///
/// WHY THIS IS NOT SIMPLY "once per process". nextest gives every test
/// its own process, so the `Once` below bounds the sweep per TEST, and
/// the scan is O(every entry in $TMPDIR) - a directory these suites do
/// not own and share with the whole OS. Measured on the dev Mac,
/// 31 Aug 2026: 75,091 entries, 47,525 of them matching a swept prefix
/// and therefore `lstat`ed one at a time. Warm that is ~0.2 s; cold, or
/// with a day of dead scratch to unlink, the same scan cost a single
/// test's fixture 58 s to 114 s
/// (`research/FLAKE-VISIBILITY-AND-SCRATCH-SWEEP-2026-08-31.md` F2), and
/// EVERY test process on the box paid it, in parallel, racing each other
/// to remove the same trees. The work is real and has to happen; what
/// was wrong is how many times.
///
/// So the stamp makes it once an hour per BOX. The common path is one
/// `metadata` call, whatever is in $TMPDIR.
///
/// The stamp is written BEFORE the scan, not after, so processes
/// starting alongside this one go straight to their test instead of
/// queueing behind it. Two or three that read the old stamp inside the
/// same instant will each sweep, which is harmless - the sweep is
/// idempotent and every removal is already best-effort - and is why this
/// needs no lock file. A stamp that cannot be written falls through to
/// sweeping, which is the old behaviour: slow beats never reclaiming.
fn claim_sweep(root: &Path) -> bool {
    let stamp = root.join(SWEEP_STAMP);
    let fresh = std::fs::metadata(&stamp).is_ok_and(|m| {
        m.modified().is_ok_and(|t| {
            SystemTime::now()
                .duration_since(t)
                .is_ok_and(|age| age < SWEEP_EVERY)
        })
    });
    if fresh {
        return false;
    }
    let _ = std::fs::write(&stamp, b"");
    true
}

fn sweep_stale_siblings() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let root = std::env::temp_dir();
        if claim_sweep(&root) {
            sweep_root(&root, SystemTime::now() - STALE_AFTER);
        }
    });
}

/// Remove every swept-prefix entry under `root` last modified before
/// `cutoff`. Split out of the caller so the age test can be driven from
/// both sides without touching a real timestamp.
fn sweep_root(root: &Path, cutoff: SystemTime) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name == SWEEP_STAMP || !SWEPT_PREFIXES.iter().any(|p| name.starts_with(p)) {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        // The mtime of a directory moves whenever its top level does, so
        // anything a live run touches stays out of reach.
        if !meta.modified().is_ok_and(|m| m < cutoff) {
            continue;
        }
        // FILES as well as directories: a leaked `<pid>-spool-<n>.nzb` is
        // one more entry every readdir on this directory pays for, and
        // holding the removal to `is_dir()` left 2,059 of them
        // unreachable by anything at all (31 Aug 2026).
        if meta.is_dir() {
            let _ = std::fs::remove_dir_all(entry.path());
        } else {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

#[cfg(test)]
mod sweep_tests {
    use super::*;

    /// A private root to sweep, so a concurrent session's real $TMPDIR -
    /// and its stamp - is neither read nor moved by any of this.
    fn private_root(tag: &str) -> ScratchDir {
        let p = std::env::temp_dir().join(format!(
            "{}-sweeptest-{tag}-{}",
            env!("CARGO_PKG_NAME"),
            std::process::id()
        ));
        ScratchDir::attach(&p)
    }

    /// The prefix set has to COVER this package, or every scratch entry
    /// the package's own tests leave behind is swept by nobody. Every
    /// copy of this file carries it and each answers for its own
    /// package.
    ///
    /// A prefix, not an exact member: `nzbfast-core` (the crate-split
    /// step 2 cut) is swept by `nzbfast-`, and giving it an entry of its
    /// own would only widen what these packages already sweep for each
    /// other.
    #[test]
    fn the_swept_prefixes_name_this_package() {
        let me = format!("{}-", env!("CARGO_PKG_NAME"));
        assert!(
            SWEPT_PREFIXES.iter().any(|p| me.starts_with(p)),
            "{me:?} is covered by nothing in {SWEPT_PREFIXES:?}, so this package's scratch is never reclaimed"
        );
    }

    /// One sweep stands for the interval; past it the claim comes back.
    #[test]
    fn claim_sweep_is_once_per_interval() {
        let root = private_root("claim");
        assert!(claim_sweep(&root), "an unstamped root must be claimable");
        assert!(!claim_sweep(&root), "a just-stamped root must not be");

        let stamp = root.join(SWEEP_STAMP);
        let aged = SystemTime::now() - SWEEP_EVERY - Duration::from_secs(60);
        std::fs::File::options()
            .write(true)
            .open(&stamp)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(aged))
            .unwrap();
        assert!(
            claim_sweep(&root),
            "a stamp older than the interval must be claimable again"
        );
    }

    /// What a sweep takes once it does run: both kinds of entry, only
    /// past the cutoff, and only under a swept prefix.
    #[test]
    fn a_sweep_takes_stale_entries_of_both_kinds_and_nothing_else() {
        let root = private_root("body");
        let dir = root.join("nzbfast-scratchy-dir");
        std::fs::create_dir_all(dir.join("inner")).unwrap();
        std::fs::write(dir.join("inner").join("f"), b"x").unwrap();
        let file = root.join("nzbfast-scratchy-spool.nzb");
        std::fs::write(&file, b"x").unwrap();
        let foreign = root.join("nzbget-not-ours");
        std::fs::create_dir_all(&foreign).unwrap();
        let stamp = root.join(SWEEP_STAMP);
        std::fs::write(&stamp, b"").unwrap();

        // Nothing is older than the epoch, so a live run is untouched.
        sweep_root(&root, SystemTime::UNIX_EPOCH);
        assert!(dir.exists(), "a directory newer than the cutoff must stay");
        assert!(file.exists(), "a file newer than the cutoff must stay");

        // Everything is older than an hour from now, so the age test is
        // satisfied and only the prefix and the stamp hold anything back.
        sweep_root(&root, SystemTime::now() + Duration::from_secs(3600));
        assert!(!dir.exists(), "a stale directory must be swept");
        assert!(!file.exists(), "a stale file must be swept");
        assert!(foreign.exists(), "an unswept prefix must never be touched");
        assert!(stamp.exists(), "the sweep must never remove its own stamp");
    }
}
