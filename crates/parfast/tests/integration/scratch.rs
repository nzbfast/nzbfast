//! The suite's scratch directories, in ONE copy, and the reason every
//! one of them carries a process id.
//!
//! # The incident this exists to stop (16 Sep 2026)
//!
//! Every file here used to keep its own four-line `scratch(tag)` that
//! named `CARGO_TARGET_TMPDIR/<tag>` - a path fixed for all time - and
//! opened by REMOVING it. One tag is unique across the suite, so within
//! a single run the tests never collide; two runs of this binary over
//! one target directory collide destructively, in both directions, and
//! that is an ordinary thing to do in this repo: a hand
//! `cargo nextest run -p parfast` beside a `tools/preflight.py` sweep is
//! two runs.
//!
//! What it looks like when it happens is not a scratch-directory
//! complaint. The second runner's `remove_dir_all` lands in the middle
//! of the first runner's `parfast c`, and the create fails on a path
//! whose directory has gone:
//!
//! ```text
//! Failed to create the recovery set:
//! I/O reading ./set.vol000+01.par2: No such file or directory (os error 2)
//! ```
//!
//! That is a create reporting, correctly, that it cannot write where it
//! was told to. It was read as the ENGINE leaving a partial recovery set
//! behind a cancel - `an_interrupt_during_a_create_leaves_no_recovery_set`
//! is where it surfaced, and the sentence above names a volume that
//! test's FIRST, interrupted create had been writing - and it cost a
//! chip. The engine was never in it: that test asserts the directory is
//! clean two lines ABOVE the one that failed, and that assertion passed.
//! Recorded at length in the 16 Sep 2026 one-process coverage note,
//! which is in the private tree, so it is not named here.
//!
//! # The rule
//!
//! A scratch directory belongs to ONE process, so `remove_dir_all` can
//! only ever reach this run's own leftovers. The id goes in the name
//! rather than in a parent directory so a directory left behind still
//! says which test wrote it.
//!
//! # Why it is a guard and not a `PathBuf`
//!
//! A pid in the name means a fresh directory per run, so nothing
//! overwrites the last one and 349 MB (measured, one full run of this
//! binary) would be left behind by every run until someone ran
//! `cargo clean`. [`Scratch`] removes its tree on the way out, and
//! deliberately does NOT when the thread is panicking: a failing test's
//! evidence is worth more than the bytes.

use std::ops::Deref;
use std::path::{Path, PathBuf};

/// A scratch directory this process owns, removed when it goes out of
/// scope unless the test is failing.
pub struct Scratch {
    dir: PathBuf,
}

impl Deref for Scratch {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.dir
    }
}

impl AsRef<Path> for Scratch {
    fn as_ref(&self) -> &Path {
        &self.dir
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("scratch kept for the failure: {}", self.dir.display());
            return;
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// An empty directory under `CARGO_TARGET_TMPDIR`, named for `tag` and
/// for THIS process. The opening `remove_dir_all` is for a leftover of
/// an earlier run that panicked under the same pid; it can no longer
/// reach a concurrent runner's directory, which is the whole point.
pub fn scratch(tag: &str) -> Scratch {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{tag}.{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    Scratch { dir }
}
