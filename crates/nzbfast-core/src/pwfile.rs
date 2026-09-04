//! Where the operator's passwords live, for the code that cannot reach
//! the daemon to ask.
//!
//! The file is a daemon setting and the paths that need it most are free
//! functions on the extraction ladder, which runs under the CLI too and
//! holds no `Daemon` handle. Threading an `Option<&[String]>` down
//! through every extraction signature to reach one process-wide fact
//! would touch a dozen functions, so the fact is stored process-wide,
//! the way `eatvol`'s mode already is.
//!
//! `smart`'s until the crate-split prep (step 1 of
//! research/PLAN-NZBFAST-CRATE-SPLIT-2026-09-01.md). It is a setting and
//! a file read, with nothing of the filing code behind it, and the
//! candidate harvester that reads it moved into `rarfix` in the same
//! pass - so leaving it up in `smart` would have put the extractor on
//! top of the filing code for a `read_to_string`. `smart` re-exports
//! both doors, so the daemon and the CLI spell them as before.

use crate::tools::MutexExt;
use std::path::{Path, PathBuf};

/// One password per line, blanks skipped. A missing or unreadable file
/// is an empty list and never an error: the setting may name a path the
/// operator has not created yet, and refusing to extract over that
/// would be worse than trying the passwords we do hold.
pub fn read_password_file(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .map(|text| {
            text.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Set at startup and again whenever the setting changes; None on a CLI
/// run, which is why every reader treats "no file" as an empty list and
/// never as an error.
static OPERATOR_PASSWORD_FILE: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

/// Point the extraction ladder at the operator's passwords file (or
/// clear it). Called wherever `hub.unpack_password_file` is set.
pub fn set_operator_password_file(path: Option<PathBuf>) {
    *OPERATOR_PASSWORD_FILE.lock_ok() = path;
}

/// The operator's passwords, read FRESH on every call.
///
/// Fresh is the point, not an accident: a line added while the download
/// was still running is exactly the case this serves, and a cached list
/// would make the operator restart the daemon to be believed. A missing
/// file is an empty list (see [`read_password_file`]).
pub fn operator_passwords() -> Vec<String> {
    let path = OPERATOR_PASSWORD_FILE.lock_ok().clone();
    path.map(|p| read_password_file(&p)).unwrap_or_default()
}
