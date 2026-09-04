//! External-tool resolution - nzbfast ships as ONE executable with NO
//! embedded tools.
//!
//! RAR extraction (all families, incl. compressed/encrypted/filtered) is
//! native via the vendored `rars` crate; verify, extraction and
//! Reed-Solomon repair (incl. obfuscated-set block adoption) have long
//! been native. A separately installed `unrar` or `par2` still resolves
//! here purely as an operator escape hatch - nzbfast invokes it as an
//! ordinary external program (mere aggregation; nothing is shipped).
//!
//! Resolution order:
//!   1. a file next to the nzbfast executable - for power users who want
//!      their own tool version;
//!   2. the bare name - whatever `$PATH` provides.

use std::path::PathBuf;

// `lock_ok()` / `read_ok()` / `write_ok()` - the poison-recovering lock
// helpers, re-exported here so the rest of the crate can say
// `crate::tools::MutexExt` rather than naming nzbkit.
//
// They lived at the crate ROOT until the crate-split prep (step 1 of
// research/PLAN-NZBFAST-CRATE-SPLIT-2026-09-01.md), which made every
// module using them depend on main.rs - the top layer - for a trait that
// belongs at the bottom. This is a parking spot in the lowest layer, not
// a claim that `tools` is where they belong forever: when
// `nzbfast-core` is cut they move to that crate's own root.
pub use nzbkit::sync::{MutexExt, RwLockExt};

pub fn resolve(name: &str) -> PathBuf {
    let file = format!("{name}{}", std::env::consts::EXE_SUFFIX);
    if let Some(p) = std::env::current_exe()
        .ok()
        .and_then(|p| Some(p.parent()?.join(&file)))
        .filter(|p| p.is_file())
    {
        return p;
    }
    PathBuf::from(name)
}
