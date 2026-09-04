//! One private CA at a time, for the modules that need one.
//!
//! Two tests in this binary hand the client a CA of their own making
//! (`tls` and `tls_chaos`), and the anchors are process-wide: whichever
//! path is in force when a `ClientConfig` is built is the one that
//! connection verifies against. That is fine as long as only one of
//! them is in force at a time, and this is what makes that true - a
//! guard that holds a lock for as long as the caller's CA is the
//! process's CA, and clears it again on the way out.
//!
//! It replaces `unsafe { std::env::set_var("NZBFAST_EXTRA_CA", ..) }`,
//! which both tests used to do and which was sound only while each was
//! the sole test in its own executable. In this binary it is not: ~20
//! modules run on parallel threads and read `NZBFAST_*` throughout, and
//! `setenv` racing `getenv` is exactly the case the Rust 2024 `unsafe`
//! on `set_var` is there to mark. `nzbkit::nntp::set_extra_ca` is the
//! same opt-in-by-path switch behind a mutex instead of the environ.
//!
//! The lock is HALF the fix and the smaller half. It orders the two
//! tests; what lets the second one connect at all is that the client's
//! config cache is keyed by the CA path (see `tls_client_config` in
//! `crates/nzbkit-base/src/nntp/tls.rs`), so the second CA builds a second
//! config rather than being served the first one's anchors.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

fn ca_lock() -> &'static Mutex<()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(Default::default)
}

/// Held for as long as `path` is the process's extra trust anchor. The
/// field is the lock and is never read, hence the underscore: naming it
/// that way is what keeps `dead_code` quiet without a waiver.
pub struct ExtraCa {
    _lock: MutexGuard<'static, ()>,
}

impl Drop for ExtraCa {
    fn drop(&mut self) {
        nzbkit::nntp::set_extra_ca(None);
    }
}

/// Make `path` the process's extra trust anchor until the guard drops.
///
/// Takes the poisoned lock too: a panicking TLS test has already
/// reported itself, and turning its neighbour red as well only buries
/// the failure that matters.
pub fn extra_ca(path: &Path) -> ExtraCa {
    let _lock = ca_lock().lock().unwrap_or_else(|e| e.into_inner());
    nzbkit::nntp::set_extra_ca(Some(PathBuf::from(path)));
    ExtraCa { _lock }
}
