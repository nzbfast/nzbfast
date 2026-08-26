//! The `/api` handler's `match mode` arms, grouped by domain. Split out
//! of `serve()` (TODO 43 step 5); each file holds the arms verbatim as a
//! `dispatch()` that answers `Some(body)` for its modes and `None`
//! otherwise. `dispatch` below chains the domains; the caller keeps the
//! catchall.

use super::*;

pub(in crate::serve) mod config;
#[cfg(feature = "indexer")]
pub(in crate::serve) mod index;
pub(in crate::serve) mod playback;
pub(in crate::serve) mod queue;
pub(in crate::serve) mod remote;
pub(in crate::serve) mod servers;
pub(in crate::serve) mod system;
#[cfg(feature = "indexer")]
pub(in crate::serve) mod wall;

/// The `serve()` locals the arms read besides the daemon itself. One
/// borrow bundle so the domain dispatchers keep the arms' original
/// bodies unchanged apart from the `ctx.` prefix.
pub(in crate::serve) struct ApiCtx<'a> {
    pub cfg_path: &'a std::path::Path,
    pub host_hdr: &'a str,
    /// Scheme + authority for client-facing links (`public_base`):
    /// honors X-Forwarded-Host/Proto, so capability URLs survive a TLS
    /// reverse proxy instead of pointing at the backend over http.
    pub base: &'a str,
    pub ua_hdr: &'a str,
    pub bootstrap_apikey: bool,
    /// The caller presented the ADD-ONLY NZB key, not the full API
    /// key. Handlers in the allowlist use it to keep the tier's
    /// stated promise that queue contents and the filesystem layout
    /// stay full-key.
    pub via_add_only: bool,
}

pub(in crate::serve) fn dispatch(
    d: &Arc<Daemon>,
    req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    mode: &str,
    ctx: &ApiCtx<'_>,
    api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    let hit = queue::dispatch(d, req, params, mode, ctx, api_body)
        .or_else(|| system::dispatch(d, req, params, mode, ctx, api_body))
        .or_else(|| config::dispatch(d, req, params, mode, ctx, api_body))
        .or_else(|| servers::dispatch(d, req, params, mode, ctx, api_body))
        .or_else(|| playback::dispatch(d, req, params, mode, ctx, api_body))
        .or_else(|| remote::dispatch(d, req, params, mode, ctx, api_body));
    #[cfg(feature = "indexer")]
    let hit = hit
        .or_else(|| index::dispatch(d, req, params, mode, ctx, api_body))
        .or_else(|| wall::dispatch(d, req, params, mode, ctx, api_body));
    hit
}
