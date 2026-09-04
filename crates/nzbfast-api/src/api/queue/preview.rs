//! §303: `mode=nzb_preview` - the §294 completable verdict BEFORE the
//! grab. POST NZB bytes, get the same verdict the queue prober would
//! hang on a row, and enqueue NOTHING - the `m_feed_preview` contract
//! (a dry run over unsaved state) applied to the add path.
//!
//! Everything queue-shaped stays out of this file: the probe itself is
//! `tasks::nzb_preview_probe`, which shares the prober's measurement
//! core (`tasks/health.rs::probe_sample`) and its whole stand-down
//! discipline. What lives HERE is the reply plumbing and the two
//! guards that replace a queue row's bookkeeping:
//!
//! * the CACHE, keyed by post identity (`spare::post_ids().identity()`)
//!   with `RECHECK_AFTER_SECS` freshness - the preview's `MAX_PROBES`,
//!   since there is no row to count probes on. The dialog re-opening on
//!   the same file, or the same post arriving from a second indexer,
//!   answers from here without a provider round trip. The ALTHUNT rule
//!   from the dashboard side holds shape here too: a render reads the
//!   cache, and only the user's own drop ever starts a probe.
//! * the BUSY latch: one probe at a time daemon-wide, because each one
//!   opens its own connection per server and a multi-file drop must not
//!   dial N fleets at once. The loser answers "not checked", which is
//!   the whole degrade-to-unknown contract: every non-verdict reply
//!   means "could not check", never "unhealthy", and the add path is
//!   untouched either way - nothing here is a gate on adding.
//!
//! POST like `feed_test` and for a stronger reason: the body IS the NZB.
//! The handler blocks its worker like `server_test` does (that is what
//! the 8-worker pool is for), under a hard ceiling well under the
//! per-server probe timeout so a mute fleet cannot wedge the worker.

use super::*;

/// Newest verdicts kept. A dialog holds a handful of files; 32 covers a
/// generous drop session while keeping the map too small to matter.
const PREVIEW_CACHE_CAP: usize = 32;

/// The handler's whole wall-clock budget. Probing opens one connection
/// per server with a 20 s per-server ceiling, so a fleet of mute hosts
/// could hold a burst for minutes; the dialog would rather hear
/// "could not check" in 25 s than a verdict in three minutes, and the
/// worker goes back in the pool either way (dropping the future closes
/// the probe's sockets - `probe_server` is written for exactly that).
const PREVIEW_TIMEOUT_SECS: u64 = 25;

/// Clears the daemon-wide busy latch on every exit path, panic and
/// timeout included - a latch that leaks reports "busy" forever.
struct BusyGuard<'a>(&'a std::sync::atomic::AtomicBool);
impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

pub(super) fn m_nzb_preview(
    d: &Arc<Daemon>,
    req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        if req.method() != &tiny_http::Method::Post {
            json!({"status": false, "error": "POST required"})
        } else {
            // The dialog sends the same multipart form as addfile so
            // the two roads cannot drift on encoding; a bare body of
            // NZB bytes is accepted for tools.
            let boundary = req
                .headers()
                .iter()
                .find(|h| h.field.equiv("Content-Type"))
                .and_then(|h| multipart_boundary(h.value.as_str()));
            let raw = api_body.take().unwrap_or_default();
            let bytes = match boundary.and_then(|b| multipart_file(&raw, &b)) {
                Some((_, file)) => file,
                None => raw,
            };
            if bytes.is_empty() {
                json!({"status": false, "error": "no nzb in request"})
            } else {
                preview_reply(d, ctx.cfg_path, bytes)
            }
        }
    })
}

/// The reply for one NZB: cache, guards, probe. Split from the HTTP
/// shell so the daemon test can reason about it as one unit.
fn preview_reply(d: &Arc<Daemon>, cfg: &std::path::Path, bytes: Vec<u8>) -> Value {
    let Ok(nzb) = nzbkit::nzb::Nzb::parse(&bytes) else {
        return json!({"status": false, "error": "not an nzb"});
    };
    let key = crate::spare::post_ids(&nzb).identity();
    drop(nzb);
    let now = unix_now();
    // A fresh cached verdict answers even while a download runs - it
    // cost its round trips when it was made.
    if let Some(h) = d
        .preview_cache
        .lock_ok()
        .iter()
        .find(|(k, at, _)| *k == key && now - at < crate::health::RECHECK_AFTER_SECS)
        .map(|(_, _, v)| v.clone())
    {
        return json!({"status": true, "checked": true, "cached": true, "health": h});
    }
    if d.preview_busy
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return json!({"status": true, "checked": false, "reason": "busy"});
    }
    let _busy = BusyGuard(&d.preview_busy);
    // Same block_on + hard-timeout pattern as server_test: the worker
    // is a spawn_blocking thread, so a runtime handle is in scope.
    let r = tokio::runtime::Handle::current().block_on(async {
        tokio::time::timeout(
            std::time::Duration::from_secs(PREVIEW_TIMEOUT_SECS),
            crate::postprobe::nzb_preview_probe(d, cfg, std::sync::Arc::new(bytes)),
        )
        .await
    });
    match r {
        // The ceiling fired: the fleet was reachable enough to keep the
        // probe alive and too slow to finish it. Not evidence either.
        Err(_) => json!({"status": true, "checked": false, "reason": "no_answer"}),
        Ok(Err(reason)) => json!({"status": true, "checked": false, "reason": reason}),
        Ok(Ok(h)) => {
            let hj = crate::health::health_json(&h);
            let mut c = d.preview_cache.lock_ok();
            c.retain(|(k, _, _)| *k != key);
            if c.len() >= PREVIEW_CACHE_CAP {
                c.remove(0);
            }
            c.push((key, now, hj.clone()));
            json!({"status": true, "checked": true, "health": hj})
        }
    }
}
