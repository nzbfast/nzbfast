//! Workstream A2, playback contract v1: the two calls the native mobile
//! clients were built to need.
//!
//! `mode=playback` is ONE compact poll - server state, the job list, per
//! job playback readiness and the byte-serving telemetry - because a
//! phone on a bad network should poll one thing, not `queue` plus
//! `history` plus a probe per job. `mode=stream_token` mints the scoped
//! per-job secret a handed-off URL carries, so nothing outside the app
//! ever has to hold the API key.
//!
//! The shapes here are FROZEN: `packaging/android/compose-app/CONTRACT.md`
//! records them and both native shells' snapshot tests read them back.
//! Keys may be added; existing keys keep their name, type and meaning.
//!
//! Nothing in here is a new source of truth. The job rows are projected
//! from the same `queue_json` / `history_json` the dashboard and the
//! *arrs read, and readiness comes from `stream::playback_readiness`,
//! which picks its file with the same two functions `/stream` serves it
//! with.

use super::super::*;
use super::ApiCtx;

/// Rows returned per list when the caller does not say. Small on
/// purpose: this is a phone poll, and both lists take `limit`.
const DEFAULT_LIMIT: usize = 10;
/// Ceiling on `limit`, so one call cannot ask the daemon to walk a
/// whole history's worth of directories.
const MAX_LIMIT: usize = 100;

fn limit_of(params: &std::collections::HashMap<String, String>) -> usize {
    params
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        // `limit=0` is the default, not an empty page: every other list
        // in the daemon reads 0 as "no window" (SAB's own history call
        // does), and answering a phone poll with zero rows because it
        // borrowed that idiom is the one reading nobody wants.
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_LIMIT)
        .min(MAX_LIMIT)
}

/// A number the client can do arithmetic on, from the SAB payload's
/// string. The SAB shapes quote everything; the mobile contract does
/// not, and a client that has to parse "91.53" out of a string is a
/// client that will one day parse it wrong.
fn num(v: &Value) -> f64 {
    v.as_f64()
        .or_else(|| v.as_str().and_then(|s| s.parse::<f64>().ok()))
        .unwrap_or(0.0)
}

/// The play URL for `id`, carrying the job's own stream token.
///
/// Never the API key: this string is handed to players, written into
/// `.strm` files, and printed in logs. The token starts THIS job and
/// nothing else (see `Daemon::stream_token`).
fn stream_url(d: &Daemon, base: &str, id: &str) -> String {
    format!("{base}/stream/{id}?t={}", d.stream_token(id))
}

fn m_playback(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    let limit = limit_of(params);
    let free_now = free_bytes(&d.out_dir());
    let warns = sab_warnings(d, ctx.cfg_path, ctx.via_add_only, free_now);
    // Projected from the SAB payloads rather than walked again here: one
    // arithmetic for the queue, whatever asks for it. See §91's "two
    // instants in one answer" - a second walk is a second instant.
    let queue = queue_json(d, params);
    let history = history_json(d, params);
    let jobs: Vec<Value> = queue["queue"]["slots"]
        .as_array()
        .map(|s| s.as_slice())
        .unwrap_or_default()
        .iter()
        .take(limit)
        .map(|s| {
            let id = s["nzo_id"].as_str().unwrap_or_default();
            json!({
                "nzo_id": id,
                "name": s["filename"],
                "status": s["status"],
                "cat": s["cat"],
                "percentage": num(&s["percentage"]),
                "mb": num(&s["mb"]),
                "mbleft": num(&s["mbleft"]),
                "timeleft": s["timeleft"],
                "activity": s["activity"],
                "playback": playback_readiness(d, id),
                "stream": stream_url(d, ctx.base, id),
            })
        })
        .collect();
    let done: Vec<Value> = history["history"]["slots"]
        .as_array()
        .map(|s| s.as_slice())
        .unwrap_or_default()
        .iter()
        .take(limit)
        .map(|s| {
            let id = s["nzo_id"].as_str().unwrap_or_default();
            json!({
                "nzo_id": id,
                "name": s["name"],
                "status": s["status"],
                "cat": s["category"],
                "bytes": s["bytes"],
                "fail_message": s["fail_message"],
                "completed": s["completed"],
                "playback": playback_readiness(d, id),
                "stream": stream_url(d, ctx.base, id),
            })
        })
        .collect();
    // The link's learned peak (§125), same source the dashboard's queue
    // poll carries: bps plus "measured"|"line"|"". 0/"" = no anchor
    // known, and clients keep scale-to-window behaviour.
    let (peak_bps, peak_src) = d.link_peak.effective(d.line_speed.load(Ordering::Relaxed));
    Some(json!({
        "status": true,
        "contract": 1,
        "version": SAB_VERSION,
        "nzbfast": env!("CARGO_PKG_VERSION"),
        "paused": d.paused.load(Ordering::Relaxed),
        "pause_int": pause_int(d),
        "speed_bps": d.current_speed_bps(),
        "link_peak": peak_bps,
        "link_peak_src": peak_src,
        "diskspace_gb": free_now.unwrap_or(0) as f64 / 1e9,
        "warnings": warns.len(),
        // Totals BEFORE the page cut, so a client showing "3 of 12" does
        // not have to page the whole list to know there are twelve.
        "queue_total": num(&queue["queue"]["noofslots"]) as u64,
        "history_total": num(&history["history"]["noofslots"]) as u64,
        // Contract ADDITION (TODO 281 AN2, 26 Aug 2026): the daemon's own
        // drain latch, which is a question no client can answer from the
        // lists above. `queue_total == 0` is NOT the same fact: a job that
        // has finished downloading is stamped Completed and retained out of
        // the queue a hundred lines before its record is filed into history
        // (`Daemon::note_queue_idle`), so there is a window in which it is
        // in NEITHER list while its tail - repair, extract, the move - is
        // still running. A phone that read an empty queue as "done" would
        // stop the engine in the middle of that. The latch is set only when
        // the queue walk is quiet AND `postproc_backlog` is zero, and it is
        // re-armed by enqueue, so it is exactly "there is no work left".
        "queue_idle": d.queue_idle_latch.load(Ordering::Relaxed),
        "queue": jobs,
        "history": done,
        "stream": stream_telemetry(d),
    }))
}

/// What the byte-serving path is doing, for a player overlay.
///
/// The counters are cumulative since the daemon started (see
/// `StreamStats`); the settings beside them are what shaped the numbers,
/// so a session that behaved oddly can be read without asking the user
/// for their environment. Names follow
/// research/STREAM-HARDENING-2026-08.md.
fn stream_telemetry(d: &Arc<Daemon>) -> Value {
    let s = &d.hub.stream_stats;
    json!({
        "readers": d.hub.stream_readers.load(Ordering::Relaxed),
        "blocked_reads": s.blocked_reads.load(Ordering::Relaxed),
        "zero_filled_bytes": s.zero_filled_bytes.load(Ordering::Relaxed),
        "runway_mb": stream_runway() / 1_000_000,
        "runway_wait_ms": stream_runway_wait_ms(),
    })
}

fn m_stream_token(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    let id = params
        .get("value")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or_default()
        .to_string();
    // Only for a job that exists. The token is derived, so one could be
    // minted for any string at all - and a client holding a token for an
    // id the daemon has never heard of would be told nothing by the
    // 404 it eventually gets from /stream.
    let known = !id.is_empty()
        && (d.history_job(&id).is_some()
            || d.queue.lock_ok().iter().any(|j| j.lock_ok().nzo_id == id));
    Some(if !known {
        json!({"status": false, "error": "unknown nzo_id"})
    } else {
        json!({
            "status": true,
            "nzo_id": id,
            "token": d.stream_token(&id),
            "stream": stream_url(d, ctx.base, &id),
            // Derived from the install's secret and the job id, so it
            // stays valid as long as the install does: a .strm written
            // into a Jellyfin library may first be played months later.
            // Scope, not lifetime, is what keeps it safe - it starts and
            // serves THIS job and nothing else.
            "expires": Value::Null,
        })
    })
}

pub(in crate::serve) fn dispatch(
    d: &Arc<Daemon>,
    req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    mode: &str,
    ctx: &ApiCtx<'_>,
    api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    match mode {
        // The one compact poll: server state + jobs + per-file playback
        // readiness + byte-serving telemetry.
        "playback" => m_playback(d, req, params, ctx, api_body),
        // The scoped per-job secret for a handed-off URL.
        "stream_token" => m_stream_token(d, req, params, ctx, api_body),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The SAB payloads quote their numbers; the mobile contract hands
    /// back numbers. Anything unparseable is 0, never a panic - the
    /// projection runs on every poll.
    #[test]
    fn quoted_numbers_become_numbers() {
        assert_eq!(num(&json!("91.53")), 91.53);
        assert_eq!(num(&json!(7)), 7.0);
        assert_eq!(num(&json!("0:00:00")), 0.0);
        assert_eq!(num(&Value::Null), 0.0);
    }

    /// `limit` is a page size a phone chose, clamped to something a
    /// daemon can answer without walking a whole history of folders.
    #[test]
    fn limit_defaults_and_clamps() {
        let p = |v: &str| std::collections::HashMap::from([("limit".to_string(), v.to_string())]);
        assert_eq!(limit_of(&std::collections::HashMap::new()), DEFAULT_LIMIT);
        assert_eq!(limit_of(&p("3")), 3);
        assert_eq!(limit_of(&p("9999")), MAX_LIMIT);
        // Nonsense is the default, not an error: this is a poll.
        assert_eq!(limit_of(&p("all")), DEFAULT_LIMIT);
        // ...and so is a borrowed "0 means everything".
        assert_eq!(limit_of(&p("0")), DEFAULT_LIMIT);
    }
}
