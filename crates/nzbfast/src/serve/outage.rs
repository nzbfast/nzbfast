//! What the UI says about a news server that is granting no sessions:
//! the outage window, the queue row's token, and the live census the
//! Providers card renders.
//!
//! Lifted out of `daemon.rs` unchanged (TODO 106's ratchet - that file
//! is at its size ceiling, and this block owes nothing to the `Daemon`
//! struct it was sitting beside). `server_outages` reads the live pool
//! through `Daemon`, which is why the module is here in `serve` rather
//! than in `nzbkit`; everything else in it takes plain values.

use super::*;

/// How long a server must have been granting NO sessions before the
/// queue row says so, in seconds. Long enough that an ordinary redial,
/// a capacity bounce or a router blip passes unremarked; short enough
/// that a user watching a row at 0 B/s is told why well inside the
/// pool's ~10 minute outage horizon.
///
/// Env-tunable for tests only - nothing in the UI offers it.
pub fn server_down_secs() -> u64 {
    std::env::var("NZBFAST_SERVER_DOWN_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60)
}

/// A configured server that is granting no sessions right now, as the
/// API and the queue row report it. Sampled from the live pool, which
/// is why it only exists while something is downloading.
#[derive(Debug, Clone)]
pub struct ServerOutage {
    pub host: String,
    /// Unix ms the episode began. Stable for its whole life (the gauge
    /// is set once and cleared on recovery), so it is what identifies
    /// an episode - `secs` drifts by a tick and cannot.
    pub since_ms: u64,
    /// Seconds since the first dial of this episode failed.
    pub secs: u64,
    /// `unreachable` | `refused` | `capacity` - see
    /// [`nzbkit::pool::DownReason`].
    pub kind: &'static str,
    /// The server's own words, verbatim.
    pub detail: String,
}

/// Which outage the QUEUE ROW reports, if any, and as which token.
///
/// Two rules, both deliberate. The row speaks only while the job is in
/// an open stall episode: a dead backup on a job downloading at full
/// speed belongs on the Providers card, not as an alarm on a working
/// row. And the outage must have outlived [`server_down_secs`], so an
/// ordinary redial or a capacity bounce that clears in seconds never
/// reaches the user at all.
///
/// `outages` arrives longest-first, so the first match is the worst.
pub fn row_outage(
    stalled: bool,
    outages: &[ServerOutage],
) -> Option<(&'static str, &ServerOutage)> {
    if !stalled {
        return None;
    }
    let win = server_down_secs();
    let o = outages.iter().find(|o| o.secs >= win)?;
    let tok = match o.kind {
        "refused" => "server_refused",
        "capacity" => "server_capacity",
        _ => "server_unreachable",
    };
    Some((tok, o))
}

/// Every server currently in an outage, worst (longest) first.
///
/// Reported whatever the rest of the pool is doing: a dead BACKUP on an
/// otherwise healthy job is a real fact about a paid-for provider, and
/// the Providers card is the right place for it. The queue row applies
/// its own extra gate (see `row_outage` above, which speaks only inside
/// an open stall episode and only past `server_down_secs`) so a job that
/// is downloading fine never shouts about it.
pub fn server_outages(d: &Daemon) -> Vec<ServerOutage> {
    let mut v: Vec<ServerOutage> = d
        .hub
        .pool_live
        .lock_ok()
        .as_ref()
        .map(|l| {
            l.servers
                .iter()
                .filter_map(|s| {
                    let secs = s.down_secs()?;
                    let r = s.down_reason.lock_ok().clone()?;
                    Some(ServerOutage {
                        host: s.host.clone(),
                        since_ms: s.down_since.load(Ordering::Relaxed),
                        secs,
                        kind: r.kind,
                        detail: r.detail,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    v.sort_by_key(|o| std::cmp::Reverse(o.secs));
    v
}
