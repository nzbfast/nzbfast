//! The Providers card's connection-cap payload: what a host granted
//! before it refused, and what the next download plans to open.
//!
//! Read by the `stats` mode, which builds the rest of its answer from
//! daemon state; these three build theirs from the conntune store and
//! the pool's live counters, which is a different subject and its own
//! file.

use super::*;

/// One host's observed connection ceiling, as the dashboard reads it.
fn cap_json(c: &crate::conntune::Capped) -> Value {
    json!({"granted_hi": c.granted_hi, "capped_at": c.capped_at, "since": c.since})
}

/// The running job's view of a provider's ceiling, merged with what
/// this daemon session already knew.
///
/// Both halves are high-waters of the same measurement, so the merge is
/// a max - and either half can be the fresher one. The pool's is newer
/// while a job runs and the cap tightens; the session's is newer for
/// the first seconds of a job, before this provider has been asked for
/// more than it will give, which is exactly the window the row used to
/// spend saying "using 12 of 100".
///
/// `None` until SOMETHING has heard a capacity refusal from this host.
pub(super) fn cap_payload(d: &Daemon, s: &nzbkit::pool::ServerLive) -> Option<Value> {
    let live = s.capped_since.load(Ordering::Relaxed);
    // Session memory has to be retired by the same proof the pool's own
    // gauge is: holding MORE sessions than a recorded ceiling says that
    // ceiling is no longer one. `ConnGauge::up` does this for the live
    // gauge (sweep 5, L6) but can only retire a cap THAT gauge
    // recorded, and the job which disproves a ceiling is usually the
    // one AFTER the job that met it - whose gauge is empty. Without
    // this half the row went on reading "using 100 of 38" until the
    // daemon restarted, which is the wrong connection budget presented
    // as a measurement (Codex sweep 6, N4).
    let seen = {
        let mut m = d.capped_hosts.lock_ok();
        let held = s.connected.load(Ordering::Relaxed);
        if m.get(&s.host).is_some_and(|c| c.disproven_by(held)) {
            m.remove(&s.host);
        }
        m.get(&s.host).cloned()
    };
    if live == 0 {
        return seen.as_ref().map(cap_json);
    }
    let (g0, a0, t0) = seen.map_or((0, 0, u64::MAX), |c| (c.granted_hi, c.capped_at, c.since));
    Some(json!({
        "granted_hi": s.granted_hi.load(Ordering::Relaxed).max(g0),
        "capped_at": s.capped_at.load(Ordering::Relaxed).max(a0),
        "since": live.min(t0),
    }))
}

/// What the NEXT download would open on each configured server.
///
/// The live `servers` list comes from the job pool, so it is empty
/// whenever nothing is downloading - and the Providers card, the only
/// place in the product that shows a connection count, hides itself when
/// that list is empty. Turn auto-tune on, then look at an idle
/// dashboard, and there is nowhere at all that answers "how many
/// connections am I going to use". Reported by a tester on 4 Aug, who
/// had just re-enabled auto-tune and therefore most needed the answer.
///
/// So an idle daemon reports the PLAN instead of nothing: the same
/// shape, `connected: 0`, and a budget computed through the very
/// function the download path uses (`applied_connections`), so this can
/// never drift into describing a number jobs would not actually open.
/// `idle: true` marks them, because "0/16 now" and "16 next time" are
/// different sentences and the UI has to be able to tell them apart.
pub(super) fn planned_servers(d: &Daemon, cfg_path: &std::path::Path) -> Vec<Value> {
    let Ok(c) = nzbkit::config::Config::load(cfg_path) else {
        return Vec::new();
    };
    let store = crate::conntune::load(cfg_path);
    let apply_knees = crate::conntune::enabled(cfg_path);
    // With the live controller on, the next download SEEDS from the
    // bucket store and the knee does not cap - report that number, not
    // the knee-capped one this install would no longer open.
    let live_tune = d.live_tune.load(Ordering::Relaxed) || crate::conntune::live_tune_on();
    let bkt = crate::conntune::bucket_of(crate::conntune::local_hour());
    let now = epoch_secs();
    let shaped = d.shaped_hosts.lock_ok();
    let capped = d.capped_hosts.lock_ok();
    let global = d.connections.load(Ordering::Relaxed).max(1);
    // TODO 208 item 1: the line-aware cap the next build will seed
    // under, so "using M of N" shows the number the job will open.
    // TODO 277: from the SAME anchor the runner stamps on the hub at
    // job start, or this card would promise a fleet the next job would
    // not open on a line fast enough to grow it.
    let (anchor_bps, _) = d.link_peak.effective(d.line_speed.load(Ordering::Relaxed));
    let line_share =
        crate::conntune::line_cap_share(c.servers.iter().filter(|s| s.enabled).count(), anchor_bps);
    c.servers
        .iter()
        .filter(|s| s.enabled)
        .map(|s| {
            let mut base = global.min(s.connections.max(1) as usize);
            if let Some(share) = line_share
                && !s.pin_connections
            {
                base = base.min(share);
            }
            let budget = if live_tune && !s.pin_connections {
                crate::conntune::seed_connections(store.get(&s.host), bkt, now, base)
            } else {
                crate::conntune::applied_connections(
                    base,
                    s.pin_connections,
                    apply_knees.then(|| store.get(&s.host)).flatten(),
                    now,
                )
            };
            json!({
                "host": s.host,
                "budget": budget,
                "connected": 0,
                "bytes": 0,
                "tried": 0,
                "missing": 0,
                "idle": true,
                // Decay flag (conn-tuning design §6): this host fell to
                // under half its usual per-connection rate.
                "shaped": shaped.get(&s.host).map(|sh| json!({
                    "since": sh.since, "ref_per_conn_bps": sh.ref_per_conn_bps})),
                // Nothing is downloading, so there is no pool half to
                // merge: this is purely what the session has already
                // seen this provider refuse.
                "capped": capped.get(&s.host).map(cap_json),
            })
        })
        .collect()
}

#[cfg(test)]
#[path = "caps_tests.rs"]
mod caps_tests;
