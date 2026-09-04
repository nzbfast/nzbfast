//! The two writes a finished connection ladder makes into DAEMON state:
//! the dashboard's shaped-host mirror, and the line-speed verdict.
//!
//! Both were in `tasks/tuner.rs` beside the lane that runs the ladder,
//! and both are called from outside that lane - `api::servers` after a
//! manual Test, `settings` when the line speed is edited, `locallink`
//! when the local link is re-measured. Neither of those has any business
//! reaching into the background-task layer, and neither function is part
//! of the lane: they read `d.shaped_hosts`, `d.line_speed`,
//! `d.local_link` and `d.tune_hint`, which are `Daemon` fields, off the
//! `conntune` store, which is a core module. The ladder is the lane; this
//! is the state it leaves behind.
//!
//! Verbatim from `tuner.rs`, visibility unchanged.

use super::*;

/// Re-point the dashboard's shaped mirror at what the store now says
/// for one host, after a ladder result has been recorded.
///
/// The store is the authority (`reconcile`: a trusted ladder is a fresh
/// reference and clears the flag), but `d.shaped_hosts` is a separate
/// in-memory map, and the only place it was reconciled with the store
/// is the live tuner's clean-epoch branch. With live tuning off, or
/// between downloads, nothing ran it - so a host whose flag a ladder
/// had just cleared kept telling the queue payload it was shaped, for
/// the life of the daemon. Called from BOTH ladder paths, the manual
/// Test and the idle auto probe.
pub fn mirror_shaped(d: &Daemon, config: &std::path::Path, host: &str) {
    let stored = crate::conntune::load(config)
        .get(host)
        .and_then(|t| t.shaped.clone());
    let mut m = d.shaped_hosts.lock_ok();
    match stored {
        Some(s) => {
            m.insert(host.to_string(), s);
        }
        None => {
            m.remove(host);
        }
    }
}

/// Judge measured provider capability against the user's stated line
/// speed (`line_speed`, the Settings hint of what the connection can
/// do) and store the verdict in `tune_hint` for the dashboard. Called
/// after every ladder - auto probe or manual run.
///
/// Only judges with a FULL picture: line speed set, and every enabled
/// server probed. A missing probe reads as capability the daemon
/// can't see yet, and a false "your setup is short" is worse than
/// saying nothing.
///
/// Two ways to be wrong, so two bands: well under the line (providers
/// are the lever) and well OVER it (the setting is the lever - the
/// ladder never stops measuring at the line speed, so a stale 300M on a
/// gigabit link shows up here rather than silently capping the reading).
/// In between, the setup covers the line and the hint clears.
pub fn update_tune_hint(
    d: &Daemon,
    servers: &[nzbkit::config::ServerConfig],
    tuned: &std::collections::HashMap<String, crate::conntune::Tuned>,
) {
    let expected_bps = d.line_speed.load(Ordering::Relaxed);
    // §210: the local link comes first, because it is the yardstick.
    // A Wi-Fi link or a port negotiated under the line caps what ANY
    // provider can show, so the provider verdict below is scored
    // against the lower of the two - otherwise a 710 Mbit line over a
    // 1200 Mbps Wi-Fi link reads "providers are short" forever, and
    // the lever it names (a faster provider) cannot help.
    let link = d.local_link.lock_ok().clone();
    let link_verdict = link
        .as_ref()
        .map(|l| l.verdict(expected_bps))
        .unwrap_or_default();
    let yardstick = link
        .as_ref()
        .and_then(|l| l.ceiling_bps())
        .filter(|c| *c < expected_bps)
        .unwrap_or(expected_bps);
    let mut hint = String::new();
    let enabled: Vec<_> = servers.iter().filter(|s| s.enabled).collect();
    // Only the servers the prober will ever measure. It skips metered
    // accounts on purpose (a ladder would spend the user's own money),
    // so requiring EVERY enabled server to carry an entry meant one
    // enabled block account suppressed the line-speed verdict for the
    // whole install, permanently and with nothing in the log saying
    // why. Same predicate as the prober's, deliberately - see
    // `may_spend_on_measurement`.
    let measured: Vec<_> = enabled
        .iter()
        .copied()
        .filter(|s| s.may_spend_on_measurement())
        .collect();
    // Key presence is NOT proof of measurement. `note_capped` creates an
    // entry for a host that has never run a ladder - the whole point is
    // to remember a cap on a provider that never got a clean probe - and
    // it carries `connections: 0`, which every knee consumer already
    // reads as "nothing measured". Treating it as measured summed its
    // zero Gbps, so the hint could claim the fleet covers half the line
    // and recommend a faster provider on the strength of a host nobody
    // had timed (Codex sweep 5, M8).
    let is_measured = |h: &str| tuned.get(h).is_some_and(|t| t.connections > 0);
    if expected_bps > 0 && !measured.is_empty() && measured.iter().all(|s| is_measured(&s.host)) {
        let cap_bytes: f64 = measured.iter().map(|s| tuned[&s.host].gbps).sum::<f64>() * 1e9 / 8.0;
        let pct = (100.0 * cap_bytes / yardstick as f64).round() as u64;
        if cap_bytes > expected_bps as f64 * 1.1 {
            // The ladder deliberately measures PAST the line speed, so a
            // reading well above it is not an error - it means the number
            // in Settings is stale (an unchanged 300M after a gigabit
            // upgrade). Say so: percentage speed limits are computed from
            // it, so a low setting silently throttles them too.
            hint = format!(
                "providers measured ~{:.0} Mbps together, {pct}% of the ~{:.0} Mbps \
                 Line speed set in Settings - the setting looks low, raise it so \
                 percentage speed limits and these readings are right",
                cap_bytes * 8.0 / 1e6,
                expected_bps as f64 * 8.0 / 1e6
            );
        } else if cap_bytes < yardstick as f64 * 0.8 {
            let meas = cap_bytes * 8.0 / 1e6;
            let want = yardstick as f64 * 8.0 / 1e6;
            let mut tips: Vec<String> = Vec::new();
            for s in &measured {
                let t = &tuned[&s.host];
                // Against what the ladder ASKED for, not what the server
                // is configured for. The ladder stops at the knee, so on
                // a server set to 20 whose knee is 8 it may never ask
                // beyond 16 - and comparing against 20 then told the
                // user their account tier was capping them, using a
                // number nothing had requested. `asked == 0` is an entry
                // from before the field existed: unknown, so say
                // nothing.
                // The knee rung against what it was actually granted -
                // "32 asked, 21 granted" - not against the CONFIGURED
                // count. The ladder stops at the knee, so on a server set
                // to 20 whose knee is 8 it may never ask beyond 16, and
                // comparing against 20 told the user their account tier
                // was capping them using a number nothing had requested.
                // `connections` is already clamped to the granted count
                // at that rung, so the pair is exact. `asked == 0` is an
                // entry from before the field existed: unknown, so say
                // nothing.
                if t.asked > 0 && t.asked > t.connections {
                    tips.push(format!(
                        "{} granted only {} of the {} connections asked for - the \
                         account tier may cap it",
                        s.host, t.connections, t.asked
                    ));
                }
            }
            if measured.len() == 1 {
                tips.push("a second provider adds parallel headroom".into());
            } else if tips.is_empty() {
                tips.push("a faster provider (or one more) is the likely lever".into());
            }
            // Name what the figure was scored against: the line the
            // user typed, or the local link when that is lower.
            let what = if yardstick < expected_bps {
                "this machine's link can carry"
            } else {
                "line"
            };
            hint = format!(
                "providers measured ~{meas:.0} Mbps together, {pct}% of the \
                 ~{want:.0} Mbps {what} - well short. {}",
                tips.join("; ")
            );
        }
    }
    let hint = match (link_verdict.is_empty(), hint.is_empty()) {
        (true, _) => hint,
        (false, true) => link_verdict,
        (false, false) => format!("{link_verdict}. Also: {hint}"),
    };
    let mut cur = d.tune_hint.lock_ok();
    if *cur != hint {
        if hint.is_empty() {
            info!(target: "tune", "provider capability now covers the stated line speed");
        } else {
            info!(target: "tune", "{hint}");
        }
        *cur = hint;
    }
}
