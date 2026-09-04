//! The daemon's five-minute local-link poll.
//!
//! The probe itself is `crate::locallink` (TODO 276 item 3): reading
//! which interface carries our traffic, and how fast it is, needs no
//! daemon, and `nzbfast sysbench` on the CLI side asks for exactly that
//! - which made `nettools` depend on `serve` for one call and held a
//! 133,000-line dependency cycle together. What stayed here is the part
//! that owns a `Daemon`: the schedule, the re-judged tune hint, and the
//! `TxMedian` series the daemon accumulates across polls.

use super::*;
pub use nzbfast_core::locallink::*;

/// Probe at startup and every five minutes (laptops roam between Wi-Fi
/// and a dock), against the first enabled server's address, and
/// re-judge the tune hint when the link changes. `NZBFAST_LOCAL_LINK=0`
/// disables it. The probe itself runs on the blocking pool: it shells
/// out, and `system_profiler` can take a second or two.
pub fn spawn(daemon: &std::sync::Arc<super::daemon::Daemon>, config: &std::path::Path) {
    if disabled() {
        return;
    }
    let d = daemon.clone();
    let cfg_path = config.to_path_buf();
    tokio::spawn(async move {
        // §210 (a): the Wi-Fi rate published is the median of the last
        // three probes, not the one frame this probe happened to catch.
        let mut tx = TxMedian::default();
        loop {
            let path = cfg_path.clone();
            let probed = tokio::task::spawn_blocking(move || {
                let cfg = nzbkit::config::Config::load(&path).ok()?;
                let srv = cfg.servers.iter().find(|s| s.enabled)?;
                let ip = target_ip(&srv.host, srv.port)?;
                Some((probe(&ip), cfg))
            })
            .await
            .ok()
            .flatten();
            if let Some((mut link, cfg)) = probed {
                match link.as_mut() {
                    Some(l) => tx.steady(l),
                    // Nothing judgeable here now; what it was before
                    // says nothing about what it will be next.
                    None => tx = TxMedian::default(),
                }
                let changed = {
                    let mut cur = d.local_link.lock_ok();
                    let changed = *cur != link;
                    if changed {
                        match &link {
                            Some(l) => tracing::info!(target: "tune",
                                "local link: {} {:?} {} Mbps {} {}",
                                l.iface, l.kind, l.link_mbps, l.phy, l.channel),
                            None => {
                                tracing::debug!(target: "tune", "local link: not judgeable here")
                            }
                        }
                    }
                    *cur = link;
                    changed
                };
                if changed {
                    super::tunestate::update_tune_hint(
                        &d,
                        &cfg.servers,
                        &crate::conntune::load(&cfg_path),
                    );
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(300)).await;
        }
    });
}
