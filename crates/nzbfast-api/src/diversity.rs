//! The diversity card's article-id sample: discover a set of message-ids
//! spanning a range of ages, so the per-provider retention comparison has
//! a shared basis to score against.
//!
//! MOVED HERE FROM `serve/mod.rs` by lane 3 of Option C. It was a free
//! function of serve's ROOT, reachable as a bare name through the root's
//! own scope, and its ONE caller is `api::servers`'s Analyze arm - so
//! with the api layer leaving the bin it had to move with the caller or
//! become a cross-layer edge from `api` up into `wiring`, which
//! `tools/modgraph.py --serve --check` refuses. It reaches nothing above
//! the daemon layer.

/// Discover an article sample spanning a range of ages for the diversity
/// sweep: recent articles (last few thousand) plus progressively older
/// ranges, so retention limits and takedowns actually differentiate the
/// providers. Uses the first reachable server for discovery.
///
/// "First" is ranked ENABLED FIRST, in config order, and the walk stops
/// at the first server that actually yields a sample. Until 23 Aug 2026
/// this was a bare `servers.first()` with no fallback of any kind, which
/// is the `servers[0]`-with-no-`enabled`-test shape the disabled-server
/// sweep of that day went looking for: on an install whose FIRST
/// configured server is the switched-off one, the sample - and so the
/// shared basis every provider in the report is scored against - came
/// off the one account the user had taken out of service. The same line
/// made a first server that is merely UNREACHABLE fail the whole card,
/// though the sentence above has promised "first reachable" throughout.
///
/// A disabled server is a LAST RESORT here rather than a refusal, and
/// that arm is load-bearing rather than defensive. `m_diversity` hands
/// this the ENABLED servers only, so the ranking above is normally the
/// whole story - but that caller has an opt-in (`value=1`) for the "is
/// this account worth turning back on?" case, and on that path the list
/// carries switched-off entries deliberately. They must still be the
/// last thing tried, and an opt-in run against an all-disabled config
/// must still discover a sample rather than refuse, or the opt-in does
/// nothing on the one config that most needs it.
pub(crate) async fn sample_ids_for_diversity(
    servers: &[nzbkit::config::ServerConfig],
    group: &str,
) -> std::result::Result<Vec<String>, String> {
    let mut last = String::new();
    for srv in servers
        .iter()
        .filter(|s| s.enabled)
        .chain(servers.iter().filter(|s| !s.enabled))
    {
        match sample_ids_from_server(srv, group).await {
            Ok(ids) => return Ok(ids),
            // Keep walking: the point of the ranking is that a candidate
            // that cannot answer costs the next one nothing.
            Err(e) => last = e,
        }
    }
    Err(if last.is_empty() {
        "no servers configured".to_string()
    } else {
        last
    })
}

/// One candidate's half of [`sample_ids_for_diversity`]: connect, walk
/// five age bands, hang up. Split out so the ranking above reads as a
/// plain walk over candidates rather than as control flow wrapped around
/// a connection.
async fn sample_ids_from_server(
    srv: &nzbkit::config::ServerConfig,
    group: &str,
) -> std::result::Result<Vec<String>, String> {
    use nzbkit::nntp::Connection;
    let (mut conn, _) = Connection::connect(srv).await.map_err(|e| e.to_string())?;
    let g = match conn.group(group).await {
        Ok(g) => g,
        Err(e) => {
            // Hang up before moving on. A candidate that greeted us and
            // then refused the group still holds a session on that
            // account until it times out, and the next candidate in the
            // walk may be the same provider under another brand.
            conn.quit().await;
            return Err(e.to_string());
        }
    };
    let mut ids = Vec::new();
    // Five age bands across the group's article-number range.
    let span = g.high.saturating_sub(g.low).max(1);
    for band in 0..5u64 {
        let center = g.high.saturating_sub(span * band / 5);
        let from = center.saturating_sub(2_000).max(g.low);
        if let Ok(entries) = conn.over(from, center).await {
            // ≥150 KB: the sample doubles as the per-server speed probe's
            // fetch set, and header-only posts would understate it.
            for e in entries
                .into_iter()
                .filter(|e| !e.message_id.is_empty() && e.bytes >= 150_000)
                .take(20)
            {
                ids.push(nzbkit::sysbench::bracket_id(&e.message_id));
            }
        }
    }
    conn.quit().await;
    if ids.is_empty() {
        return Err("no sample articles found".into());
    }
    Ok(ids)
}

/// The diversity card's id sample must not be discovered from a server
/// the user switched off while an enabled one is sitting right there.
///
/// Same shape as the disabled-server sweep of 23 Aug 2026, which found a
/// machine holding live sockets to a provider marked `"enabled": false`
/// while another machine was using that same shared account: a lane took
/// `servers[0]` and consulted the flag nowhere. This one is reached by an
/// explicit click rather than by a background tick, so it is the milder
/// case - but it is the same line, and the sample it discovers is the
/// shared basis every provider in the report is scored against.
///
/// Both listeners hang up on the greeting, so no sample can succeed and
/// the call is expected to fail. That is the point: the assertion is on
/// WHICH accounts the walk reached and in what ORDER, which is the only
/// thing this ranking decides. The old `servers.first()` line reaches the
/// disabled listener and nothing else, so it fails here twice over.
#[cfg(test)]
mod diversity_sample_prefers_an_enabled_server {
    use std::sync::mpsc;

    /// A listener that reports the moment it accepts, then hangs up.
    ///
    /// Hanging up rather than going silent matters: `Connection::connect`
    /// has its own multi-second ceiling, and a listener that accepts and
    /// then says nothing makes every run of this test pay a network
    /// timeout it is not measuring.
    fn spy(tx: mpsc::Sender<&'static str>, tag: &'static str) -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((s, _)) = l.accept() {
                // Send BEFORE the shutdown, so the report is on the
                // channel before the client can observe the hang-up and
                // move to the next candidate. That is what makes the
                // order assertion below deterministic rather than a race.
                let _ = tx.send(tag);
                let _ = s.shutdown(std::net::Shutdown::Both);
            }
        });
        port
    }

    fn server(port: u16, enabled: bool) -> nzbkit::config::ServerConfig {
        serde_json::from_value(serde_json::json!({
            "host": "127.0.0.1", "port": port, "tls": false,
            "enabled": enabled, "connections": 1
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn the_switched_off_server_is_the_last_candidate_not_the_first() {
        let (tx, rx) = mpsc::channel();
        // The incident's shape exactly: the DISABLED account is first in
        // the array, which is the position the old line took outright.
        let off = spy(tx.clone(), "disabled");
        let on = spy(tx, "enabled");
        let servers = [server(off, false), server(on, true)];

        let r = super::sample_ids_for_diversity(&servers, "alt.binaries.test").await;
        assert!(r.is_err(), "a listener that hangs up cannot yield a sample");

        let reached: Vec<&str> = rx.try_iter().collect();
        assert_eq!(
            reached,
            ["enabled", "disabled"],
            "the sample walk must try the ENABLED server first and reach a \
             switched-off one only after every enabled candidate has failed"
        );
    }

    /// The fallback is deliberate, so it is pinned: an all-disabled config
    /// still gets its sample discovered rather than a refusal. Which
    /// accounts the Analyze button may touch is a decision for its caller,
    /// not something this helper should settle by erroring.
    #[tokio::test]
    async fn an_all_disabled_config_still_walks_its_servers() {
        let (tx, rx) = mpsc::channel();
        let only = spy(tx, "disabled");
        let servers = [server(only, false)];

        let _ = super::sample_ids_for_diversity(&servers, "alt.binaries.test").await;

        assert_eq!(
            rx.try_iter().collect::<Vec<_>>(),
            ["disabled"],
            "with nothing enabled the walk must still reach the one \
             configured server"
        );
    }

    #[tokio::test]
    async fn an_empty_server_list_is_still_an_error() {
        let r = super::sample_ids_for_diversity(&[], "alt.binaries.test").await;
        assert_eq!(r.unwrap_err(), "no servers configured");
    }
}
