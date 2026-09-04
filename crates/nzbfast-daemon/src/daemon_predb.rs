//! The pre feed's connection - whether to open it, what it is doing,
//! and what to open. A child module of `daemon` rather than more lines
//! of it (TODO 106, the code-quality refactor).
//!
//! One subject at three moments, which is why it is one module.
//! BEFORE: `predb_feed_on` is the two-switch admission - its own,
//! because this is an outbound connection to a network nothing else
//! here talks to, and the indexer's, because what the feed hears is
//! written into the index database. WHAT TO OPEN:
//! `predb_irc_config` turns the stored settings into a connection
//! description. WHILE IT RUNS: `predb_say` records what the feed is
//! doing for the settings card.
//!
//! A second `impl Daemon` in a child module of `daemon`, so `Daemon`'s
//! private fields (`predb.enabled`, `index_enabled`, `predb.status`,
//! and the settings path the config is read from) stay in scope exactly
//! as they were inline. `pub(super)` became `pub(crate)`
//! here, because `super` is `daemon` from inside a child.
//!
//! No cfg on the module - the per-item `indexer` gates move with the
//! items, which is the shape daemon_indexgate.rs already uses.

use super::*;

impl Daemon {
    /// Should the pre feed be connected right now?
    ///
    /// Two switches, both required. Its own, because it is an outbound
    /// connection to a network nothing else here talks to. The indexer's,
    /// because the feed writes into the index database and names indexed
    /// releases - with the indexer off there is nothing for it to name
    /// and nowhere to put what it hears.
    #[cfg(feature = "indexer")]
    pub fn predb_feed_on(&self) -> bool {
        self.predb.enabled.load(Ordering::Relaxed) && self.index_enabled.load(Ordering::Relaxed)
    }

    /// Record what the feed is doing, for the settings card.
    #[cfg(feature = "indexer")]
    pub fn predb_say(&self, what: &str) {
        *self.predb.status.lock_ok() = what.to_string();
    }

    /// Turn the stored settings into a connection description.
    #[cfg(feature = "indexer")]
    pub fn predb_irc_config(&self) -> nzbkit::predb::IrcConfig {
        let raw = self.predb.server.lock_ok().trim().to_string();
        // `host`, `host:port`, `[v6]`, `[v6]:port`. The bracket form has
        // to be split before the last colon is consulted, or every
        // literal IPv6 address reads as a host with a nonsense port.
        let (host, port) = if let Some(rest) = raw.strip_prefix('[') {
            match rest.split_once("]:") {
                Some((h, p)) => (
                    h.to_string(),
                    p.parse().unwrap_or(nzbkit::predb::DEFAULT_PORT),
                ),
                None => (
                    rest.trim_end_matches(']').to_string(),
                    nzbkit::predb::DEFAULT_PORT,
                ),
            }
        } else {
            match raw.rsplit_once(':') {
                Some((h, p)) => match p.parse::<u16>() {
                    Ok(n) => (h.to_string(), n),
                    Err(_) => (raw.clone(), nzbkit::predb::DEFAULT_PORT),
                },
                None => (raw.clone(), nzbkit::predb::DEFAULT_PORT),
            }
        };
        nzbkit::predb::IrcConfig {
            host: if host.is_empty() {
                nzbkit::predb::DEFAULT_HOST.to_string()
            } else {
                host
            },
            port,
            // TLS, and no automatic downgrade. What TLS buys here is not
            // privacy (the channel is public) but ATTRIBUTION: without
            // it, anyone on the path can block 6697, answer on 6667 and
            // inject release names the exact legs go on to match
            // automatically. An operator whose network has no TLS relay
            // opts back in with NZBFAST_PREDB_ALLOW_PLAINTEXT.
            tls: true,
            allow_plaintext: std::env::var_os("NZBFAST_PREDB_ALLOW_PLAINTEXT")
                .is_some_and(|v| v == "1"),
            nick: self.predb.nick.lock_ok().clone(),
            channels: self
                .predb
                .channels
                .lock_ok()
                .split(',')
                .map(str::trim)
                .filter(|c| !c.is_empty())
                .map(str::to_string)
                .collect(),
        }
    }
}
