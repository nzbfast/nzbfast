//! Which configured server a lane should talk to.
//!
//! Three pure selectors over `nzbkit::config::Config`: the one server a
//! single-connection lane dials, the servers worth scanning HEADERS
//! from, and the resolution of a persisted scan-primary key back to its
//! entry. All three answer from `enabled`, `level`, the block-account
//! flags and the backbone grouping and touch nothing else.
//!
//! THEY LIVED IN `nettools`, a BIN module, until the crate-split step 3
//! cut, and the move is the same kind step 1 made ten times: `scan`
//! calls all three and `scan` is `nzbfast-meta`, one layer BELOW the
//! bin. Nothing had reported the edge, because `scan` named them BARE -
//! main.rs carries `use nettools::*;` at its root and a crate-root glob
//! is visible to every descendant module - and `tools/modgraph.py`
//! reads `crate::X` paths, so a bare name resolved through a root glob
//! is precisely the shape it cannot see. The compiler found it the
//! moment the file moved; the fix is to put the selectors under
//! everything that asks, which is here.
//!
//! `find_scan_server` is `#[cfg(feature = "indexer")]` and so is
//! `scan_servers`: both are the index scanner's, and the gate came with
//! them. `load_server` is not - the CLI's one-connection lanes use it in
//! every build.

use anyhow::{Context, Result};
use nzbkit::config::{Config, ServerConfig};
use std::path::Path;

/// The single server a one-connection lane should talk to: the first
/// ENABLED entry, in config order.
///
/// The `enabled` filter is the whole point of this function and is not a
/// refinement. Until 23 Aug 2026 this was `cfg.servers[0].clone()`, which
/// consulted the flag nowhere - so on any install whose FIRST configured
/// server is the switched-off one, every caller here dialled the one
/// account the user had taken out of service. That is not theoretical: it
/// was found in the field holding seven established sockets to a disabled
/// provider, opened by the hourly group-profile sampler
/// (`serve::groupscan::sample_one_group`), while a benchmark round on
/// another machine was using that same shared account. Nothing in the log named the
/// host, because only the download planner prints "<host> disabled - not
/// in the pool" and no download had run - so the switch looked like it was
/// holding for four days while it was not.
///
/// Deliberately an ERROR rather than a fallback to `servers[0]` when
/// everything is off. "The user disabled every server" and "the user has
/// no servers" are the same instruction, and the §154 queue hold already
/// treats them alike; quietly dialling a disabled account to avoid an
/// error message is exactly the behaviour this function is being fixed for.
pub fn load_server(config: &Path) -> Result<ServerConfig> {
    let cfg = Config::load(config).with_context(|| {
        format!(
            "loading {} (copy config.local.json.example?)",
            config.display()
        )
    })?;
    cfg.servers
        .iter()
        .find(|s| s.enabled)
        .cloned()
        .with_context(|| {
            format!(
                "no enabled server in {} ({} configured, all switched off)",
                config.display(),
                cfg.servers.len()
            )
        })
}

/// Resolve a marks server key (see [`nzbkit::index::Index::server_key`])
/// back to its config entry - the scan loop persists only the key.
/// None = the config no longer carries that server, or no longer carries
/// it ENABLED.
///
/// `enabled` is part of "carries". The key is written by the full pass out
/// of [`scan_servers`], which is already enabled-only, but it OUTLIVES the
/// config: a server switched off after the pass that chose it leaves its
/// key in the index until the next full pass re-chooses, and resolving
/// that key unfiltered handed the tip watcher a disabled account to hold a
/// session on. `None` is the right answer and the caller already handles
/// it - it skips the group until the next pass, exactly as it does for a
/// key naming a server that was deleted outright.
#[cfg(feature = "indexer")]
pub fn find_scan_server(config: &Path, key: &str) -> Option<ServerConfig> {
    let cfg = Config::load(config).ok()?;
    cfg.servers
        .iter()
        .find(|s| s.enabled && nzbkit::index::Index::server_key(&s.host) == key)
        .cloned()
}

/// A8 multi-server indexing: the servers worth scanning HEADERS from.
///
/// - enabled only;
/// - never a metered account ([`ServerConfig::may_spend_on_measurement`]:
///   the explicit block-account flag, or a configured prepaid block):
///   OVER traffic is bytes the user's download never asked for, and on a
///   block it burns the credit that exists to rescue missing bodies;
/// - one per backbone: mirrors share a spool, so a second reseller of
///   the same backbone contributes no headers the first didn't. Mirrors
///   are detected by the explicit `group` field first, else by
///   [`nzbkit::oracle::backbone_of`];
/// - ranked level-then-config-order, which is the tiebreak order the
///   per-group primary choice uses.
///
/// An all-metered (but enabled) config falls back to the enabled list
/// unfiltered - a user who configured indexing gets an index; the
/// caller logs that headers are spending billed bytes. Indexing is
/// opt-in and asks before it starts, so someone who turned it on with
/// nothing but metered servers has already chosen to spend on it; the
/// flag reorders who scans, and only silences it where there is a
/// free alternative.
#[cfg(feature = "indexer")]
pub fn scan_servers(cfg: &Config) -> Vec<ServerConfig> {
    let eligible: Vec<&ServerConfig> = {
        let flat: Vec<&ServerConfig> = cfg
            .servers
            .iter()
            .filter(|s| s.enabled && s.may_spend_on_measurement())
            .collect();
        if flat.is_empty() {
            cfg.servers.iter().filter(|s| s.enabled).collect()
        } else {
            flat
        }
    };
    let mut ranked = eligible;
    // Stable: config order survives within a level.
    ranked.sort_by_key(|s| s.level);
    let mut seen = std::collections::HashSet::new();
    ranked
        .into_iter()
        .filter(|s| {
            let backbone = s
                .group
                .clone()
                .unwrap_or_else(|| nzbkit::oracle::backbone_of(&s.host));
            seen.insert(backbone)
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `Config` from a servers array, for the selectors that take one
    /// already parsed. Only `scan_servers` takes one, and it is gated.
    #[cfg(feature = "indexer")]
    fn cfg(servers: serde_json::Value) -> Config {
        serde_json::from_value(serde_json::json!({ "servers": servers })).unwrap()
    }

    /// A8: header scanning never spends block credit, never reads the
    /// same backbone twice (mirrors share a spool), and ranks
    /// level-then-config-order.
    #[cfg(feature = "indexer")]
    #[test]
    fn scan_servers_skip_blocks_and_dedupe_backbones() {
        let c = cfg(serde_json::json!([
            { "host": "news.newshosting.com" },
            // Same SPOOL (another Highwinds reseller): contributes
            // nothing. Eweka would NOT qualify - same owner, own spool.
            { "host": "news.usenetserver.com" },
            // Prepaid block: OVER would burn rescue credit.
            { "host": "news.blocknews.net", "block_bytes": 5_000_000_000u64 },
            // Fill server, flatrate, own backbone: eligible, ranked after
            // the level-0 entries.
            { "host": "news.xsnews.nl", "level": 1 },
            { "host": "news.usenetexpress.com", "enabled": false },
        ]));
        let picked: Vec<String> = scan_servers(&c).into_iter().map(|s| s.host).collect();
        assert_eq!(picked, ["news.newshosting.com", "news.xsnews.nl"]);
    }

    /// M7b.2 §5.7: the block-account flag keeps headers off a metered
    /// server just as a configured block size does, and it works on a
    /// level-0 host - which the block-size inference alone would have
    /// happily scanned.
    #[cfg(feature = "indexer")]
    #[test]
    fn scan_servers_skip_servers_flagged_as_billed_per_byte() {
        let c = cfg(serde_json::json!([
            // Metered by declaration, not by topology: level 0, no block
            // size, and still not somewhere to spend header traffic.
            { "host": "news.eweka.nl", "block_account": true },
            { "host": "news.xsnews.nl" },
        ]));
        let picked: Vec<String> = scan_servers(&c).into_iter().map(|s| s.host).collect();
        assert_eq!(picked, ["news.xsnews.nl"]);
    }

    /// The explicit mirror `group` field outranks hostname clustering:
    /// two hosts the alias map would call separate backbones are one
    /// spool when the user says so.
    #[cfg(feature = "indexer")]
    #[test]
    fn scan_servers_honour_the_mirror_group_field() {
        let c = cfg(serde_json::json!([
            { "host": "news.eweka.nl", "group": "main" },
            { "host": "news.xsnews.nl", "group": "main" },
        ]));
        let picked: Vec<String> = scan_servers(&c).into_iter().map(|s| s.host).collect();
        assert_eq!(picked, ["news.eweka.nl"]);
    }

    /// Write a config to disk - `load_server` and `find_scan_server` both
    /// take a path, because both are called from lanes that re-read the
    /// file rather than hold a parsed copy.
    /// The guard comes back with the path for the reason `tmp_nzb` above
    /// gives.
    fn cfg_file(
        name: &str,
        servers: serde_json::Value,
    ) -> (crate::testscratch::ScratchDir, std::path::PathBuf) {
        let d = crate::testscratch::ScratchDir::attach(
            &std::env::temp_dir().join(format!("nzbfast-nettools-{name}-{}", std::process::id())),
        );
        let p = d.join("config.local.json");
        std::fs::write(&p, serde_json::json!({ "servers": servers }).to_string()).unwrap();
        (d, p)
    }

    /// The 23 Aug 2026 defect, at the helper every one-connection
    /// lane goes through: with the DISABLED account sorted first, this
    /// used to hand it straight back.
    #[test]
    fn load_server_skips_a_switched_off_server_however_early_it_sorts() {
        let (_scratch, p) = cfg_file(
            "off-first",
            serde_json::json!([
                { "host": "news.newshosting.com", "enabled": false },
                { "host": "news.giganews.com" },
            ]),
        );
        assert_eq!(load_server(&p).unwrap().host, "news.giganews.com");
    }

    /// All off is an instruction, not a config error to route around. A
    /// fallback to `servers[0]` here would reintroduce the whole defect
    /// for the single-server install that switched its one server off.
    #[test]
    fn load_server_refuses_when_every_server_is_switched_off() {
        let (_scratch, p) = cfg_file(
            "all-off",
            serde_json::json!([
                { "host": "news.newshosting.com", "enabled": false },
                { "host": "news.eweka.nl", "enabled": false },
            ]),
        );
        let e = load_server(&p).unwrap_err().to_string();
        assert!(
            e.contains("no enabled server"),
            "the error must say WHICH rule stopped it, got: {e}"
        );
    }

    /// A `scan_primary:<group>` key outlives the config that produced it,
    /// so resolving one has to re-check `enabled` - otherwise the tip
    /// watcher holds a session on an account switched off after the pass
    /// that chose it.
    #[cfg(feature = "indexer")]
    #[test]
    fn find_scan_server_does_not_resurrect_a_disabled_primary() {
        let (_scratch, p) = cfg_file(
            "stale-primary",
            serde_json::json!([
                { "host": "news.newshosting.com", "enabled": false },
                { "host": "news.giganews.com" },
            ]),
        );
        let stale = nzbkit::index::Index::server_key("news.newshosting.com");
        assert!(
            find_scan_server(&p, &stale).is_none(),
            "a primary key naming a disabled server must resolve to None"
        );
        let live = nzbkit::index::Index::server_key("news.giganews.com");
        assert_eq!(
            find_scan_server(&p, &live).map(|s| s.host),
            Some("news.giganews.com".to_string()),
            "an enabled primary must still resolve"
        );
    }

    /// An all-block config still gets an index: the user configured
    /// indexing, and "no index at all" is worse than spending credit.
    #[cfg(feature = "indexer")]
    #[test]
    fn scan_servers_fall_back_to_blocks_when_nothing_else_exists() {
        let c = cfg(serde_json::json!([
            { "host": "news.blocknews.net", "block_bytes": 5_000_000_000u64 },
            { "host": "news.abavia.com", "enabled": false },
        ]));
        let picked: Vec<String> = scan_servers(&c).into_iter().map(|s| s.host).collect();
        assert_eq!(picked, ["news.blocknews.net"]);
    }
}
