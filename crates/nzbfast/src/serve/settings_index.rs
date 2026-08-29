//! The indexer family's own `apply_setting` validators (TODO 106).
//!
//! settings.rs crossed the size gate's 3,000-line file ceiling as the
//! §131 rungs landed - the predb feed, the scoreboard, Spotnet, eviction
//! and the gate expression each brought a setter with it. They are one
//! subject and they moved here whole; the dispatch table itself did not
//! move, so both source-scanning guards on `apply_setting` still read
//! every arm where they always did (settings.rs + settings_apply.rs).
//!
//! A child module of `settings` like settings_apply, so `use super::*`
//! names `Daemon`, `ConfigCtx` and the shared helpers exactly as the
//! inline definitions did, and the parent globs these back in.

use super::*;

pub(super) fn set_predb_enabled(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let on = v == "1" || v.eq_ignore_ascii_case("true");
        let was = d.predb_enabled.swap(on, Ordering::Relaxed);
        if on != was {
            // The listener polls this flag; say what changed rather
            // than leaving an outbound connection to appear in
            // somebody's firewall log unexplained.
            *d.predb_status.lock_ok() = String::new();
            if on {
                info!(
                    target: "predb",
                    "pre feed ON - connecting to {} and listening on {}",
                    d.predb_server.lock_ok(),
                    d.predb_channels.lock_ok()
                );
            } else {
                info!(target: "predb", "pre feed off - the connection closes and nothing is fetched");
            }
        }
        (true, json!(on))
    })
}

pub(super) fn set_predb_corr_enabled(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let on = v == "1" || v.eq_ignore_ascii_case("true");
        let was = d.predb_corr_enabled.swap(on, Ordering::Relaxed);
        if on != was {
            info!(
                target: "predb",
                "correlation {} - obfuscated posts {} suggested names from pre timing+size",
                if on { "ON" } else { "off" },
                if on { "get" } else { "no longer get" }
            );
        }
        (true, json!(on))
    })
}

pub(super) fn set_predb_corr_auto(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let on = v == "1" || v.eq_ignore_ascii_case("true");
        let was = d.predb_corr_auto.swap(on, Ordering::Relaxed);
        if on != was {
            info!(
                target: "predb",
                "auto-apply {} - strong unique correlations {}",
                if on { "ON" } else { "off" },
                if on {
                    "become display names without a click (revocable, never renames files)"
                } else {
                    "stay suggestions"
                }
            );
        }
        (true, json!(on))
    })
}

#[cfg(feature = "indexer")]
pub(super) fn set_predb_max_rows(
    d: &Arc<Daemon>,
    name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let uint = || {
        v.trim()
            .parse::<u64>()
            .map_err(|_| format!("{name}: not a number"))
    };
    Ok({
        // Clamped rather than rejected: this is a capacity knob, and
        // a number outside the sane range is a typo, not a request.
        let n = uint()?.clamp(
            super::predb_seed::PREDB_MAX_ROWS_MIN,
            super::predb_seed::PREDB_MAX_ROWS_MAX,
        );
        d.predb_max_rows.store(n, Ordering::Relaxed);
        info!(target: "predb", "feed table capped at {n} pre row(s)");
        (true, json!(n))
    })
}

pub(super) fn set_scoreboard_enabled(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let on = v == "1" || v.eq_ignore_ascii_case("true");
        let was = d.scoreboard_enabled.swap(on, Ordering::Relaxed);
        if on != was {
            // Same courtesy as the pre feed: this switch creates daily
            // outbound requests to a third party, so say so.
            if on {
                // Name the source the way the sampler will resolve it:
                // the chosen account's name, or the manual URL.
                let from = {
                    let src = d.scoreboard_source.lock_ok().clone();
                    if src.is_empty() {
                        d.scoreboard_url.lock_ok().clone()
                    } else {
                        src
                    }
                };
                info!(
                    target: "scoreboard",
                    "parity scoreboard ON - one daily sample per category from {from}",
                );
            } else {
                info!(target: "scoreboard", "parity scoreboard off - nothing is sampled");
            }
        }
        (true, json!(on))
    })
}

pub(super) fn set_scoreboard_url(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let s = v.trim().trim_end_matches('/').to_string();
        if !s.is_empty() && !(s.starts_with("http://") || s.starts_with("https://")) {
            return Err("scoreboard_url: expected an http(s) newznab base URL".into());
        }
        // The key travels in its own field. A pasted ?apikey=... would
        // otherwise ride into every log line and the settings echo -
        // and the URL IS echoed, unlike the key.
        if s.contains('?') {
            return Err(
                "scoreboard_url: paste the base URL only - the API key has its own field".into(),
            );
        }
        *d.scoreboard_url.lock_ok() = s.clone();
        (true, json!(s))
    })
}

pub(super) fn set_scoreboard_source(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // The name of one of the user's own indexer accounts. Checked
        // against the live list so a typo through the raw API fails
        // loudly here rather than as a status line tomorrow; the UI
        // only ever offers names that exist. Emptying it returns the
        // scoreboard to the manual URL+key pair.
        let s = v.trim().to_string();
        if !s.is_empty() && !d.indexers.lock_ok().iter().any(|i| i.name == s) {
            return Err(format!(
                "scoreboard_source: no indexer account named \"{s}\" - add it under indexer accounts first, or leave this empty to use the URL and key fields"
            ));
        }
        *d.scoreboard_source.lock_ok() = s.clone();
        (true, json!(s))
    })
}

pub(super) fn set_corr_confirm_enabled(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let on = v == "1" || v.eq_ignore_ascii_case("true");
        let was = d.corr_confirm_enabled.swap(on, Ordering::Relaxed);
        if on != was {
            // Same courtesy as the scoreboard: this switch spends the
            // user's own indexer quota, so say so, naming the account.
            if on {
                let src = d.corr_confirm_source.lock_ok().clone();
                let from = if src.is_empty() {
                    "NO account picked - inert until corr_confirm_source names one".to_string()
                } else {
                    src
                };
                info!(
                    target: "confirm",
                    "indexer-confirm ON - up to {} suggestion lookup(s)/day from {from}",
                    crate::serve::tasks::CONFIRM_PER_DAY,
                );
            } else {
                info!(target: "confirm", "indexer-confirm off - nothing is looked up");
            }
        }
        (true, json!(on))
    })
}

pub(super) fn set_corr_confirm_source(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // The name of one of the user's own indexer accounts, same
        // contract as scoreboard_source: a typo through the raw API
        // fails loudly here. There is no manual URL+key fallback - the
        // lane fetches NZBs, which indexers meter as grabs, so it only
        // runs against an account whose quotas live in the editor.
        let s = v.trim().to_string();
        if !s.is_empty() && !d.indexers.lock_ok().iter().any(|i| i.name == s) {
            return Err(format!(
                "corr_confirm_source: no indexer account named \"{s}\" - add it under indexer accounts first"
            ));
        }
        *d.corr_confirm_source.lock_ok() = s.clone();
        (true, json!(s))
    })
}

pub(super) fn set_scoreboard_cats(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // The requests-per-day dial. It can only ever REDUCE the day's
        // cost, never raise it: the value is a subset of the built-in
        // SCOREBOARD_CATEGORIES, empty means all four (the ceiling),
        // and scoreboard_categories() filters rather than reads, so
        // nothing stored here can invent a fifth request.
        let cats = parse_scoreboard_cats(v).map_err(|e| format!("scoreboard_cats: {e}"))?;
        // One category is the floor. An all-unticked list would read as
        // "measure nothing" but store as the empty default, which is
        // "measure everything" - the opposite of what was asked - so it
        // is refused here rather than silently inverted.
        if !v.trim().is_empty() && cats.is_empty() {
            return Err(
                "scoreboard_cats: name at least one category, or turn the scoreboard off".into(),
            );
        }
        let n = if cats.is_empty() {
            SCOREBOARD_CATEGORIES.len()
        } else {
            cats.len()
        };
        *d.scoreboard_cats.lock_ok() = cats.clone();
        info!(
            target: "scoreboard",
            "sampling {n} categor{} a day - {n} request(s)",
            if n == 1 { "y" } else { "ies" }
        );
        (true, json!(cats))
    })
}

pub(super) fn set_predb_server(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // `host` or `host:port`. Validated only for shape: the set of
        // networks carrying a relay is not ours to enumerate.
        let s = v.trim().to_string();
        if s.contains(char::is_whitespace) {
            return Err("predb_server: expected a host or host:port".into());
        }
        if let Some((_, port)) = s.rsplit_once(':')
            && port.parse::<u16>().is_err()
        {
            return Err("predb_server: the part after ':' must be a port number".into());
        }
        *d.predb_server.lock_ok() = if s.is_empty() {
            nzbkit::predb::DEFAULT_HOST.to_string()
        } else {
            s.clone()
        };
        (true, json!(d.predb_server.lock_ok().clone()))
    })
}

pub(super) fn set_predb_channels(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let chans: Vec<String> = v
            .split(',')
            .map(str::trim)
            .filter(|c| !c.is_empty())
            // A channel name may not contain a space, a comma or a
            // control character - a malformed one would be sent
            // verbatim in a JOIN, which is the one place this client
            // writes to somebody else's server.
            .map(|c| {
                c.chars()
                    .filter(|ch| !ch.is_whitespace() && !ch.is_control() && *ch != ',')
                    .collect::<String>()
            })
            .filter(|c| !c.is_empty())
            .collect();
        let joined = if chans.is_empty() {
            nzbkit::predb::DEFAULT_CHANNELS.join(",")
        } else {
            chans.join(",")
        };
        *d.predb_channels.lock_ok() = joined.clone();
        (true, json!(joined))
    })
}

pub(super) fn set_predb_nick(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // Nick charset per RFC 2812, minus the leading-digit rule
        // (the random suffix is appended, so the base only has to be
        // safe). Empty falls back to the default rather than sending
        // a bare suffix.
        let n: String = v
            .trim()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || "[]\\`_^{|}-".contains(*c))
            .take(12)
            .collect();
        let n = if n.is_empty() {
            nzbkit::predb::DEFAULT_NICK.to_string()
        } else {
            n
        };
        *d.predb_nick.lock_ok() = n.clone();
        (true, json!(n))
    })
}

pub(super) fn set_index_paused(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let on = v == "1" || v.eq_ignore_ascii_case("true");
        d.index_paused.store(on, Ordering::Relaxed);
        // Resuming should not wait out the rest of the interval -
        // the user just asked for it.
        if !on {
            d.scan_now.notify_one();
        }
        (true, json!(on))
    })
}

/// Stop or restart the metadata lanes. No wake to send: those lanes poll
/// (`Daemon::park_metadata_lanes`), so resuming costs at most one park
/// interval, which is invisible next to the provider round-trips that
/// follow it.
pub(super) fn set_enrich_paused(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let on = v == "1" || v.eq_ignore_ascii_case("true");
        d.enrich_paused.store(on, Ordering::Relaxed);
        (true, json!(on))
    })
}

#[cfg(feature = "indexer")]
pub(super) fn set_index_enabled(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let on = v == "1" || v.eq_ignore_ascii_case("true");
        d.index_enabled.store(on, Ordering::Relaxed);
        if on {
            // Switching on mid-run: turn any interests the wizard
            // recorded into groups (a no-op if that already
            // happened) and scan straight away rather than after a
            // full interval of an empty wall.
            apply_interests(d);
            d.scan_now.notify_one();
            info!(target: "index", "indexer switched on");
        } else {
            // Order matters: stop the workers reaching for the
            // database before closing it, so the next `with_index`
            // cannot re-open what we just dropped. The atomic above
            // is what both of those read.
            d.close_index();
            info!(target: "index", "indexer switched off - nothing is scanned, fetched or stored");
        }
        (true, json!(on))
    })
}

#[cfg(feature = "indexer")]
pub(super) fn set_spot_enabled(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let on = v == "1" || v.eq_ignore_ascii_case("true");
        d.spot_enabled.store(on, Ordering::Relaxed);
        if on {
            // Same reasoning as the indexer switch: scan now rather
            // than after a full interval of an empty list.
            d.scan_now.notify_one();
            info!(target: "spots", "Spotnet spots switched on");
        } else {
            // A no-op while the indexer still wants the database.
            d.close_index();
            info!(target: "spots", "Spotnet spots switched off - no spot group is scanned");
        }
        (true, json!(on))
    })
}

pub(super) fn set_spot_groups(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let groups: Vec<String> = v
            .split(&[',', ' ', '\n'][..])
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        *d.spot_groups.lock_ok() = groups.clone();
        d.scan_now.notify_one();
        (true, json!(groups))
    })
}

pub(super) fn set_spot_backfill(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // A first pass walks back this many articles; later passes
        // resume from the high-water mark, so this only ever costs
        // once per group. Capped so one pass cannot be minutes of OVER
        // - reading the whole 4.4M-article history is `spot_deepen`'s
        // job, a bounded slice at a time.
        let n: u64 = v
            .trim()
            .parse()
            .map_err(|_| "spot_backfill: expected a number".to_string())?;
        let n = n.clamp(1_000, 1_000_000);
        d.spot_backfill.store(n, Ordering::Relaxed);
        (true, json!(n))
    })
}

pub(super) fn set_spot_deepen(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // Articles of history per pass, below the low-water mark.
        // 0 = off; the walk stops on its own at the group's first
        // article, so this is a rate, not a budget.
        let n: u64 = v
            .trim()
            .parse()
            .map_err(|_| "spot_deepen: expected a number".to_string())?;
        let n = n.min(1_000_000);
        d.spot_deepen.store(n, Ordering::Relaxed);
        d.scan_now.notify_one();
        (true, json!(n))
    })
}

pub(super) fn set_spot_resolve(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // Spot NZBs fetched per pass. Unlike the scan legs this one
        // costs a HEAD plus a few BODYs each, so the cap is low and
        // deliberate: the queue is newest-first, so a deep backlog
        // trickles in behind the live feed rather than delaying it.
        let n: u64 = v
            .trim()
            .parse()
            .map_err(|_| "spot_resolve: expected a number".to_string())?;
        let n = n.min(1_000);
        d.spot_resolve.store(n, Ordering::Relaxed);
        d.scan_now.notify_one();
        (true, json!(n))
    })
}

#[cfg(feature = "indexer")]
pub(super) fn set_index_evict_order(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let o = v.trim().to_ascii_lowercase();
        if parse_evict_order(&o).is_none() {
            return Err(format!(
                "index_evict_order: expected one of {}",
                EVICT_ORDERS.join(", ")
            ));
        }
        *d.index_evict_order.lock_ok() = o.clone();
        (true, json!(o))
    })
}

#[cfg(feature = "indexer")]
pub(super) fn set_index_evict_kinds(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // Restriction list, not an exclusion list: empty = every
        // kind may be evicted. Validated because a typo would
        // restrict eviction to a kind no row carries, leaving a cap
        // that silently never frees a byte.
        let kinds = parse_evict_kinds(v).map_err(|e| format!("index_evict_kinds: {e}"))?;
        *d.index_evict_kinds.lock_ok() = kinds.clone();
        (true, json!(kinds))
    })
}

#[cfg(feature = "indexer")]
pub(super) fn set_index_keep_kinds(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // Exclusion list, the protective complement of index_evict_kinds:
        // a kind named here is NEVER evicted, and a kind in both lists is
        // kept. Same vocabulary, same typo refusal - a misspelt kind here
        // would silently protect nothing.
        let kinds = parse_evict_kinds(v).map_err(|e| format!("index_keep_kinds: {e}"))?;
        *d.index_keep_kinds.lock_ok() = kinds.clone();
        (true, json!(kinds))
    })
}

#[cfg(feature = "indexer")]
pub(super) fn set_index_evict_scope(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let s = v.trim().to_ascii_lowercase();
        if parse_evict_scope(&s).is_none() {
            return Err(format!(
                "index_evict_scope: expected one of {}",
                EVICT_SCOPES.join(", ")
            ));
        }
        // "" parses as All for a hand-edited file; store the canonical
        // spelling so the UI's select always finds its option.
        let s = if s.is_empty() { "all".to_string() } else { s };
        *d.index_evict_scope.lock_ok() = s.clone();
        (true, json!(s))
    })
}

#[cfg(feature = "indexer")]
pub(super) fn set_index_evict_headroom(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // Percent below the cap an eviction empties to, 0..=50. Out of
        // range is refused rather than clamped silently: 60 is more
        // likely a misread of the control than a wish to halve the
        // database.
        let n: u64 = v
            .trim()
            .parse()
            .map_err(|_| "index_evict_headroom: expected a percent, 0 to 50".to_string())?;
        if n > 50 {
            return Err("index_evict_headroom: at most 50 percent".to_string());
        }
        d.index_evict_headroom.store(n, Ordering::Relaxed);
        (true, json!(n))
    })
}

pub(super) fn set_index_evict(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // The one switch that lets the daemon delete indexed rows on
        // its own. Default OFF and it stays off until the user says
        // otherwise - see the field doc on Daemon::index_evict.
        let on = v == "1" || v.eq_ignore_ascii_case("true");
        d.index_evict.store(on, Ordering::Relaxed);
        if on {
            let cap = d.index_max_bytes.load(Ordering::Relaxed);
            info!(
                target: "index",
                "automatic eviction ON{}",
                if cap == 0 {
                    " - but index_max_bytes is 0 (unlimited), so nothing will be evicted"
                        .to_string()
                } else {
                    format!(" - cap {:.0} MB", cap as f64 / (1u64 << 20) as f64)
                }
            );
        }
        (true, json!(on))
    })
}

#[cfg(feature = "indexer")]
pub(super) fn set_index_gates(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let text = v.trim().to_string();
        let parsed = if text.is_empty() {
            None
        } else {
            Some(crate::gates::Gates::from_json(&text).map_err(|e| format!("gates: {e}"))?)
        };
        *d.index_gates.lock_ok() = (text.clone(), parsed);
        (true, json!(text))
    })
}
