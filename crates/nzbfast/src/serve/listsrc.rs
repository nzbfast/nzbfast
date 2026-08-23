//! TODO 151 (issue #36): the daemon half of external list sources - the
//! fetching, the sync loop, the settings validator and the Plex account
//! link. The pure model, the merge and the union live in
//! `crate::listsrc`; Plex's wire formats live in `crate::plex`.
//!
//! What this does NOT do is grab anything. A sync writes ENTRIES into a
//! list of its own and wakes the watcher; `watchlist_pass` still makes
//! every decision, so a synced entry gets the same quality ladder,
//! upgrades, season packs, duplicate hold, age window and instant grab a
//! hand-typed one does. There has been exactly one grab path since §74
//! and this does not add a second.
//!
//! One way only: nothing here ever writes to Plex or marks anything
//! watched.

use super::*;

use crate::listsrc::{ListSource, SourceHealth, SyncOutcome, SyncedItem, merge};
use crate::plex;
use crate::watchlist::WatchItem;

/// How long a started Plex link stays pollable. Plex's own strong pins
/// expire in fifteen minutes, and a code that has gone stale should say
/// so rather than poll a dead id for ever.
const PIN_TTL_SECS: i64 = 900;

/// Everything §151 keeps on the daemon.
///
/// One field on `Daemon` rather than six, and declared here rather than
/// there, because it is one subsystem and this is the file that owns it.
#[derive(Default)]
pub(super) struct ListState {
    /// The configured sources (settings key `list_sources`) - a live
    /// setting, re-read every sync pass. Entries carry the watchlist RSS
    /// url and the Plex account token: masked in get_config
    /// (`has_url` / `has_token`), never logged, never sent to a browser.
    pub sources: Mutex<Vec<ListSource>>,
    /// The watchlist items those sources own, spooled to
    /// `.spool/list-watchlist.json`.
    ///
    /// A list of their OWN, never appended into `Daemon::watchlist`: the
    /// dashboard editor rewrites that whole array on save, so one writer
    /// would destroy the other's rows. [`Daemon::watch_items`] joins the
    /// two, and it is what every reader of the watchlist must use.
    pub items: Mutex<Vec<SyncedItem>>,
    /// What each source's last sync did, keyed by source id. In memory
    /// only, like `feed_health`: it describes this daemon's run, and the
    /// first pass after a restart refills it.
    pub health: Mutex<std::collections::HashMap<u64, SourceHealth>>,
    /// `mode=list_sync_now`: wakes the loop, and makes every source due.
    pub now: tokio::sync::Notify,
    /// A Plex link started but not yet approved.
    pub pin: Mutex<Option<PendingPin>>,
    /// This install's `X-Plex-Client-Identifier` - random, minted once,
    /// kept in the spool. Not a user setting and not a credential: it is
    /// what Plex shows in the account's authorised-devices list.
    pub client_id: Mutex<String>,
}

/// A Plex link the user has started but not finished.
#[derive(Debug, Clone)]
pub(super) struct PendingPin {
    /// Plex's id for the pin, which is what gets polled.
    pub id: String,
    /// The source the resulting token belongs to.
    pub src: u64,
    /// When it was started, for [`PIN_TTL_SECS`].
    pub started: i64,
}

/// The spool file's shape.
///
/// The client identifier lives here rather than in settings.json because
/// it is not a user setting - it is a random per-install string Plex
/// wants to see on every request from the same app, and a settings key
/// would have to be declared, echoed, documented and translated for
/// something nobody will ever type.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct ListSpool {
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    items: Vec<SyncedItem>,
}

fn spool_path(d: &Daemon) -> PathBuf {
    d.spool.join("list-watchlist.json")
}

fn write_spool(d: &Daemon) {
    let spool = ListSpool {
        client_id: d.lists.client_id.lock_ok().clone(),
        items: d.lists.items.lock_ok().clone(),
    };
    if let Ok(body) = serde_json::to_vec(&spool) {
        let _ = crate::persist::write_atomic(&spool_path(d), &body);
    }
}

impl Daemon {
    /// §151: the watchlist as the watcher must see it - the user's own
    /// items, then every synced one that does not duplicate them.
    ///
    /// EVERY reader of the watchlist goes through this, not through
    /// `self.watchlist` directly. The two lists have separate writers on
    /// purpose (see [`ListState::items`]), so a reader that took only
    /// one of them would silently ignore half the list - and the one
    /// reader that matters is `watchlist_pass`, which is the single path
    /// that grabs anything.
    ///
    /// The one deliberate exception is the settings row for `watchlist`,
    /// which echoes back what the dashboard EDITOR owns and must not
    /// include rows the editor would then write into the user's own
    /// array.
    pub fn watch_items(&self) -> Vec<crate::watchlist::WatchItem> {
        crate::listsrc::union_watchlist(&self.watchlist.lock_ok(), &self.lists.items.lock_ok())
    }
}

// ---------------------------------------------------------------------------
// The settings validator
// ---------------------------------------------------------------------------

/// `mode=config&name=list_sources`. A JSON array of [`ListSource`].
///
/// Blank-means-keep on BOTH credentials, matched by `id` and not by name:
/// a source's name is editable, and get_config never echoes the url or
/// the token, so the dashboard round-trips blanks. Matching on the name
/// would have handed one source's token to another the moment somebody
/// renamed a row.
///
/// The consequence to know about: because a blank keeps, there is no way
/// to ERASE a stored credential through this path. That is what
/// `mode=plex_forget` is for.
pub(super) fn set_list_sources(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let text = v.trim();
    let mut list: Vec<ListSource> = if text.is_empty() {
        Vec::new()
    } else {
        serde_json::from_str(text).map_err(|e| format!("list_sources: {e}"))?
    };
    {
        let cur = d.lists.sources.lock_ok();
        for s in list.iter_mut() {
            s.name = s.name.trim().to_string();
            s.url = s.url.trim().to_string();
            s.token = s.token.trim().to_string();
            s.kind = s.kind.trim().to_ascii_lowercase();
            s.mode = s.mode.trim().to_ascii_lowercase();
            s.series_scope = s.series_scope.trim().to_ascii_lowercase();
            if let Some(old) = cur.iter().find(|o| o.id == s.id) {
                if s.url.is_empty() {
                    s.url = old.url.clone();
                }
                if s.token.is_empty() {
                    s.token = old.token.clone();
                }
            }
        }
    }
    let mut seen = std::collections::HashSet::new();
    for s in &list {
        if s.id == 0 {
            return Err("list_sources: every source needs an id".into());
        }
        if !seen.insert(s.id) {
            return Err("list_sources: two sources share an id".into());
        }
        // Only Plex today. The seam exists so Trakt / IMDb / Letterboxd
        // are cheap later, and an unknown kind is refused rather than
        // fetched blindly - we would not know what we were reading.
        if s.kind != "plex" {
            return Err(format!(
                "list_sources: {} is not a list we can read",
                s.kind
            ));
        }
        if s.mode != "rss" && s.mode != "account" {
            return Err("list_sources: a source is either an RSS url or a linked account".into());
        }
        if s.mode == "rss"
            && !s.url.is_empty()
            && !(s.url.starts_with("http://") || s.url.starts_with("https://"))
        {
            return Err("list_sources: the watchlist RSS address must be http(s)".into());
        }
        if s.series_scope != crate::listsrc::SCOPE_NEW
            && s.series_scope != crate::listsrc::SCOPE_ALL
        {
            return Err("list_sources: unknown series scope".into());
        }
    }
    for s in list.iter_mut() {
        s.interval_secs = s.interval();
    }
    // Forget the health of sources that are gone, so a removed-and-re-
    // added one starts clean rather than inheriting a stale error, and
    // drop the items they owned: a source the user deleted stops
    // watching what it added. Nothing downloaded is touched.
    {
        let live: std::collections::HashSet<u64> = list.iter().map(|s| s.id).collect();
        d.lists.health.lock_ok().retain(|id, _| live.contains(id));
        d.lists.items.lock_ok().retain(|i| live.contains(&i.src));
    }
    let persist = serde_json::to_value(&list).unwrap_or(json!([]));
    *d.lists.sources.lock_ok() = list;
    write_spool(d);
    // A source that just changed its defaults should restamp them now,
    // not in six hours.
    d.lists.now.notify_one();
    Ok((true, persist))
}

// ---------------------------------------------------------------------------
// Fetching
// ---------------------------------------------------------------------------

/// Every error out of here goes through the redactor before it is
/// recorded, logged or shown: a Plex watchlist RSS url is a bearer
/// capability, not an address, and ureq's errors lead with the url they
/// were handed.
fn wire_err(e: impl std::fmt::Display) -> String {
    redact_url_creds(&e.to_string())
}

fn fetch_rss(url: &str) -> std::result::Result<Vec<crate::listsrc::ListEntry>, String> {
    let body = ssrf_safe_agent(4, 30)
        .get(url)
        .call()
        .map_err(wire_err)?
        .into_string()
        .map_err(wire_err)?;
    plex::parse_watchlist_rss(&body)
}

/// Read a linked account's whole watchlist, a page at a time.
///
/// The token goes in the `X-Plex-Token` HEADER and never into the url -
/// see [`plex::watchlist_url`]. Paging stops when a page comes back
/// shorter than it asked for, and [`plex::MAX_PAGES`] is the backstop for
/// a server that ignores the container offsets.
fn fetch_account(
    token: &str,
    client_id: &str,
) -> std::result::Result<Vec<crate::listsrc::ListEntry>, String> {
    let agent = ssrf_safe_agent(4, 30);
    let mut out = Vec::new();
    for page in 0..plex::MAX_PAGES {
        let body = agent
            .get(&plex::watchlist_url(page * plex::PAGE_SIZE))
            .set("X-Plex-Token", token)
            .set("X-Plex-Client-Identifier", client_id)
            .set("X-Plex-Product", plex::PRODUCT)
            .set("Accept", "application/xml")
            .call()
            .map_err(wire_err)?
            .into_string()
            .map_err(wire_err)?;
        let (entries, seen) = plex::parse_watchlist_xml(&body)?;
        out.extend(entries);
        if seen < plex::PAGE_SIZE {
            break;
        }
    }
    Ok(out)
}

/// One fetch of one source, as a [`SyncOutcome`].
///
/// The three arms are the whole point: a fetch that failed and a fetch
/// that came back with nothing are both "no news", and neither may ever
/// be read as "the list is empty".
fn fetch_source(d: &Arc<Daemon>, src: &ListSource) -> SyncOutcome {
    let client_id = d.lists.client_id.lock_ok().clone();
    let got = match src.mode.as_str() {
        "account" => fetch_account(&src.token, &client_id),
        _ => fetch_rss(&src.url),
    };
    match got {
        Ok(list) if list.is_empty() => SyncOutcome::Empty,
        Ok(list) => SyncOutcome::Fetched(list),
        Err(e) => SyncOutcome::Failed(e),
    }
}

/// Sync one source: fetch it, merge what came back into the items it
/// owns, and record what happened.
///
/// Blocking. Called on a blocking thread by the loop below, and directly
/// by the tests.
pub(super) fn sync_one(d: &Arc<Daemon>, src: &ListSource) -> SyncOutcome {
    let outcome = fetch_source(d, src);
    apply_outcome(d, src, &outcome);
    outcome
}

/// Is `src` still the source we were told to sync, byte for byte?
///
/// Called after the network fetch and before any side effect. A source the
/// user deleted mid-fetch is gone from the live list; one they edited has a
/// different fingerprint, and the answer we are holding was fetched under
/// the OLD address, credential and rules.
fn still_authorized(d: &Arc<Daemon>, src: &ListSource) -> bool {
    d.lists
        .sources
        .lock_ok()
        .iter()
        .any(|s| s.id == src.id && s.fetch_fingerprint() == src.fetch_fingerprint())
}

/// Everything a sync does with what it fetched - the half with no
/// network in it, so the rules that matter are testable without one.
fn apply_outcome(d: &Arc<Daemon>, src: &ListSource, outcome: &SyncOutcome) {
    // The revocation check, immediately before the first side effect.
    // Without it the completion of a fetch started before a delete
    // reinserted the deleted source's items, wrote them to the spool,
    // republished its health and woke the watcher - so the account kept
    // auto-grabbing and came back after a restart (Codex sweep 12 Aug F6a).
    if !still_authorized(d, src) {
        info!(
            target: "list",
            "{}: deleted or changed while it was being fetched - discarding that result",
            src.name
        );
        return;
    }
    let now = unix_now();
    let watching = {
        let mut items = d.lists.items.lock_ok();
        let have: Vec<WatchItem> = items
            .iter()
            .filter(|i| i.src == src.id)
            .map(|i| i.item.clone())
            .collect();
        let merged = merge(src, &have, outcome);
        items.retain(|i| i.src != src.id);
        items.extend(merged.iter().map(|item| SyncedItem {
            src: src.id,
            item: item.clone(),
        }));
        merged.len()
    };
    {
        let mut health = d.lists.health.lock_ok();
        let prev = health.get(&src.id).cloned().unwrap_or_default();
        let h = match outcome {
            SyncOutcome::Fetched(list) => SourceHealth::ok(now, list.len(), watching),
            SyncOutcome::Empty => SourceHealth::ok(now, 0, watching),
            SyncOutcome::Failed(msg) => {
                // Already redacted by `wire_err` / the parsers, which
                // never echo a body. This line reaches the dashboard log.
                warn!(target: "list", "{}: {msg}", src.name);
                SourceHealth::failed(&prev, now, msg)
            }
        };
        health.insert(src.id, h);
    }
}

/// One pass over the sources that are due. Returns how many it synced.
pub(super) fn list_sources_pass(d: &Arc<Daemon>, todo: &[ListSource]) -> usize {
    let mut n = 0;
    for src in todo {
        sync_one(d, src);
        n += 1;
    }
    if n > 0 {
        write_spool(d);
        // The watcher decides everything; this only tells it there is
        // something new to look at.
        d.watch_now.notify_one();
    }
    n
}

// ---------------------------------------------------------------------------
// The loop
// ---------------------------------------------------------------------------

/// Restore the sources and the items they own, then poll them.
///
/// Same shape as `spawn_watchlist_watcher`: the source list is a live
/// setting re-read every pass, so dashboard edits apply without a
/// restart, and the items are spooled so a restart does not re-add
/// everything and re-grab it.
pub(super) fn spawn_list_sync(daemon: &Arc<Daemon>, settings_path: &std::path::Path) {
    // Did the source list load, or is `sources` empty because we could not
    // read it? The spool filter below turns on that distinction, so it is
    // tracked rather than inferred from emptiness.
    let mut sources_known = true;
    if let Some(v) = load_settings(settings_path).get("list_sources") {
        match serde_json::from_value(v.clone()) {
            Ok(l) => *daemon.lists.sources.lock_ok() = l,
            Err(e) => {
                warn!(target: "list", "ignoring saved list_sources setting: {e}");
                sources_known = false;
            }
        }
    }
    let path = spool_path(daemon);
    if let Some(v) = crate::persist::load_json_with_backup(&path) {
        match serde_json::from_value::<ListSpool>(v) {
            Ok(s) => {
                *daemon.lists.client_id.lock_ok() = s.client_id;
                // Filtered against the sources that actually exist. Every
                // spooled item is OWNED by a source, and `set_list_sources`
                // drops the items of a source the user deleted - so an item
                // naming an id that is not in the settings describes a
                // source that is gone, whether it got there through the
                // revocation race (see `apply_outcome`) or a hand-edited
                // settings file. Belt to that brace: nothing should be
                // watched on behalf of an account that no longer exists
                // (Codex sweep 12 Aug F6a).
                //
                // Skipped entirely when the setting did not PARSE. There,
                // an empty source list is ignorance rather than a fact, and
                // filtering against it would silently delete every synced
                // item the user has - a worse outcome than keeping a few
                // orphans the next successful save will drop anyway.
                let items = if sources_known {
                    let live: std::collections::HashSet<u64> = daemon
                        .lists
                        .sources
                        .lock_ok()
                        .iter()
                        .map(|s| s.id)
                        .collect();
                    let total = s.items.len();
                    let kept: Vec<_> = s
                        .items
                        .into_iter()
                        .filter(|i| live.contains(&i.src))
                        .collect();
                    if kept.len() != total {
                        warn!(
                            target: "list",
                            "dropped {} spooled item(s) belonging to list sources that no \
                             longer exist",
                            total - kept.len()
                        );
                    }
                    kept
                } else {
                    s.items
                };
                *daemon.lists.items.lock_ok() = items;
            }
            Err(e) => warn!(target: "list", "ignoring {}: {e}", path.display()),
        }
    }
    if daemon.lists.client_id.lock_ok().is_empty() {
        // Plex wants a stable per-install identifier on every request,
        // and it is what the user sees in their account's authorised
        // devices list. Minted once and kept in the spool.
        if let Some(id) = random_apikey() {
            *daemon.lists.client_id.lock_ok() = id;
            write_spool(daemon);
        }
    }
    let d = daemon.clone();
    tokio::spawn(async move {
        // Next-sync deadlines, keyed by source id. A removed source's
        // entry goes stale and a re-added one syncs at once.
        let mut due: std::collections::HashMap<u64, Instant> = std::collections::HashMap::new();
        loop {
            // Sleep first: nothing is due in the first minute of a
            // daemon's life that was not due a moment before it started.
            let mut forced = false;
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
                _ = d.lists.now.notified() => { forced = true }
            }
            let sources = d.lists.sources.lock_ok().clone();
            let now = Instant::now();
            let mut todo: Vec<ListSource> = Vec::new();
            for s in sources {
                // A source with no address is not broken, it is
                // unfinished - an account row nobody has linked yet. It
                // is left alone and the card says so.
                if !s.enabled || !s.ready() {
                    continue;
                }
                if !forced && due.get(&s.id).is_some_and(|t| *t > now) {
                    continue;
                }
                due.insert(s.id, now + std::time::Duration::from_secs(s.interval()));
                todo.push(s);
            }
            if todo.is_empty() {
                continue;
            }
            let d2 = d.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let _busy = d2.busy.hold("list sync");
                list_sources_pass(&d2, &todo)
            })
            .await;
        }
    });
}

// ---------------------------------------------------------------------------
// The Plex account link
// ---------------------------------------------------------------------------

/// `mode=plex_link_start&value=<source id>`: ask Plex for a code.
///
/// No password ever reaches us - the user approves the code on Plex's own
/// page, which is the only version of account linking worth shipping.
pub(super) fn plex_link_start(d: &Arc<Daemon>, src_id: u64) -> std::result::Result<Value, String> {
    {
        let sources = d.lists.sources.lock_ok();
        let Some(s) = sources.iter().find(|s| s.id == src_id) else {
            return Err("that list source is gone".into());
        };
        if s.mode != "account" {
            return Err("that source reads an RSS address, so it has nothing to link".into());
        }
    }
    let client_id = d.lists.client_id.lock_ok().clone();
    if client_id.is_empty() {
        return Err("this install has no Plex client identifier yet".into());
    }
    let body = ssrf_safe_agent(4, 30)
        .post(plex::PIN_URL)
        .set("X-Plex-Client-Identifier", &client_id)
        .set("X-Plex-Product", plex::PRODUCT)
        .set("Accept", "application/json")
        // ureq needs a body on a POST; Plex takes the parameters in the
        // query string and the headers.
        .send_string("")
        .map_err(wire_err)?
        .into_string()
        .map_err(wire_err)?;
    let pin = plex::parse_pin(&body)?;
    *d.lists.pin.lock_ok() = Some(PendingPin {
        id: pin.id.clone(),
        src: src_id,
        started: unix_now(),
    });
    Ok(json!({
        "status": true,
        "id": pin.id,
        "code": pin.code,
        "url": plex::LINK_PAGE,
    }))
}

/// `mode=plex_link_poll&value=<pin id>`: has the user approved it yet?
///
/// The token NEVER goes to the browser. It is written onto the source,
/// persisted, and the answer is a boolean.
pub(super) fn plex_link_poll(d: &Arc<Daemon>, pin_id: &str) -> std::result::Result<Value, String> {
    let pending = d.lists.pin.lock_ok().clone();
    let Some(p) = pending.filter(|p| p.id == pin_id) else {
        return Err("that link has been started again somewhere else".into());
    };
    if unix_now() - p.started > PIN_TTL_SECS {
        *d.lists.pin.lock_ok() = None;
        return Err("that code has expired - start the link again".into());
    }
    let client_id = d.lists.client_id.lock_ok().clone();
    let body = ssrf_safe_agent(4, 30)
        .get(&plex::pin_poll_url(&p.id))
        .set("X-Plex-Client-Identifier", &client_id)
        .set("X-Plex-Product", plex::PRODUCT)
        .set("Accept", "application/json")
        .call()
        .map_err(wire_err)?
        .into_string()
        .map_err(wire_err)?;
    let pin = plex::parse_pin(&body)?;
    if pin.token.is_empty() {
        // The normal answer to almost every poll.
        return Ok(json!({"status": true, "linked": false}));
    }
    // The PREVIOUS token, kept for the rollback below. A credential that
    // could not be written down must not stay live in memory: the restart
    // would silently un-link the account and nothing would have said so.
    let (sources, prev) = {
        let mut sources = d.lists.sources.lock_ok();
        let Some(s) = sources.iter_mut().find(|s| s.id == p.src) else {
            return Err("that list source is gone".into());
        };
        let prev = std::mem::replace(&mut s.token, pin.token);
        (sources.clone(), prev)
    };
    // save_settings, not save_setting: the void wrapper discarded the
    // result and this action reported linked:true regardless, so on a
    // read-only or full settings filesystem the dashboard said the account
    // was connected and the next restart had never heard of it (Codex sweep
    // 12 Aug F8).
    if !save_settings(
        &d.settings_path,
        &[(
            "list_sources",
            serde_json::to_value(&sources).unwrap_or(json!([])),
        )],
    ) {
        if let Some(s) = d.lists.sources.lock_ok().iter_mut().find(|s| s.id == p.src) {
            s.token = prev;
        }
        // The pin is deliberately NOT cleared: the link did not happen, so
        // the user can approve again without starting over.
        return Err(
            "linked, but the settings file could not be written - the account \
                    would be forgotten at the next restart, so it was not kept"
                .into(),
        );
    }
    *d.lists.pin.lock_ok() = None;
    info!(target: "list", "a Plex account was linked");
    d.lists.now.notify_one();
    Ok(json!({"status": true, "linked": true}))
}

/// `mode=plex_forget&value=<source id>`: erase a stored token.
///
/// Its own action precisely BECAUSE a blank credential means "keep the
/// stored one" everywhere else: there is otherwise no way to erase one.
/// This is the comment's "one button forgets it".
pub(super) fn plex_forget(d: &Arc<Daemon>, src_id: u64) -> std::result::Result<Value, String> {
    let (sources, prev) = {
        let mut sources = d.lists.sources.lock_ok();
        let Some(s) = sources.iter_mut().find(|s| s.id == src_id) else {
            return Err("that list source is gone".into());
        };
        let prev = (std::mem::take(&mut s.token), std::mem::take(&mut s.url));
        (sources.clone(), prev)
    };
    // Report the truth, and roll back rather than lie. This is the
    // security-significant direction: a Forget that answered status:true
    // after a failed write told the user the account was disconnected,
    // while the next restart reloaded the old bearer token and resumed
    // reading the supposedly revoked Plex account (Codex sweep 12 Aug F8).
    if !save_settings(
        &d.settings_path,
        &[(
            "list_sources",
            serde_json::to_value(&sources).unwrap_or(json!([])),
        )],
    ) {
        if let Some(s) = d
            .lists
            .sources
            .lock_ok()
            .iter_mut()
            .find(|s| s.id == src_id)
        {
            (s.token, s.url) = prev;
        }
        return Err(
            "the settings file could not be written, so the credential was NOT \
                    erased - it is still stored and would come back at the next restart"
                .into(),
        );
    }
    if d.lists
        .pin
        .lock_ok()
        .as_ref()
        .is_some_and(|p| p.src == src_id)
    {
        *d.lists.pin.lock_ok() = None;
    }
    // The items it added are left exactly where they are: forgetting a
    // credential is not the same as saying "stop watching all of this",
    // and a sync has never been allowed to delete a download either.
    // Removing the SOURCE removes its items; this only unlinks it.
    Ok(json!({"status": true}))
}

/// The settings row's per-source block: everything the dashboard may see
/// about a source, which is everything except the two credentials.
pub(super) fn list_sources_config(d: &Arc<Daemon>) -> Value {
    let sources = d.lists.sources.lock_ok().clone();
    let health = d.lists.health.lock_ok();
    Value::Array(
        sources
            .iter()
            .map(|s| {
                let h = health.get(&s.id);
                json!({
                    "id": s.id,
                    "name": s.name,
                    "kind": s.kind,
                    "mode": s.mode,
                    "enabled": s.enabled,
                    "interval_secs": s.interval(),
                    "min_quality": s.min_quality,
                    "target_quality": s.target_quality,
                    "category": s.category,
                    "upgrade": s.upgrade,
                    "series_scope": s.series_scope,
                    // The EFFECTIVE answer, not the raw Option: the
                    // checkbox has to show what the sync will actually
                    // do, and unset means "this mode's default".
                    "remove_missing": s.removes_missing(),
                    // Never the url or the token themselves. The UI
                    // learns only that one is stored, exactly as it does
                    // for an indexer's apikey.
                    "has_url": !s.url.is_empty(),
                    "has_token": !s.token.is_empty(),
                    "last_sync": h.map(|h| h.last_sync).unwrap_or(0),
                    "last_ok": h.map(|h| h.last_ok).unwrap_or(0),
                    "last_error": h.map(|h| h.last_error.clone()).unwrap_or_default(),
                    "items_seen": h.map(|h| h.items_seen).unwrap_or(0),
                    "watching": h.map(|h| h.watching).unwrap_or(0),
                })
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::super::testutil::test_daemon;
    use super::*;
    use crate::listsrc::ListEntry;

    /// House temp-dir pattern, with Drop cleanup so a failing assertion
    /// still removes the directory.
    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new(name: &str) -> TmpDir {
            let p =
                std::env::temp_dir().join(format!("nzbfast-lsrc-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            TmpDir(p)
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn daemon_in(name: &str) -> (TmpDir, Arc<Daemon>) {
        let t = TmpDir::new(name);
        let d = test_daemon(&t.0);
        (t, d)
    }

    fn one(mode: &str, url: &str, token: &str) -> String {
        json!([{
            "id": 7, "name": "my plex", "kind": "plex", "mode": mode,
            "url": url, "token": token, "enabled": true,
            "interval_secs": 21600, "min_quality": "720p",
            "target_quality": "1080p", "category": "tv", "upgrade": true,
            "series_scope": "new",
        }])
        .to_string()
    }

    fn entry(kind: &str, title: &str) -> ListEntry {
        ListEntry {
            title: title.into(),
            year: None,
            kind: kind.into(),
            ids: Vec::new(),
        }
    }

    /// The masking contract, and the reason it is matched on the ID: a
    /// source's NAME is editable, so a name-matched merge would have
    /// handed one source's credential to another the first time somebody
    /// renamed a row.
    #[test]
    fn a_blank_credential_keeps_the_stored_one_even_across_a_rename() {
        let (_t, d) = daemon_in("keep");
        set_list_sources(
            &d,
            "list_sources",
            &one("rss", "https://rss.plex.tv/abc", ""),
        )
        .unwrap();
        // A second save with a blank url, under a different name.
        let renamed = json!([{
            "id": 7, "name": "renamed", "kind": "plex", "mode": "rss",
            "url": "", "token": "", "enabled": true, "interval_secs": 21600,
            "min_quality": "any", "target_quality": "2160p", "category": "",
            "upgrade": false, "series_scope": "all",
        }])
        .to_string();
        set_list_sources(&d, "list_sources", &renamed).unwrap();
        let saved = d.lists.sources.lock_ok().clone();
        assert_eq!(saved[0].url, "https://rss.plex.tv/abc", "blank means keep");
        assert_eq!(saved[0].name, "renamed", "and the rest of the edit lands");
        assert_eq!(saved[0].target_quality, "2160p");
    }

    /// Neither credential is ever echoed to a browser. get_config is a
    /// read anyone holding the API key can make, and a Plex watchlist
    /// address is a bearer capability - having it IS reading the list.
    #[test]
    fn the_settings_row_carries_no_credential() {
        let (_t, d) = daemon_in("mask");
        set_list_sources(
            &d,
            "list_sources",
            &one("account", "", "plex-token-do-not-leak"),
        )
        .unwrap();
        let row = list_sources_config(&d).to_string();
        assert!(!row.contains("plex-token-do-not-leak"), "{row}");
        assert!(row.contains("\"has_token\":true"), "{row}");
        assert!(row.contains("\"has_url\":false"), "{row}");
        // ...and the EFFECTIVE delete-sync answer, which is what the
        // checkbox has to show: on for a linked account.
        assert!(row.contains("\"remove_missing\":true"), "{row}");
        // The log line gets a count and nothing else.
        assert_eq!(
            super::super::settings::log_value("list_sources", &one("rss", "https://secret/x", "")),
            "1 list sources"
        );
    }

    /// A sync clones its source, awaits a slow network fetch, and only
    /// then writes items, health and the spool. Deleting or editing the
    /// source in that window used to change none of that: the completion
    /// reinserted the deleted source's items, persisted them, republished
    /// its health and woke the watcher, so a revoked Plex account kept
    /// auto-grabbing - and came back after a restart, because the spool
    /// loader never filtered items against live sources either (Codex
    /// sweep 12 Aug F6a).
    ///
    /// `apply_outcome` is that whole second half, so calling it with a
    /// source that is no longer configured IS the race.
    #[test]
    fn a_sync_that_finished_after_its_source_was_revoked_writes_nothing() {
        let (_t, d) = daemon_in("revoked");
        set_list_sources(&d, "list_sources", &one("account", "", "tok")).unwrap();
        let src = d.lists.sources.lock_ok()[0].clone();
        let fetched = SyncOutcome::Fetched(vec![entry("tv", "The Bear")]);

        // Deleted mid-fetch.
        set_list_sources(&d, "list_sources", "[]").unwrap();
        apply_outcome(&d, &src, &fetched);
        assert!(
            d.lists.items.lock_ok().is_empty(),
            "a deleted source must not resurrect its items"
        );
        assert!(
            d.lists.health.lock_ok().is_empty(),
            "nor its health row - the card would show a source that is gone"
        );

        // Re-added, but with the credential CHANGED: the answer in hand
        // was fetched with the old one and describes a different account.
        set_list_sources(&d, "list_sources", &one("account", "", "tok")).unwrap();
        let mut edited = src.clone();
        edited.token = "different".into();
        apply_outcome(&d, &edited, &fetched);
        assert!(
            d.lists.items.lock_ok().is_empty(),
            "an answer fetched with a superseded credential must be discarded"
        );

        // ...and the unchanged source still works, or the guard is just
        // a way of never syncing.
        apply_outcome(&d, &src, &fetched);
        assert_eq!(d.lists.items.lock_ok().len(), 1);
    }

    /// The invariant everything else hangs off: a fetch that failed
    /// changes NOTHING. Run on the mode where removal IS allowed, which
    /// is the only one where getting this wrong could unwatch anything.
    #[test]
    fn a_failed_sync_leaves_the_list_exactly_as_it_was() {
        let (_t, d) = daemon_in("nonews");
        set_list_sources(&d, "list_sources", &one("account", "", "tok")).unwrap();
        let src = d.lists.sources.lock_ok()[0].clone();
        apply_outcome(
            &d,
            &src,
            &SyncOutcome::Fetched(vec![entry("tv", "The Bear"), entry("movie", "Dune")]),
        );
        assert_eq!(d.lists.items.lock_ok().len(), 2);
        for bad in [
            SyncOutcome::Empty,
            SyncOutcome::Fetched(Vec::new()),
            SyncOutcome::Failed("HTTP 401".into()),
        ] {
            apply_outcome(&d, &src, &bad);
            assert_eq!(d.lists.items.lock_ok().len(), 2, "{bad:?} must be no news");
        }
        // ...and the failure is VISIBLE, with the last good answer kept
        // so a parked row can say what it was before it broke rather
        // than just "broken".
        {
            let health = d.lists.health.lock_ok();
            let h = health.get(&7).expect("a synced source has health");
            assert_eq!(h.last_error, "HTTP 401");
            assert!(h.last_ok > 0, "it worked once and the row still says so");
        }
        // A source that starts answering again clears its error - "no
        // news" is not a permanent state.
        apply_outcome(
            &d,
            &src,
            &SyncOutcome::Fetched(vec![entry("tv", "The Bear"), entry("movie", "Dune")]),
        );
        let health = d.lists.health.lock_ok();
        let h = health.get(&7).unwrap();
        assert!(h.last_error.is_empty());
        assert_eq!(h.items_seen, 2);
        assert_eq!(h.watching, 2);
    }

    /// The public promise, end to end through the daemon: an address
    /// truncates at fifty titles so it may not prune, a linked account
    /// returns the whole list so it may.
    #[test]
    fn an_account_prunes_and_an_address_does_not() {
        for (mode, left) in [("rss", 2), ("account", 1)] {
            let (_t, d) = daemon_in(&format!("prune-{mode}"));
            set_list_sources(&d, "list_sources", &one(mode, "https://x/y", "tok")).unwrap();
            let src = d.lists.sources.lock_ok()[0].clone();
            apply_outcome(
                &d,
                &src,
                &SyncOutcome::Fetched(vec![entry("tv", "The Bear"), entry("movie", "Dune")]),
            );
            apply_outcome(
                &d,
                &src,
                &SyncOutcome::Fetched(vec![entry("tv", "The Bear")]),
            );
            assert_eq!(d.lists.items.lock_ok().len(), left, "mode {mode}");
        }
    }

    /// What `watchlist_pass` walks. The two lists have separate writers
    /// on purpose, so a reader taking only one of them would silently
    /// ignore half the watchlist.
    #[test]
    fn the_list_the_watcher_walks_is_the_union() {
        let (_t, d) = daemon_in("union");
        set_list_sources(&d, "list_sources", &one("rss", "https://x/y", "")).unwrap();
        let src = d.lists.sources.lock_ok()[0].clone();
        apply_outcome(
            &d,
            &src,
            &SyncOutcome::Fetched(vec![entry("tv", "The Bear"), entry("movie", "Dune")]),
        );
        d.watchlist.lock_ok().push(WatchItem {
            id: 1_700_000_000_001,
            kind: "movie".into(),
            title: "Arrival".into(),
            ..crate::listsrc::to_watch_item(&src, &entry("movie", "Arrival"))
        });
        let all = d.watch_items();
        assert_eq!(all.len(), 3);
        assert!(all.iter().any(|i| i.title == "The Bear"));
        assert!(all.iter().any(|i| i.title == "Arrival"));
        // The settings row for `watchlist` stays the EDITOR's own array -
        // if the synced rows entered it, the next save from a browser
        // tab would copy them into the user's list and the two writers
        // would start losing each other's rows.
        assert_eq!(d.watchlist.lock_ok().len(), 1);
    }

    /// Forget is its own action precisely because blank-means-keep: with
    /// that convention there is no other way to erase a credential.
    #[test]
    fn forgetting_a_source_erases_what_was_stored_and_keeps_the_source() {
        let (_t, d) = daemon_in("forget");
        set_list_sources(&d, "list_sources", &one("account", "", "tok")).unwrap();
        let src = d.lists.sources.lock_ok()[0].clone();
        apply_outcome(
            &d,
            &src,
            &SyncOutcome::Fetched(vec![entry("tv", "The Bear")]),
        );
        plex_forget(&d, 7).unwrap();
        let after = d.lists.sources.lock_ok().clone();
        assert_eq!(after.len(), 1, "the source stays, unlinked");
        assert!(after[0].token.is_empty());
        assert!(!after[0].ready(), "so nothing is read from it");
        // Unlinking is not "stop watching all of this": what it already
        // added stays watched until the SOURCE is removed.
        assert_eq!(d.lists.items.lock_ok().len(), 1);
        // ...and removing the source does stop watching them.
        set_list_sources(&d, "list_sources", "").unwrap();
        assert!(d.lists.items.lock_ok().is_empty());
        assert!(d.lists.health.lock_ok().is_empty());
    }

    /// The seam refuses what it cannot read rather than fetching it
    /// blindly, and an unusable interval is floored rather than obeyed.
    #[test]
    fn a_source_we_cannot_read_is_refused() {
        let (_t, d) = daemon_in("refuse");
        let bad = |k: &str, m: &str, scope: &str, url: &str| {
            json!([{"id": 1, "name": "x", "kind": k, "mode": m,
                    "url": url, "series_scope": scope}])
            .to_string()
        };
        for (k, m, scope, url) in [
            ("trakt", "rss", "new", "https://x/y"),
            ("plex", "guess", "new", "https://x/y"),
            ("plex", "rss", "some", "https://x/y"),
            ("plex", "rss", "new", "ftp://x/y"),
        ] {
            assert!(
                set_list_sources(&d, "list_sources", &bad(k, m, scope, url)).is_err(),
                "{k}/{m}/{scope}/{url} must be refused"
            );
        }
        // Two sources may not share an id: the items and the health are
        // both keyed on it.
        let dupe = json!([
            {"id": 1, "name": "a", "kind": "plex", "mode": "rss", "url": "https://x/1"},
            {"id": 1, "name": "b", "kind": "plex", "mode": "rss", "url": "https://x/2"},
        ])
        .to_string();
        assert!(set_list_sources(&d, "list_sources", &dupe).is_err());
        // A too-eager interval is floored, not refused - the cost of
        // asking harder is borne entirely by somebody else's service.
        let eager = json!([{"id": 1, "name": "a", "kind": "plex", "mode": "rss",
                    "url": "https://x/1", "interval_secs": 5}])
        .to_string();
        set_list_sources(&d, "list_sources", &eager).unwrap();
        assert_eq!(
            d.lists.sources.lock_ok()[0].interval_secs,
            crate::listsrc::MIN_INTERVAL_SECS
        );
    }
}
