//! M35 pull search: the external-indexer runtime state (caps cache,
//! per-day usage, limit backoff, the token->result cache that keeps the
//! user's indexer apikey out of the browser) and NZBLNK resolution.
//!
//! Split out of serve/mod.rs by TODO 106 phase 4 - the code is verbatim,
//! only visibility changed.

use super::*;
// `redact_url_creds` moved to `crate::netfetch` (TODO 276 item 3); three
// callers spell it `super::indexers::redact_url_creds`, so it is re-exported
// by name here rather than only through the glob.
pub use crate::netfetch::redact_url_creds;

/// M35 pull-search runtime state, one lock for all of it: the caps
/// cache, the per-day usage counters, limit backoffs, and the
/// token->result cache. The result cache is the security seam: an
/// external result's NZB link embeds the user's indexer apikey, so the
/// browser only ever sees an opaque token and `indexer_grab` will fetch
/// exactly the URLs a search stored - never one the client supplies.
#[derive(Default)]
pub struct IndexerRuntime {
    /// M35 phase 2: what each indexer's `t=caps` said, so an id search
    /// is only ever sent to a site that advertises the parameter. A
    /// FAILED probe is cached too (as None) - an indexer that cannot
    /// answer caps must not be re-probed on every keystroke-driven
    /// search - just for much less time than a success.
    ///
    /// Keyed by [`IndexerConfig::identity`] - the far end - and NOT by
    /// name: caps describe a site and an account, while the name is a
    /// label the user edits, reuses and types into unsaved drafts.
    /// See that method for what keying on the name cost.
    ///
    /// [`IndexerConfig::identity`]: crate::newznab::IndexerConfig::identity
    pub caps: std::collections::HashMap<String, (Instant, Option<crate::newznab::Caps>)>,
    /// Far ends that answered the seed lane's newest-listing sweep with
    /// a refusal of the request SHAPE (`is_unsupported_request`), so it
    /// must stop asking. Keyed by [`IndexerConfig::identity`] for the
    /// same reason `caps` is: what a far end will serve is a property of
    /// the site AND the account, not of the label the user typed.
    ///
    /// In memory on purpose, so a daemon restart re-probes once. What a
    /// site accepts changes - a tier upgrade, a software bump - and a
    /// latch persisted to the index would outlive the reason for it with
    /// nothing that ever clears it. One hit per restart is the price.
    ///
    /// That price is small because the SWEEP is rare: `seed_next` runs
    /// only when the expected pick and the corr pick both yield nothing,
    /// so the hourly throttle is a ceiling it does not reach - measured
    /// once in 3 h 17 m on the live daemon, 2 Sep 2026. The latch is not
    /// here to save hits. It is here so a source that will never serve
    /// this request stops being asked, and says so once instead of
    /// warning forever.
    ///
    /// [`IndexerConfig::identity`]: crate::newznab::IndexerConfig::identity
    #[cfg(feature = "indexer")]
    pub no_listing: std::collections::HashSet<String>,
    /// Indexers backing off after a limit error, by name. The name is
    /// right here: a budget/backoff belongs to the configured ENTRY the
    /// user set limits on, and only a saved entry ever runs a search.
    pub penalty_until: std::collections::HashMap<String, Instant>,
    pub usage: crate::newznab::Usage,
    #[cfg(feature = "indexer")]
    pub results: std::collections::HashMap<String, IndexerHit>,
    /// Insertion order, for capping `results`.
    #[cfg(feature = "indexer")]
    pub order: std::collections::VecDeque<String>,
}

/// One cached external search result, grabbable by token.
#[cfg(feature = "indexer")]
#[derive(Clone)]
pub struct IndexerHit {
    pub url: String,
    pub title: String,
    pub indexer: String,
    /// The indexer that offered this result: its configured URL and the
    /// addresses it answered the search from, kept beside the link
    /// because `url` is an `<enclosure url>` the search RESPONSE chose.
    /// The grab binds the fetch to this origin (M12/M9), so a hostile
    /// indexer cannot point the daemon at another service on the user's
    /// LAN, nor repoint its own name at one between search and grab.
    /// Stored at search time rather than looked up by `indexer` at grab
    /// time: the name is a label the user can rename or repoint between
    /// the two, and the address is gone by then either way.
    pub origin: SourceOrigin,
    pub at: Instant,
    /// Which SEARCH minted this token. TODO 282 item 5 holds the next
    /// ranked candidates of the search that produced a grab, and this is
    /// how the grab finds its own siblings in a cache that is otherwise
    /// one flat LRU of every search the daemon has answered.
    pub cohort: String,
    /// Which merged ROW of that search, and whether this is the row's
    /// headline copy.
    ///
    /// A row is one release; its copies are the same release listed by
    /// several indexers, which are very often literally the same post
    /// (§282 item 6 refuses those anyway, but only after paying for the
    /// fetch). So the spare walk takes ONE candidate per other row, and
    /// takes the headline - deterministically, because the cache is a
    /// HashMap and "whichever copy we happened to see first" is a
    /// different answer on every run of the same search.
    pub row: u32,
    pub headline: bool,
}

/// How far back the `addnzblnk` rate gate looks.
pub(super) const NZBLNK_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
/// Link resolutions allowed per window, PER PEER, before the endpoint
/// refuses. A person clicking board links does a handful a minute; a
/// page in a loop does not stop.
pub(super) const NZBLNK_MAX: usize = 20;
/// ...and how many of those may reach the user's indexers. Lower,
/// because this is the threshold that guards a metered account rather
/// than our own CPU. Past it the ladder still runs, local-only.
pub(super) const NZBLNK_EXTERNAL_MAX: usize = 6;
/// Resolutions allowed per window across ALL peers.
///
/// Deliberately looser than [`NZBLNK_MAX`], which is the point of
/// keying per peer at all: with one shared window, whoever spends it
/// first denies everyone else, and that is what a hostile page in a
/// loop does to the user's own paste. Not unbounded, because the peer
/// map has to be bounded by something and because the indexer quota
/// this protects is one account however many machines ask - a peer only
/// ever gets an entry by being ADMITTED, so this is also the ceiling on
/// how many entries the map can hold.
pub(super) const NZBLNK_GLOBAL_MAX: usize = NZBLNK_MAX * 3;
/// Resolutions allowed to be RUNNING at once, across all peers.
///
/// The window bounds arrivals per minute and says nothing about how
/// many are in flight: twenty in one second all passed it. The HTTP
/// surface is an 8-worker pool over one listener, and a resolution can
/// hold its worker for a while - rung 3 of `find_by_header` is an
/// unindexed table scan, and rung 2 fans out to the user's indexer
/// accounts under a 15 s per-call ceiling. Half the pool is the cap, so
/// a burst of links can never take the whole of it and leave the
/// dashboard unanswered on the machine the person is looking at.
pub(super) const NZBLNK_INFLIGHT_MAX: usize = 4;

/// The `mode=addnzblnk` rate and concurrency gate.
///
/// This endpoint is the one an OS protocol handler exposes to the open
/// web: once `nzblnk:` is registered, any page can navigate to one and,
/// past the browser's own "Open nzbfast?" prompt, reach it. A link
/// cannot name a location - `h` is a search key, so the daemon only
/// ever reads its own index or the user's own indexers - but a page in
/// a loop can still spend three things that are not free: the unindexed
/// filename scan, the user's metered indexer quota, and a worker off
/// the HTTP pool for as long as either takes.
///
/// **Keyed on the TRANSPORT peer, never on a header.** `X-Forwarded-For`
/// is written by whoever sent the request, so keying on it would hand a
/// hostile page an unlimited supply of buckets and turn the per-peer
/// half into no gate at all. The cost of that choice is that behind a
/// reverse proxy every request shares the proxy's address and therefore
/// one bucket, which is exactly the single global window this replaced -
/// no worse than before, and [`NZBLNK_GLOBAL_MAX`] still bounds it.
///
/// **Which half does the work depends on how the link arrived, and the
/// clicked one is not the flattering case.** A protocol-handler click
/// reaches the daemon through the installed app on the same machine, so
/// every clicked link in the world shares one bucket - localhost - and
/// the per-peer window is doing nothing there that the old single
/// window did not. What bounds THAT path is the in-flight cap, which is
/// the half §51's residue named first and the half no sliding window
/// can supply. The per-peer window is what stops the OTHER shapes -
/// a *arr, a phone, a second machine on the LAN, a script - from
/// spending each other's budget, which one shared window could not tell
/// apart from a single loop.
#[derive(Default)]
pub struct NzblnkGate {
    /// Arrival instants inside [`NZBLNK_WINDOW`], newest last, one
    /// window per peer. `None` is the bucket for a transport that
    /// reports no address at all, which is one bucket for all of them
    /// rather than a hole in the gate.
    pub windows: Mutex<std::collections::HashMap<Option<std::net::IpAddr>, VecDeque<Instant>>>,
    /// Resolutions running right now. Separate from the windows because
    /// it is held for the whole of a resolution while the lock above is
    /// held only across the decision.
    pub inflight: std::sync::atomic::AtomicUsize,
}

/// One in-flight slot, released when the resolution ends.
///
/// A guard rather than a decrement at the end of `resolve_nzblnk`,
/// because that function returns from a dozen places - and an early
/// return that forgot to give the slot back would leak it permanently,
/// which after four of them refuses every link until the daemon
/// restarts. A leak that only shows up under the failure paths is the
/// one a test is least likely to reach.
pub(super) struct NzblnkPermit<'a> {
    gate: &'a NzblnkGate,
    /// How many of this peer's window this resolution is, 1-based.
    /// [`NZBLNK_EXTERNAL_MAX`] is read against it, so the expensive
    /// half is spent per peer like the cheap half.
    pub(super) nth_for_peer: usize,
}

impl Drop for NzblnkPermit<'_> {
    fn drop(&mut self) {
        self.gate
            .inflight
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// Why the gate turned a resolution away.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum NzblnkRefusal {
    /// This peer, or everyone together, has had its window's worth.
    Rate,
    /// Too many resolutions already running.
    Busy,
}

impl NzblnkGate {
    /// Admit one resolution, or say why not.
    ///
    /// `now` is a parameter so the tests can drive the window without
    /// sleeping through a minute of it.
    ///
    /// The in-flight slot is taken FIRST and dropped again if the
    /// windows refuse, so a refused request never counts as running;
    /// the other order would let a peer that is only ever refused hold
    /// slots off the peers that would be admitted.
    pub(super) fn admit(
        &self,
        peer: Option<std::net::IpAddr>,
        now: Instant,
    ) -> std::result::Result<NzblnkPermit<'_>, NzblnkRefusal> {
        let mut permit = self.take_slot().ok_or(NzblnkRefusal::Busy)?;
        permit.nth_for_peer = self.admit_window(peer, now).ok_or(NzblnkRefusal::Rate)?;
        Ok(permit)
    }

    /// Take one of [`NZBLNK_INFLIGHT_MAX`] slots, or `None`.
    ///
    /// A CAS loop rather than `fetch_add` then compare: the add would
    /// let a burst push the counter past the cap before any of them
    /// checked, and a counter that has been over its ceiling reads as
    /// "full" to everyone who looks while the overshoot unwinds.
    fn take_slot(&self) -> Option<NzblnkPermit<'_>> {
        use std::sync::atomic::Ordering;
        let mut cur = self.inflight.load(Ordering::Acquire);
        loop {
            if cur >= NZBLNK_INFLIGHT_MAX {
                return None;
            }
            match self.inflight.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(NzblnkPermit {
                        gate: self,
                        nth_for_peer: 1,
                    });
                }
                Err(seen) => cur = seen,
            }
        }
    }

    /// Record one arrival for `peer`, or refuse it. Answers how many of
    /// this peer's window the arrival is, counting itself.
    fn admit_window(&self, peer: Option<std::net::IpAddr>, now: Instant) -> Option<usize> {
        let mut w = self.windows.lock_ok();
        // Trim EVERY peer, not just this one, and drop the peers left
        // with nothing: an entry is only ever created by an admitted
        // arrival, so this is what keeps the map bounded by
        // NZBLNK_GLOBAL_MAX rather than by however many addresses have
        // ever spoken to us. It is a walk of at most that many short
        // deques, under a lock held for no I/O.
        w.retain(|_, q| {
            while q
                .front()
                .is_some_and(|t| now.saturating_duration_since(*t) > NZBLNK_WINDOW)
            {
                q.pop_front();
            }
            !q.is_empty()
        });
        if w.values().map(VecDeque::len).sum::<usize>() >= NZBLNK_GLOBAL_MAX {
            return None;
        }
        let q = w.entry(peer).or_default();
        if q.len() >= NZBLNK_MAX {
            return None;
        }
        q.push_back(now);
        Some(q.len())
    }
}

/// A grab token stays valid this long after its search.
#[cfg(feature = "indexer")]
pub const INDEXER_HIT_TTL: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// How long a pull search will wait for an xREL slot before giving up on
/// the id enrichment. Their search budget is 2 calls per 5 s, so a
/// second search inside that window finds the bucket empty - and a
/// search that returns its releases a beat sooner without an IMDb id is
/// a better answer than one that returns everything late.
#[cfg(feature = "indexer")]
pub const XREL_UI_WAIT: std::time::Duration = std::time::Duration::from_millis(400);
/// Ceiling on cached external results across all searches.
#[cfg(feature = "indexer")]
pub const INDEXER_HIT_CAP: usize = 5000;
/// Ceiling on one search/caps response body. A 100-item page of XML is
/// well under 1 MB; 8 MB is runaway-response territory, same idea as
/// [`FETCH_MAX_BYTES`].
pub(super) const INDEXER_BODY_MAX: u64 = 8 * 1024 * 1024;
/// How long a limit error (daily quota, HTTP 429) parks an indexer.
pub const INDEXER_LIMIT_BACKOFF: std::time::Duration = std::time::Duration::from_secs(60 * 60);
/// How long a successful `t=caps` answer stays fresh. Capabilities
/// change when a site is upgraded, which is rare.
#[cfg(feature = "indexer")]
pub(super) const INDEXER_CAPS_TTL: std::time::Duration =
    std::time::Duration::from_secs(24 * 60 * 60);
/// How long a FAILED caps probe is remembered. Short, because the cause
/// is usually transient (the site was down), but not zero, because the
/// alternative is a caps request in front of every search.
#[cfg(feature = "indexer")]
pub(super) const INDEXER_CAPS_FAIL_TTL: std::time::Duration =
    std::time::Duration::from_secs(10 * 60);

/// The one agent every pull-search call goes out through: SSRF-guarded
/// like every other daemon fetch, 15 s ceiling per call so a dead
/// indexer costs one timeout, not a wedged search.
///
/// Idle connections are NOT kept, which is the one place this agent
/// differs from [`shared_enrich_agent`]. A reused connection skips the
/// resolver entirely, and the resolver is where a search learns the
/// address its indexer answered from - the fact every later grab is
/// checked against (M9, see [`OriginBoundResolver`]). Caps-then-search,
/// or the scoreboard's seven sequential categories, would otherwise
/// witness the first request and nothing after it, and a LAN indexer's
/// grabs would start being refused.
///
/// The price is one connection setup per search request, against an
/// endpoint that meters us per DAY: a handful of requests per user
/// action, already paced by sleeps in the loops that repeat.
pub(super) fn shared_indexer_agent() -> ureq::Agent {
    static AGENT: std::sync::OnceLock<ureq::Agent> = std::sync::OnceLock::new();
    AGENT
        .get_or_init(|| {
            ureq::AgentBuilder::new()
                .resolver(SsrfGuardResolver)
                .redirects(4)
                .timeout(std::time::Duration::from_secs(15))
                .max_idle_connections_per_host(0)
                .build()
        })
        .clone()
}

/// GET one indexer API URL, capped. Transport-level limit answers (a
/// real HTTP 429/503) map to `Limit` here; protocol errors ship as
/// HTTP 200 XML and are the caller's `parse_error` pass.
/// Blank the `apikey=` value anywhere in a string. A transport error's
/// Display carries the URL it failed on, and that URL carries the user's
/// key - which then rode into a toast, a rendered error row and anything
/// the user pasted into a bug report. M35's contract is that the key
/// never reaches a browser or a log, so it is scrubbed at the one choke
/// point every indexer error passes through.
pub fn redact_apikey(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    // `key=`, not `apikey=`, since TODO 297: nzbindex's API spells its
    // credential `key=`, and matching the shorter literal covers BOTH
    // spellings because one is a suffix of the other - `apikey=SECRET`
    // matches at the `key=` and the leading `api` is copied through
    // ahead of it, so the Newznab output is byte-identical to what the
    // narrower pass produced. Over-matching is the safe direction here:
    // redacting one query parameter too many costs a reader nothing,
    // and this function's whole job is that a credential never reaches
    // a log line or the dashboard.
    while let Some(p) = rest.find("key=") {
        out.push_str(&rest[..p + "key=".len()]);
        out.push_str("***");
        // The value runs to the next query separator or to whatever ends
        // the URL inside a longer sentence.
        let tail = &rest[p + "key=".len()..];
        let end = tail
            .find(|c: char| c == '&' || c == '#' || c.is_whitespace())
            .unwrap_or(tail.len());
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// Scrub an error that came out of an indexer's own RESPONSE BODY.
///
/// [`redact_apikey`] and [`redact_url_creds`] both guard errors we
/// built, whose text we therefore know the shape of. This guards text
/// the far end wrote. Newznab reports protocol errors with HTTP 200, so
/// the body arrives AFTER every transport-level scrub has run, and its
/// `<error description>` is echoed verbatim to Test results, search
/// notes, the wall and the logs. Indexers routinely reflect the request
/// back - `description="invalid apikey=SECRET"` - and some spell the key
/// no particular way at all, so the `apikey=` pass alone is not enough:
/// the configured value itself is blanked wherever it appears (14 Aug
/// sweep). Keys shorter than 8 characters are left alone; blanking a
/// 3-character string would redact ordinary prose.
pub fn scrub_indexer_body_error(
    e: crate::newznab::NewznabError,
    apikey: &str,
) -> crate::newznab::NewznabError {
    use crate::newznab::NewznabError as E;
    let clean = |m: &str| {
        let m = redact_apikey(m);
        if apikey.len() >= 8 {
            m.replace(apikey, "***")
        } else {
            m
        }
    };
    match e {
        E::Auth(c, m) => E::Auth(c, clean(&m)),
        E::Limit(c, m) => E::Limit(c, clean(&m)),
        E::Api(c, m) => E::Api(c, clean(&m)),
    }
}

pub(super) fn indexer_fetch(
    url: &str,
) -> std::result::Result<String, crate::newznab::NewznabError> {
    use crate::newznab::NewznabError;
    use std::io::Read as _;
    let resp = match shared_indexer_agent().get(url).call() {
        Ok(r) => r,
        Err(ureq::Error::Status(code @ (429 | 503), _)) => {
            return Err(NewznabError::Limit(code, format!("HTTP {code}")));
        }
        Err(ureq::Error::Status(code, _)) => {
            return Err(NewznabError::Api(code, format!("HTTP {code}")));
        }
        Err(e) => return Err(NewznabError::Api(0, redact_apikey(&e.to_string()))),
    };
    let mut bytes = Vec::new();
    resp.into_reader()
        .take(INDEXER_BODY_MAX + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| NewznabError::Api(0, redact_apikey(&e.to_string())))?;
    if bytes.len() as u64 > INDEXER_BODY_MAX {
        return Err(NewznabError::Api(0, "response too large".into()));
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// One search against one indexer: the results, and the [`SourceOrigin`]
/// every link in them is bound to when grabbed.
///
/// The origin is built HERE, from this request's own resolution, and
/// travels with the results. That is the point: at grab time the same
/// hostname may answer differently, and comparing names alone would call
/// the new answer the source's own socket (M9). See
/// [`OriginBoundResolver`].
pub fn indexer_search_one(
    cfg: &crate::newznab::IndexerConfig,
    q: &crate::newznab::SearchQuery,
) -> std::result::Result<
    (Vec<crate::newznab::SearchResult>, SourceOrigin),
    crate::newznab::NewznabError,
> {
    use crate::newznab::SourceKind;
    // TODO 297: the one place that knows there are two protocols. Every
    // caller above this - pull search, the hunt, the watchlist, the
    // `nzblnk:` ladder - is untouched, which is the whole reason the
    // nzbindex adapter answers in `newznab::SearchResult`.
    let url = match cfg.kind {
        SourceKind::Newznab => crate::newznab::search_url(cfg, q),
        SourceKind::Nzbindex => {
            // An empty query is refused HERE rather than sent. Newznab
            // answers a `q=` with an error document; nzbindex answers it
            // with its whole firehose (10,000 elements, measured 26 Aug
            // 2026), so the same mistake that fails loudly against one
            // source would quietly flood the merge from the other.
            if q.q.trim().is_empty() {
                return Err(crate::newznab::NewznabError::Api(
                    0,
                    "nzbindex: refusing an empty query (it would return everything)".into(),
                ));
            }
            crate::nzbindex::search_url(cfg, q)
        }
    };
    // The netloc of the CONFIGURED url, which is what the grab compares
    // against; `endpoint()` only ever adds a path, so it is the netloc
    // this request is dialling too.
    let (body, addrs) = witness_resolution(&url_netloc(&cfg.url), || indexer_fetch(&url));
    let body = body?;
    let items = match cfg.kind {
        SourceKind::Newznab => {
            if let Some(e) = crate::newznab::parse_error(&body) {
                return Err(scrub_indexer_body_error(e, &cfg.apikey));
            }
            crate::newznab::parse_results(&body)
        }
        // Strict, and it reports a schema break as an ERROR rather than
        // as an empty result list - see `nzbindex::parse_results`. That
        // error reaches the user as this entry's own note in the search
        // answer, which is the point: a hardcoded third-party schema
        // WILL move, and when it does the source has to say it is
        // broken rather than look like it found nothing.
        SourceKind::Nzbindex => {
            crate::nzbindex::parse_results(&body, cfg).map_err(|e| {
                // Same scrub as the Newznab body path. Their
                // `errorMessage` is a third party's text echoed to the
                // dashboard and the logs, and this API takes its key in
                // the query string.
                scrub_indexer_body_error(e, &cfg.apikey)
            })?
        }
    };
    Ok((items, SourceOrigin::witnessed(&cfg.url, addrs)))
}

/// This indexer's caps, from the cache when fresh, else probed. A probe
/// failure caches None (briefly) and the caller then plans a plain
/// free-text search, so caps trouble degrades the search rather than
/// failing it.
///
/// Only called when a query actually carries an id worth planning
/// around: a plain free-text search needs no caps at all, and must not
/// pay for a probe.
#[cfg(feature = "indexer")]
pub fn indexer_caps_cached(
    d: &Daemon,
    cfg: &crate::newznab::IndexerConfig,
) -> Option<crate::newznab::Caps> {
    let id = cfg.identity();
    if let Some((at, caps)) = d.indexer_rt.lock_ok().caps.get(&id) {
        let ttl = if caps.is_some() {
            INDEXER_CAPS_TTL
        } else {
            INDEXER_CAPS_FAIL_TTL
        };
        if at.elapsed() < ttl {
            return caps.clone();
        }
    }
    let got = indexer_caps_one(cfg).ok();
    d.indexer_rt
        .lock_ok()
        .caps
        .insert(id, (Instant::now(), got.clone()));
    got
}

/// One `t=caps` against one indexer, with a sanity check that the far
/// end is a Newznab API at all (a parked domain answers 200 with HTML,
/// which parses to an all-default Caps).
pub fn indexer_caps_one(
    cfg: &crate::newznab::IndexerConfig,
) -> std::result::Result<crate::newznab::Caps, crate::newznab::NewznabError> {
    // TODO 297: nzbindex publishes no `t=caps`, so "does this entry
    // work" is answered by the only question that API takes - a real,
    // narrow search. That is a better Test than caps anyway: it
    // exercises the exact path a search will take, including the strict
    // schema check, so a Test that passes means results will parse.
    if cfg.kind == crate::newznab::SourceKind::Nzbindex {
        let body = indexer_fetch(&crate::nzbindex::probe_url(cfg))?;
        // The probe is judged by whether the ANSWER PARSES, not by
        // whether it found anything: `q=test` legitimately matching
        // nothing is a working source, while a body that is not the
        // documented shape is the rot this source has to report.
        crate::nzbindex::parse_results(&body, cfg)
            .map_err(|e| scrub_indexer_body_error(e, &cfg.apikey))?;
        return Ok(crate::newznab::Caps {
            server: "nzbindex".into(),
            // Free-text search is the whole of what this API does: no
            // categories, no id search. Saying so truthfully is what
            // keeps `plan_query` from ever planning one - and what lets
            // the dashboard's Test line tell the user what they got.
            search: true,
            ..Default::default()
        });
    }
    let body = indexer_fetch(&crate::newznab::caps_url(cfg))?;
    if let Some(e) = crate::newznab::parse_error(&body) {
        return Err(scrub_indexer_body_error(e, &cfg.apikey));
    }
    let caps = crate::newznab::parse_caps(&body);
    if !caps.search && caps.server.is_empty() && caps.categories.is_empty() {
        return Err(crate::newznab::NewznabError::Api(
            0,
            "not a newznab API (no caps)".into(),
        ));
    }
    Ok(caps)
}

/// Persist the day's indexer hit/grab counters.
///
/// The snapshot and the write are ONE critical section, and the write is
/// atomic. Both matter, and neither used to hold: the clone happened
/// under the runtime lock, the lock was then released, and a bare
/// `fs::write` followed. Two concurrent grabs could therefore snapshot 1
/// and 2 and land in that order or the other, so the file could end up
/// recording 1 after 2 was already counted - and a same-day restart
/// reloads whatever is on disk, handing back budget the user's paid
/// account had already spent. The bare write could also leave a
/// half-truncated file that reloads as no counters at all.
pub fn save_indexer_usage(d: &Daemon) {
    // Separate from indexer_rt: this is held across file I/O, and
    // indexer_rt is on the search path.
    static IO: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _g = IO.lock_ok();
    let u = d.indexer_rt.lock_ok().usage.clone();
    if let Ok(b) = serde_json::to_vec(&u)
        && let Err(e) = crate::persist::write_atomic(&d.spool.join("indexer-usage.json"), &b)
    {
        warn!(target: "indexer", "could not persist usage counters: {e}");
    }
}

/// Turn one parsed NZBLNK into a queued job, or say why not.
///
/// The ladder is our own index first (free, offline, and it can emit the
/// NZB straight from the segment ids the scan stored) and the user's
/// configured indexers second (one API hit each, under the same daily
/// budgets and limit backoff the pull search obeys).
///
/// A local hit that is INCOMPLETE does not short-circuit the ladder: a
/// synthesized NZB missing parts downloads and then fails repair, so the
/// indexers get their turn first and the partial release is only used
/// when nothing else answered - with a note saying so, because "queued,
/// and we already know parts are missing" is not the same promise as
/// "queued".
pub fn resolve_nzblnk(
    d: &Daemon,
    l: &nzbkit::nzblnk::NzbLnk,
    cat: &str,
    prio: i32,
    password: Option<&str>,
    dupe_ok: bool,
    peer: Option<std::net::IpAddr>,
) -> serde_json::Value {
    let mut notes: Vec<serde_json::Value> = Vec::new();

    // ---- The gate. --------------------------------------------------
    // Three thresholds, because the three things a loop can spend are
    // not equally scarce. Local resolution costs CPU (rung 3 of
    // find_by_header is an unindexed scan); asking the indexers costs
    // the user's metered account; and either one holds a worker off an
    // 8-strong HTTP pool while it runs. So the cheap half stays
    // available far longer than the expensive one, passing the second
    // threshold DEGRADES to local-only rather than failing - a link our
    // own index can answer is answered - and the third is a hard cap on
    // how many can be running at once. See `NzblnkGate`.
    //
    // The permit lives to the end of this function: dropping it is what
    // gives the in-flight slot back, on every path out including the
    // failures.
    let permit = match d.nzblnk_gate.admit(peer, Instant::now()) {
        Ok(p) => p,
        // One `reason` for both, because they are one sentence to the
        // person holding the mouse ("too many at once, wait a moment")
        // and the dashboard already says it in their language. The
        // `error` string is what tells the two apart in a log.
        Err(NzblnkRefusal::Rate) => {
            return json!({"status": false, "reason": "toofast",
                "error": "too many links at once - wait a moment and try again"});
        }
        Err(NzblnkRefusal::Busy) => {
            return json!({"status": false, "reason": "toofast",
                "error": "too many links are still being looked up - wait a moment and try again"});
        }
    };
    let may_ask_indexers = permit.nth_for_peer <= NZBLNK_EXTERNAL_MAX;

    // ---- Rung 1: our own header index. ------------------------------
    // Ranking, strongest first: complete beats partial, a release in a
    // group the link named beats one somewhere else, then size. `>` and
    // not `>=`, so ties keep find_by_header's own ordering (exact stem
    // ahead of a filename match).
    #[cfg(feature = "indexer")]
    let rank = |r: &nzbkit::index::Release| {
        (
            r.complete,
            l.groups.is_empty() || l.groups.iter().any(|g| g.eq_ignore_ascii_case(&r.grp)),
            r.total_bytes,
        )
    };
    // A read-only connection on both index calls: this is an
    // interactive handler, and rung 3 of find_by_header is a table scan.
    // On the read-write connection a catch-up ingest or maintenance pass
    // would park the paste for as long as it holds the mutex (measured
    // at 62s for wall2 before the read-only connection existed).
    //
    // index_read_checked, not with_index_read: the flattening wrapper
    // reports a saturated read pool or a twice-failed SQLITE_SCHEMA as
    // None, which this ladder cannot tell from "we do not have that
    // post" - so it would fall through to rung 2 and send the user's
    // header to third-party indexers, spending their API quota and
    // re-downloading a post the index already holds (read-only sweep 3,
    // 16 Aug 2026, L2). Both causes are transient: say so and let the
    // user paste again rather than escalating on a read that never
    // happened.
    #[cfg(feature = "indexer")]
    let local = match d.index_read_checked(|ix| {
        let mut best: Option<nzbkit::index::Release> = None;
        for r in ix.find_by_header(&l.header, 8).ok()? {
            if best.as_ref().is_none_or(|b| rank(&r) > rank(b)) {
                best = Some(r);
            }
        }
        best
    }) {
        Err(why) => {
            return why.refusal();
        }
        Ok(best) => best,
    };
    #[cfg(feature = "indexer")]
    let queue_local = |r: &nzbkit::index::Release,
                       partial: bool,
                       notes: &Vec<serde_json::Value>| {
        let xml = match d.with_index_read(|ix| ix.make_nzb(r.id).ok()) {
            Some(x) => x,
            None => {
                return json!({"status": false, "error": "the index could not rebuild that post"});
            }
        };
        let name = if l.title.is_empty() {
            r.stem.clone()
        } else {
            l.title.clone()
        };
        match d.enqueue(
            xml.as_bytes(),
            &name,
            cat,
            prio,
            None,
            password,
            "nzblnk",
            dupe_ok,
        ) {
            Ok(Enqueued { nzo_id: nzo, .. }) => {
                // Same protection a wall grab gets: the row this job came
                // from must survive the index size cap.
                d.touch_opened_release(r.id);
                json!({"status": true, "nzo_ids": [nzo], "name": name, "via": "index",
                       "partial": partial, "notes": notes})
            }
            Err(e) => json!({"status": false, "error": e.to_string()}),
        }
    };
    #[cfg(feature = "indexer")]
    if let Some(r) = local.as_ref().filter(|r| r.complete) {
        return queue_local(r, false, &notes);
    }
    #[cfg(feature = "indexer")]
    if local.is_some() {
        notes.push(json!({"index": "found the post, but parts are still missing"}));
    }

    // ---- Rung 2: the user's indexers, over the M35 client. -----------
    // A header is free text, so this is a plain `t=search` - no caps
    // probe (an id-less query never needs one) and no category filter,
    // because an obfuscated release name tells nobody what it is.
    let list: Vec<crate::newznab::IndexerConfig> = if may_ask_indexers {
        d.indexers
            .lock_ok()
            .iter()
            .filter(|i| i.enabled)
            .cloned()
            .collect()
    } else {
        notes.push(json!({"indexers":
            "skipped: too many link lookups just now, so only the local index was searched"}));
        Vec::new()
    };
    let mut runnable = Vec::new();
    {
        let mut rt = d.indexer_rt.lock_ok();
        rt.usage.roll(unix_now());
        let now = Instant::now();
        for i in list {
            if rt.penalty_until.get(&i.name).is_some_and(|t| *t > now) {
                notes.push(json!({"indexer": i.name,
                    "skipped": "backing off after a limit error"}));
            } else if !rt.usage.hit_allowed(&i) {
                notes.push(json!({"indexer": i.name, "skipped": "daily API budget reached"}));
            } else {
                rt.usage.count_hit(&i.name);
                runnable.push(i);
            }
        }
    }
    if !runnable.is_empty() {
        save_indexer_usage(d);
    }
    let query = crate::newznab::SearchQuery {
        q: l.header.clone(),
        limit: 100,
        ..Default::default()
    };
    let outcomes: Vec<_> = std::thread::scope(|s| {
        let handles: Vec<_> = runnable
            .into_iter()
            .map(|i| {
                let query = query.clone();
                s.spawn(move || {
                    let r = indexer_search_one(&i, &query);
                    (i, r)
                })
            })
            .collect();
        handles.into_iter().filter_map(|h| h.join().ok()).collect()
    });
    // A header identifies ONE posting, so this picks a single winner
    // rather than building a result list: a title that actually contains
    // the header beats one that merely matched some token of it, then
    // indexer priority, then the newest upload.
    let norm = |s: &str| {
        s.to_ascii_lowercase()
            .replace(['.', '_', '-'], " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    };
    let want = norm(&l.header);
    /// The single result the ladder settles on, with the indexer that
    /// offered it: the name for budgets and messages, and the origin the
    /// enclosure fetch is bound to (M12/M9).
    struct Pick {
        key: (u8, i32, i64),
        item: crate::newznab::SearchResult,
        indexer: String,
        origin: SourceOrigin,
    }
    let mut best: Option<Pick> = None;
    {
        let mut rt = d.indexer_rt.lock_ok();
        let now = Instant::now();
        for (cfg, outcome) in outcomes {
            match outcome {
                Ok((items, origin)) => {
                    for item in items {
                        let key = (
                            u8::from(!norm(&item.title).contains(&want)),
                            cfg.priority,
                            -item.posted,
                        );
                        if best.as_ref().is_none_or(|b| key < b.key) {
                            best = Some(Pick {
                                key,
                                item,
                                indexer: cfg.name.clone(),
                                origin: origin.clone(),
                            });
                        }
                    }
                }
                Err(e) => {
                    if matches!(e, crate::newznab::NewznabError::Limit(..)) {
                        rt.penalty_until
                            .insert(cfg.name.clone(), now + INDEXER_LIMIT_BACKOFF);
                    }
                    notes.push(json!({"indexer": cfg.name, "error": e.to_string()}));
                }
            }
        }
    }
    if let Some(Pick {
        item,
        indexer,
        origin,
        ..
    }) = best
    {
        let allowed = {
            let mut rt = d.indexer_rt.lock_ok();
            rt.usage.roll(unix_now());
            d.indexers
                .lock_ok()
                .iter()
                .find(|i| i.name == indexer)
                .is_none_or(|c| rt.usage.grab_allowed(c))
        };
        if !allowed {
            notes.push(json!({"indexer": indexer, "skipped": "daily grab budget reached"}));
        } else {
            let name = if l.title.is_empty() {
                item.title.clone()
            } else {
                l.title.clone()
            };
            // fetch_url_from, not fetch_url: item.link is an
            // `<enclosure url>` this indexer's search response chose, so
            // it may not reach a private address other than the
            // indexer's own socket (M12).
            match fetch_url_from(&item.link, &origin)
                .map_err(|e| e.to_string())
                .and_then(|f| {
                    d.enqueue_fetched(
                        &f,
                        &name,
                        cat,
                        prio,
                        None,
                        password,
                        0,
                        "nzblnk",
                        DupeExempt::asked(dupe_ok),
                    )
                    .map_err(|e| e.to_string())
                }) {
                Ok(Enqueued { nzo_id: nzo, .. }) => {
                    d.indexer_rt.lock_ok().usage.count_grab(&indexer);
                    save_indexer_usage(d);
                    return json!({"status": true, "nzo_ids": [nzo], "name": name,
                                  "via": indexer, "partial": false, "notes": notes});
                }
                // The NZB link itself failed. Not fatal to the ladder -
                // a partial local copy may still be better than nothing.
                //
                // redact_url_creds: fetch_url names the URL it failed on,
                // and that URL is the enclosure link out of the indexer's
                // XML, which carries the user's account credential. This
                // string goes straight into the dashboard's notes.
                Err(e) => notes.push(json!({"indexer": indexer, "error": redact_url_creds(&e)})),
            }
        }
    }

    // ---- Last resort: the partial local hit, honestly labelled. ------
    #[cfg(feature = "indexer")]
    if let Some(r) = local.as_ref() {
        return queue_local(r, true, &notes);
    }
    json!({"status": false, "reason": "notfound", "notes": notes,
           "error": "nothing found for that link - the post may be too new to be indexed, \
                     or too old to still be on your server"})
}

#[cfg(all(test, feature = "indexer"))]
mod nzblnk_local_read_tests {
    use super::*;

    /// A local index read that FAILED must not be spent as "we do not
    /// have that post".
    ///
    /// `with_index_read` flattens a saturated read pool and a
    /// twice-failed SQLITE_SCHEMA into `None`, and this ladder read that
    /// as a clean local miss: it walked on to rung 2 and sent the user's
    /// header to every configured third-party indexer, spending their
    /// API quota and re-downloading a post the index already held
    /// (read-only sweep 3, 16 Aug 2026, L2). Both causes are transient,
    /// so the honest answer is "not right now" and the user pastes
    /// again.
    #[test]
    fn a_failed_local_read_is_not_a_local_miss() {
        let dir = std::env::temp_dir().join(format!("nzbfast-nzblnk-busy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let d = crate::testutil::test_daemon(&dir);
        d.index_enabled
            .store(true, std::sync::atomic::Ordering::Relaxed);
        // A read-write open runs the migrations and publishing it sets
        // `index_migrated`, which is what routes the lookup below to the
        // read POOL rather than to the startup fallback on the write
        // mutex (the same setup the seam's own tests use).
        let era = d.index_era();
        let fresh = nzbkit::index::Index::open(&d.index_db).expect("open the index");
        d.publish_index(era, fresh);

        // Arm the pooled connection and hand it straight back: the idle
        // list is a stack, so the very next read pops the connection
        // just released. Two injected faults is one more than the retry
        // absorbs, so the header lookup stamps the fault the seam reads
        // - the real race (a writer changing the schema between prepare
        // and step, twice) is what this stands in for.
        assert!(
            matches!(
                d.index_read_checked(|ix| {
                    ix.debug_fail_next_queries(2);
                    Some(())
                }),
                Ok(Some(()))
            ),
            "arming must not itself look like a fault"
        );

        let l = nzbkit::nzblnk::NzbLnk {
            header: "some.obfuscated.header".into(),
            ..Default::default()
        };
        let j = resolve_nzblnk(&d, &l, "", 0, None, false, None);
        assert_eq!(
            j["busy"],
            json!(true),
            "a read that FAILED must be reported as transient, not escalated: {j}"
        );
        assert_ne!(
            j["reason"],
            json!("notfound"),
            "the ladder must not have run to the bottom on a read that never happened: {j}"
        );
        drop(d);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod nzblnk_gate_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(last: u8) -> Option<IpAddr> {
        Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, last)))
    }

    /// Fill `peer`'s window with `n` admitted-and-finished resolutions.
    fn burn(gate: &NzblnkGate, peer: Option<IpAddr>, now: Instant, n: usize) {
        for i in 0..n {
            assert!(
                gate.admit(peer, now).is_ok(),
                "arrival {i} of {n} should have been admitted"
            );
        }
    }

    /// The point of keying per peer: with one shared window, whoever
    /// spends it first denies everyone else - which is what a page in a
    /// loop does to the user's own paste, and is the whole of §51's open
    /// residue.
    #[test]
    fn one_peer_burning_its_window_does_not_deny_another() {
        let gate = NzblnkGate::default();
        let now = Instant::now();
        burn(&gate, ip(10), now, NZBLNK_MAX);
        assert_eq!(
            gate.admit(ip(10), now).err(),
            Some(NzblnkRefusal::Rate),
            "the noisy peer is out of window"
        );
        assert!(
            gate.admit(ip(11), now).is_ok(),
            "the legitimate user's own paste still goes through"
        );
        // ...and an unknown-address transport is one bucket of its own,
        // not a hole every refused peer can fall through.
        assert!(gate.admit(None, now).is_ok());
    }

    /// The other half: per-peer windows must not add up to an unbounded
    /// total, because the indexer quota underneath is one account
    /// however many machines ask.
    #[test]
    fn the_global_ceiling_bounds_every_peer_together() {
        let gate = NzblnkGate::default();
        let now = Instant::now();
        let peers = NZBLNK_GLOBAL_MAX / NZBLNK_MAX;
        for p in 0..peers {
            burn(&gate, ip(p as u8), now, NZBLNK_MAX);
        }
        // A peer that has never been seen, and so has a completely empty
        // window of its own, is still refused.
        assert_eq!(
            gate.admit(ip(200), now).err(),
            Some(NzblnkRefusal::Rate),
            "the global ceiling is not per-peer"
        );
    }

    /// The expensive half is spent per peer like the cheap half, and
    /// passing it still DEGRADES rather than failing - the resolution is
    /// admitted, it just may not reach the user's metered accounts.
    #[test]
    fn the_external_threshold_is_counted_per_peer() {
        let gate = NzblnkGate::default();
        let now = Instant::now();
        for n in 1..=NZBLNK_EXTERNAL_MAX {
            let p = gate.admit(ip(10), now).expect("under the rate cap");
            assert_eq!(p.nth_for_peer, n);
            assert!(p.nth_for_peer <= NZBLNK_EXTERNAL_MAX, "may ask indexers");
        }
        let p = gate.admit(ip(10), now).expect("still admitted, just local");
        assert!(
            p.nth_for_peer > NZBLNK_EXTERNAL_MAX,
            "past the threshold this peer is local-only"
        );
        drop(p);
        // A different peer starts at one, so one loop cannot spend
        // another machine's share of the account either.
        assert_eq!(gate.admit(ip(11), now).expect("fresh peer").nth_for_peer, 1);
    }

    /// Twenty arrivals in one second all pass the window; nothing in it
    /// says how many may be RUNNING. The pool this endpoint answers from
    /// has eight workers.
    #[test]
    fn only_four_resolutions_run_at_once() {
        let gate = NzblnkGate::default();
        let now = Instant::now();
        let held: Vec<_> = (0..NZBLNK_INFLIGHT_MAX)
            .map(|i| {
                gate.admit(ip(i as u8), now)
                    .expect("under the in-flight cap")
            })
            .collect();
        assert_eq!(
            gate.admit(ip(200), now).err(),
            Some(NzblnkRefusal::Busy),
            "a fresh peer with an empty window is still refused while the pool is full"
        );
        drop(held);
        assert!(
            gate.admit(ip(200), now).is_ok(),
            "a finished resolution gives its slot back"
        );
    }

    /// The guard is the reason this holds on the failure paths too: a
    /// refused arrival must not keep a slot, or four refusals in a row
    /// would wedge the endpoint until the daemon restarted.
    #[test]
    fn a_rate_refusal_does_not_keep_its_in_flight_slot() {
        let gate = NzblnkGate::default();
        let now = Instant::now();
        burn(&gate, ip(10), now, NZBLNK_MAX);
        for _ in 0..NZBLNK_INFLIGHT_MAX * 2 {
            assert_eq!(gate.admit(ip(10), now).err(), Some(NzblnkRefusal::Rate));
        }
        assert_eq!(
            gate.inflight.load(std::sync::atomic::Ordering::Acquire),
            0,
            "every refusal handed its slot straight back"
        );
        assert!(gate.admit(ip(11), now).is_ok());
    }

    /// The window slides, or a peer that hit the cap once would be
    /// refused for the life of the process.
    #[test]
    fn the_window_slides_off_the_back() {
        let gate = NzblnkGate::default();
        let now = Instant::now();
        burn(&gate, ip(10), now, NZBLNK_MAX);
        assert_eq!(gate.admit(ip(10), now).err(), Some(NzblnkRefusal::Rate));
        let later = now + NZBLNK_WINDOW + std::time::Duration::from_secs(1);
        assert_eq!(
            gate.admit(ip(10), later)
                .expect("window is out")
                .nth_for_peer,
            1,
            "the peer starts over, it does not resume mid-window"
        );
    }

    /// A map keyed by peer address is a map an attacker would like to
    /// grow. It cannot: an entry is only ever created by an ADMITTED
    /// arrival, so the global ceiling bounds the entry count too, and a
    /// peer whose window has run out is dropped rather than kept as an
    /// empty deque forever.
    #[test]
    fn peers_are_forgotten_once_their_window_runs_out() {
        let gate = NzblnkGate::default();
        let now = Instant::now();
        for p in 0..50u8 {
            assert!(gate.admit(ip(p), now).is_ok());
        }
        assert_eq!(gate.windows.lock_ok().len(), 50);
        let later = now + NZBLNK_WINDOW + std::time::Duration::from_secs(1);
        assert!(gate.admit(ip(200), later).is_ok());
        assert_eq!(
            gate.windows.lock_ok().len(),
            1,
            "the 50 stale buckets went with the window, not just the one asked about"
        );
    }
}

#[cfg(test)]
mod redaction_case_tests {
    use super::{fetch_head, redact_url_creds};

    /// The real error, end to end, not a hand-written imitation of it.
    ///
    /// `fetch_head` refuses a scheme it does not recognise by naming the
    /// WHOLE url, and a mixed-case link gets that far because every gate
    /// in front of it compares schemes case-insensitively. The refusal
    /// then goes to the log ring (`failurelink`, `confirm`, feed health)
    /// and into `indexer_grab`'s JSON response. This pins the pairing:
    /// whatever that message contains, the scrubber takes the credential
    /// out of it. No socket is opened - the bail is the first statement.
    #[test]
    fn a_refused_mixed_case_url_cannot_leak_through_its_error() {
        let e = fetch_head(
            "HTTPS://user:pw@idx.example/getnzb/abc?apikey=SECRET123",
            None,
        )
        .expect_err("a mixed-case scheme is still refused, deliberately");
        let msg = redact_url_creds(&e.to_string());
        assert!(!msg.contains("SECRET123"), "{msg}");
        assert!(!msg.contains("user:pw"), "{msg}");
        assert!(msg.contains("idx.example"), "the host must survive: {msg}");
    }

    /// The pairing above only holds for a url the scrubber can PARSE.
    /// It finds one by its `://`, and `fetch_head` refuses strings that
    /// need not be well formed at all - so a single-slash
    /// `https:/host/x?apikey=...` used to travel whole into the API
    /// answer and the log with nothing to strip it (Fable sweep 15 Aug).
    /// The refusal now names at most scheme and authority.
    #[test]
    fn a_refused_malformed_url_cannot_leak_its_query_either() {
        let e = fetch_head("https:/idx.example/getnzb/abc?apikey=SECRET123", None)
            .expect_err("a single-slash url is refused");
        let msg = redact_url_creds(&e.to_string());
        assert!(!msg.contains("SECRET123"), "{msg}");
        assert!(!msg.contains("getnzb"), "the path is not diagnostic: {msg}");
    }

    /// The malformed-url cut has to drop USERINFO as well as the path.
    ///
    /// `https:user:pw@idx.example/feed` is the shape that got past both
    /// halves: no `://`, so the refusal's authority scan started at
    /// byte 0 and the cut at the first slash kept the whole
    /// `https:user:pw@idx.example`, and `redact_url_creds` finds a url
    /// by its `://` and so had nothing to strip. Feed health writes
    /// that string to the settings row and the log ring, and
    /// `indexer_grab` returns it to the browser. A feed url the user
    /// mistyped one slash out of is exactly the one carrying their
    /// account credential (sweep 2 L3).
    #[test]
    fn a_refused_malformed_url_cannot_leak_its_userinfo() {
        let e = fetch_head("https:user:pw@idx.example/feed?apikey=SECRET123", None)
            .expect_err("a url with no // is refused");
        let msg = redact_url_creds(&e.to_string());
        assert!(!msg.contains("SECRET123"), "{msg}");
        assert!(!msg.contains("pw@"), "the userinfo must not survive: {msg}");
        assert!(!msg.contains("user:pw"), "{msg}");
        // The other direction: the refusal is still worth reading. The
        // host names who was refused and the scheme names why.
        assert!(msg.contains("idx.example"), "the host must survive: {msg}");
        assert!(
            msg.contains("https"),
            "the rejected scheme must survive: {msg}"
        );

        // And a well-formed url loses nothing it used to say.
        let e = fetch_head("ftp://idx.example/getnzb/abc", None).expect_err("ftp is refused");
        assert_eq!(e.to_string(), "addurl: unsupported url ftp://idx.example");
    }

    /// The scrubber must not care how the scheme is spelled.
    ///
    /// Everything else in the URL layer compares schemes with
    /// `eq_ignore_ascii_case`, so `HTTPS://...` survives every origin
    /// and downgrade gate and only `fetch_head` refuses it - by name,
    /// in a message that carries the whole URL. That message is logged
    /// (`failurelink`, `confirm`, the RSS feed health row), exported
    /// from the log pane, and returned to the browser by `indexer_grab`.
    /// When this function only knew the two lowercase spellings, every
    /// one of those sinks got the credential verbatim.
    #[test]
    fn a_mixed_case_scheme_is_redacted_like_any_other() {
        let got =
            redact_url_creds("addurl: unsupported url HTTPS://idx.example/getnzb/abc?r=SECRET123");
        assert!(!got.contains("SECRET123"), "{got}");
        assert_eq!(got, "addurl: unsupported url HTTPS://idx.example/...");

        let got = redact_url_creds("Http://user:pw@idx.example/x?k=1 failed");
        assert!(!got.contains("pw"), "{got}");
        assert_eq!(got, "Http://idx.example/... failed");
    }

    /// Any scheme, not just the two we write.
    ///
    /// `set_feeds` is the one config writer with no scheme check, so an
    /// `ftp://user:pw@host/path` feed reaches the poller, fails, and has
    /// its error recorded in the feed health row and the log ring.
    #[test]
    fn a_scheme_we_never_write_is_redacted_too() {
        let got = redact_url_creds("ftp://user:pw@h/p failed");
        assert!(!got.contains("pw"), "{got}");
        assert_eq!(got, "ftp://h/... failed");
    }

    /// Finding URLs by `://` must not start eating prose.
    ///
    /// The walk-back stops at the first byte that cannot be in a scheme,
    /// and a `://` with nothing in front of it is left exactly as it was
    /// rather than being treated as an empty-scheme URL.
    #[test]
    fn prose_around_a_url_survives_the_walk_back() {
        assert_eq!(
            redact_url_creds("failed at https://idx.example/x?k=1 twice"),
            "failed at https://idx.example/... twice"
        );
        assert_eq!(redact_url_creds("no scheme :// here"), "no scheme :// here");
        assert_eq!(redact_url_creds("plain error"), "plain error");
        // Non-ASCII in the sentence: the byte walk must stay on char
        // boundaries (these strings come out of indexer XML).
        assert_eq!(
            redact_url_creds("fehlgeschlagen: größer https://idx.example/x?k=1"),
            "fehlgeschlagen: größer https://idx.example/..."
        );
    }
}

/// FLOOR of the daily indexer-confirm budget. Each attempt costs one
/// API hit and (on a listing match) one grab against the user's own
/// account. This was the whole ceiling until 1 Sep 2026; the ruling
/// that day was to spend aggressively, so the ceiling is now DERIVED
/// from the account's own configured quotas (`confirm_budget` below)
/// and this constant is only the never-worse-than-before floor. It
/// lives here, in the indexer RUNTIME STATE rather than in the indexer
/// LANE, because the settings setter quotes the budget in the switch-on
/// line and `api::index` reports it, and both of those are below or
/// beside the lane that spends it - `tools/modgraph.py --serve` calls
/// the other arrangement an upward edge, twice over. The setter is
/// compiled with or without the `indexer` feature and this module is
/// too, which is what the old home could not offer either.
pub(crate) const CONFIRM_PER_DAY: u32 = 24;

/// The confirm budget when the account's quotas say nothing (0 means
/// unlimited on both fields): a fixed aggressive number rather than
/// actually unbounded, because an unmetered lane against somebody
/// else's service is how an account gets flagged. 400/day is well
/// inside what an ordinary *arr stack does against the same account.
pub(crate) const CONFIRM_UNLIMITED_PER_DAY: u32 = 400;

/// Daily indexer-confirm budget for one reference account: 80% of the
/// account's own configured allowance, whichever of hits/grabs binds
/// first (an attempt costs one of each), floored at [`CONFIRM_PER_DAY`].
///
/// The floor CANNOT overspend a deliberately tiny configured quota:
/// the runtime `hit_allowed`/`grab_allowed` guard is checked before
/// every attempt and is the hard wall - this number is only the lane's
/// self-restraint, and the floor just keeps it from throttling itself
/// below the long-standing 24.
pub fn confirm_budget(cfg: &crate::newznab::IndexerConfig) -> u32 {
    let cap = |q: u32| {
        if q == 0 {
            CONFIRM_UNLIMITED_PER_DAY
        } else {
            q.saturating_mul(4) / 5
        }
    };
    cap(cfg.grabs_per_day)
        .min(cap(cfg.hits_per_day))
        .max(CONFIRM_PER_DAY)
}

#[cfg(test)]
mod confirm_budget_tests {
    use super::{CONFIRM_PER_DAY, CONFIRM_UNLIMITED_PER_DAY, confirm_budget};

    fn cfg(hits: u32, grabs: u32) -> crate::newznab::IndexerConfig {
        crate::newznab::IndexerConfig {
            kind: Default::default(),
            nzbindex: Default::default(),
            name: String::new(),
            url: String::new(),
            apikey: String::new(),
            enabled: true,
            priority: 0,
            hits_per_day: hits,
            grabs_per_day: grabs,
        }
    }

    /// The four corners of the rule: unlimited takes the fixed
    /// aggressive number, a configured account takes 80% of whichever
    /// field binds first, and a tiny quota floors at the old 24 - safe
    /// only because the runtime quota guard is the hard wall, which is
    /// the fact the function's doc carries.
    #[test]
    fn the_budget_is_80_percent_of_the_binding_quota_with_floor_and_unlimited() {
        assert_eq!(confirm_budget(&cfg(0, 0)), CONFIRM_UNLIMITED_PER_DAY);
        // grabs bind (100 grabs vs 1000 hits): 80.
        assert_eq!(confirm_budget(&cfg(1000, 100)), 80);
        // hits bind when smaller.
        assert_eq!(confirm_budget(&cfg(50, 0)), 40);
        // a tiny quota floors at the old flat number.
        assert_eq!(confirm_budget(&cfg(10, 10)), CONFIRM_PER_DAY);
        // one unlimited field defers to the configured one.
        assert_eq!(confirm_budget(&cfg(0, 500)), 400);
    }
}
