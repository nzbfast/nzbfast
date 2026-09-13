//! Resolving SPOTS: taking the spot rows the scanner has already stored
//! and turning the ones worth having into real, fetched NZBs - the
//! connection budget one resolver pass may spend, the fetch outcome it
//! classifies each candidate into, the miss report, and the `spot_search`
//! entry point the CLI drives.
//!
//! Its own subject and its own network shape: everything above it in
//! `scan.rs` reads and writes the index over a group scan, while
//! everything here goes back out to a server for one article at a time
//! and has to budget for it.
//!
//! Cut out of `scan.rs` on 7 Sep 2026 (claim `debt-split-hot-files-7sep`)
//! at 3,223 of the size gate's 4,000-line file ceiling. Verbatim move;
//! the public items are re-exported beside the `mod` line, so
//! `scan::spot_search` and friends are unchanged for callers.

use super::*;

/// What one spot-NZB resolver pass did.
#[derive(Debug, Default)]
pub struct SpotResolveSummary {
    pub fetched: u32,
    pub promoted: u32,
    pub upgraded: u32,
    pub unusable: u32,
    pub failed: u32,
    /// Fresh cards whose head article was STATed, and how many of those
    /// came back gone (and so were demoted to incomplete).
    pub checked: u32,
    pub gone: u32,
}

/// How many connections one spot resolver pass fetches over.
///
/// Half the account's sessions, capped at [`SPOT_FETCH_CONNS_MAX`], in
/// the spirit of the header scanner's own 5/10 OVER clamp: the resolver
/// is a background lane and the connections belong to downloads first.
/// The corroborating STATs take one more, opened lazily, so a pass that
/// promotes nothing never asks for it - and on a one-connection account
/// it is that STAT session that gets refused, not the fetching.
///
/// Never more than there are spots to fetch: a 3-spot pass on a 60
/// connection account would otherwise open 8 sessions to leave 5 of
/// them idle.
pub(crate) fn spot_fetch_conns(connections: u32, pending: usize) -> usize {
    ((connections as usize) / 2)
        .clamp(1, SPOT_FETCH_CONNS_MAX)
        .min(pending.max(1))
}

/// Ceiling for [`spot_fetch_conns`]. Eight is the header scanner's own
/// idle-line clamp; the resolver is latency-bound rather than
/// bandwidth-bound, so past this the pass stops being the scan lap's
/// long pole and there is nothing left to buy.
pub(crate) const SPOT_FETCH_CONNS_MAX: usize = 8;

/// One budgeted spot-NZB resolver pass (E3 / TODO 131): fetch the NZB
/// for spots that have no release row yet and fold each into the index -
/// a fresh named release normally, an upgrade of the row our scanner
/// already holds for the ~0.6% that overlap. `stop` is polled between
/// results so a starting download preempts promptly.
///
/// Each spot costs one HEAD plus a handful of BODYs on the first scan
/// server, so a pass is bounded at `budget` such fetches; the backlog
/// after a first backfill drains over a few passes, newest first.
///
/// The fetches run on a few connections at once and the index writes
/// stay on this task: nearly all of a spot's ~0.58 s is round trips, so
/// the fan-out is what stops a larger `budget` simply making the scan
/// lap longer. Per-spot server cost is unchanged.
///
/// A freshly promoted card then gets ONE corroborating STAT of its head
/// article, up to `SPOT_STAT_PER_PASS` per pass: its completeness comes
/// from the NZB's own declaration and has never been checked against a
/// provider, which is survivable at the tip and not at 2011 depth. See
/// `Index::spot_stat_verdict`.
pub async fn spot_resolve_pass(
    config: &Path,
    ix: &mut nzbkit::index::Index,
    budget: u32,
    stop: impl Fn() -> bool,
) -> Result<SpotResolveSummary> {
    use nzbkit::index::SpotPromotion;
    let mut sum = SpotResolveSummary::default();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_secs() as i64)
        .unwrap_or(0);
    // One-shot, kv-guarded, and cheap enough to sit in front of the
    // pass: cards named with the spot XML's raw `<![CDATA[…]]>` markup
    // (54 live) get the title that was inside it.
    match ix.repair_cdata_spot_titles(now) {
        Ok(n) if n > 0 => info!(target: "spots", "repaired {n} spot cards named with XML markup"),
        Ok(_) => {}
        Err(e) => warn!(target: "spots", "CDATA title repair: {e}"),
    }
    // Likewise one-shot: spot cards promoted before the fresh branch
    // wrote a claims row get their ledger entry and the arbitrable
    // `proven:msgid-set:spot` label, so a byte proof can correct a
    // wrong spot title on them the way it can on new ones.
    match ix.relabel_spot_names(now) {
        Ok(n) if n > 0 => {
            info!(target: "spots", "put {n} spot-named releases on the claims ledger")
        }
        Ok(_) => {}
        Err(e) => warn!(target: "spots", "spot claim backfill: {e}"),
    }
    let pending = ix.spots_unresolved(budget)?;
    if pending.is_empty() {
        return Ok(sum);
    }
    let cfg = Config::load(config)?;
    let server = scan_servers(&cfg)
        .into_iter()
        .next()
        .context("no enabled server to fetch spot NZBs from")?;
    // The FETCHES fan out; the index writes do not. A spot costs one
    // HEAD plus two or three BODYs and ~0.58 s of that is round trips,
    // so this pass is latency-bound and N connections buy ~N. That is
    // what takes the budget/lap trade off the table: the pass runs
    // inside the scan lap, so a serial pass made a bigger budget a
    // longer lap (`lap = 1078 + 0.58B` seconds, measured 1 Sep 2026 -
    // research/SPOT-RESOLVER-IS-THROTTLED-2026-09-01.md), which is why
    // the shipped budget stopped at 500 of a 1,000 cap. Per-spot server
    // cost is unchanged; only the waiting overlaps. Measured at 7.3 of
    // a theoretical 8 - per-spot marginal cost 0.856 s serial against
    // 0.117 s at eight, on one binary A/B'd by `connections` alone:
    // research/SPOT-RESOLVER-CONCURRENT-FETCH-2026-09-01.md.
    //
    let fetchers = spot_fetch_conns(server.connections, pending.len());
    // Each worker owns its connection and pulls the next spot off a
    // shared cursor, so a slow fetch costs its own slot and nobody
    // else's; results come back out of order and are folded into the
    // index by THIS task alone (`with_index_mut` is the blocking write
    // door - fanning the writes out too would only move the contention).
    let msgids: Arc<Vec<String>> = Arc::new(pending.iter().map(|s| s.msgid.clone()).collect());
    let cursor = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    // Bound the queue at the fan-out, not deeper: an inflated spot NZB
    // is capped at 32 MiB and a fetched one is resident until this task
    // folds it, so the buffer is what decides how far past the fan-out
    // itself the worst case can go. Folding a result is microseconds
    // (one SAVEPOINT) except when it draws a STAT, so a deeper queue
    // would buy nothing anyway.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SpotFetch>(fetchers);
    // A JoinSet, not detached spawns: dropping it aborts every worker,
    // which is the exit the caller's `tokio::select!` preemption takes -
    // and an aborted fetch drops its session rather than quit()ing a
    // half-read BODY, which is the same rule `desynced` encodes below.
    let mut workers = tokio::task::JoinSet::new();
    for _ in 0..fetchers {
        let server = server.clone();
        let msgids = msgids.clone();
        let cursor = cursor.clone();
        let tx = tx.clone();
        workers.spawn(async move {
            let mut conn: Option<Connection> = None;
            loop {
                // Connect BEFORE claiming a spot: a worker that cannot
                // open a session must not consume one, or an account at
                // its connection limit would burn a retry counter on
                // spots it never asked the server about.
                if conn.is_none() {
                    match Connection::connect(&server).await {
                        Ok((c, _)) => conn = Some(c),
                        Err(e) => {
                            let _ = tx.send(SpotFetch::NoConnection(e.to_string())).await;
                            return;
                        }
                    }
                }
                let idx = cursor.fetch_add(1, Ordering::Relaxed);
                let Some(mid) = msgids.get(idx) else { break };
                let sent = match nzbkit::spot::fetch_spot_nzb(conn.as_mut().unwrap(), mid).await {
                    Ok((sx, bytes)) => tx.send(SpotFetch::Got { idx, sx, bytes }).await,
                    Err(_) => {
                        // Drop the session on ANY fetch error. A BODY
                        // that died mid-read still owes us the rest of
                        // its dot-stuffed payload, so the next command
                        // would read one reply behind forever - the
                        // same desync the STAT rule below describes,
                        // and the serial pass only survived it because
                        // its breaker ended the pass three failures
                        // later. A reconnect is cheap at the measured
                        // 1.1% failure rate, and it is now the whole
                        // answer to a dead connection.
                        conn = None;
                        tx.send(SpotFetch::Failed { idx }).await
                    }
                };
                if sent.is_err() {
                    break;
                }
            }
            if let Some(c) = conn {
                c.quit().await;
            }
        });
    }
    // The workers hold the only other senders; without this the
    // receive loop below would never see the end of the pass.
    drop(tx);

    // The serial breaker was `consecutive_failures >= 3`: a dead
    // connection fails every remaining fetch identically, a missing
    // article fails one. Dropping the session on every fetch error
    // (above) now answers the dead-connection half directly, so what is
    // left for the breaker is the server that answers and refuses -
    // and "consecutive" has to be read in COMPLETION order, where up to
    // `fetchers` independent misses can land back to back purely
    // because they were in flight together. Hence 3 plus the fan-out:
    // a genuine run still trips it within one batch, and at the
    // measured 1.1% failure rate a healthy pass never does. (The
    // shipped rule cut a healthy 500-budget pass short at 473 fetches,
    // so this is not only a loosening.)
    let breaker = 3 + fetchers as u32;
    let mut consecutive_failures = 0u32;
    // Completeness corroboration, rate-limited per pass, on a session
    // of its own so a desync here cannot poison a fetcher. `stat_dead`
    // is the M29 sampler's rule: a STAT that timed out or errored
    // leaves an unread status in the socket, so that session must be
    // DROPPED, never quit() - the goodbye it would read is the STAT's
    // answer, and the next command reads one reply behind forever.
    let mut stat_budget = budget.min(nzbkit::index::SPOT_STAT_PER_PASS);
    let mut stat_conn: Option<Connection> = None;
    let mut stat_dead = false;
    // Only reported when NOTHING was fetched: one worker losing its
    // slot is survivable, every worker losing it is the unreachable
    // server the serial pass used to fail outright on.
    let mut connect_err: Option<String> = None;
    while let Some(msg) = rx.recv().await {
        match msg {
            SpotFetch::NoConnection(e) => {
                connect_err = Some(e);
                continue;
            }
            SpotFetch::Failed { idx } => {
                consecutive_failures += 1;
                sum.failed += 1;
                ix.spot_nzb_failed(&pending[idx].msgid)?;
            }
            SpotFetch::Got { idx, sx, bytes } => {
                consecutive_failures = 0;
                sum.fetched += 1;
                let s = &pending[idx];
                // The signed full-spot title outranks the header title,
                // same precedence as a grab.
                let title = if sx.title.is_empty() {
                    s.title.clone()
                } else {
                    sx.title
                };
                match nzbkit::nzb::Nzb::parse(&bytes) {
                    Ok(nzb) => match ix.promote_spot(&s.msgid, &title, &nzb, now)? {
                        SpotPromotion::Promoted(rid) => {
                            sum.promoted += 1;
                            // Only fresh cards: an Upgraded row is one
                            // the header scanner already read off the
                            // wire, so its completeness is an
                            // observation rather than a declaration and
                            // there is nothing to corroborate.
                            if stat_budget > 0
                                && !stat_dead
                                && let Some(head) = ix.release_head_article(rid)?
                            {
                                if stat_conn.is_none() {
                                    match Connection::connect(&server).await {
                                        Ok((c, _)) => stat_conn = Some(c),
                                        // No session to spare (or no
                                        // server): the cards still land,
                                        // uncorroborated, exactly as they
                                        // do when the budget runs out.
                                        Err(_) => stat_dead = true,
                                    }
                                }
                                if let Some(c) = stat_conn.as_mut() {
                                    stat_budget -= 1;
                                    match stat_one(c, &head).await {
                                        Ok(present) => {
                                            sum.checked += 1;
                                            sum.gone += u32::from(!present);
                                            ix.spot_stat_verdict(&s.msgid, rid, present)?;
                                        }
                                        Err(_) => stat_dead = true,
                                    }
                                }
                                if stat_dead && stat_conn.is_some() {
                                    warn!(
                                        target: "spots",
                                        "dropping the STAT connection after an unanswered STAT"
                                    );
                                    drop(stat_conn.take());
                                }
                            }
                        }
                        SpotPromotion::Upgraded(_) => sum.upgraded += 1,
                        SpotPromotion::Unusable => sum.unusable += 1,
                    },
                    // Inflated but unparseable: deterministic, so the
                    // retry cap writes it off after a few passes.
                    Err(_) => {
                        sum.unusable += 1;
                        ix.spot_nzb_failed(&s.msgid)?;
                    }
                }
            }
        }
        // Checked AFTER the fold, not before it: a result that is
        // already off the wire costs one index write to keep and a
        // whole re-fetch next pass to throw away. The caller's
        // `tokio::select!` is the prompt half of preemption anyway -
        // it polls every 100 ms and drops this future outright.
        if stop() || consecutive_failures >= breaker {
            break;
        }
    }
    // Whatever is still in flight is abandoned, not drained: a pass
    // that stopped stopped for a reason, and an aborted fetch drops its
    // session rather than reading a half-finished BODY to the end.
    workers.abort_all();
    if let Some(c) = stat_conn {
        c.quit().await;
    }
    if sum.fetched == 0
        && sum.failed == 0
        && let Some(e) = connect_err
    {
        anyhow::bail!("no connection to fetch spot NZBs: {e}");
    }
    Ok(sum)
}

/// One fetched spot on its way back from a resolver worker to the task
/// that owns the index.
pub(crate) enum SpotFetch {
    Got {
        /// Index into the pass's `pending` list - results arrive out of
        /// order, so the spot they belong to travels with them.
        idx: usize,
        sx: nzbkit::spot::SpotXml,
        bytes: Vec<u8>,
    },
    Failed {
        idx: usize,
    },
    /// A worker could not open a session and has retired.
    NoConnection(String),
}

/// One STAT, sent and read: `Ok(true)` if the article is there.
///
/// The timeout is what makes the caller's desync flag necessary - a
/// session abandoned mid-command still owes us a status line, so it can
/// only be dropped, never reused and never quit().
async fn stat_one(conn: &mut Connection, msgid: &str) -> Result<bool> {
    let present = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        conn.send_stat(msgid).await?;
        conn.flush().await?;
        conn.read_stat().await
    })
    .await
    .context("STAT timed out")??;
    Ok(present)
}

/// TODO 131 D3: the search-miss readout, without a daemon.
///
/// Same numbers `mode=search_misses` serves, for the index-ops case
/// where you have the database file and want to know what the people
/// using it could not find. Read-only - it opens the index read-write
/// only because `Index::open` is the call that guarantees the schema,
/// and a fresh checkout's index may predate the table.
pub fn search_misses(
    db: &Path,
    days: i64,
    thin: u32,
    surface: Option<&str>,
    limit: u32,
) -> Result<()> {
    let ix = nzbkit::index::Index::open(db)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_secs() as i64)
        .unwrap_or(0);
    let since = now - days.clamp(1, 365) * 86_400;
    let surface = surface.filter(|s| matches!(*s, "wall" | "newznab"));
    let summary = ix.search_log_summary(since, thin)?;
    let rows = ix.search_misses(since, thin, surface, limit.clamp(1, 500))?;
    println!(
        "{} searches over {days} days, {} distinct; {} came back empty ({:.1}%)",
        summary.searches,
        summary.distinct,
        summary.zero_searches,
        if summary.searches > 0 {
            summary.zero_searches as f64 * 100.0 / summary.searches as f64
        } else {
            0.0
        },
    );
    println!(
        "{} queries still unanswered, {} the scanner has since caught up with",
        summary.missing, summary.resolved,
    );
    if rows.is_empty() {
        println!("nothing missed in this window");
        return Ok(());
    }
    println!();
    println!(
        "{:<50} {:>8} {:>6} {:>6}  {:<8} kind",
        "query", "asked", "empty", "hits", "surface"
    );
    for m in &rows {
        println!(
            "{:<50} {:>8} {:>6} {:>6}  {:<8} {}",
            trunc(&m.q, 50),
            m.n,
            m.zero_n,
            m.last_hits,
            m.surface,
            m.kind,
        );
    }
    Ok(())
}

pub fn spot_search(query: &str, db: &Path) -> Result<()> {
    let ix = nzbkit::index::Index::open(db)?;
    let hits = ix.spot_search(query, 30)?;
    if hits.is_empty() {
        println!("no spots match '{query}'");
        return Ok(());
    }
    for s in &hits {
        println!(
            "{:<60} {:>9.2} GB  cat {}{}  {}  {}{}",
            trunc(&s.title, 60),
            s.size as f64 / 1e9,
            s.category,
            if s.subcats.is_empty() {
                String::new()
            } else {
                format!(" [{}]", s.subcats)
            },
            s.spotter_id,
            s.msgid,
            if s.hashcash_ok { "" } else { "  (hashcash!)" },
        );
    }
    Ok(())
}

pub async fn spot_get(config: &Path, msgid: &str, nzb: &Path, db: &Path) -> Result<()> {
    let server = load_server(config)?;
    let (mut conn, _) = Connection::connect(&server).await?;
    let (sx, bytes) = nzbkit::spot::fetch_spot_nzb(&mut conn, msgid).await?;
    conn.quit().await;
    std::fs::write(nzb, &bytes)?;
    // Cache the release payload message-ids on the indexed spot, if we
    // have it. NOT sx.nzb_segments: those are the alt.binaries.ftd
    // deflate-chunk ids the NZB rides on, which never appear in any
    // content group and so can never join a header-scanned index.
    let mid = if msgid.starts_with('<') {
        msgid.to_string()
    } else {
        format!("<{msgid}>")
    };
    if let Ok(ix) = nzbkit::index::Index::open(db) {
        let _ = ix.set_spot_nzb(&mid, &nzbkit::spot::payload_msgids(&bytes));
    }
    println!(
        "wrote {} ({} bytes, {} payload segments) - {}",
        nzb.display(),
        bytes.len(),
        sx.nzb_segments.len(),
        if sx.title.is_empty() {
            msgid
        } else {
            &sx.title
        },
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// nzb-import - posted-NZB ingestion rung (research REDTEAM 5c, §131)
// ---------------------------------------------------------------------------

/// Fetch every one-file `*.nzb` post the index holds, parse each, and
/// join its payload message-ids against the index. Prints (and
/// optionally writes as JSON) the parse-success rate and the exact
/// multi-message-id overlap - the rung's measured deliverable. Names
/// come only from message-id identity; never from time/size.
///
/// Report-only: the write side (proven-name claims with provenance
/// `nzb-import`) goes through the identity substrate's
/// `apply_proven_name` when that lands.
pub async fn nzb_import(
    config: &Path,
    db: &Path,
    limit: usize,
    after: i64,
    report: Option<&Path>,
    apply: bool,
) -> Result<()> {
    let cfg = Config::load(config)?;
    let servers = scan_servers(&cfg);
    anyhow::ensure!(!servers.is_empty(), "no enabled server to fetch from");
    let mut ix = nzbkit::index::Index::open(db)?;

    #[derive(serde::Serialize)]
    struct ObjReport {
        release_id: i64,
        stem: String,
        grp: String,
        junk: i64,
        articles: usize,
        fetch: String,
        parse: String,
        files: usize,
        segments: usize,
        matched_ids: usize,
        inner_stem: Option<String>,
        meta_title: Option<String>,
        joins: Vec<JoinReport>,
    }
    #[derive(serde::Serialize)]
    struct JoinReport {
        release_id: i64,
        stem: String,
        matched: usize,
        row_nsegs: u32,
        quorum: bool,
    }

    let mut conns: std::collections::HashMap<String, Connection> = Default::default();
    let mut objs: Vec<ObjReport> = Vec::new();
    // (report slot, this NZB's ids) - joined in one batch at the end.
    let mut parsed: Vec<(usize, Vec<String>)> = Vec::new();
    let mut cursor = after;
    'outer: loop {
        let cands = ix.posted_nzb_candidates(cursor, 200)?;
        if cands.is_empty() {
            break;
        }
        for c in cands {
            // The walk's cursor is an arrival ordinal, not a release id
            // (ids are recycled - see `posted_nzb_candidates`).
            cursor = c.arrival_seq;
            if limit > 0 && objs.len() >= limit {
                break 'outer;
            }
            let mut fetch: Result<Vec<u8>, String> = Err("no server had it".into());
            for s in &servers {
                if !conns.contains_key(&s.host) {
                    match Connection::connect(s).await {
                        Ok((conn, _)) => {
                            conns.insert(s.host.clone(), conn);
                        }
                        Err(e) => {
                            info!(target: "nzbimport", "{}: connect: {e}", s.host);
                            continue;
                        }
                    }
                }
                let conn = conns.get_mut(&s.host).expect("just inserted");
                let attempt = tokio::time::timeout(
                    std::time::Duration::from_secs(120),
                    nzbkit::nzbimport::fetch_posted_nzb(conn, &c.segs),
                )
                .await;
                match attempt {
                    Ok(Ok(bytes)) => {
                        fetch = Ok(bytes);
                        break;
                    }
                    Ok(Err(nzbkit::nzbimport::NzbImportError::Missing(mid))) => {
                        // Retention/propagation differs per backbone -
                        // the next server may still hold it.
                        fetch = Err(format!("missing {mid}"));
                    }
                    Ok(Err(nzbkit::nzbimport::NzbImportError::Nntp(e))) => {
                        // Connection-level: drop the session, next
                        // server (this one reconnects next object).
                        fetch = Err(format!("nntp: {e}"));
                        conns.remove(&s.host);
                    }
                    Ok(Err(e)) => {
                        // Content property (yEnc damage, cap, holes):
                        // identical bytes everywhere - stop trying.
                        fetch = Err(e.to_string());
                        break;
                    }
                    Err(_) => {
                        fetch = Err("timeout".into());
                        conns.remove(&s.host);
                    }
                }
            }
            let mut rep = ObjReport {
                release_id: c.release_id,
                stem: c.stem.clone(),
                grp: c.grp.clone(),
                junk: c.junk,
                articles: c.segs.len(),
                fetch: String::new(),
                parse: String::new(),
                files: 0,
                segments: 0,
                matched_ids: 0,
                inner_stem: None,
                meta_title: None,
                joins: Vec::new(),
            };
            match fetch {
                Err(e) => rep.fetch = e,
                Ok(bytes) => {
                    rep.fetch = "ok".into();
                    match nzbkit::nzbimport::nzb_identity(&bytes) {
                        Err(e) => rep.parse = e.to_string(),
                        Ok(id) => {
                            rep.parse = "ok".into();
                            rep.files = id.files;
                            rep.segments = id.segments;
                            rep.inner_stem = id.inner_stem.clone();
                            rep.meta_title = id.meta_title.clone();
                            parsed.push((objs.len(), id.msgids));
                        }
                    }
                }
            }
            objs.push(rep);
            if objs.len().is_multiple_of(25) {
                println!(
                    "… {} objects ({} fetched, {} parsed)",
                    objs.len(),
                    objs.iter().filter(|o| o.fetch == "ok").count(),
                    objs.iter().filter(|o| o.parse == "ok").count()
                );
            }
        }
    }
    for c in conns.into_values() {
        c.quit().await;
    }

    // One batched reverse lookup for every parsed NZB's ids, grouped
    // back per NZB so match counts never conflate.
    let all_ids: Vec<String> = {
        let mut seen = std::collections::HashSet::new();
        parsed
            .iter()
            .flat_map(|(_, ids)| ids.iter())
            .filter(|id| seen.insert((*id).clone()))
            .cloned()
            .collect()
    };
    println!(
        "joining {} distinct payload message-ids against the index …",
        all_ids.len()
    );
    let rows = ix.msgid_lookup(&all_ids)?;
    // (report slot, target release) → the matched ids themselves. The
    // canonical MsgidSet key digests the MATCHED set, per join, so the
    // ids ride beside the report rather than inside it.
    let mut join_ids: std::collections::HashMap<(usize, i64), Vec<String>> = Default::default();
    for (slot, ids) in &parsed {
        let hits = nzbkit::nzbimport::group_hits(ids, &rows);
        let rep = &mut objs[*slot];
        rep.matched_ids = hits.iter().map(|h| h.matched).sum();
        rep.joins = hits
            .into_iter()
            // Self-joins carry no information: the posted .nzb cannot
            // name itself.
            .filter(|h| h.release_id != rep.release_id)
            .map(|h| {
                join_ids.insert((*slot, h.release_id), h.ids);
                JoinReport {
                    release_id: h.release_id,
                    stem: h.stem.clone(),
                    matched: h.matched,
                    row_nsegs: h.row_nsegs,
                    quorum: nzbkit::nzbimport::quorum(h.matched, h.row_nsegs),
                }
            })
            .collect();
    }

    // Write side: quorum joins become MsgidSet claims through the
    // identity substrate. The name ladder prefers the name the .nzb
    // was POSTED under (that is the uploader speaking); an obfuscated
    // post name falls back to the NZB's own meta title, then to the
    // dominant inner filename stem - and if all three are junk there
    // is no name worth claiming, however exact the join.
    let mut applied = 0usize;
    if apply {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.as_secs() as i64)
            .unwrap_or(0);
        for (slot, _ids) in &parsed {
            let rep = &objs[*slot];
            if !rep.joins.iter().any(|j| j.quorum) {
                continue;
            }
            let posted = nzbkit::nzbimport::strip_nzb_suffix(&rep.stem).to_string();
            // `stem_is_a_name`, not the raw verdict: every one of
            // these three is a whole stem, and a whole stem can carry a
            // trailing `.7z`/`.zip`/`.mkv` that makes the raw function
            // read a blob as two readable tokens (M7, 10 Aug sweep).
            let name = if nzbkit::release::stem_is_a_name(&posted) {
                Some(posted)
            } else if let Some(t) = rep
                .meta_title
                .as_ref()
                .filter(|t| nzbkit::release::stem_is_a_name(t))
            {
                Some(t.clone())
            } else {
                rep.inner_stem
                    .as_ref()
                    .filter(|s| nzbkit::release::stem_is_a_name(s))
                    .cloned()
            };
            let Some(name) = name else { continue };
            for j in rep.joins.iter().filter(|j| j.quorum) {
                // Displacement policy is the claims layer's
                // (apply_proven_name respects a readable stem): a
                // season-pack NZB joining its per-episode rows comes
                // back Conflict - recorded, never applied. Expected.
                // Canonical key = digest of the MATCHED set for THIS
                // join (not the whole NZB), so any other lane proving
                // the same join produces the same key and the claims
                // dedupe instead of reading as independent evidence.
                let Some(mids) = join_ids.get(&(*slot, j.release_id)) else {
                    continue;
                };
                let claim = nzbkit::index::NameClaim {
                    name: name.clone(),
                    evidence: nzbkit::index::NameEvidence::MsgidSet,
                    key: nzbkit::index::msgid_set_key(mids),
                    source: "posted-nzb".into(),
                };
                match ix.apply_proven_name(j.release_id, &claim, now) {
                    Ok(o) => {
                        applied += 1;
                        println!(
                            "  claim #{} {:?} <- {name:?} ({}/{} ids) -> {o:?}",
                            j.release_id, j.stem, j.matched, j.row_nsegs
                        );
                    }
                    Err(e) => println!("  claim #{} failed: {e}", j.release_id),
                }
            }
        }
    }

    let fetched = objs.iter().filter(|o| o.fetch == "ok").count();
    let parsed_ok = objs.iter().filter(|o| o.parse == "ok").count();
    let with_join = objs.iter().filter(|o| !o.joins.is_empty()).count();
    let with_quorum = objs
        .iter()
        .filter(|o| o.joins.iter().any(|j| j.quorum))
        .count();
    let quorum_rows: usize = objs
        .iter()
        .flat_map(|o| o.joins.iter())
        .filter(|j| j.quorum)
        .count();
    println!("posted-NZB ingestion census:");
    println!("  candidates walked   {}", objs.len());
    println!(
        "  fetched             {fetched} ({:.1}%)",
        100.0 * fetched as f64 / objs.len().max(1) as f64
    );
    println!(
        "  parsed as NZB       {parsed_ok} ({:.1}% of fetched)",
        100.0 * parsed_ok as f64 / fetched.max(1) as f64
    );
    println!("  with any index join {with_join}");
    println!("  with quorum join    {with_quorum} (naming {quorum_rows} index rows)");
    if apply {
        println!("  claims written      {applied}");
    }
    for o in objs.iter().filter(|o| o.joins.iter().any(|j| j.quorum)) {
        let named = nzbkit::nzbimport::strip_nzb_suffix(&o.stem).to_string();
        for j in o.joins.iter().filter(|j| j.quorum) {
            println!(
                "    {} → #{} {} ({}/{} ids)",
                named, j.release_id, j.stem, j.matched, j.row_nsegs
            );
        }
    }
    if let Some(path) = report {
        std::fs::write(path, serde_json::to_vec_pretty(&objs)?)?;
        println!("report written to {}", path.display());
    }
    Ok(())
}
