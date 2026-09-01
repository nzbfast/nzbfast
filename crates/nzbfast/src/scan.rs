//! The index and spotnet scan commands: header scanning passes, backfill bisection, index search, spot search/get, and the release/test NZB synthesis.
//!
//! Split out of main.rs verbatim; behaviour unchanged.

use crate::*;
use nzbkit::extract::release_stem;
use std::path::Path;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// index / search - the built-in indexer (M12)
// ---------------------------------------------------------------------------

/// "90d" / "26w" / "6m" / "2y" (bare number = days) → seconds; ""/0 = 0.
pub(crate) fn parse_age(s: &str) -> Result<u64> {
    let s = s.trim();
    if s.is_empty() || s == "0" {
        return Ok(0);
    }
    let (num, unit) = match s.chars().last().unwrap() {
        c if c.is_ascii_digit() => (s, 'd'),
        // Slice at a char boundary: `s.len() - 1` lands inside a multi-byte
        // final char (e.g. "90д") and panics; strip the char's real width.
        c => (&s[..s.len() - c.len_utf8()], c.to_ascii_lowercase()),
    };
    let per = match unit {
        'd' => 86_400.0,
        'w' => 7.0 * 86_400.0,
        'm' => 30.44 * 86_400.0,
        'y' => 365.25 * 86_400.0,
        _ => anyhow::bail!("age unit must be d/w/m/y: {s:?}"),
    };
    let n: f64 = num
        .parse()
        .map_err(|_| anyhow::anyhow!("can't parse age {s:?}"))?;
    Ok((n * per) as u64)
}

/// First article number whose Date ≥ cutoff, found by bisecting the
/// group's number range with small OVER probes (~20 round-trips) instead
/// of fetching years of headers only to discard them. Expired holes and
/// dateless articles read as "old side", which errs toward scanning more.
pub(crate) async fn bisect_cutoff(
    conn: &mut Connection,
    mut lo: u64,
    mut hi: u64,
    cutoff: i64,
) -> u64 {
    // An empty group legitimately reports `low == high + 1` (RFC 3977), so
    // `hi < lo` reaches here on any group whose articles have all expired.
    // There is nothing to bisect, and `hi - lo` below would underflow: a
    // subtract-overflow panic in debug, ~64 OVER probes over garbage ranges
    // in release. `hi == lo` already fell straight through the loop.
    if hi <= lo {
        return lo;
    }
    async fn date_at(conn: &mut Connection, n: u64, hi: u64) -> i64 {
        match conn.over(n, (n + 999).min(hi)).await {
            Ok(es) => es.iter().map(|e| e.date).find(|d| *d > 0).unwrap_or(0),
            Err(_) => 0,
        }
    }
    if date_at(conn, lo, hi).await >= cutoff {
        return lo; // whole retention is newer than the cutoff
    }
    while hi - lo > 1000 {
        let mid = lo + (hi - lo) / 2;
        let d = date_at(conn, mid, hi).await;
        if d == 0 || d < cutoff {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    lo
}

/// How stale the index totals on a scan progress or per-group summary
/// line may be. The exact query behind them is a full `SCAN releases`
/// (seconds on a production-sized index), asked every ~100k headers by
/// up to eight concurrent groups before this memo existed.
const SCAN_STATS_TTL: std::time::Duration = std::time::Duration::from_secs(45);

pub(crate) async fn index_scan(
    config: &Path,
    group: &str,
    backfill: u64,
    max_age_secs: u64,
    gates: Option<&gates::Gates>,
    db: &Path,
) -> Result<()> {
    let mut ix = nzbkit::index::Index::open(db)?;
    // CLI scans classify with the built-ins only (custom categories are
    // daemon settings); the daemon's reclassify pass reconciles any rows
    // a CLI scan ingested.
    index_scan_into(
        config,
        group,
        backfill,
        max_age_secs,
        gates,
        Vec::new(),
        &mut ix,
        None,
        0,
        None,
        1,
        true,
        true,
        // §74: no watchlist in a CLI scan, so nothing to report an
        // arrival TO.
        None,
    )
    .await?;
    // The one exact summary a CLI scan gets - the per-group line above
    // serves the TTL memo (A4).
    let (rel, comp) = ix.stats()?;
    println!("index now {rel} releases, {comp} complete");
    Ok(())
}

/// §74: arm the arrival watch for ONE leg, or stand it down.
///
/// `arrivals` says whether this leg is reading articles that were posted
/// since the last pass looked - which is what an arrival IS, and the same
/// question the tip watcher settles with its own mark. Only a leg
/// starting strictly ABOVE a mark the group already had qualifies:
///
/// * mark 0 is a first-sight backfill, tens of thousands of articles of
///   GROUP HISTORY;
/// * a leg starting at or below the mark is a deliberate deep re-scan of
///   ground already covered (`index_scan_now&value=n`);
/// * the deepen leg walks history by definition.
///
/// Reporting any of those would tell the watchlist that a whole shelf of
/// old posts had just landed.
fn arm_arrival_watch(
    ix: &mut nzbkit::index::Index,
    watch: Option<&crate::watchlist::InstantMatcher>,
    arrivals: bool,
) {
    // No watchlist at all: never install anything. The index pays a null
    // check per touched release for an absent watch and a closure call
    // for a present one, and an install with nothing watched should keep
    // paying the former.
    let Some(m) = watch else { return };
    if !arrivals {
        // Not `set_watch_names(None)`, which is the same seam's HYGIENE
        // call and empties the journal with it - so standing down that
        // way between two legs threw away everything the previous leg
        // had just reported and the pass ended with nothing to hand
        // back. A predicate that admits nothing stands the watch down
        // over the history legs and leaves the journal alone.
        ix.set_watch_names(Some(Box::new(|_: &str| false)));
        return;
    }
    let m = m.clone();
    ix.set_watch_names(Some(Box::new(move |name: &str| m.wants(name))));
}

/// Scan into an already-open Index - the daemon shares ONE connection
/// between the scan loop and every query handler, so committed rows are
/// visible immediately (two connections in one process don't reliably
/// share WAL state until checkpoint).
///
/// OVER fetching fans out over a few concurrent connections (headers are
/// the bottleneck at ~10-50k/s/conn; ingest keeps up on one thread). The
/// high-water mark only ever advances over a CONTIGUOUS completed prefix,
/// so an aborted pass resumes without holes.
///
/// `deep` = one-off backfill override: rescan the last n articles even
/// below the high-water mark (ingest is idempotent - message-id keyed).
/// `progress`, when given, is kept at the pass's fetched-header count.
#[expect(clippy::too_many_arguments)]
pub(crate) async fn index_scan_into(
    config: &Path,
    group: &str,
    backfill: u64,
    max_age_secs: u64,
    gates: Option<&gates::Gates>,
    // 24D user categories: applied to the ingest gate AND installed on
    // the index so classification at ingest matches the daemon's rules.
    cats: Vec<nzbkit::categories::CustomCategory>,
    ix: &mut nzbkit::index::Index,
    deep: Option<u64>,
    // Articles of HISTORY to add per pass below the low-water mark
    // (auto-deepen); 0 = off.
    deepen: u64,
    progress: Option<Arc<AtomicU64>>,
    // M28: how many group scans run concurrently (this one included) -
    // the per-scan connection budget divides the account limit by this
    // so parallel groups never exceed it.
    share: usize,
    // M30 turbo: nothing is downloading, so header fetch may use a
    // deeper per-group connection fan-out (clamp 10 instead of 5).
    turbo: bool,
    // A8: scan the OTHER eligible backbones' tips too (their own marks),
    // so propagation holes and single-backbone posts reach the index.
    coverage: bool,
    // §74: the compiled watchlist, so a release this pass is the first
    // to READ still reaches the instant path. The tip watcher is not the
    // only leg that ingests new articles - it stands down for the whole
    // of every download, every full pass and every indexing pause, and
    // what covers the range it missed is this pass's forward leg. Armed
    // for the forward legs only; see `arm_arrival_watch`. The caller
    // drains the journal with `take_watch_hits` when the pass returns.
    arrival_watch: Option<crate::watchlist::InstantMatcher>,
) -> Result<()> {
    if let Some(g) = gates {
        let g = g.clone();
        let gc = cats.clone();
        ix.set_gate(Box::new(move |stem| g.allows_with(stem, &gc)));
    }
    ix.set_custom(cats);
    let cfg = Config::load(config).with_context(|| {
        format!(
            "loading {} (copy config.local.json.example?)",
            config.display()
        )
    })?;
    if cfg.servers.is_empty() {
        anyhow::bail!("no servers configured");
    }
    // Single-server-era marks rows (server='') were built against
    // whichever server was first in the config - claim them before any
    // mark is read. Idempotent, so every scan path may call it.
    let _ = ix.adopt_legacy_marks(&cfg.servers[0].host);

    // Probe every scan-eligible backbone: who carries this group, and
    // how much of it? A probe failure only drops that server from this
    // pass - its coverage resumes from its own marks next time.
    struct Probe {
        server: ServerConfig,
        key: String,
        conn: Connection,
        info: nzbkit::nntp::GroupInfo,
    }
    let mut probes: Vec<Probe> = Vec::new();
    for s in scan_servers(&cfg) {
        match Connection::connect(&s).await {
            Ok((mut c, _)) => match c.group(group).await {
                Ok(info) => probes.push(Probe {
                    key: nzbkit::index::Index::server_key(&s.host),
                    server: s,
                    conn: c,
                    info,
                }),
                Err(e) => {
                    // 411 = this server does not carry the group. Routine,
                    // and exactly what per-group provider choice is for.
                    info!(target: "scan", "{}: {group}: {e}", s.host);
                    c.quit().await;
                }
            },
            Err(e) => info!(target: "scan", "{}: connect: {e}", s.host),
        }
    }
    if probes.is_empty() {
        anyhow::bail!("no configured server carries {group}");
    }
    if probes.iter().all(|p| !p.server.may_spend_on_measurement()) {
        info!(
            target: "scan",
            "{group}: every server carrying it is metered (block account \
             or billed per byte) - header traffic is spending the user's \
             own bytes"
        );
    }
    // Primary = the probe with the largest article span: one number
    // that captures both carriage and retention depth, and comparable
    // across servers in magnitude even though the numbers themselves
    // are per-server. Ties keep the level/config-order rank. The
    // primary runs the full forward + deepen legs; every other
    // backbone contributes a cheap tip leg below.
    let pi = probes
        .iter()
        .enumerate()
        .max_by_key(|(i, p)| {
            (
                p.info.high.saturating_sub(p.info.low),
                std::cmp::Reverse(*i),
            )
        })
        .map(|(i, _)| i)
        .expect("probes is non-empty");
    let chosen = probes.remove(pi);
    // Persist the choice so the realtime tip watcher follows the same
    // server between passes (marks are only valid against their server).
    let _ = ix.kv_set(&format!("scan_primary:{group}"), &chosen.key);
    let server = chosen.server;
    let skey = chosen.key;
    let mut conn = chosen.conn;
    let g = chosen.info;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let mark = ix.high_water(group, &skey);
    // Resume from the mark; first scan starts at the age cutoff when
    // one is set (Date bisection), else backfill-count from the newest.
    // A deep override starts n articles back regardless of the mark.
    let mut low = if let Some(n) = deep {
        let start = g.high.saturating_sub(n).max(g.low);
        if mark > 0 {
            start.min(mark.saturating_add(1))
        } else {
            start
        }
    } else if mark > 0 {
        mark.saturating_add(1)
    } else if max_age_secs > 0 {
        let at = bisect_cutoff(&mut conn, g.low, g.high, now - max_age_secs as i64).await;
        println!(
            "{group}: age cutoff at article {at} (group spans {}..{})",
            g.low, g.high
        );
        at
    } else {
        g.high.saturating_sub(backfill).max(g.low)
    };
    // Max-age still gates a deep backfill: never walk past the cutoff.
    if deep.is_some() && max_age_secs > 0 && low < g.high {
        let at = bisect_cutoff(&mut conn, g.low, g.high, now - max_age_secs as i64).await;
        low = low.max(at);
    }
    let t0 = Instant::now();
    let mut scanned = 0u64;
    let mut completed = 0u32;
    // False once a pass has been abandoned on the idle deadline: the
    // fan-out is unhealthy, so no leg after it may claim coverage.
    let mut healthy = true;
    if low > g.high {
        println!("{group}: up to date (high {})", g.high);
    } else {
        println!(
            "indexing {group}: articles {low}..{} ({})",
            g.high,
            g.high - low + 1
        );
        arm_arrival_watch(ix, arrival_watch.as_ref(), mark > 0 && low > mark);
        let pass = scan_article_range(
            &server,
            group,
            &skey,
            low,
            g.high,
            ix,
            now,
            Some(mark),
            progress.as_ref(),
            0,
            t0,
            share,
            turbo,
        )
        .await?;
        scanned += pass.scanned;
        completed += pass.completed;
        // An abandoned forward pass needs no repair here: the high-water
        // only ever advanced over the contiguous prefix, so the next pass
        // resumes exactly where coverage ends. The deepen leg is skipped
        // though - the fan-out is already unhealthy, and a second pass on
        // the same server would just spend another idle deadline.
        healthy = pass.complete;
        // The forward leg is over; everything below this point is
        // history (the deepen slice) until a coverage leg arms again.
        arm_arrival_watch(ix, arrival_watch.as_ref(), false);
    }
    // Seed the low-water on first sight of the group - including the
    // up-to-date branch (a group idle at scan time otherwise never
    // starts deepening). Worst case the seed sits above already-scanned
    // coverage and one slice gets rescanned; ingest is idempotent.
    if ix.low_water(group, &skey) == 0 {
        let seed = if low > g.high { mark } else { low }.max(g.low);
        if seed > 0 {
            let _ = ix.set_low_water(group, &skey, seed);
        }
    }

    // Auto-deepen: besides tracking NEW posts, each pass also extends
    // the index a bounded slice BACKWARD through group history, so
    // depth accumulates in the background (a fresh index otherwise only
    // ever covers its seed backfill - ~40k articles ≈ 2 h of a busy
    // group - plus the live trickle, and 'left overnight it barely
    // grew'). The low-water mark moves only once the WHOLE slice lands;
    // a failed slice is rescanned next pass (ingest is idempotent).
    if deepen > 0 && healthy {
        let cur = ix.low_water(group, &skey);
        let mut floor = g.low;
        if max_age_secs > 0 && cur > floor {
            floor =
                floor.max(bisect_cutoff(&mut conn, g.low, g.high, now - max_age_secs as i64).await);
        }
        if cur > floor {
            let hi2 = cur - 1;
            let lo2 = cur.saturating_sub(deepen).max(floor);
            println!(
                "deepening {group}: articles {lo2}..{hi2} ({})",
                hi2 - lo2 + 1
            );
            let pass = scan_article_range(
                &server,
                group,
                &skey,
                lo2,
                hi2,
                ix,
                now,
                None,
                progress.as_ref(),
                scanned,
                t0,
                share,
                turbo,
            )
            .await?;
            scanned += pass.scanned;
            completed += pass.completed;
            // The low-water marks history as COVERED, and this leg tracks
            // no contiguous prefix - so an abandoned pass must not move
            // it, or the un-scanned slice is written off forever. The
            // whole slice is simply retried next pass (ingest is
            // idempotent).
            if pass.complete {
                ix.set_low_water(group, &skey, lo2)?;
                println!(
                    "  history now back to article {lo2} ({} older articles remain)",
                    lo2.saturating_sub(floor)
                );
            } else {
                println!(
                    "  deepen pass abandoned - history mark left at {cur}, slice retried next pass"
                );
            }
        }
    }
    conn.quit().await;

    // A8 coverage legs: every other eligible backbone advances its OWN
    // forward tip under its own (grp, server) marks. Message-ids are
    // portable, so ingest merges whatever the primary's spool never
    // received - the release that looked permanently incomplete
    // completes the moment another backbone's headers land. Forward
    // only, on purpose: history depth is the primary's job (it was
    // chosen for having the most of it), and old incompletes are the
    // targeted gap-fill pass's job - re-deepening every backbone would
    // multiply the whole history cost for mostly-duplicate headers.
    // A secondary's failure never fails the pass; it resumes from its
    // own marks next time.
    if coverage {
        for p in probes {
            let Probe {
                server: s,
                key,
                conn: mut sconn,
                info,
            } = p;
            let smark = ix.high_water(group, &key);
            let lo = if smark > 0 {
                smark.saturating_add(1)
            } else if max_age_secs > 0 {
                bisect_cutoff(&mut sconn, info.low, info.high, now - max_age_secs as i64).await
            } else {
                info.high.saturating_sub(backfill).max(info.low)
            };
            sconn.quit().await;
            if lo > info.high {
                continue;
            }
            println!(
                "coverage {group} via {}: articles {lo}..{} ({})",
                s.host,
                info.high,
                info.high - lo + 1
            );
            // Forward, over this backbone's OWN mark - an arrival here is
            // an arrival like any other, and on a propagation hole this
            // is the leg that sees the post first.
            arm_arrival_watch(ix, arrival_watch.as_ref(), smark > 0 && lo > smark);
            let leg = scan_article_range(
                &s,
                group,
                &key,
                lo,
                info.high,
                ix,
                now,
                Some(smark),
                progress.as_ref(),
                scanned,
                t0,
                share,
                turbo,
            )
            .await;
            arm_arrival_watch(ix, arrival_watch.as_ref(), false);
            match leg {
                Ok(pass) => {
                    scanned += pass.scanned;
                    completed += pass.completed;
                }
                Err(e) => info!(target: "scan", "{}: coverage leg for {group}: {e}", s.host),
            }
        }
    } else {
        for p in probes {
            p.conn.quit().await;
        }
    }

    if let Some(g) = gates {
        let (min, max) = g.size_bounds();
        if min > 0 || max > 0 {
            let n = ix.prune_size(min, max)?;
            if n > 0 {
                println!("  pruned {n} releases outside size gates");
            }
        }
    }
    // A4: no exact stats query here - this runs once per GROUP, and the
    // daemon fans out up to eight groups per pass, each of which would
    // pay a full `SCAN releases` on a production-sized index. The
    // cached figures cost nothing a progress line already paid; the
    // daemon computes one exact set per pass after its JoinSet, and the
    // CLI prints an exact summary in `index_scan`.
    let (rel, comp) = ix.stats_cached(SCAN_STATS_TTL)?;
    println!(
        "done: {scanned} headers in {:.1?} - index around {rel} releases, {comp} complete (+{completed} this run)",
        t0.elapsed()
    );
    Ok(())
}

/// A8 phase 2: targeted gap-fill. Pick up to `count` incomplete
/// releases and re-OVER each one's posting window on the OTHER eligible
/// backbones - idempotent ingest merges whatever headers the release's
/// scanning server never received, and `complete` flips the moment the
/// last part lands. Marks are untouched (out-of-band coverage, exactly
/// like the one-off deep rescan); every pick is stamped afterwards so
/// the rotation moves on whatever the outcome.
///
/// The oracle ledger RANKS the candidate backbones (best measured
/// carrier of the release's family and age first) but never skips one:
/// the ledger measures BODY availability, and headers may well still be
/// listed where bodies are gone - and an NZB indexed here is
/// downloadable from the whole pool, not just the server that indexed
/// it.
///
/// Returns (releases tried, releases now complete).
pub(crate) async fn index_gapfill_pass(
    config: &Path,
    ix: &mut nzbkit::index::Index,
    count: u32,
    stop: impl Fn() -> bool,
) -> Result<(u32, u32)> {
    // The window around first_posted to re-read. first_posted is the
    // EARLIEST article date seen, and uploads run forward from there,
    // so the window leans forward. Multi-day uploads outrun this; the
    // budget below bounds the spend either way.
    const WIN_BACK: i64 = 1800;
    const WIN_FWD: i64 = 4 * 3600;
    // OVER budget per (group, server) per pass - a busy group's 4.5 h
    // window can span ~100k articles, and this is background polish
    // that must never crowd out the scan proper.
    const MAX_ARTICLES: u64 = 100_000;
    const CHUNK: u64 = 20_000;

    let cfg = Config::load(config)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let servers = scan_servers(&cfg);
    if servers.len() < 2 {
        // One backbone total: there is no "other" provider to ask.
        // Decided BEFORE the pick: the pick sorts the whole incomplete
        // band, and a single-backbone install would otherwise pay that
        // sort every pass to feed a loop that can never run (B1).
        return Ok((0, 0));
    }
    let picks = ix.gapfill_pick(count, now)?;
    if picks.is_empty() {
        return Ok((0, 0));
    }
    let snap = ix.oracle_snapshot().unwrap_or_default();
    let mut by_grp: std::collections::BTreeMap<String, Vec<(i64, i64)>> = Default::default();
    for (id, grp, posted) in &picks {
        by_grp.entry(grp.clone()).or_default().push((*id, *posted));
    }
    let mut completed = 0u32;
    'grps: for (grp, mut rels) in by_grp {
        if stop() {
            break;
        }
        let primary = ix
            .kv_get(&format!("scan_primary:{grp}"))
            .unwrap_or_default();
        let fam = nzbkit::oracle::group_family(&grp);
        rels.sort_by_key(|&(_, p)| p);
        // Cluster overlapping windows: one busy evening's picks cost one
        // bisection pair, not one per release.
        let mut windows: Vec<(i64, i64)> = Vec::new();
        for &(_, p) in &rels {
            let (s, e) = (p - WIN_BACK, p + WIN_FWD);
            match windows.last_mut() {
                Some(w) if s <= w.1 => w.1 = w.1.max(e),
                _ => windows.push((s, e)),
            }
        }
        // The ledger bucket the ranking reads: the median pick's age.
        let mid_posted = rels[rels.len() / 2].1;
        let bucket = nzbkit::oracle::age_bucket(((now - mid_posted).max(0) / 86_400) as u32);
        let mut secs: Vec<&ServerConfig> = servers
            .iter()
            .filter(|s| nzbkit::index::Index::server_key(&s.host) != primary)
            .collect();
        if secs.is_empty() {
            continue;
        }
        // Best measured carrier first; a blind spot ranks between a good
        // and a bad cell (unknown is not gone).
        let rate = |s: &ServerConfig| {
            snap.carry_rate(&nzbkit::oracle::backbone_of(&s.host), &fam, bucket)
                .unwrap_or(0.75)
        };
        secs.sort_by(|a, b| {
            rate(b)
                .partial_cmp(&rate(a))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        for s in secs {
            if stop() {
                break 'grps;
            }
            let Ok((mut conn, _)) = Connection::connect(s).await else {
                continue;
            };
            let Ok(g) = conn.group(&grp).await else {
                conn.quit().await;
                continue;
            };
            let mut budget = MAX_ARTICLES;
            for &(ws, we) in &windows {
                if budget == 0 || stop() {
                    break;
                }
                let lo = bisect_cutoff(&mut conn, g.low, g.high, ws).await;
                let hi = bisect_cutoff(&mut conn, g.low, g.high, we)
                    .await
                    .min(g.high);
                if hi <= lo {
                    continue;
                }
                let mut at = lo;
                while at <= hi && budget > 0 && !stop() {
                    let chunk_hi = at.saturating_add(CHUNK.min(budget) - 1).min(hi);
                    match conn.over(at, chunk_hi).await {
                        Ok(entries) => {
                            // blocking_db: an inline ingest transaction on
                            // an async worker starves the runtime (see
                            // persist::blocking_db).
                            let _ = crate::persist::blocking_db(|| ix.ingest(&grp, &entries, now));
                        }
                        Err(_) => break,
                    }
                    budget = budget.saturating_sub(chunk_hi - at + 1);
                    at = chunk_hi.saturating_add(1);
                }
            }
            conn.quit().await;
            if rels.iter().all(|&(id, _)| ix.is_complete(id)) {
                break; // every pick in this group landed - stop spending
            }
        }
        for &(id, _) in &rels {
            if ix.is_complete(id) {
                completed += 1;
            }
        }
    }
    // Stamp every pick - including ones a stop() cut short. Rotating an
    // untried pick is the lesser evil against a pause storm pinning the
    // same picks forever.
    for (id, _, _) in &picks {
        let _ = ix.gapfill_mark(*id, now);
    }
    Ok((picks.len() as u32, completed))
}

/// Connect for a header scan, opting in to RFC 8054 COMPRESS DEFLATE
/// when the server advertises it - overview text compresses ~10:1 and a
/// scan is pure OVER traffic. Scan path ONLY: the download path never
/// compresses (yEnc bodies don't compress, the CPU would be waste).
/// Provider tolerance beats the win: a refused or malformed COMPRESS
/// exchange falls back to a fresh uncompressed connection, never a
/// corrupted scan. NZBFAST_NNTP_COMPRESS=0 is the kill switch.
pub(crate) async fn scan_connect(
    server: &nzbkit::config::ServerConfig,
) -> Result<Connection, nzbkit::nntp::NntpError> {
    let (mut c, _) = Connection::connect(server).await?;
    if std::env::var("NZBFAST_NNTP_COMPRESS").is_ok_and(|v| v == "0") {
        return Ok(c);
    }
    match c.capabilities().await {
        Ok(caps) if nzbkit::nntp::caps_support_compress_deflate(&caps) => {
            match c.enable_compression().await {
                Ok(cc) => {
                    // Say so ONCE per host: raw deflate is invisible on
                    // the wire, and if a server's compression is slow or
                    // flaky, a user's log must show what was negotiated
                    // (NZBFAST_NNTP_COMPRESS=0 is the off switch).
                    static ANNOUNCED: std::sync::Mutex<Vec<String>> =
                        std::sync::Mutex::new(Vec::new());
                    let mut seen = ANNOUNCED.lock_ok();
                    if !seen.iter().any(|h| h == &server.host) {
                        seen.push(server.host.clone());
                        info!(target: "scan", "COMPRESS DEFLATE active on {}", server.host);
                    }
                    Ok(cc)
                }
                // Advertised but the exchange failed - retry plain once,
                // and say so: a broken COMPRESS implementation costs a
                // failed handshake per scan connection to this server.
                Err(e) => {
                    info!(
                        target: "scan",
                        "{} advertised COMPRESS DEFLATE but the exchange \
                         failed ({e}) - scanning uncompressed",
                        server.host
                    );
                    Ok(Connection::connect(server).await?.0)
                }
            }
        }
        // No COMPRESS on offer, or a pre-3977 server rejecting
        // CAPABILITIES outright (its status line was consumed, the
        // connection is still clean) - carry on uncompressed.
        Ok(_) | Err(nzbkit::nntp::NntpError::Unexpected { .. }) => Ok(c),
        Err(e) => Err(e),
    }
}

/// Outcome of one OVER fan-out pass.
pub(crate) struct ScanPass {
    pub(crate) scanned: u64,
    pub(crate) completed: u32,
    /// False when the pass was ABANDONED on the idle deadline: some chunk
    /// never came back, so coverage of `lo..=hi` is NOT complete. The
    /// caller must not claim the range - in particular the deepen leg's
    /// `set_low_water` has to be skipped, or the missing slice is written
    /// off as scanned and never revisited.
    pub(crate) complete: bool,
}

/// How long the collector waits for ANY worker to deliver a chunk before
/// abandoning the pass. Generous: it is idle time across the whole
/// fan-out, not per chunk.
///
/// The workers used to be detached tasks each holding a clone of the
/// result sender, and the collector was a bare `while let Some(..) =
/// rx.recv()`. One worker wedged somewhere the NNTP idle deadline does not
/// reach never dropped its sender, so `recv()` never returned None,
/// `index_scan_into` never returned, and the caller's scan JoinSet blocked
/// forever - no group indexed again until restart. Two changes close that:
/// the workers now live in a JoinSet that is aborted when this function
/// returns, and the collector is bounded by this deadline.
pub(crate) fn scan_idle_timeout() -> std::time::Duration {
    let secs = std::env::var("NZBFAST_SCAN_IDLE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(300);
    std::time::Duration::from_secs(secs)
}

/// Fan OVER chunks for articles lo..=hi over a few connections and
/// ingest them. `forward_mark` = Some(mark): the group's high-water
/// advances over the contiguous completed prefix (an aborted pass
/// resumes without holes). None = a backward deepen slice - no marks
/// are touched here; the caller moves the low-water once the whole
/// slice has landed.
#[expect(clippy::too_many_arguments)]
pub(crate) async fn scan_article_range(
    server: &nzbkit::config::ServerConfig,
    group: &str,
    // Marks identity of `server` - the high-water this pass advances
    // belongs to (group, mark_server).
    mark_server: &str,
    low: u64,
    g_high: u64,
    ix: &mut nzbkit::index::Index,
    now: i64,
    forward_mark: Option<u64>,
    progress: Option<&Arc<AtomicU64>>,
    progress_base: u64,
    t0: Instant,
    // M28: concurrent scans sharing the account's connection budget.
    share: usize,
    turbo: bool,
) -> Result<ScanPass> {
    // A few connections multiply header throughput; OVER is cheap for
    // the server, but stay well inside the account's connection budget.
    let nconn =
        (server.connections as u64 / share.max(1) as u64).clamp(1, if turbo { 10 } else { 5 });
    // Chunk size scales INVERSELY with the fan-out: per-request server
    // latency (not RTT - measured stalls up to ~1 s before a response
    // starts streaming) dominates small requests, so a lone connection
    // wants big streaming ranges (100k articles ≈ 82-95k hdr/s vs
    // 31-54k/s at 10k measured per-request). A wide fan-out keeps the
    // old 10k chunks: there the whole pass finishes in seconds and
    // work-stealing granularity wins - the 23 Jul A/B measured 20k
    // chunks at 10 conns ~14% SLOWER by median (a straggling last
    // chunk sets the tail). Budget also bounds buffered headers and
    // keeps the contiguous-prefix resume mark reasonably fine-grained.
    let chunk: u64 = (100_000 / nconn).clamp(10_000, 100_000);
    let nconn = nconn.min(g_high.saturating_sub(low) / chunk + 1) as usize;
    let next = Arc::new(AtomicU64::new(low));
    // Bounded channel: workers stall rather than outrun SQLite ingest.
    // Bound counts CHUNKS, so it shrinks as chunks grow - queued headers
    // stay ~200k regardless of the chunk/fan-out split.
    let bound = ((100_000 / chunk) as usize).clamp(2, 8);
    let (tx, mut rx) =
        tokio::sync::mpsc::channel::<Result<(u64, u64, Vec<nzbkit::nntp::OverEntry>)>>(bound);
    // A JoinSet, not detached `tokio::spawn`: dropping it on the way out
    // ABORTS every worker, so an abandoned pass takes its wedged
    // connection with it instead of leaving it running for the life of
    // the process (see `scan_idle_timeout`).
    let mut workers = tokio::task::JoinSet::new();
    // Bytes every worker has taken off the wire, so the collector's
    // deadline can be a no-progress one rather than a whole-chunk one
    // (see `collect_scan_pass`). One counter for the whole fan-out: the
    // question it answers is "is ANY OVER still moving", which is
    // exactly the question the deadline asks.
    let wire = Arc::new(AtomicU64::new(0));
    for _ in 0..nconn {
        let server = server.clone();
        let group_s = group.to_string();
        let next = next.clone();
        let tx = tx.clone();
        let wire = wire.clone();
        let mut conn: Option<Connection> = None;
        // `tx` is moved into the task, so it drops on every exit path -
        // normal return, early `break`, and panic-unwind alike (tokio
        // drops a panicked task's future). What it does NOT cover is a
        // worker that simply never returns; that is the collector's
        // idle deadline below.
        workers.spawn(async move {
            loop {
                let lo = next.fetch_add(chunk, Ordering::Relaxed);
                if lo > g_high {
                    break;
                }
                // Saturating: `g_high` is server-supplied (validated below
                // u64::MAX in `group()`), but keep the chunk-high computation
                // itself wrap-proof so a near-ceiling `lo` can never produce a
                // reversed `hi < lo` range (which would underflow the
                // `hi - lo + 1` accounting below and revisit ranges forever).
                let hi = lo.saturating_add(chunk - 1).min(g_high);
                // One reconnect-and-retry per chunk before giving up.
                let mut retried = false;
                let entries = loop {
                    if conn.is_none() {
                        // E2: compressed when the server offers it - see
                        // scan_connect for the fallback contract. A chunk
                        // RETRY reconnects PLAIN: if the first attempt
                        // died mid-stream (e.g. a server whose deflate
                        // implementation is broken past the handshake),
                        // trying compression again would just fail the
                        // chunk for good.
                        let fresh = if retried {
                            Connection::connect(&server).await.map(|(c, _)| c)
                        } else {
                            scan_connect(&server).await
                        };
                        match fresh {
                            Ok(mut c) => match c.group(&group_s).await {
                                Ok(_) => {
                                    c.note_over_progress(wire.clone());
                                    conn = Some(c);
                                }
                                Err(e) if retried => break Err(anyhow::Error::from(e)),
                                Err(_) => {
                                    retried = true;
                                    continue;
                                }
                            },
                            Err(e) if retried => break Err(anyhow::Error::from(e)),
                            Err(_) => {
                                retried = true;
                                continue;
                            }
                        }
                    }
                    match conn.as_mut().unwrap().over(lo, hi).await {
                        Ok(es) => break Ok(es),
                        Err(e) => {
                            conn = None;
                            if retried {
                                break Err(anyhow::Error::from(e));
                            }
                            retried = true;
                        }
                    }
                };
                let failed = entries.is_err();
                if tx.send(entries.map(|es| (lo, hi, es))).await.is_err() || failed {
                    break;
                }
            }
            if let Some(c) = conn {
                c.quit().await;
            }
        });
    }
    drop(tx);

    let pass = collect_scan_pass(
        &mut rx,
        ix,
        group,
        mark_server,
        low,
        g_high,
        now,
        forward_mark,
        progress,
        progress_base,
        chunk,
        t0,
        scan_idle_timeout(),
        &wire,
    )
    .await;
    // Dropping `workers` here aborts anything still running - including
    // the worker that wedged - which also releases its connection.
    drop(workers);
    pass
}

/// The collect half of [`scan_article_range`], split out so the abandon
/// path is reachable from a test without an NNTP server.
#[expect(clippy::too_many_arguments)]
pub(crate) async fn collect_scan_pass(
    rx: &mut tokio::sync::mpsc::Receiver<Result<(u64, u64, Vec<nzbkit::nntp::OverEntry>)>>,
    ix: &mut nzbkit::index::Index,
    group: &str,
    mark_server: &str,
    low: u64,
    g_high: u64,
    now: i64,
    forward_mark: Option<u64>,
    progress: Option<&Arc<AtomicU64>>,
    progress_base: u64,
    chunk: u64,
    t0: Instant,
    // How long to wait without PROGRESS before abandoning (a parameter
    // so the abandon path is testable without a 5-minute test).
    idle: std::time::Duration,
    // Bytes the workers have taken off the wire, cumulative across the
    // whole fan-out. A chunk landing is progress; so is this number
    // moving, which is what makes the deadline below no-progress rather
    // than whole-chunk. See the abandon arm.
    wire: &AtomicU64,
) -> Result<ScanPass> {
    let mut scanned = 0u64;
    let mut completed = 0u32;
    // Chunks land out of order; the mark advances over the contiguous
    // prefix only (never regressing below a pre-existing mark).
    let mut next_expected = low;
    let mut pending: std::collections::BTreeMap<u64, u64> = std::collections::BTreeMap::new();
    let mut failure: Option<anyhow::Error> = None;
    let mut complete = true;
    let mut seen_wire = wire.load(Ordering::Relaxed);
    loop {
        let msg = match tokio::time::timeout(idle, rx.recv()).await {
            Ok(Some(m)) => m,
            // Every worker finished and dropped its sender: the pass
            // covered the range.
            Ok(None) => break,
            Err(_) => {
                // Nothing DELIVERED for the whole deadline - but a chunk
                // is a whole OVER range, and a 100k-row range on a slow
                // link is minutes of perfectly healthy transfer that
                // delivers nothing until it finishes. Judging on delivery
                // alone abandoned a live stream mid-transfer, and the
                // articles it had already paid for were refetched next
                // pass. The wire counter is the difference: any byte off
                // any worker's socket since the last look is progress,
                // and the deadline re-arms.
                let now_wire = wire.load(Ordering::Relaxed);
                if now_wire != seen_wire {
                    seen_wire = now_wire;
                    continue;
                }
                // Nothing delivered AND nothing on the wire. Abandon
                // the pass rather than block the scan loop forever. What
                // has been ingested stays (ingest is idempotent and the
                // marks below only ever advanced over the CONTIGUOUS
                // prefix), but the range is not claimed.
                complete = false;
                let dropped = g_high
                    .saturating_sub(low)
                    .saturating_add(1)
                    .saturating_sub(scanned);
                info!(
                    target: "scan",
                    "{group}: nothing on the wire for {}s - abandoning this pass \
                     ({scanned} headers in, ~{dropped} articles of {low}..{g_high} not scanned; \
                     they are retried next pass)",
                    idle.as_secs()
                );
                rx.close();
                break;
            }
        };
        match msg {
            Ok((lo, hi, entries)) => {
                // blocking_db: same reasoning as the gapfill leg - this
                // is the deepen pass's main ingest, three of which ran
                // concurrently in the measured 38 s runner starvation.
                completed += crate::persist::blocking_db(|| ix.ingest(group, &entries, now))?;
                scanned += hi - lo + 1;
                if let Some(p) = progress {
                    p.store(progress_base + scanned, Ordering::Relaxed);
                }
                pending.insert(lo, hi);
                while pending
                    .first_key_value()
                    .is_some_and(|(&l, _)| l == next_expected)
                {
                    let (_, hi) = pending.pop_first().unwrap();
                    next_expected = hi.saturating_add(1);
                    if let Some(mark) = forward_mark
                        && hi > mark
                    {
                        ix.set_high_water(group, mark_server, hi)?;
                    }
                }
                if scanned % 100_000 < chunk {
                    // A4: memoized - the exact query is a full table
                    // scan and this line fires every ~100k headers on
                    // each of up to eight concurrent group connections.
                    let (rel, comp) = ix.stats_cached(SCAN_STATS_TTL)?;
                    println!(
                        "  … {scanned} headers, {rel} releases ({comp} complete), {:.0}/s",
                        scanned as f64 / t0.elapsed().as_secs_f64()
                    );
                }
            }
            Err(e) => {
                // Stop the fan-out; the contiguous mark makes the next
                // pass resume exactly where coverage ends.
                failure = Some(e);
                rx.close();
            }
        }
    }
    if let Some(e) = failure {
        return Err(e);
    }
    Ok(ScanPass {
        scanned,
        completed,
        complete,
    })
}

/// Truncate to at most `n` BYTES on a char boundary - `&s[..60]` panics
/// mid-char on non-ASCII release names (Usenet-controlled text).
pub(crate) fn trunc(s: &str, n: usize) -> &str {
    if s.len() <= n {
        return s;
    }
    let mut i = n;
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    &s[..i]
}

pub(crate) fn search_index(
    query: &str,
    db: &Path,
    nzb_out: Option<&std::path::Path>,
) -> Result<()> {
    let ix = nzbkit::index::Index::open(db)?;
    let hits = ix.search(query, 30)?;
    if hits.is_empty() {
        println!("no matches for '{query}'");
        return Ok(());
    }
    for r in &hits {
        println!(
            "{:>6}  {:<60} {:>9.2} GB  {:>3} files  {}{}",
            r.id,
            trunc(&r.stem, 60),
            r.total_bytes as f64 / 1e9,
            r.files,
            if r.complete { "complete" } else { "partial" },
            if r.has_par2 { " +par2" } else { "" },
        );
    }
    if let Some(path) = nzb_out {
        let xml = ix.make_nzb(hits[0].id)?;
        std::fs::write(path, xml)?;
        println!("wrote {} ({})", path.display(), hits[0].stem);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// spots / spot-search / spot-get - Spotnet ingestion (M14j)
// ---------------------------------------------------------------------------

pub(crate) async fn spots_scan(config: &Path, group: &str, backfill: u64, db: &Path) -> Result<()> {
    let server = load_server(config)?;
    let mut ix = nzbkit::index::Index::open(db)?;
    let (mut conn, _) = Connection::connect(&server).await?;
    let t0 = Instant::now();
    let _ = ix.adopt_legacy_marks(&server.host);
    let sum =
        nzbkit::spot::scan_spots(&mut conn, &mut ix, group, &server.host, backfill, 0).await?;
    conn.quit().await;
    let total = ix.spot_stats()?;
    let records = sum.valid + sum.unverified;
    println!(
        "scanned {} headers in {:.1?}: {} spot records, {} verified{} ({} new), {} unverified, \
         {} not spots{}{} - index now {total} spots",
        sum.scanned,
        t0.elapsed(),
        records,
        sum.valid,
        if records > 0 {
            format!(" ({:.1}%)", 100.0 * sum.valid as f64 / records as f64)
        } else {
            String::new()
        },
        sum.new,
        sum.unverified,
        sum.invalid - sum.unverified,
        if sum.moderation > 0 {
            format!(", {} moderation records", sum.moderation)
        } else {
            String::new()
        },
        if sum.hashcash_warn > 0 {
            format!(", {} hashcash warnings", sum.hashcash_warn)
        } else {
            String::new()
        },
    );
    Ok(())
}

/// One daemon spot pass over one group, into an already-open index.
///
/// Spots ride a single server: the feed is one decentralized group that
/// every backbone carries the same way, so a second server would re-scan
/// the same 200-odd records a day for nothing. Marks are per-server (A8),
/// so switching servers later just costs one backfill.
pub(crate) async fn spot_scan_pass(
    config: &Path,
    ix: &mut nzbkit::index::Index,
    group: &str,
    backfill: u64,
    deepen: u64,
) -> Result<nzbkit::spot::SpotScanSummary> {
    let cfg = Config::load(config)?;
    let server = scan_servers(&cfg)
        .into_iter()
        .next()
        .context("no enabled server to scan spots from")?;
    let (mut conn, _) = Connection::connect(&server).await?;
    let _ = ix.adopt_legacy_marks(&server.host);
    let sum = nzbkit::spot::scan_spots(&mut conn, ix, group, &server.host, backfill, deepen).await;
    conn.quit().await;
    Ok(sum?)
}

/// What one spot-NZB resolver pass did.
#[derive(Debug, Default)]
pub(crate) struct SpotResolveSummary {
    pub(crate) fetched: u32,
    pub(crate) promoted: u32,
    pub(crate) upgraded: u32,
    pub(crate) unusable: u32,
    pub(crate) failed: u32,
    /// Fresh cards whose head article was STATed, and how many of those
    /// came back gone (and so were demoted to incomplete).
    pub(crate) checked: u32,
    pub(crate) gone: u32,
}

/// One budgeted spot-NZB resolver pass (E3 / TODO 131): fetch the NZB
/// for spots that have no release row yet and fold each into the index -
/// a fresh named release normally, an upgrade of the row our scanner
/// already holds for the ~0.6% that overlap. `stop` is polled between
/// spots so a starting download preempts promptly.
///
/// Each spot costs one HEAD plus a handful of BODYs on the first scan
/// server, so a pass is bounded at `budget` such fetches; the backlog
/// after a first backfill drains over a few passes, newest first.
///
/// A freshly promoted card then gets ONE corroborating STAT of its head
/// article, up to `SPOT_STAT_PER_PASS` per pass: its completeness comes
/// from the NZB's own declaration and has never been checked against a
/// provider, which is survivable at the tip and not at 2011 depth. See
/// `Index::spot_stat_verdict`.
pub(crate) async fn spot_resolve_pass(
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
    let (mut conn, _) = Connection::connect(&server).await?;
    // A dead connection fails every remaining fetch identically; a
    // missing article fails one. The breaker tells them apart so a
    // mid-pass disconnect does not burn a retry on every pending spot.
    let mut consecutive_failures = 0u32;
    // Completeness corroboration, rate-limited per pass. `desynced` is
    // the M29 sampler's rule: a STAT that timed out or errored leaves
    // an unread status in the socket, so this session must be DROPPED,
    // never quit() - the goodbye it would read is the STAT's answer,
    // and the next command reads one reply behind forever.
    let mut stat_budget = budget.min(nzbkit::index::SPOT_STAT_PER_PASS);
    let mut desynced = false;
    for s in &pending {
        if stop() || consecutive_failures >= 3 || desynced {
            break;
        }
        match nzbkit::spot::fetch_spot_nzb(&mut conn, &s.msgid).await {
            Ok((sx, bytes)) => {
                consecutive_failures = 0;
                sum.fetched += 1;
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
                                && let Some(head) = ix.release_head_article(rid)?
                            {
                                stat_budget -= 1;
                                match stat_one(&mut conn, &head).await {
                                    Ok(present) => {
                                        sum.checked += 1;
                                        sum.gone += u32::from(!present);
                                        ix.spot_stat_verdict(&s.msgid, rid, present)?;
                                    }
                                    Err(_) => desynced = true,
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
            Err(_) => {
                consecutive_failures += 1;
                sum.failed += 1;
                ix.spot_nzb_failed(&s.msgid)?;
            }
        }
    }
    if desynced {
        warn!(target: "spots", "dropping the resolver connection after an unanswered STAT");
        drop(conn);
    } else {
        conn.quit().await;
    }
    Ok(sum)
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
pub(crate) fn search_misses(
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

pub(crate) fn spot_search(query: &str, db: &Path) -> Result<()> {
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

pub(crate) async fn spot_get(config: &Path, msgid: &str, nzb: &Path, db: &Path) -> Result<()> {
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
pub(crate) async fn nzb_import(
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

// `release_stem` is `nzbkit::extract::release_stem`, imported at the head
// of this file. It USED to be written out a second time here, and the two
// spellings drifted twice: once into a third private `.vol-NN` rule, which
// stemmed a complete post's volumes to `Rel.vol-01` while its main and data
// stemmed to `Rel`, so `make_release_nzb` below never saw main, volume and
// data in one release map and reported "no complete release with par2
// found" (14 Aug 2026 sweep - that fix shared `nzb::par2_vol_suffix` and
// left the rest of the function duplicated); and then into a missing
// split-container cut, so a split 7z or zip post shattered into one
// "release" per volume and could never reach the three-file floor the
// qualifier applies (31 Aug 2026, `research/RELEASE-STEM-TWIN-2026-08-31.md`).
// Do not write a second one: there is one public home for this rule.

/// Does this release member put a RAR extractor in the job's path?
/// Suffix-only, so a `.rar` in the middle of a name does not count:
/// `x.rar` and `x.part01.rar` both end `.rar`, and the old split
/// shapes are `x.r00` / `x.s00`.
///
/// DELIBERATELY NARROWER THAN THE CUT `release_stem` MAKES, and this
/// used to claim they were the same spellings - which stopped being true
/// on 31 Aug 2026 when the twin above was collapsed onto
/// `extract::release_stem`, whose old-style continuation range is
/// `r..=z` (a set past `.s99` rolls on into `.t00` … `.z99`, and
/// `vol_sort_key` orders that whole range). Two reasons this question
/// stays at `r`/`s` rather than following it:
///
/// * `.zNN` is ALSO how PKZIP spells a split zip volume - the shape
///   `manifest::is_consumable_source` names as its ZIP arm - so a
///   widened rule answers true for a set with no RAR anywhere in it,
///   and the ONE caller is `--require-rar`, a screen whose whole job is
///   to refuse a release that puts no extractor in path.
/// * It loses nothing here even so. The caller asks this of every
///   member of a release (`rel.keys().any(..)`), and an old-style
///   sequence that reaches `.t00` began at `.rar` and passed through
///   `.r00` … `.s99` to get there, so such a set always carries a
///   member this answers true for. A false negative would only make the
///   descent continue; a false positive hands back the fixture the flag
///   exists to reject.
pub(crate) fn is_rar_member(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".rar") {
        return true;
    }
    let Some(dot) = lower.rfind('.') else {
        return false;
    };
    let tail = &lower[dot + 1..];
    tail.len() >= 2
        && (tail.starts_with('r') || tail.starts_with('s'))
        && tail[1..].bytes().all(|c| c.is_ascii_digit())
}

pub(crate) async fn make_release_nzb(
    config: &Path,
    group: &str,
    min_gb: f64,
    max_gb: f64,
    require_rar: bool,
    out: &Path,
) -> Result<()> {
    use std::collections::BTreeMap;
    use std::collections::HashMap;

    let server = load_server(config)?;
    let (mut conn, _) = Connection::connect(&server).await?;
    let g = conn.group(group).await?;

    // (poster, stem) → filename → (total parts, part → (msgid, bytes))
    type Parts = BTreeMap<u32, (String, u64)>;
    type Release = HashMap<String, (u32, Parts)>;
    let mut releases: HashMap<(String, String), Release> = HashMap::new();

    let mut high = g.high;
    let mut scanned = 0u64;
    let mut winner: Option<((String, String), Release)> = None;
    while winner.is_none() && high > g.low && scanned < 2_000_000 {
        let from = high.saturating_sub(20_000).max(g.low);
        for e in conn.over(from, high).await? {
            // Files without a (n/m) counter (nfo/sfv posts) are single-part.
            let (base, part, total) =
                split_subject(&e.subject).unwrap_or_else(|| (e.subject.clone(), 1, 1));
            if e.message_id.is_empty() || part == 0 || total == 0 {
                continue;
            }
            // Quoted filename from the counter-stripped subject.
            let Some(fname) = quoted_name(&base) else {
                continue;
            };
            let stem = release_stem(&fname);
            if stem.is_empty() {
                continue;
            }
            let rel = releases.entry((e.from.clone(), stem)).or_default();
            let entry = rel.entry(fname).or_insert_with(|| (total, BTreeMap::new()));
            entry.1.insert(part, (e.message_id, e.bytes));
        }
        scanned += high - from;

        // A release qualifies when: every seen file is complete, it has a
        // par2 main + at least one volume + at least one data file, and the
        // total size is in range. (Volumes prove the par2 set is fetchable;
        // the main index is what activates in-stream verification.)
        for (key, rel) in &releases {
            let all_complete = rel.values().all(|(t, p)| p.len() as u32 == *t);
            if !all_complete || rel.len() < 3 {
                continue;
            }
            let has_main = rel.keys().any(|n| {
                let l = n.to_ascii_lowercase();
                l.ends_with(".par2") && nzbkit::nzb::par2_vol_suffix(n).is_none()
            });
            let has_vol = rel
                .keys()
                .any(|n| nzbkit::nzb::par2_vol_suffix(n).is_some());
            let has_data = rel
                .keys()
                .any(|n| !n.to_ascii_lowercase().ends_with(".par2"));
            // `--require-rar` keeps the DESCENT going past a release
            // that qualifies on every other count, rather than
            // returning it and making the caller re-scan a different
            // group. Sourcing class F's fixtures on 23 Aug 2026 found
            // the newest complete par2-bearing release was RAR-shaped
            // in 2 of 20 groups, so one-sample-per-group roulette is
            // the wrong instrument for a corpus that has moved: see
            // `research/NOTE-2026-08-23-class-F-fixture-sourcing-measured.md`.
            if require_rar && !rel.keys().any(|n| is_rar_member(n)) {
                continue;
            }
            let size: u64 = rel
                .values()
                .flat_map(|(_, p)| p.values())
                .map(|v| v.1)
                .sum();
            let gb = size as f64 / 1e9;
            if has_main && has_vol && has_data && gb >= min_gb && gb <= max_gb {
                println!(
                    "release: {} ({} files, {:.2} GB) by {}",
                    key.1,
                    rel.len(),
                    gb,
                    key.0
                );
                winner = Some((key.clone(), rel.clone()));
                break;
            }
        }
        if from == g.low {
            break;
        }
        high = from - 1;
    }
    conn.quit().await;

    let Some(((poster, _stem), rel)) = winner else {
        let want = if require_rar { " with rar members" } else { "" };
        anyhow::bail!("no complete release{want} with par2 found in {scanned} headers");
    };
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    let mut names: Vec<&String> = rel.keys().collect();
    names.sort();
    for fname in names {
        let (total, parts) = &rel[fname];
        let size: u64 = parts.values().map(|v| v.1).sum();
        println!("  {fname}  ({total} parts, {:.1} MB)", size as f64 / 1e6);
        xml.push_str(&format!(
            "  <file poster=\"{}\" date=\"0\" subject=\"{}\">\n    <groups><group>{}</group></groups>\n    <segments>\n",
            xml_escape(&poster),
            xml_escape(&format!("\"{fname}\" yEnc (1/{total})")),
            group,
        ));
        for (num, (msgid, bytes)) in parts {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{}</segment>\n",
                xml_escape(msgid.trim_matches(['<', '>']))
            ));
        }
        xml.push_str("    </segments>\n  </file>\n");
    }
    xml.push_str("</nzb>\n");
    std::fs::write(out, xml)?;
    println!("wrote {}", out.display());
    Ok(())
}

/// First quoted substring (unquoted-convention fallback included) -
/// shared with the indexer so both paths accept the same subjects.
pub(crate) fn quoted_name(s: &str) -> Option<String> {
    nzbkit::index::quoted_name(s)
}

// ---------------------------------------------------------------------------
// make-test-nzb - assemble a real NZB from complete posts in a group
// ---------------------------------------------------------------------------

pub(crate) async fn make_test_nzb(
    config: &Path,
    group: &str,
    want_files: usize,
    max_file_mb: u64,
    out: &Path,
) -> Result<()> {
    use std::collections::BTreeMap;
    use std::collections::HashMap;

    let server = load_server(config)?;
    let (mut conn, _) = Connection::connect(&server).await?;
    let g = conn.group(group).await?;

    // (poster, base-subject) → (total parts, map part → (msgid, bytes))
    type Parts = BTreeMap<u32, (String, u64)>;
    let mut groups: HashMap<(String, String), (u32, Parts)> = HashMap::new();
    let mut complete: Vec<((String, String), (u32, Parts))> = Vec::new();

    let mut high = g.high;
    let mut scanned = 0u64;
    while complete.len() < want_files && high > g.low && scanned < 300_000 {
        let from = high.saturating_sub(8_000).max(g.low);
        for e in conn.over(from, high).await? {
            let Some((base, part, total)) = split_subject(&e.subject) else {
                continue;
            };
            if e.message_id.is_empty() || part == 0 || total < 2 {
                continue;
            }
            let entry = groups
                .entry((e.from.clone(), base))
                .or_insert_with(|| (total, BTreeMap::new()));
            entry.1.insert(part, (e.message_id, e.bytes));
            if entry.1.len() as u32 == entry.0 {
                let key = (e.from.clone(), split_subject(&e.subject).unwrap().0);
                if let Some(done) = groups.remove(&key) {
                    let size: u64 = done.1.values().map(|v| v.1).sum();
                    if size <= max_file_mb * 1_000_000 {
                        complete.push((key, done));
                    }
                }
            }
        }
        scanned += high - from;
        if from == g.low {
            break;
        }
        high = from - 1;
    }
    conn.quit().await;
    anyhow::ensure!(
        complete.len() >= want_files,
        "only {} complete files found (wanted {want_files})",
        complete.len()
    );
    complete.truncate(want_files);

    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for ((poster, base), (total, parts)) in &complete {
        let size: u64 = parts.values().map(|v| v.1).sum();
        println!("  {base}  ({total} parts, {:.1} MB)", size as f64 / 1e6);
        xml.push_str(&format!(
            "  <file poster=\"{}\" date=\"0\" subject=\"{}\">\n    <groups><group>{}</group></groups>\n    <segments>\n",
            xml_escape(poster),
            xml_escape(&format!("{base} (1/{total})")),
            group,
        ));
        for (num, (msgid, bytes)) in parts {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{}</segment>\n",
                xml_escape(msgid.trim_matches(['<', '>']))
            ));
        }
        xml.push_str("    </segments>\n  </file>\n");
    }
    xml.push_str("</nzb>\n");
    std::fs::write(out, xml)?;
    println!("wrote {} ({} files)", out.display(), complete.len());
    Ok(())
}

/// Split `… "name" yEnc (n/m)` → (base subject without the counter, n, m).
/// Shared with the indexer - rightmost parsing counter, `[n/m]`/`of` forms.
pub(crate) fn split_subject(subject: &str) -> Option<(String, u32, u32)> {
    nzbkit::index::split_subject(subject)
}

pub(crate) fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod scan_pass_tests {
    use super::*;
    use std::time::Duration;

    /// 14 Aug sweep: this file kept a THIRD private spelling of the
    /// "is it a recovery volume?" rule, demanding digits before the
    /// separator. `make_release_nzb` groups by this stem, so on a
    /// `.vol-NN.par2` post the volumes stemmed to `Rel.vol-01` while
    /// main and data stemmed to `Rel` - no group ever held all three,
    /// and a complete post finished "no complete release with par2
    /// found". Every volume shape must reduce to the same stem.
    #[test]
    fn every_par2_volume_shape_shares_the_release_stem() {
        for n in [
            "Rel.par2",
            "Rel.vol000+01.par2",
            "Rel.vol127-199.par2",
            // The bare ordinal - the shape that was missed.
            "Rel.vol-01.par2",
            "Rel.vol-09.par2",
            "Rel.part01.rar",
            "Rel.rar",
            "Rel.r00",
        ] {
            assert_eq!(release_stem(n), "Rel", "{n} must stem to the release");
        }
        // The negatives the shared rule protects: a spelt-out "volume"
        // and a compilation numbered Vol-3 name releases, not volumes.
        assert_eq!(release_stem("Rel.volume-2.par2"), "Rel.volume-2");
        assert_eq!(
            release_stem("VA.Best.Hits.Vol-3.par2"),
            "VA.Best.Hits.Vol-3"
        );
    }

    /// `make_release_nzb` groups by this stem, so a split-container
    /// post - 7-Zip's `%s.%03d` volumes, or a PKZIP byte split - has to
    /// reduce every part AND its par2 sidecar to one key or the release
    /// shatters into one "release" per volume and can never reach the
    /// three-file floor the qualifier applies. The canonical rule cuts
    /// the numeric tail and KEEPS the container extension, which is what
    /// puts `Big.Post.7z.001` and `Big.Post.7z.par2` in one map.
    #[test]
    fn a_split_container_post_groups_every_part_with_its_par2() {
        for (n, want) in [
            ("Big.Post.7z.001", "Big.Post.7z"),
            ("Big.Post.7z.002", "Big.Post.7z"),
            ("Big.Post.7z.100", "Big.Post.7z"),
            // Four digits past 999 - 7-Zip widens the field.
            ("Big.Post.7z.1000", "Big.Post.7z"),
            ("Big.Post.7z.par2", "Big.Post.7z"),
            ("Big.Post.7z.vol000+01.par2", "Big.Post.7z"),
            ("Big.Post.zip.001", "Big.Post.zip"),
            ("Big.Post.ZIP.001", "Big.Post.ZIP"),
        ] {
            assert_eq!(release_stem(n), want, "{n} must stem to the set");
        }
        // The negatives the digit bounds protect: one and two digits stay,
        // because `Track.01` is somebody's music and not a volume, and a
        // numeric tail after anything other than a container extension is
        // part of the name.
        assert_eq!(release_stem("Track.01"), "Track.01");
        assert_eq!(release_stem("Big.Post.7z.01"), "Big.Post.7z.01");
        assert_eq!(
            release_stem("Show.S01E05.1080p.264"),
            "Show.S01E05.1080p.264"
        );
    }

    /// The screen `--require-rar` applies, and the reason class F's
    /// fixture sourcing needed it: on 23 Aug 2026 the newest complete
    /// par2-bearing release was a bare payload plus a par2 ladder in
    /// 12 of the 14 groups that yielded anything, so a job sourced
    /// without this runs with no extractor in path. The negatives are
    /// what stop it: a par2 member and an `.mkv` are not rar members,
    /// and neither is a name that merely contains "rar".
    #[test]
    fn rar_members_are_recognised_by_suffix_only() {
        for n in [
            "Rel.rar",
            "Rel.part01.rar",
            "Rel.PART01.RAR",
            "Rel.r00",
            "Rel.s01",
        ] {
            assert!(is_rar_member(n), "{n} puts an extractor in path");
        }
        for n in [
            "Rel.par2",
            "Rel.vol000+01.par2",
            "Show.S01E05.1080p.WEB-DL.mkv",
            "Rel.rar.txt",
            "Rel.nfo",
            "rar",
        ] {
            assert!(!is_rar_member(n), "{n} is not a rar member");
        }
    }

    fn tmp_index(tag: &str) -> (PathBuf, nzbkit::index::Index) {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-scanpass-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ix = nzbkit::index::Index::open(&dir.join("index.db")).unwrap();
        (dir, ix)
    }

    /// Tear the fixture down, closing the index BEFORE removing its
    /// directory.
    ///
    /// The drop is load-bearing, not tidiness. `Index` holds an open SQLite
    /// connection to `dir/index.db`, and SQLite opens its files without
    /// FILE_SHARE_DELETE, so Windows refuses to remove the directory
    /// underneath it: "The process cannot access the file because it is
    /// being used by another process" (os error 32). Unix unlinks an open
    /// file quite happily, which is why leaving the connection alive was
    /// invisible here for as long as the suite only ever ran on Linux and
    /// macOS. Every product assertion in these tests passed first - the
    /// teardown was the only thing Windows objected to.
    fn teardown(dir: PathBuf, ix: nzbkit::index::Index) {
        drop(ix);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// BUG (HIGH): one wedged scan worker froze ALL indexing for the
    /// process lifetime. Each worker held a clone of the result sender and
    /// the collector was a bare `while let Some(..) = rx.recv().await`, so
    /// a worker that never reached its exit path never dropped its sender,
    /// `recv()` never returned None, `scan_article_range` and
    /// `index_scan_into` never returned, and the caller's scan JoinSet
    /// blocked forever - no further pass for ANY group until restart.
    ///
    /// The collector is now bounded: a stall abandons the pass.
    #[tokio::test]
    async fn a_wedged_worker_cannot_freeze_the_scan_collector() {
        let (dir, mut ix) = tmp_index("wedged");
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        // One chunk lands, then a worker wedges holding its sender.
        let wedged = tx.clone();
        tx.send(Ok((100, 199, Vec::new()))).await.unwrap();
        drop(tx);

        let pass = tokio::time::timeout(
            Duration::from_secs(10),
            collect_scan_pass(
                &mut rx,
                &mut ix,
                "alt.test",
                "srv1",
                100,
                999,
                0,
                Some(0),
                None,
                0,
                100,
                Instant::now(),
                Duration::from_millis(50),
                &AtomicU64::new(0),
            ),
        )
        .await
        .expect("the collector must not block on a sender that never drops")
        .unwrap();

        assert!(!pass.complete, "an abandoned pass must not report complete");
        assert_eq!(pass.scanned, 100);
        // CRITICAL: the contiguous prefix stops where coverage really
        // ends. Advancing it to g_high would write the missing 200..999
        // off as scanned forever.
        assert_eq!(ix.high_water("alt.test", "srv1"), 199);
        drop(wedged);
        teardown(dir, ix);
    }

    /// The control: a healthy pass must still report complete, so the
    /// caller's `set_low_water` (the deepen leg) keeps running.
    #[tokio::test]
    async fn a_healthy_pass_reports_complete_and_advances_the_prefix() {
        let (dir, mut ix) = tmp_index("healthy");
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        // Out-of-order arrival: the prefix must still reach 299.
        tx.send(Ok((200, 299, Vec::new()))).await.unwrap();
        tx.send(Ok((100, 199, Vec::new()))).await.unwrap();
        drop(tx);

        let pass = tokio::time::timeout(
            Duration::from_secs(10),
            collect_scan_pass(
                &mut rx,
                &mut ix,
                "alt.test",
                "srv1",
                100,
                299,
                0,
                Some(0),
                None,
                0,
                100,
                Instant::now(),
                Duration::from_millis(50),
                &AtomicU64::new(0),
            ),
        )
        .await
        .expect("a healthy pass must not hit the idle deadline")
        .unwrap();

        assert!(pass.complete);
        assert_eq!(pass.scanned, 200);
        assert_eq!(ix.high_water("alt.test", "srv1"), 299);
        teardown(dir, ix);
    }

    /// TODO 23: the collector's deadline is a NO-PROGRESS one, not a
    /// whole-chunk one.
    ///
    /// A chunk is a whole OVER range - up to 100,000 rows - and nothing
    /// reaches the channel until it is finished. So a slow-but-live
    /// stream delivered nothing for minutes and the collector, which
    /// only ever looked at deliveries, abandoned the pass mid-transfer.
    /// The articles already paid for were thrown away and refetched next
    /// pass, and on a link slow enough the group could never finish a
    /// pass at all.
    ///
    /// The wire counter is what tells a slow OVER from a dead one. Here
    /// it moves across four whole idle windows with NOTHING delivered,
    /// which under the old rule was four abandons; the pass must survive
    /// all of them and then complete on the chunk that finally lands.
    #[tokio::test]
    async fn a_slow_but_live_over_stream_is_not_abandoned_mid_transfer() {
        let (dir, mut ix) = tmp_index("slowwire");
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let idle = Duration::from_millis(50);
        let wire = Arc::new(AtomicU64::new(0));

        // The worker: silent on the channel for 4 x idle while bytes
        // keep landing, then it finishes its one chunk and goes away.
        let w = wire.clone();
        let feeder = tokio::spawn(async move {
            for _ in 0..8 {
                tokio::time::sleep(idle / 2).await;
                w.fetch_add(4096, Ordering::Relaxed);
            }
            tx.send(Ok((100, 199, Vec::new()))).await.unwrap();
        });

        let pass = tokio::time::timeout(
            Duration::from_secs(10),
            collect_scan_pass(
                &mut rx,
                &mut ix,
                "alt.test",
                "srv1",
                100,
                199,
                0,
                Some(0),
                None,
                0,
                100,
                Instant::now(),
                idle,
                &wire,
            ),
        )
        .await
        .expect("the collector must not block")
        .unwrap();

        feeder.await.unwrap();
        assert!(
            pass.complete,
            "a stream that was moving the whole time was abandoned - the \
             deadline is still whole-chunk, not no-progress"
        );
        assert_eq!(pass.scanned, 100);
        assert_eq!(ix.high_water("alt.test", "srv1"), 199);
        teardown(dir, ix);
    }

    /// The other half of the same rule: a wire that is NOT moving is
    /// still abandoned on time. Without this, "re-arm on progress" could
    /// be satisfied by never abandoning at all, which is the freeze the
    /// deadline exists to prevent.
    #[tokio::test]
    async fn a_silent_wire_is_still_abandoned_on_the_deadline() {
        let (dir, mut ix) = tmp_index("deadwire");
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let wedged = tx.clone();
        tx.send(Ok((100, 199, Vec::new()))).await.unwrap();
        drop(tx);
        // Non-zero from the start: the collector must compare against
        // what it last SAW, not against zero.
        let wire = Arc::new(AtomicU64::new(9_000_000));

        let t0 = Instant::now();
        let pass = tokio::time::timeout(
            Duration::from_secs(10),
            collect_scan_pass(
                &mut rx,
                &mut ix,
                "alt.test",
                "srv1",
                100,
                999,
                0,
                Some(0),
                None,
                0,
                100,
                Instant::now(),
                Duration::from_millis(50),
                &wire,
            ),
        )
        .await
        .expect("a silent wire must not hold the collector open")
        .unwrap();

        assert!(!pass.complete, "an abandoned pass must not report complete");
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "abandoning took {:?} - a static counter must not re-arm the \
             deadline",
            t0.elapsed()
        );
        assert_eq!(ix.high_water("alt.test", "srv1"), 199);
        drop(wedged);
        teardown(dir, ix);
    }

    /// A HOLE in the middle must not let the mark jump the gap, abandoned
    /// or not: the prefix stops at the hole and the pass is incomplete.
    #[tokio::test]
    async fn an_abandoned_pass_never_marks_over_a_hole() {
        let (dir, mut ix) = tmp_index("hole");
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let wedged = tx.clone();
        tx.send(Ok((100, 199, Vec::new()))).await.unwrap();
        // 200..299 never arrives; 300..399 does.
        tx.send(Ok((300, 399, Vec::new()))).await.unwrap();
        drop(tx);

        let pass = tokio::time::timeout(
            Duration::from_secs(10),
            collect_scan_pass(
                &mut rx,
                &mut ix,
                "alt.test",
                "srv1",
                100,
                399,
                0,
                Some(0),
                None,
                0,
                100,
                Instant::now(),
                Duration::from_millis(50),
                &AtomicU64::new(0),
            ),
        )
        .await
        .expect("the collector must not block")
        .unwrap();

        assert!(!pass.complete);
        assert_eq!(
            ix.high_water("alt.test", "srv1"),
            199,
            "the mark must stop at the hole, not follow the last chunk in"
        );
        drop(wedged);
        teardown(dir, ix);
    }
}
