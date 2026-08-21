//! The metadata lanes: everything that puts NAMES and artwork on what
//! the index already holds. The wall enricher's three provider lanes, the
//! person-photo fetcher and its art cache pruner, the IMDb ratings
//! refresher, and the predb feed that names obfuscated releases.
//!
//! All network happens in here - the API thread only ever reads the
//! caches these workers fill. Pacing is per PROVIDER (`ratelimit`), which
//! is why the wall runs as three lanes rather than one serial loop.
//!
//! Split out of `serve/tasks.rs` whole (TODO 106) - the code is verbatim,
//! only visibility changed. Everything is re-exported from `super`, so
//! `tasks::wall_enricher(..)` and friends still resolve for callers.

use super::*;

/// M13 background enricher: look up pending wall titles (TMDB with a
/// key; TVmaze/Wikidata keyless otherwise), cache posters/backdrops to
/// `.spool/art/`, record results (including "found nothing") in the
/// index db. All network happens HERE - the API thread only ever reads
/// the cache. Pacing is per PROVIDER, in `ratelimit` - every request a
/// lane makes waits for that provider's bucket, so a title that needs
/// six calls costs six slots and a title that needs one costs one. The
/// lanes used to sleep a fixed window after each TITLE instead, which
/// could not see the burst inside one: measured 27 Jul, that let the
/// movie lane spend a quarter of Wikidata's 10-request window on a
/// single title and stall ~55 s on a 429 for 3-4 titles in every 10.
///
/// Runs as THREE lanes (M21 speedup, extended): movies (Wikidata /
/// Wikipedia / OMDb), TV + junk (TVmaze), and music + books
/// (MusicBrainz / Cover Art Archive / OpenLibrary). The rate limits are
/// per-provider, so one serial loop made every TV title queue behind the
/// movie crawl - and MusicBrainz's hard 1 request/second would have put
/// an album backlog in front of every new episode had it shared a lane.
#[cfg(feature = "indexer")]
pub(in crate::serve) fn wall_enricher(
    d: Arc<Daemon>,
    api_key: Option<String>,
    stop: crate::serve::RunStop,
) {
    use nzbkit::index::Lane;
    for lane in [Lane::Movies, Lane::MusicBooks] {
        let (d2, k2) = (d.clone(), api_key.clone());
        crate::serve::spawn_aux("wall-enrich", move || wall_enrich_lane(d2, k2, lane, stop));
    }
    wall_enrich_lane(d, api_key, Lane::Shows, stop);
}

/// The `titles.kind` string as the wall's enum. Music and books used to
/// fall into the `_` arm here and land on `Kind::Other`, which returns
/// before touching any provider - so those rows were stamped "checked"
/// having never been looked up.
#[cfg(feature = "indexer")]
pub(in crate::serve) fn lane_kind(kind: &str) -> crate::wall::Kind {
    match kind {
        "tv" => crate::wall::Kind::Tv,
        "movie" => crate::wall::Kind::Movie,
        "music" => crate::wall::Kind::Music,
        "book" => crate::wall::Kind::Book,
        _ => crate::wall::Kind::Other,
    }
}

/// How many keys in backoff one over-fetch is willing to see past. A
/// bound on the query, not a policy: past a couple of hundred the lane
/// is not starved, it is offline.
#[cfg(feature = "indexer")]
const OVER_FETCH_CAP: usize = 200;

/// The rows a lane may actually work this pass, drawn through `fetch`.
///
/// Asking for exactly `want` and filtering afterwards is starvation, not
/// a rounding error, and the shape of these queues is what makes it one:
/// every lane's priority order is head-stable, and a row only leaves the
/// set when a provider ANSWERS about it. So `want` permanently
/// unanswerable rows at the head - a TVmaze 404, a merged show id -
/// occupy the whole batch on every pass forever, and the eligible rows
/// behind them are never even fetched. A transient outage does the same
/// thing for up to the backoff ceiling (Codex sweep 7, M2: the TVDB
/// queue was the one lane still filtering after its LIMIT).
///
/// So: over-fetch by the number of keys currently in backoff, drop those,
/// and take `want` of what is left.
#[cfg(feature = "indexer")]
fn eligible_batch<T>(
    want: usize,
    unreached: &std::collections::HashMap<String, (u32, std::time::Instant)>,
    now: std::time::Instant,
    key: impl Fn(&T) -> &str,
    fetch: impl FnOnce(u32) -> Vec<T>,
) -> Vec<T> {
    let rows = fetch(want as u32 + unreached.len().min(OVER_FETCH_CAP) as u32);
    eligible(rows, unreached, now, key, want)
}

/// The eligibility half on rows already in hand - the viewport queue,
/// which is a set of cards on screen rather than a priority order, so
/// nothing at its head can starve anything behind it.
#[cfg(feature = "indexer")]
fn eligible<T>(
    rows: Vec<T>,
    unreached: &std::collections::HashMap<String, (u32, std::time::Instant)>,
    now: std::time::Instant,
    key: impl Fn(&T) -> &str,
    want: usize,
) -> Vec<T> {
    rows.into_iter()
        .filter(|r| unreached.get(key(r)).is_none_or(|(_, next)| *next <= now))
        .take(want)
        .collect()
}

#[cfg(feature = "indexer")]
pub(in crate::serve) fn wall_enrich_lane(
    d: Arc<Daemon>,
    api_key: Option<String>,
    lane: nzbkit::index::Lane,
    stop: crate::serve::RunStop,
) {
    let art = d.spool.join("art");
    let _ = std::fs::create_dir_all(&art);
    let mut said_backfilling = false;
    // Titles whose whole provider chain could not be REACHED
    // (DNS, timeout, TLS, 5xx - as opposed to "answered and had
    // nothing"). Such a row deliberately stays unstamped so a later
    // pass retries it, but without memory of the failure the lane
    // offers it again on the very next batch: the live daemon spent a
    // whole night logging the same title every ~7 seconds. Each key
    // now waits BACKOFF_MIN after its first failed pass, doubling to
    // the BACKOFF_MAX ceiling, and any pass that reaches a provider
    // clears its slate. In-memory on purpose, like the photo
    // fetcher's failed set: a restart retrying at once is fine, the
    // tight loop is not. Keyed per title, so one unreachable title
    // never delays the rest of the queue.
    const BACKOFF_MIN: u64 = 60;
    const BACKOFF_MAX: u64 = 6 * 3600;
    let mut unreached: std::collections::HashMap<String, (u32, std::time::Instant)> =
        std::collections::HashMap::new();
    let backoff_after = |fails: u32| {
        std::time::Instant::now()
            + std::time::Duration::from_secs(
                BACKOFF_MIN
                    .saturating_mul(1u64 << fails.saturating_sub(1).min(9))
                    .min(BACKOFF_MAX),
            )
    };
    loop {
        // This lane holds a strong `Arc<Daemon>` throughout - it reads
        // the daemon on nearly every line - so returning here is what
        // reclaims the generation under an embedded host.
        if stop.stopping() {
            return;
        }
        if d.park_if_off(30) {
            continue;
        }
        // Entries whose wait has expired retry on sight, so dropping
        // them merely resets a counter - done only to bound the map
        // for the life of the thread.
        if unreached.len() > 2_048 {
            let now_i = std::time::Instant::now();
            unreached.retain(|_, (_, next)| *next > now_i);
        }
        // M30: what the wall is showing unenriched RIGHT NOW jumps the
        // backlog. Keys stay queued until this lane's query confirms
        // they're pending here (the other lane's keys just no-op), and
        // processed ones are removed below.
        let hot_keys: Vec<String> = d.enrich_hot.lock_ok().iter().cloned().collect();
        let hot = if hot_keys.is_empty() {
            Vec::new()
        } else {
            d.with_index(|ix| ix.titles_hot(&hot_keys, lane).ok())
                .unwrap_or_default()
        };
        let now_i = std::time::Instant::now();
        // Batch of 12 (was 6): fewer db round-trips, and it costs
        // nothing in pacing - the per-title sleeps are gone, the rate
        // now lives in the per-provider buckets, which do not care how
        // many titles a batch holds. A fresh priority order is re-read
        // every batch anyway.
        let batch: Vec<_> = if !hot.is_empty() {
            {
                let mut q = d.enrich_hot.lock_ok();
                q.retain(|k| !hot.iter().any(|t| &t.key == k));
            }
            eligible(
                hot,
                &unreached,
                now_i,
                |r: &nzbkit::index::TitleRow| r.key.as_str(),
                12,
            )
        } else {
            eligible_batch(
                12,
                &unreached,
                now_i,
                |r: &nzbkit::index::TitleRow| r.key.as_str(),
                |n| {
                    d.with_index(|ix| ix.titles_pending_lane(n, lane).ok())
                        .unwrap_or_default()
                },
            )
        };
        if batch.is_empty() {
            // TODO 187: idle time also fills the TVDB ids the newznab
            // facade's `tvdbid` search resolves through. Shows lane
            // only - nothing else has one - and one exact
            // `/shows/<tvmaze id>` GET per row rather than a search,
            // because the row already carries the id that names the
            // show. It retires itself once every show has been asked,
            // and until it has run at least once the facade does not
            // advertise the parameter at all.
            let mut did_tvdb = false;
            if lane == nzbkit::index::Lane::Shows {
                // Over-fetched then filtered, like its sibling lanes -
                // it used to be the one queue that took its six rows
                // first and skipped them afterwards, so six shows TVmaze
                // permanently 404s on pinned the lane for good (Codex
                // sweep 7, M2).
                let tv = eligible_batch(
                    6,
                    &unreached,
                    now_i,
                    |r: &nzbkit::index::TitleRow| r.key.as_str(),
                    |n| {
                        d.with_index(|ix| ix.titles_missing_tvdb(n).ok())
                            .unwrap_or_default()
                    },
                );
                did_tvdb = !tv.is_empty();
                let _busy = d.busy.hold("enriching");
                for row in tv {
                    crate::wall::clear_unreachable();
                    match crate::wall::tvmaze_tvdb_id(row.tmdb_id) {
                        // An answer, id or no id. Recorded either way:
                        // "TVmaze publishes none for this show" is what
                        // stops the lane returning to it forever.
                        Some(id) => {
                            unreached.remove(&row.key);
                            let _ = d.with_index(|ix| ix.title_set_tvdb(&row.key, id).ok());
                        }
                        // Not an answer. tvdb_tried is as permanent as
                        // the enricher's checked stamp, so a row we
                        // could not reach a provider for must stay
                        // eligible rather than be retired unasked.
                        None => {
                            let fails = unreached.get(&row.key).map_or(0, |(n, _)| *n) + 1;
                            unreached.insert(row.key.clone(), (fails, backoff_after(fails)));
                        }
                    }
                }
            }
            // Idle time goes on backfilling release dates onto titles
            // enriched before we stored them - otherwise the wall's
            // release-date sort would only ever work for titles indexed
            // from this version on, and an existing library would sort by
            // year forever. Only the date column is written, so artwork
            // and any hand-corrected metadata are left alone.
            // Same backoff as the enrichment batch above: a title whose
            // backfill could not reach a provider waits its turn instead
            // of being re-asked every pass.
            let back = eligible_batch(
                6,
                &unreached,
                now_i,
                |r: &nzbkit::index::TitleRow| r.key.as_str(),
                |n| {
                    d.with_index(|ix| ix.titles_missing_date(n, lane).ok())
                        .unwrap_or_default()
                },
            );
            if back.is_empty() {
                // Only idle when BOTH passes had nothing: a tvdb pass
                // that just drained six rows should come straight back
                // for the next six, not wait 15s per batch and take
                // hours to make the facade's promise true.
                if !did_tvdb && !stop.sleep(std::time::Duration::from_secs(15)) {
                    return;
                }
                continue;
            }
            let _busy = d.busy.hold("enriching");
            if !said_backfilling {
                said_backfilling = true;
                info!(
                    target: "wall",
                    "backfilling release dates for already-enriched {} titles",
                    match lane {
                        nzbkit::index::Lane::Movies => "movie",
                        nzbkit::index::Lane::MusicBooks => "music and book",
                        nzbkit::index::Lane::Shows => "TV",
                    }
                );
            }
            for row in back {
                let kind = lane_kind(&row.kind);
                crate::wall::clear_unreachable();
                let date = crate::wall::lookup(api_key.as_deref(), &kind, &row.title, row.year)
                    .map(|m| m.air_date)
                    .unwrap_or_default();
                // Written even when empty: that records "asked, provider
                // had none" and keeps this lane from re-asking forever.
                // But only when it really was ASKED - air_tried=1 is just
                // as permanent as the enricher's checked stamp, so a
                // provider we could not reach must leave the row alone.
                if date.is_empty() && crate::wall::saw_unreachable() {
                    let fails = unreached.get(&row.key).map_or(0, |(n, _)| *n) + 1;
                    let next = backoff_after(fails);
                    info!(
                        target: "wall",
                        "{}: date backfill could not reach a provider, retrying \
                         in {} min",
                        row.key,
                        next.saturating_duration_since(std::time::Instant::now())
                            .as_secs()
                            .div_ceil(60)
                    );
                    unreached.insert(row.key.clone(), (fails, next));
                } else {
                    unreached.remove(&row.key);
                    let _ = d.with_index(|ix| ix.title_set_air_date(&row.key, &date).ok());
                }
            }
            continue;
        }
        let _busy = d.busy.hold("enriching");
        for row in batch {
            let kind = lane_kind(&row.kind);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|t| t.as_secs() as i64)
                .unwrap_or(0);
            // Provider chain (all keyless unless a TMDB key exists):
            //   TV    → TVmaze (+/cast, +externals.imdb) → AniList
            //   Movie → OMDb when the user's free key is set (exact
            //           data + cast + imdb id in one call), else
            //           Wikidata (art + date + genres + cast + imdb id)
            //           (+Wikipedia plot when the description is empty)
            //           → AniList
            // The imdb id joins the local IMDb ratings snapshot at wall
            // time, so ratings stay fresh without re-enrichment.
            use crate::wall::{self, Kind};
            // Tracks whether the Wikidata half of the chain has already
            // run, so the OMDb-poster fallback below doesn't ask twice.
            let mut hit_wikidata = false;
            // Start this row's "did anything fail to answer" window. See
            // wall::saw_unreachable - an empty result has to mean "the
            // provider has nothing", never "we could not reach it", or
            // the stamp below retires the row for good.
            wall::clear_unreachable();
            let mut meta = match (&api_key, &kind) {
                _ if kind == Kind::Other => None,
                // Music and books before the TMDB arm, not after: TMDB
                // is a film database, so a key being configured must not
                // divert an album into a movie search.
                (_, Kind::Music) | (_, Kind::Book) => wall::media_lookup(&kind, &row.title),
                (Some(k), _) => wall::tmdb_lookup(k, &kind, &row.title, row.year),
                // ONE request, not two: the embed form returns the show,
                // its cast (with character names, person ids and
                // headshots) and its crew together, so the old
                // lookup-then-/cast pair - and the 400 ms courtesy sleep
                // between them - is gone.
                (None, Kind::Tv) => wall::tvmaze_lookup_full(&row.title),
                (None, _) => {
                    let omdb = d.omdb_key.lock_ok().clone();
                    let (mut m, mut imdb) = match &omdb {
                        // OMDb (the user's free key) is exact and
                        // complete but does not always answer, so
                        // Wikidata resolves the imdb id alongside it -
                        // independent services, independent limits.
                        Some(k) => std::thread::scope(|s| {
                            let imdb = s.spawn(|| wall::wikidata_imdb(&row.title, row.year));
                            let m = wall::omdb_lookup(k, &row.title, row.year);
                            (m, imdb.join().unwrap_or(None))
                        }),
                        // Keyless: Wikidata IS the provider now, and it
                        // returns the imdb id itself - so unlike the
                        // iTunes path it replaced, no second lookup is
                        // needed to get one.
                        None => {
                            hit_wikidata = true;
                            let m = wall::wikidata_movie(&row.title, row.year);
                            let imdb = m.as_ref().map(|x| x.imdb.clone()).filter(|s| !s.is_empty());
                            (m, imdb)
                        }
                    };
                    // OMDb title-miss but Wikidata knows the film →
                    // exact OMDb lookup by tconst.
                    if m.is_none()
                        && let (Some(k), Some(t)) = (&omdb, &imdb)
                    {
                        m = wall::omdb_lookup_imdb(k, t);
                    }
                    // OMDb configured but no answer (daily cap, niche
                    // title) → the keyless chain still applies.
                    if m.is_none() && omdb.is_some() {
                        hit_wikidata = true;
                        m = wall::wikidata_movie(&row.title, row.year);
                        if imdb.is_none() {
                            imdb = m.as_ref().map(|x| x.imdb.clone()).filter(|s| !s.is_empty());
                        }
                    }
                    // OMDb hit without a poster → Wikidata art fills in.
                    if let Some(meta) = &mut m
                        && meta.poster_url.is_empty()
                        && omdb.is_some()
                        && !hit_wikidata
                        && let Some(w) = wall::wikidata_movie(&row.title, row.year)
                    {
                        meta.poster_url = w.poster_url;
                    }
                    // Wikipedia supplies both the plot AND the poster:
                    // a film article's infobox image is the poster, and
                    // it is the only free source for one (Wikidata
                    // cannot host non-free art - see parse_wikidata_film).
                    // Fetched once and used for whichever is missing.
                    let wiki = match &m {
                        Some(meta) if meta.overview.is_empty() || meta.poster_url.is_empty() => {
                            wall::wikipedia_page(&row.title, row.year)
                        }
                        Some(_) => None,
                        None => wall::wikipedia_page(&row.title, row.year),
                    };
                    match &mut m {
                        Some(meta) => {
                            if meta.imdb.is_empty() {
                                meta.imdb = imdb.unwrap_or_default();
                            }
                            if let Some(w) = wiki {
                                if meta.overview.is_empty() {
                                    meta.overview = w.extract;
                                }
                                if meta.poster_url.is_empty() {
                                    meta.poster_url = w.image;
                                }
                            }
                        }
                        None => {
                            // No provider hit - a Wikipedia-only card
                            // (poster + plot + IMDb rating) still beats
                            // a bare stem.
                            let w = wiki.unwrap_or_default();
                            if imdb.is_some() || !w.extract.is_empty() || !w.image.is_empty() {
                                m = Some(wall::TitleMeta {
                                    // A Wikipedia-only card: no provider
                                    // resolved an id, so there is no
                                    // namespace to record either.
                                    tmdb_id: 0,
                                    id_src: String::new(),
                                    overview: w.extract,
                                    rating: 0.0,
                                    genres: String::new(),
                                    poster_url: w.image,
                                    backdrop_url: String::new(),
                                    imdb: imdb.unwrap_or_default(),
                                    actors: String::new(),
                                    air_date: String::new(),
                                    credits: Vec::new(),
                                });
                            }
                        }
                    }
                    m
                }
            };
            // AniList is the last-chance fallback for video. It is an
            // anime database, so it is not consulted for an album or a
            // book - a fuzzy title match there would attach anime art to
            // a record, which is worse than leaving the card bare.
            if meta.is_none() && !matches!(kind, Kind::Other | Kind::Music | Kind::Book) {
                meta = wall::anilist_lookup(&row.title);
            }
            // Junk rows never touched a provider - stamp and move on;
            // sleeping 3.2 s per obfuscated stem was the old behavior
            // and made big walls take forever to settle.
            if kind == Kind::Other {
                let _ = d.with_index(|ix| ix.title_fill(&row.key, &Default::default(), now).ok());
                continue;
            }
            match meta {
                Some(m) => {
                    // A provider answered: whatever backoff this key
                    // accrued is over.
                    unreached.remove(&row.key);
                    let save = |url: &str, backdrop: bool| -> String {
                        let name = wall::art_name(&row.key, backdrop);
                        match wall::fetch_image(url) {
                            Some(bytes) if std::fs::write(art.join(&name), &bytes).is_ok() => name,
                            _ => String::new(),
                        }
                    };
                    let (poster, backdrop) = std::thread::scope(|s| {
                        let bd = s.spawn(|| save(&m.backdrop_url, true));
                        (save(&m.poster_url, false), bd.join().unwrap_or_default())
                    });
                    // Credits go in BEFORE the fill, because the fill is
                    // what stamps `checked` and that stamp is final: no
                    // lane ever offers a checked row again. The credits
                    // write used to run after it with its error dropped
                    // by .ok(), so a busy timeout behind a long retention
                    // prune left the card showing an actors string while
                    // the person pages, cast chips and cast-affinity
                    // graph permanently lacked the title, with nothing to
                    // retry it.
                    //
                    // Written only when the provider actually gave some:
                    // one that answered without a cast (OMDb, AniList)
                    // must not wipe what an earlier one supplied. Setting
                    // credits is idempotent, so re-running a pass that
                    // failed after this point simply writes them again.
                    let credits_ok = m.credits.is_empty()
                        || d.with_index(|ix| {
                            Some(ix.title_credits_set(&row.key, &m.credits).is_ok())
                        })
                        .unwrap_or(false);
                    if credits_ok {
                        let _ = d.with_index(|ix| {
                            ix.title_fill(
                                &row.key,
                                &nzbkit::index::TitleFill {
                                    tmdb_id: m.tmdb_id,
                                    // The id is unreadable without it -
                                    // see TitleFill::id_src.
                                    id_src: &m.id_src,
                                    overview: &m.overview,
                                    rating: m.rating,
                                    genres: &m.genres,
                                    poster: &poster,
                                    backdrop: &backdrop,
                                    imdb: &m.imdb,
                                    actors: &m.actors,
                                    air_date: &m.air_date,
                                },
                                now,
                            )
                            .ok()
                        });
                    } else {
                        info!(
                            target: "enrich",
                            "{}: could not write credits, leaving the title \
                             unstamped so a later pass retries it",
                            row.key
                        );
                    }
                }
                None => {
                    // Only stamp when the providers actually ANSWERED and
                    // had nothing. If any of them could not be reached -
                    // DNS, timeout, TLS, a 5xx, or retries exhausted -
                    // this row is unknown, not empty, and stamping it
                    // here would retire it permanently: title_fill sets
                    // checked=now and air_tried=1, and every lane query
                    // requires checked=0. A brief uplink blip used to
                    // blank every title the lane touched while it lasted.
                    if wall::saw_unreachable() {
                        // Remembered, so the retry waits out an
                        // exponential backoff instead of burning a
                        // batch slot (and this log line) every pass.
                        let fails = unreached.get(&row.key).map_or(0, |(n, _)| *n) + 1;
                        let next = backoff_after(fails);
                        info!(
                            target: "enrich",
                            "{}: no provider could be reached, leaving it for a \
                             later pass rather than recording an empty card \
                             (next try in {} min)",
                            row.key,
                            next.saturating_duration_since(std::time::Instant::now())
                                .as_secs()
                                .div_ceil(60)
                        );
                        unreached.insert(row.key.clone(), (fails, next));
                    } else {
                        // Providers answered and had nothing: the stamp
                        // below retires the row, so its backoff entry
                        // has nothing left to guard.
                        unreached.remove(&row.key);
                        let _ = d.with_index(|ix| {
                            ix.title_fill(&row.key, &Default::default(), now).ok()
                        });
                    }
                }
            }
        }
    }
}

/// How much disk the headshot cache may use. Person photos are ~15-40 KB
/// each, but a large index credits tens of thousands of people, and this
/// is the difference between a bounded cache and a NAS quietly filling up
/// with portraits. Least-recently-USED wins: the person pages someone
/// actually opens keep their art (the /art/ route touches the file on
/// each read), and the long tail is what goes.
#[cfg(feature = "indexer")]
pub(in crate::serve) const PERSON_ART_CAP_BYTES: u64 = 192 * 1024 * 1024;

/// Headshot lane: fetch person photos the enricher recorded URLs for, and
/// keep the cache under its cap.
///
/// Deliberately its own thread and not part of a metadata lane. These are
/// CDN image reads, not API calls, so they must not spend any provider's
/// rate-limit budget - and a photo arriving late costs nothing, whereas a
/// card without a poster is visible.
#[cfg(feature = "indexer")]
pub(in crate::serve) fn person_photo_fetcher(d: Arc<Daemon>, stop: crate::serve::RunStop) {
    let art = d.spool.join("art");
    let _ = std::fs::create_dir_all(&art);
    // Rows whose URL answered nothing this run. Kept in memory rather
    // than cleared in the db, because a transient CDN failure should be
    // retried next start, not treated as "this person has no photo".
    let mut failed: std::collections::HashSet<i64> = std::collections::HashSet::new();
    let mut after: i64 = 0;
    // Did this walk of the table actually fetch anything? A settled index
    // adds people rarely, so an idle walk backs off instead of re-asking
    // the same question every minute; a walk that found work resets to the
    // short interval, which is what makes a fresh enrichment show faces
    // within the minute rather than within the hour.
    let mut got_any = false;
    let mut idle_secs = 60u64;
    loop {
        if stop.stopping() {
            return;
        }
        // Before prune_person_art, which is a directory walk: an idle
        // walk of the art cache is exactly the disk work the switch
        // promises not to do.
        if d.park_if_off(60) {
            continue;
        }
        let batch = d
            .with_index(|ix| ix.people_photo_queue(after, 200).ok())
            .unwrap_or_default();
        if batch.is_empty() {
            // Walk done: prune, then start the cursor over so evicted
            // photos for people who are still credited come back.
            prune_person_art(&art, PERSON_ART_CAP_BYTES);
            after = 0;
            failed.clear();
            idle_secs = if got_any {
                60
            } else {
                (idle_secs * 2).min(900)
            };
            got_any = false;
            if !stop.sleep(std::time::Duration::from_secs(idle_secs)) {
                return;
            }
            continue;
        }
        after = batch.last().map(|(id, _)| *id).unwrap_or(after);
        let _busy = d.busy.hold("enriching");
        for (id, url) in batch {
            if failed.contains(&id) {
                continue;
            }
            let name = crate::wall::person_art_name(id);
            let path = art.join(&name);
            if path.is_file() {
                continue;
            }
            match crate::wall::fetch_image(&url) {
                Some(bytes) => {
                    let _ = std::fs::write(&path, &bytes);
                    got_any = true;
                }
                None => {
                    failed.insert(id);
                }
            }
            // A courtesy gap. Nothing here is urgent and a burst of image
            // requests at a provider's CDN is exactly the behaviour that
            // gets an anonymous client throttled.
            if !stop.sleep(std::time::Duration::from_millis(250)) {
                return;
            }
        }
        // Cheap to check mid-round, and it bounds the cache even when the
        // queue never empties.
        prune_person_art(&art, PERSON_ART_CAP_BYTES);
    }
}

/// Evict least-recently-used headshots until the cache fits `cap`.
///
/// Only `p<digits>.jpg` files are considered - posters and backdrops
/// share this directory and are NOT evictable (they are the wall, and
/// nothing re-fetches them on demand).
#[cfg(feature = "indexer")]
pub(in crate::serve) fn prune_person_art(dir: &std::path::Path, cap: u64) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<(std::time::SystemTime, u64, std::path::PathBuf)> = Vec::new();
    let mut total: u64 = 0;
    for e in rd.flatten() {
        let name = e.file_name();
        let Some(name) = name.to_str() else { continue };
        if !crate::wall::is_person_art_name(name) {
            continue;
        }
        let Ok(md) = e.metadata() else { continue };
        if !md.is_file() {
            continue;
        }
        total += md.len();
        // atime where the filesystem keeps it, mtime otherwise - the
        // point is "when was this last wanted", and a read-only serve
        // does not touch mtime.
        let when = md
            .accessed()
            .or_else(|_| md.modified())
            .unwrap_or(std::time::UNIX_EPOCH);
        files.push((when, md.len(), e.path()));
    }
    if total <= cap {
        return;
    }
    files.sort_by_key(|(when, _, _)| *when);
    let mut freed = 0u64;
    let mut n = 0;
    for (_, len, path) in &files {
        if total - freed <= cap {
            break;
        }
        if std::fs::remove_file(path).is_ok() {
            freed += len;
            n += 1;
        }
    }
    if n > 0 {
        info!(
            target: "wall",
            "headshot cache over {} MB - evicted {n} least-recently-used ({} MB)",
            cap / (1024 * 1024),
            freed / (1024 * 1024)
        );
    }
}

/// Nightly-ish IMDb ratings snapshot: keyless ~8 MB gz download from
/// datasets.imdbws.com, ingested wholesale into the index db. The wall
/// joins titles.imdb → imdb_ratings at query time, so every card with a
/// resolved tconst shows the real IMDb rating + vote count, offline.
#[cfg(feature = "indexer")]
pub(in crate::serve) fn imdb_ratings_refresher(d: Arc<Daemon>, stop: crate::serve::RunStop) {
    loop {
        if stop.stopping() {
            return;
        }
        // MUST come before the staleness read. With no database the
        // `kv_get` below answers None, which this loop reads as "never
        // fetched" - so an indexer that is switched off would pull the
        // whole ratings dataset every six hours, forever, for a wall
        // nobody can open.
        if d.park_if_off(600) {
            continue;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.as_secs() as i64)
            .unwrap_or(0);
        let stale = d
            .with_index(|ix| ix.kv_get("imdb_ratings_at"))
            .and_then(|s| s.parse::<i64>().ok())
            .is_none_or(|t| now - t > 20 * 3600);
        if stale {
            let _busy = d.busy.hold("enriching");
            match crate::wall::imdb_ratings_fetch() {
                Some(rows) => {
                    let n = rows.len();
                    let ok = d
                        .with_index_mut(|ix| {
                            ix.imdb_ratings_replace(rows.into_iter()).ok()?;
                            ix.kv_set("imdb_ratings_at", &now.to_string()).ok()
                        })
                        .is_some();
                    info!(
                        target: "wall",
                        "IMDb ratings snapshot: {n} titles {}",
                        if ok { "ingested" } else { "FAILED to store" }
                    );
                }
                None => info!(target: "wall", "IMDb ratings snapshot download failed - will retry"),
            }
        }
        if !stop.sleep(std::time::Duration::from_secs(6 * 3600)) {
            return;
        }
    }
}

/// The pre feed: two tasks, both inert unless the user has switched
/// it on.
///
/// Task 1 holds the IRC connection and does nothing but listen and
/// buffer. Task 2 owns every database write, so the listener never
/// takes the index write lock in the middle of a burst and cannot be
/// stalled by a scan pass holding it.
#[cfg(feature = "indexer")]
pub(in crate::serve) fn spawn_predb_feed(daemon: &Arc<Daemon>) {
    {
        let daemon2 = daemon.clone();
        tokio::spawn(async move {
            // Ordinary failures - a dropped socket, a netsplit, DNS -
            // retry promptly and back off to half an hour.
            const RETRY_MIN: u64 = 30;
            const RETRY_MAX: u64 = 1_800;
            // Being told to go away is different in kind. A network that
            // has K-lined us will not change its mind in thirty seconds,
            // and a client that keeps asking is the reason bans get
            // widened. Hours, up to most of a day.
            const REJECT_MIN: u64 = 3_600;
            const REJECT_MAX: u64 = 21_600;
            // A connection that lasted this long counts as having
            // worked, so the next failure starts the ladder over.
            const SETTLED: u64 = 300;
            let mut retry = RETRY_MIN;
            let mut reject = REJECT_MIN;
            loop {
                if !daemon2.predb_feed_on() {
                    tokio::time::sleep(std::time::Duration::from_secs(15)).await;
                    continue;
                }
                let cfg = daemon2.predb_irc_config();
                if cfg.channels.is_empty() {
                    daemon2.predb_say("no channels configured");
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    continue;
                }
                daemon2.predb_say(&format!("connecting to {}", cfg.host));
                let started = Instant::now();
                let heard = daemon2.clone();
                let quit = daemon2.clone();
                let stop = move || !quit.predb_feed_on();
                let reason = nzbkit::predb::run_once(
                    &cfg,
                    |m| {
                        let Some(line) = nzbkit::predb::parse_line(m.text) else {
                            return;
                        };
                        let mut pend = heard.predb_pending.lock_ok();
                        // Bounded. If the writer is wedged - a scan
                        // holding the lock through a long pass - the
                        // right failure is to lose the newest lines
                        // rather than to grow without limit inside a
                        // daemon whose memory budget is somebody's NAS.
                        if pend.len() < 20_000 {
                            pend.push(line);
                        }
                    },
                    &stop,
                )
                .await;
                let lasted = started.elapsed().as_secs();
                if lasted >= SETTLED {
                    retry = RETRY_MIN;
                    reject = REJECT_MIN;
                }
                let wait = match reason {
                    nzbkit::predb::IrcStop::Cancelled => {
                        daemon2.predb_say("stopped");
                        continue;
                    }
                    nzbkit::predb::IrcStop::Rejected(why) => {
                        // Said out loud in the log as well as the UI:
                        // this is the state where the honest advice is
                        // "leave it off", and a silent hourly retry
                        // would never say so.
                        warn!(
                            target: "predb",
                            "{} turned us away ({why}) - not trying again for {} minutes",
                            cfg.host,
                            reject / 60
                        );
                        daemon2.predb_say(&format!("refused by the server: {why}"));
                        let w = reject;
                        reject = (reject * 2).min(REJECT_MAX);
                        w
                    }
                    nzbkit::predb::IrcStop::Transient(why) => {
                        daemon2.predb_say(&format!("disconnected: {why}"));
                        let w = retry;
                        retry = (retry * 2).min(RETRY_MAX);
                        w
                    }
                };
                // Slept in slices so switching the feature off (or on
                // again) is felt in seconds rather than at the end of a
                // six-hour ban timer.
                for _ in 0..wait {
                    if !daemon2.predb_feed_on() {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        });
    }
    {
        // Task 2: the only writer. Drains what the listener heard, then
        // matches it against the index - both directions - and keeps the
        // feed's own table capped.
        let daemon2 = daemon.clone();
        tokio::spawn(async move {
            // 90 days of pre lines, capped at whatever `predb_max_rows`
            // says (a quarter of a million by default). A pre line's
            // value decays with the post's retention, and at ~64 bytes
            // of keys per row the default is single-digit MB. The cap is
            // read per tick, not captured: raising it should take effect
            // without a restart, and the seed importer reads the SAME
            // number so it can refuse rather than import into a prune.
            const KEEP_SECS: i64 = 90 * 86_400;
            // Per tick. Small on purpose: this runs beside a scanner and
            // a download, and there is no deadline on naming a post.
            const SWEEP_BUDGET: u32 = 200;
            const BACKLOG_BUDGET: u32 = 200;
            // The split-merge and sidecar-fold walks hold the
            // shared index write mutex for their whole call, and the
            // pause predicate is only consulted BETWEEN legs - so the
            // per-call time budget is what keeps any single leg from
            // parking ingest, the API and a starting download behind
            // it for tens of seconds (observed live, 5 Aug).
            const WALK_BUDGET: std::time::Duration = std::time::Duration::from_secs(1);
            let mut last_prune = 0i64;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(20)).await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|t| t.as_secs() as i64)
                    .unwrap_or(0);
                // Drain first and unconditionally: lines already heard
                // are cheap to store and losing them to a pause would
                // mean losing the announcement entirely. The MATCHING
                // below is what respects the pause.
                let batch: Vec<nzbkit::predb::PreLine> =
                    std::mem::take(&mut *daemon2.predb_pending.lock_ok());
                if !batch.is_empty() {
                    let _busy = daemon2.busy.hold("predb");
                    let n = batch.len();
                    // retiring_ddl: the first-ever feed batch builds the
                    // named-count index, and the pooled readers must not
                    // keep statements prepared against the old schema.
                    let stored =
                        daemon2.with_index_mut_retiring_ddl(|ix| ix.predb_store(&batch, now).ok());
                    match stored {
                        Some(nameable) => {
                            info!(
                                target: "predb",
                                "{n} pre line(s) stored, {nameable} carrying a posted filename"
                            );
                            daemon2.predb_say(&format!("listening - {n} line(s) just in"));
                        }
                        None => {
                            // The index was unavailable (switched off, or
                            // locked). Put them back rather than drop
                            // them; the cap above is what bounds this.
                            let mut pend = daemon2.predb_pending.lock_ok();
                            let keep = 20_000usize.saturating_sub(pend.len());
                            let mut back = batch;
                            back.truncate(keep);
                            back.append(&mut pend);
                            *pend = back;
                        }
                    }
                }
                if !daemon2.predb_enabled.load(Ordering::Relaxed) {
                    continue;
                }
                // Matching is index work: it stands down for a download
                // exactly like every other index maintenance leg.
                if daemon2.indexing_pause_reason().is_some() {
                    continue;
                }
                // §74 hook B: a release that gains a name here was an
                // obfuscated stem no watchlist entry could ever match, so
                // naming it IS an arrival. Installed once for the whole
                // tick and drained at the end of it - every naming leg
                // below funnels through the same seam inside the index.
                // Covers the correlation sweeps below to the end of the
                // tick; the 20 s sleep sits at the loop top, so the
                // chip can never span the idle wait.
                let _busy = daemon2.busy.hold("predb");
                let matcher = daemon2.instant_matcher();
                daemon2.with_index_mut(|ix| {
                    install_instant_watch(ix, matcher);
                    Some(())
                });
                if let Some((tried, named)) =
                    daemon2.with_index_mut(|ix| ix.predb_sweep(SWEEP_BUDGET, now).ok())
                    && named > 0
                {
                    info!(target: "predb", "{named} indexed release(s) named from {tried} pre line(s)");
                }
                if daemon2.indexing_pause_reason().is_some() {
                    continue;
                }
                if let Some((_, named)) = daemon2
                    .with_index_mut(|ix| ix.predb_backlog(BACKLOG_BUDGET, KEEP_SECS, now).ok())
                    && named > 0
                {
                    info!(target: "predb", "{named} older release(s) named from the feed");
                }
                // One-time hygiene: fold pre-fix split-container
                // fragments back into whole releases. Independent of
                // the predb switches (fragmentation hurts everything),
                // parks permanently once the walk completes, and its
                // completion re-opens the correlation walks via the
                // seed generation.
                if daemon2.indexing_pause_reason().is_none()
                    && let Some((g, n, done)) = daemon2.with_index_mut(|ix| {
                        // An error here must be SAID: a silent Err loops
                        // forever looking exactly like "nothing to do".
                        match ix.split_merge(now, WALK_BUDGET) {
                            Ok(t) => Some(t),
                            Err(e) => {
                                warn!(target: "index", "split-set merge error: {e}");
                                None
                            }
                        }
                    })
                {
                    if g > 0 {
                        info!(
                            target: "index",
                            "split-set merge: {n} fragment(s) folded into {g} release(s)"
                        );
                    }
                    if done && g + n > 0 {
                        info!(target: "index", "split-set merge complete - correlation will re-walk");
                    }
                }
                // §87 the par2-sidecar fold: a split posting's recovery
                // set lands as its own par2-only row on the bare base
                // stem (88% of split-container rows have one). Folding
                // it in kills the junk row and gives the container a
                // true has_par2, closing the hidden-par2 scoring leak.
                // Not one-time: ingest keeps producing pairs, so the
                // walk parks at the top id and follows it.
                if daemon2.indexing_pause_reason().is_none()
                    && let Some((p, f)) = daemon2.with_index_mut(|ix| {
                        // Same rule as above: an error must be SAID.
                        match ix.par2_sidecar_fold(WALK_BUDGET) {
                            Ok((p, f, _)) => Some((p, f)),
                            Err(e) => {
                                warn!(target: "index", "par2 sidecar fold error: {e}");
                                None
                            }
                        }
                    })
                    && p > 0
                {
                    info!(
                        target: "index",
                        "par2 sidecar fold: {p} sidecar row(s) folded in ({f} par2 file(s))"
                    );
                }
                // Phase 2: the correlation legs, behind their own
                // switch. Same stand-down discipline as the exact legs;
                // budgets smaller because each row costs a window query.
                if daemon2.predb_corr_enabled.load(Ordering::Relaxed) {
                    const CORR_SWEEP_BUDGET: u32 = 100;
                    // Sized against the population, not caution: the
                    // obfuscated backlog measured 27.5M rows on the
                    // first live run, and 50/tick walks that in months.
                    // 400 evals cost well under a second inside the
                    // tick and still stand down for any download.
                    const CORR_BACKLOG_BUDGET: u32 = 400;
                    // How far back the corr backlog bothers: generous
                    // enough to cover a full seed import window.
                    const CORR_WINDOW: i64 = 366 * 86_400;
                    let auto = daemon2.predb_corr_auto.load(Ordering::Relaxed);
                    if daemon2.indexing_pause_reason().is_none()
                        && let Some((_, s, a)) = daemon2.with_index_mut(|ix| {
                            ix.predb_corr_sweep(CORR_SWEEP_BUDGET, auto, now).ok()
                        })
                        && s + a > 0
                    {
                        info!(target: "predb", "correlation (live): {s} suggestion(s), {a} auto-applied");
                    }
                    if daemon2.indexing_pause_reason().is_none()
                        && let Some((_, s, a)) = daemon2.with_index_mut(|ix| {
                            ix.predb_corr_backlog(CORR_BACKLOG_BUDGET, CORR_WINDOW, auto, now)
                                .ok()
                        })
                        && s + a > 0
                    {
                        info!(
                            target: "predb",
                            "correlation (backlog): {s} suggestion(s), {a} auto-applied"
                        );
                    }
                    // The catch-up pass: one walk over every sized pre
                    // (seeds included) per seed generation. This is the
                    // leg that actually covers a fresh import - see the
                    // population arithmetic on predb_corr_catchup.
                    const CORR_CATCHUP_BUDGET: u32 = 150;
                    if daemon2.indexing_pause_reason().is_none()
                        && let Some((n, s, a)) = daemon2.with_index_mut(|ix| {
                            ix.predb_corr_catchup(CORR_CATCHUP_BUDGET, auto, now).ok()
                        })
                        && n > 0
                        && s + a > 0
                    {
                        info!(
                            target: "predb",
                            "correlation (catch-up): {s} suggestion(s), {a} auto-applied"
                        );
                    }
                }
                if now - last_prune >= 3_600 && daemon2.index_maintenance_ok() {
                    last_prune = now;
                    let keep_rows = daemon2.predb_max_rows.load(Ordering::Relaxed);
                    // `.ok()` used to fold the error into the same None
                    // the "no index" case returns, and `last_prune` was
                    // advanced before the call - so a failure was both
                    // silent and lost for a full hour. That matters more
                    // since the prune became ONE transaction: a `?`
                    // anywhere inside rolls the whole thing back, where
                    // the old autocommitting version at least kept what
                    // its first statement had done. SQLITE_BUSY from the
                    // maintenance/VACUUM machinery is the ordinary way
                    // in, and the feed then grows past both its row cap
                    // and its retention window with nothing said.
                    match daemon2.with_index(|ix| Some(ix.predb_prune(keep_rows, KEEP_SECS, now))) {
                        Some(Ok(n)) if n > 0 => {
                            info!(
                                target: "predb",
                                "pruned {n} pre line(s) past the retention window"
                            );
                        }
                        Some(Err(e)) => {
                            // Retry sooner than the hour, but not on the
                            // next 20 s tick: whatever the prune was
                            // contending with deserves room to finish.
                            last_prune = now.saturating_sub(3_000);
                            warn!(
                                target: "predb",
                                "prune failed and rolled back, retrying in ~10 min: {e}"
                            );
                        }
                        _ => {}
                    }
                }
                // §74 hook B, the other half: whatever the naming legs
                // rescued this tick, offered to the watchlist. A named
                // release is nearly always an old post that is long
                // complete, so most of these go straight to a pass.
                if let Some((hits, dropped)) =
                    daemon2.with_index_mut(|ix| Some(ix.take_watch_hits()))
                {
                    instant_arrivals(&daemon2, hits, dropped, now);
                }
            }
        });
    }
}

#[cfg(all(test, feature = "indexer"))]
mod eligibility_tests {
    use super::{eligible, eligible_batch};
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    /// A backoff map holding `keys`, none of them due for a long while.
    fn backing_off(keys: &[&str]) -> HashMap<String, (u32, Instant)> {
        let next = Instant::now() + Duration::from_secs(3_600);
        keys.iter().map(|k| ((*k).to_string(), (1, next))).collect()
    }

    /// Codex sweep 7, M2: a run of skipped rows at the HEAD of a lane's
    /// priority order must not starve the eligible rows behind them.
    ///
    /// The queues this draws from are head-stable - the order is fixed
    /// and a row only leaves the set when a provider answers about it -
    /// so a batch fetched at exactly the batch size and filtered
    /// afterwards is not merely thinner, it is empty on every pass
    /// forever. Permanently unanswerable heads are ordinary: TVmaze
    /// 404s a show it has dropped, and returns another show's payload
    /// for a merged id, and both are `None` for good.
    #[test]
    fn a_blocked_head_does_not_starve_the_queue_behind_it() {
        // Six unanswerable rows at the head of a queue of thirty.
        let queue: Vec<String> = (0..30).map(|i| format!("t:show {i:02}")).collect();
        let unreached = backing_off(&[
            "t:show 00",
            "t:show 01",
            "t:show 02",
            "t:show 03",
            "t:show 04",
            "t:show 05",
        ]);
        let mut asked = 0u32;
        let got = eligible_batch(
            6,
            &unreached,
            Instant::now(),
            |r: &String| r.as_str(),
            |n| {
                asked = n;
                queue.iter().take(n as usize).cloned().collect()
            },
        );
        assert_eq!(asked, 12, "the fetch was not over-fetched past the backoff");
        assert_eq!(
            got,
            [
                "t:show 06",
                "t:show 07",
                "t:show 08",
                "t:show 09",
                "t:show 10",
                "t:show 11"
            ],
            "the lane worked nothing at all behind its blocked head"
        );
    }

    /// The over-fetch is bounded, and an empty backoff map costs
    /// nothing: the ordinary pass asks for exactly what it wants.
    #[test]
    fn the_over_fetch_is_bounded_and_free_when_nothing_is_backing_off() {
        let mut asked = 0u32;
        let _: Vec<String> = eligible_batch(
            6,
            &HashMap::new(),
            Instant::now(),
            |r: &String| r.as_str(),
            |n| {
                asked = n;
                Vec::new()
            },
        );
        assert_eq!(asked, 6);

        let many: Vec<&str> = Vec::new();
        let mut unreached = backing_off(&many);
        let next = Instant::now() + Duration::from_secs(3_600);
        for i in 0..500 {
            unreached.insert(format!("k{i}"), (1, next));
        }
        let _: Vec<String> = eligible_batch(
            6,
            &unreached,
            Instant::now(),
            |r: &String| r.as_str(),
            |n| {
                asked = n;
                Vec::new()
            },
        );
        assert_eq!(asked, 6 + super::OVER_FETCH_CAP as u32);
    }

    /// A backoff whose wait has EXPIRED is not a skip - that is what
    /// lets a title retried after an outage back into the queue.
    #[test]
    fn an_expired_backoff_is_eligible_again() {
        let mut unreached = backing_off(&["t:a"]);
        unreached.insert("t:b".into(), (3, Instant::now() - Duration::from_secs(60)));
        let rows = vec!["t:a".to_string(), "t:b".to_string(), "t:c".to_string()];
        let got = eligible(rows, &unreached, Instant::now(), |r: &String| r.as_str(), 9);
        assert_eq!(got, ["t:b", "t:c"]);
    }
}
