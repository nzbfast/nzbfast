//! The newznab facade's XML: caps, search, tvsearch and movie, enough
//! of the protocol for Sonarr/Radarr to use the built-in index as an
//! indexer.
//!
//! Split out of `sabcompat.rs` for the size gate (TODO 106) - the
//! parent was at its 3,000-line ceiling. Same module, its own file;
//! `use super::*;` carries every helper it reads (esc_xml, kind_for_cat,
//! newznab_category, newznab_error, httpdate) exactly as before.

use super::*;

/// M12: the newznab facade - enough of the protocol for Sonarr/Radarr
/// to use the built-in index as an indexer (caps, search, tvsearch,
/// movie; results link to /getnzb/<id>).
#[cfg(feature = "indexer")]
pub(in crate::serve) fn newznab_xml(
    d: &Daemon,
    params: &std::collections::HashMap<String, String>,
    base: &str,
    apikey: &str,
) -> String {
    let t = params.get("t").map(String::as_str).unwrap_or("");
    // Canonicalize the accepted spellings BEFORE anything reads `t`.
    // Dispatch took `t=tv-search` and `t=moviesearch`, but the
    // no-cat kind fallback below matched only the canonical names, so
    // the alias forms lost their implicit TV/movie filter and a movie
    // search could come back holding TV (Codex sweep 5 Aug M11).
    let t = match t {
        "tv-search" => "tvsearch",
        "moviesearch" => "movie",
        other => other,
    };
    // The facade IS the index, published over newznab, so the master
    // switch closes it too - otherwise an *arr keeps a healthy indexer
    // entry pointed at something that can only ever answer zero results.
    // Code 101 is the spec's "account suspended", the nearest thing it
    // has to "this indexer is switched off"; Sonarr and Radarr surface
    // the description verbatim, so the description is the real message.
    // caps is refused as well, on purpose: it is what an *arr tests with,
    // so the failure shows up when someone adds us, not weeks later on a
    // search that quietly returns nothing.
    if d.indexer_off() {
        return newznab_error(
            101,
            "nzbfast's built-in indexer is switched off (Settings → Indexing)",
        );
    }
    // `supportedParams` is a PROMISE, and the *arrs read it once and
    // cache it: a param listed here is one a client will send and expect
    // filtered results from, and a param missing is one it will not send
    // at all. So this list must be exactly the set the search path below
    // honours - advertising more is how AIOStreams came to report
    // "ID search: none (series)" while tvsearch quietly ignored the
    // tvdbid it was handed (TODO 187).
    //
    // `tvdbid` is the one entry that depends on DATA rather than on
    // code, and that is the whole ordering story of TODO 187. Sonarr
    // switches to tvdbid the moment caps offers it, so promising it
    // against a column the enrichment backfill has not filled yet would
    // answer every series search with nothing - which Sonarr reads as
    // "this indexer has nothing", strictly worse than the name search it
    // would otherwise have done. One id present means the lane has run
    // and the promise is real. The search path honours the parameter
    // either way, so this can only ever promise LESS than we deliver,
    // never more. `rid` (TVRage, long dead) stays absent for good.
    if t == "caps" {
        // A read we could not make is not a promise we can keep, so
        // anything but a plain yes leaves the parameter out.
        // ...and "the lane has run" means DRAINED, not started. The
        // backfill fills six rows per idle pass, so the first id to land
        // used to flip the promise on for the whole catalogue while
        // almost none of it was resolvable - Sonarr switches to tvdbid
        // the moment caps offers it, and every series the lane had not
        // reached yet then answered empty (Codex sweep 7, M1). One
        // unfilled row is enough to keep the promise back; the search
        // path honours the parameter regardless, so this can only ever
        // promise less than we deliver.
        let tvdb = match d.index_read_checked(|ix| {
            Some(ix.has_tvdb_ids().ok()? && !ix.tvdb_backfill_pending().ok()?)
        }) {
            Ok(Some(true)) => "tvdbid,",
            _ => "",
        };
        return format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<caps>
  <server title="nzbfast" version="1.0"/>
  <limits max="200" default="100"/>
  <searching>
    <search available="yes" supportedParams="q,cat"/>
    <tv-search available="yes" supportedParams="q,imdbid,{tvdb}tvmazeid,season,ep,cat"/>
    <movie-search available="yes" supportedParams="q,imdbid,tmdbid,cat"/>
  </searching>
  <categories>
    <category id="2000" name="Movies"/>
    <category id="4000" name="PC"/>
    <category id="5000" name="TV"/>
    <category id="8000" name="Other"/>
  </categories>
</caps>"#
        );
    }
    // Function dispatch. Everything that searches shares one path; the
    // categories we carry no rows for get the spec's own "not available"
    // rather than falling through, which used to answer a Lidarr audio
    // search with the whole index. Errors ride HTTP 200 + an <error>
    // body, which is the newznab convention (only bad credentials, which
    // the caller handles, answer with a status code).
    match t {
        "" | "search" | "tvsearch" | "movie" => {}
        "music" | "audio" | "book" | "bookssearch" | "booksearch" => {
            return newznab_error(203, "Function not available");
        }
        _ => return newznab_error(202, "No such function"),
    }
    let mut q = params.get("q").cloned().unwrap_or_default();
    // Season/episode narrowing. A *season-pack* search sends `season=`
    // with NO `ep=`, and dropping the season there answered with every
    // release of the series - so the season alone still narrows the
    // query. Two shapes deliberately do not: a season that is really a
    // year (daily series are filed by airdate, never SxxEyy) and an `ep`
    // that will not parse as a number (the `ep=07/28` daily form). Both
    // keep today's plain-title search, which Sonarr then date-filters,
    // instead of an `s2026` that can never match anything.
    let season = params.get("season").and_then(|v| v.parse::<u32>().ok());
    let ep = params.get("ep").and_then(|v| v.parse::<u32>().ok());
    let ep_given = params.get("ep").is_some_and(|v| !v.trim().is_empty());
    match (season, ep) {
        (Some(se), Some(ep)) if se < 100 => q = format!("{q} s{se:02}e{ep:02}").trim().to_string(),
        (Some(se), None) if se < 100 && !ep_given => q = format!("{q} s{se:02}").trim().to_string(),
        _ => {}
    }
    let limit: u32 = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(100)
        .min(200);
    let offset: u32 = params
        .get("offset")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    // cat= is a comma list of Newznab category ids (2xxx Movies, 4xxx
    // PC/software, 5xxx TV, 8xxx Other). When every requested id maps to
    // one kind, filter in SQL; mixed/absent = no kind filter.
    // Sonarr/Radarr only ever ask within their own top-level category.
    let cats: Vec<u32> = params
        .get("cat")
        .map(String::as_str)
        .unwrap_or("")
        .split(',')
        .filter_map(|c| c.trim().parse::<u32>().ok())
        .collect();
    let kinds: Vec<&str> = cats.iter().filter_map(|c| kind_for_cat(*c)).collect();
    let kind = match kinds.as_slice() {
        [first, rest @ ..] if rest.iter().all(|k| k == first) => Some(first.to_string()),
        // No usable `cat`, so let the OPERATION speak. `t=movie` and
        // `t=tvsearch` are each already a statement about which half of
        // the index is being asked for, and an id-only query - Radarr's
        // primary lookup - routinely carries no cat at all. Without
        // this, such a query was answered with no kind filter whatever,
        // so a movie search could come back holding TV.
        _ => match t {
            "movie" => Some("movie".to_string()),
            "tvsearch" => Some("tv".to_string()),
            _ => None,
        },
    };
    // Every requested id names a category we do not carry (audio, books,
    // console, xxx): the honest answer is an empty feed. Falling through
    // to an unfiltered query would answer a Lidarr audio search with our
    // whole index.
    let unavailable = !cats.is_empty() && kinds.is_empty();
    // `maxage` is the age ceiling in days, and the *arrs lean on it for
    // RSS sync. It filters on the same upload date the items report, so
    // a row can never be returned by a query that its own pubDate would
    // then fail.
    let newer_than = params
        .get("maxage")
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|d| *d > 0)
        // Saturating on BOTH operations: the value is client-supplied and
        // unclamped, so `maxage=999999999999999` wrapped the product
        // large-negative and turned `newer_than` into a far-future cutoff
        // - a silently EMPTY feed where an unfiltered one was owed - and
        // the subtraction then overflowed independently. Saturated, a
        // huge age lands at i64::MIN, which browse() reads as "no age
        // filter", the same answer the maxage=99999 test already pins.
        // Normal values take the identical path they always did. Same
        // treatment as the neighbouring spot handler.
        .map(|days| (epoch_secs() as i64).saturating_sub(days.saturating_mul(86_400)))
        .unwrap_or(0);
    // An id-based search (Radarr's primary lookup) resolves through the
    // enriched titles table to the parse-key its releases carry. An id
    // we hold nothing for answers EMPTY: the old code ignored the param
    // entirely, so an id-only query - which has no q, no season and
    // often no cat - returned the whole index newest-first for the *arr
    // to title-match against.
    let mut id_missing = false;
    // index_read_checked, not with_index_read, on BOTH index reads below.
    // An *arr acts on this answer: an empty feed is "this indexer has
    // nothing", which Sonarr and Radarr accept as a fact about the world
    // and do not re-ask. A read that FAILED - a saturated pool, or a
    // query whose statements went stale under a schema change and were
    // still stale after nzbkit re-prepared them - is not that fact, and
    // rendering it as one is how a working index comes to be reported as
    // an empty one. An <error> element is retryable at the client; a
    // total="0" is not.
    let mut unready = None;
    // Which ids THIS function can actually resolve, and - just as
    // important - which it cannot. `imdbid` reaches both halves of the
    // index because an IMDb id is unique across them; the other two are
    // namespaced, and `titles.tmdb_id` holds a TMDB movie id on a movie
    // row and a TVmaze show id on a TV row, so each resolver names the
    // kind it means (see `title_key_for_tvmaze`).
    let honoured: &[&str] = match t {
        "movie" => &["imdbid", "tmdbid"],
        "tvsearch" => &["imdbid", "tvdbid", "tvmazeid"],
        _ => &["imdbid", "tmdbid", "tvdbid", "tvmazeid"],
    };
    // Every id parameter the protocol has a spelling for. One we cannot
    // honour is REFUSED, never ignored: an ignored id turns "find me
    // this series" into "give me everything", and a client reads that
    // dump as matches. Measured on 1.1.5 (TODO 187): `tvdbid=121361`
    // and `tvdbid=999999999` answered with the same 100 rows - every
    // series' first episode, presented to Sonarr as one series'. 201 is
    // the spec's "Incorrect parameter"; the description names the
    // parameter, which is the part Sonarr and Prowlarr surface.
    //
    // An id we CAN resolve but hold no row for is a different answer: an
    // empty feed, from `id_missing` below. That distinction is the point
    // - "we do not speak this id" is permanent and belongs in an error,
    // "we have nothing filed under it" is a fact about the catalogue.
    //
    // Nothing well-behaved trips this: the *arrs send only what `t=caps`
    // advertises, and caps advertises exactly `honoured`. What trips it
    // is a client that guessed - which is precisely the case that used
    // to be answered with a dump.
    const ID_PARAMS: [&str; 8] = [
        "imdbid", "tmdbid", "tvdbid", "tvmazeid", "rid", "tvrageid", "traktid", "doubanid",
    ];
    if let Some(bad) = ID_PARAMS.iter().find(|p| {
        // Blank is not "sent": a client that fills its template with an
        // id it does not have leaves the value empty, and that has to
        // stay an ordinary search.
        !honoured.contains(*p) && params.get(**p).is_some_and(|v| !v.trim().is_empty())
    }) {
        return newznab_error(
            201,
            &format!(
                "{bad} is not a search parameter nzbfast can honour here - use {} or q",
                honoured.join("/")
            ),
        );
    }
    // The SET of keys the id names, not one of them. Two title keys can
    // genuinely carry one external id - a show posted under two
    // spellings, or a film keyed with and without its year - and
    // resolving to an arbitrary single key answered with one arbitrary
    // half of the title's releases (Codex sweep 7, M4). The first id
    // parameter that actually RESOLVES wins, exactly as before: a sent
    // id we hold nothing for still lets a later one be tried.
    let mut title_keys: Vec<String> = Vec::new();
    for p in honoured {
        let Some(raw) = params
            .get(*p)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
        else {
            continue;
        };
        let found = match d.index_read_checked(|ix| match *p {
            "imdbid" => ix.title_key_for_imdb(&raw).ok(),
            "tvdbid" => ix.title_key_for_tvdb(raw.parse().unwrap_or(0)).ok(),
            "tvmazeid" => ix.title_key_for_tvmaze(raw.parse().unwrap_or(0)).ok(),
            _ => ix.title_key_for_tmdb(raw.parse().unwrap_or(0)).ok(),
        }) {
            Ok(found) => found.unwrap_or_default(),
            Err(why) => {
                unready = Some(why);
                Vec::new()
            }
        };
        id_missing = found.is_empty();
        if !found.is_empty() {
            title_keys = found;
            break;
        }
    }
    // An id we could not LOOK UP is not an id we hold nothing for, so
    // this has to be answered before `id_missing` is allowed to mean
    // "empty feed".
    if let Some(why) = unready {
        return newznab_error(900, why.message());
    }
    // Honest SQL pagination + complete-only in the query itself - the
    // old path pulled limit+offset rows and filtered/paged in memory,
    // so deep pages silently thinned out.
    let bq = nzbkit::index::BrowseQuery {
        q,
        kind,
        complete_only: true,
        newer_than,
        title_keys,
        limit,
        offset,
        ..Default::default()
    };
    // An unresolved id no longer throws away a query the client sent
    // alongside it (Codex sweep 7, M1). The id search is a NARROWING of
    // the request, and our coverage of the id namespace is not the
    // client's problem: `tvdbid` is filled six rows at a time by an idle
    // backfill lane, so a series we hold releases for is routinely one
    // the id column has not reached yet - and answering "nothing" to a
    // request that also said `q=Some Show` is a coverage gap reported as
    // a fact about the catalogue. Dropping the key set still leaves q,
    // the kind and any season/ep narrowing in force, so nothing
    // unfiltered can escape.
    //
    // Deliberately the RAW `q` parameter rather than `bq.q`: a bare
    // `season=`/`ep=` has already been folded into the latter, and an id
    // plus an episode number with no query is exactly the shape TODO
    // 187's regression guard pins at zero. No query typed, no fallback.
    let q_given = params.get("q").is_some_and(|v| !v.trim().is_empty());
    let (hits, total) = if unavailable || (id_missing && !q_given) {
        (Vec::new(), 0)
    } else {
        match d.index_read_checked(|ix| ix.browse(&bq).ok()) {
            Ok(found) => found.unwrap_or_default(),
            // 900 is the spec's "unknown error", the only generic it
            // has. What matters to the client is that this is an
            // <error> at all: the description is what Sonarr and Radarr
            // surface verbatim, so it carries the cause.
            Err(why) => return newznab_error(900, why.message()),
        }
    };
    // §131 D3 search-miss log. The *arr surface is where the misses
    // that matter most show up - Sonarr asks the same question every
    // RSS sync, so a query it never gets an answer to is a coverage
    // hole with a date on it. First page only (a deep page is the same
    // search), and only when a query was actually typed: an id lookup
    // that resolved to no title_key is an ENRICHMENT gap, not a
    // catalogue one, and belongs in a different readout. `unavailable`
    // is excluded outright: a Lidarr audio search we answer empty by
    // POLICY is not a hole anyone should backfill.
    if offset == 0 && !unavailable && !bq.q.trim().is_empty() {
        d.note_search(
            "newznab",
            &bq.q,
            bq.kind.as_deref().unwrap_or(""),
            total as usize,
        );
    }
    let mut items = String::new();
    for r in hits.iter() {
        let link = format!(
            "{base}/getnzb/{}.nzb?apikey={}",
            r.id,
            super::http::query_escape(apikey)
        );
        // The name a *arr client parses, which for a release the pre
        // feed rescued is the real title rather than the random stem it
        // was posted under. Sonarr and Radarr match on this string and
        // nothing else, so an obfuscated stem here is a release they can
        // never accept.
        let name = r.display_name();
        let cat = newznab_category(&r.kind, name);
        // pubDate is the UPLOAD date, not when we happened to index it.
        // Sonarr and Radarr derive a release's age from it and reject on
        // that age twice over (retention, and the minimum-age hold that
        // lets a bad post get replaced before they grab it) - answering
        // with first_seen advertises every backfilled release as posted
        // today, so the minimum-age hold never fires. first_posted 0 is
        // the live sentinel for "the OVER Date did not parse"; emitting
        // it bare would date those rows to 1970, which reads as
        // infinitely old and is rejected wholesale, so they keep
        // first_seen.
        let posted = if r.first_posted > 0 {
            r.first_posted
        } else {
            r.first_seen
        };
        // The extended attrs cost one row each and are what the *arrs
        // and Prowlarr show without re-fetching the NZB. `usenetdate`
        // repeats pubDate deliberately: clients that treat pubDate as
        // the indexing date read age off this one instead.
        let mut extra = String::new();
        if r.files > 0 {
            extra.push_str(&format!(
                "      <newznab:attr name=\"files\" value=\"{}\"/>\n",
                r.files
            ));
        }
        if !r.grp.is_empty() {
            extra.push_str(&format!(
                "      <newznab:attr name=\"group\" value=\"{}\"/>\n",
                esc_xml(&r.grp)
            ));
        }
        if !r.poster.is_empty() {
            extra.push_str(&format!(
                "      <newznab:attr name=\"poster\" value=\"{}\"/>\n",
                esc_xml(&r.poster)
            ));
        }
        items.push_str(&format!(
            r#"    <item>
      <title>{title}</title>
      <guid isPermaLink="false">nzbfast-{id}</guid>
      <link>{link}</link>
      <pubDate>{date}</pubDate>
      <enclosure url="{link}" length="{size}" type="application/x-nzb"/>
      <newznab:attr name="category" value="{cat}"/>
      <newznab:attr name="size" value="{size}"/>
      <newznab:attr name="usenetdate" value="{date}"/>
{extra}    </item>
"#,
            title = esc_xml(name),
            id = r.id,
            link = esc_xml(&link),
            date = httpdate(posted),
            size = r.total_bytes,
        ));
    }
    // <newznab:response> is how a client knows whether to ask for
    // another page. Without it Prowlarr and Sonarr treat every response
    // as the last one, so a search never went past its first 100 rows -
    // and browse() had the real total all along, it was being discarded.
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:newznab="http://www.newznab.com/DTD/2010/feeds/attributes/">
  <channel>
    <title>nzbfast</title>
    <description>nzbfast built-in index</description>
    <newznab:response offset="{offset}" total="{total}"/>
{items}  </channel>
</rss>"#
    )
}
