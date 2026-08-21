use super::super::*;
use super::ApiCtx;

fn m_wall_search(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let q = params.get("q").cloned().unwrap_or_default();
        let year = params.get("year").and_then(|v| v.parse().ok()).unwrap_or(0);
        let kind = match params.get("kind").map(String::as_str) {
            Some("tv") => crate::wall::Kind::Tv,
            _ => crate::wall::Kind::Movie,
        };
        if q.trim().is_empty() {
            json!({"status": false, "error": "empty query"})
        } else {
            // How long an interactive search may wait on a
            // bucket before giving up on that provider.
            const SEARCH_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);
            let omdb = d.omdb_key.lock_ok().clone();
            let mut paced_out = false;
            // Movies: prefer OMDb when the user's key is set
            // (exact titles + imdb ids); empty result falls
            // back to the keyless chain.
            let mut cands = match (&omdb, &kind) {
                (Some(k), crate::wall::Kind::Movie) if ctx.tmdb_key.is_none() => {
                    if crate::ratelimit::try_acquire(
                        crate::ratelimit::Provider::Omdb,
                        SEARCH_BUDGET,
                    ) {
                        crate::wall::omdb_search(k, q.trim())
                    } else {
                        paced_out = true;
                        Vec::new()
                    }
                }
                _ => Vec::new(),
            };
            if cands.is_empty() {
                let p = crate::wall::search_provider(ctx.tmdb_key.as_deref(), &kind);
                if crate::ratelimit::try_acquire(p, SEARCH_BUDGET) {
                    cands = crate::wall::search_candidates(
                        ctx.tmdb_key.as_deref(),
                        &kind,
                        q.trim(),
                        year,
                    );
                } else {
                    paced_out = true;
                }
            }
            if cands.is_empty() && paced_out {
                // Nothing local to fall back on here, and an
                // empty list would read as "no such film" -
                // which is not what happened. Say what did.
                json!({
                    "status": false,
                    "error": "the metadata provider is busy right now - try again in a moment",
                })
            } else {
                json!({"status": true, "candidates": cands.iter().map(|c| json!({
                                "id": c.id,
                                "kind": c.kind,
                                "title": c.title,
                                "year": c.year,
                                "overview": c.overview,
                                "rating": c.rating,
                                "genres": c.genres,
                                "poster_url": c.poster_url,
                                "backdrop_url": c.backdrop_url,
                                "imdb": c.imdb,
                                "provider": c.provider,
                                "air_date": c.air_date,
                            })).collect::<Vec<_>>()})
            }
        }
    })
}

/// A candidate's `provider` as an id namespace we will actually store.
///
/// The list is the one `wall::Candidate::provider` can hold, and an
/// allowlist rather than a pass-through because the value arrives in a
/// request body: an unrecognised name would be stored verbatim and then
/// match no reader at all, which is a row whose id nothing can resolve.
/// Unlabelled is the honest answer for anything else, and it is exactly
/// what a client too old to send the field produces.
fn id_source(provider: &str) -> &'static str {
    match provider {
        "tmdb" => "tmdb",
        "tvmaze" => "tvmaze",
        "omdb" => "omdb",
        "anilist" => "anilist",
        "wikidata" => "wikidata",
        _ => "",
    }
}

/// The pending `titles` row a key deserves, derived from the releases it
/// names - or `None` when it names none.
///
/// Endpoints that read-modify-write a title row cannot assume one
/// exists. A wall poll seeds the cards it draws, and the scan loop's
/// `seed_missing_titles` is a later, bounded, kind-filtered sweep, so a
/// card reached before either has touched it has no row at all: a direct
/// link, a `key=`-scoped fetch, the Releases surface's hover preview, or
/// simply a page the user never scrolled to. `wall_fix` has always
/// coped, because `title_set_identity` upserts; `wall_art` and
/// `wall_refresh` write through a bare UPDATE and used to answer
/// "unknown title key" for a key that is perfectly good. They seed first
/// now, which is also what lets the wall poll stop writing on the HTTP
/// request path.
///
/// Derived exactly as `mode=wall2` derives its own seeds - one card via
/// `title_keys`, `parse_release` for the display title a row without
/// metadata has to carry - so a key seeded here and the same key seeded
/// by a poll produce the identical row.
///
/// Uncurated on purpose, and `matched_only` off. Junk gating, per-title
/// hides and the adult filter decide what the WALL DRAWS, not whether a
/// key EXISTS: a card reached from the Hidden panel is a real key with
/// real releases, and "unknown title key" would be a lie about the
/// index. `matched_only` is the sharper one - it keeps only rows the
/// enricher already filled, which is the exact complement of the rows
/// that need seeding. `None` is therefore the genuinely bad key, and
/// stays worth reporting as one.
fn seed_for_key(ix: &nzbkit::index::Index, key: &str) -> Option<nzbkit::index::TitleSeed> {
    let bq = nzbkit::index::BrowseQuery {
        title_keys: vec![key.to_string()],
        limit: 1,
        ..Default::default()
    };
    let (cards, _) = ix
        .browse_cards(&bq, nzbkit::index::CardSort::Latest, false, false, None)
        .ok()?;
    let c = cards.into_iter().next()?;
    let p = crate::wall::parse_release(&c.rep_stem);
    Some(nzbkit::index::TitleSeed {
        key: c.title_key,
        kind: c.kind,
        title: if c.title.is_empty() { p.title } else { c.title },
        year: if c.year > 0 {
            c.year
        } else {
            p.year.unwrap_or(0)
        },
    })
}

fn m_wall_fix(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let raw = api_body.take().unwrap_or_default();
        let body: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
        let key = body["key"].as_str().unwrap_or("").to_string();
        let title = body["title"].as_str().unwrap_or("").trim().to_string();
        let kind = match body["kind"].as_str() {
            Some("tv") => "tv",
            Some("other") => "other",
            _ => "movie",
        };
        let year = body["year"].as_u64().unwrap_or(0) as u32;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.as_secs() as i64)
            .unwrap_or(1);
        // The manual arm's "keep what you were not editing" read, taken
        // BEFORE the write below because a busy read pool has to stop
        // the whole edit rather than contribute a blank to it - see the
        // arm itself for what an absent `old` would do to the row.
        let manual = !body.get("meta").is_some_and(Value::is_object)
            && body["refetch"].as_bool() != Some(true);
        let old = if manual && !key.is_empty() && !title.is_empty() {
            match d.index_read_checked(|ix| ix.title_get(&key).ok().flatten()) {
                Ok(old) => old,
                Err(why) => {
                    return Some(json!({
                        "status": false,
                        "error": why.message(),
                    }));
                }
            }
        } else {
            None
        };
        if key.is_empty() || title.is_empty() {
            json!({"status": false, "error": "key and title are required"})
        } else {
            let art = d.spool.join("art");
            let _ = std::fs::create_dir_all(&art);
            // Every arm writes the identity AND the metadata that goes
            // with it as ONE index write (`title_set_identity_and_fill`,
            // `title_set_identity_and_reset`). The rename used to
            // autocommit on its own, ahead of the branch: losing the
            // writer for the second half then left the card renamed to
            // the picked series wearing the PREVIOUS series' poster,
            // overview, rating and ids - with nothing to prompt a
            // re-fix, because the card now reads as a title somebody
            // already identified.
            let ok = if let Some(meta) = body.get("meta").filter(|m| m.is_object()) {
                // Art fetch happens OUTSIDE with_index - never
                // hold the index lock across the network.
                //
                // Bytes now, files after the commit. An art path is
                // derived from the title key, so the candidate's poster
                // lands exactly where the current one is: written before
                // the index write, a refused edit would leave the old
                // identity wearing the new series' picture - the same
                // half-applied result, moved to the disk.
                //
                // Poster and backdrop come off CDNs - fetch
                // them concurrently (this is a user click;
                // two serial 15 s timeouts felt like a hang).
                let (poster_img, backdrop_img) = std::thread::scope(|s| {
                    let bd = s.spawn(|| {
                        crate::wall::fetch_image(meta["backdrop_url"].as_str().unwrap_or(""))
                    });
                    (
                        crate::wall::fetch_image(meta["poster_url"].as_str().unwrap_or("")),
                        bd.join().unwrap_or_default(),
                    )
                });
                // A filename is stored only for art we actually hold. A
                // fetch that came back with nothing clears the column
                // and deletes the file below: the image sitting there
                // belongs to the series this row just stopped being.
                let named = |img: &Option<Vec<u8>>, backdrop: bool| match img {
                    Some(_) => crate::wall::art_name(&key, backdrop),
                    None => String::new(),
                };
                let (poster, backdrop) = (named(&poster_img, false), named(&backdrop_img, true));
                let ok = d
                    .with_index(|ix| {
                        ix.title_set_identity_and_fill(
                            &key,
                            kind,
                            &title,
                            year,
                            &nzbkit::index::TitleFill {
                                tmdb_id: meta["id"].as_i64().unwrap_or(0),
                                // The candidate list this id came from
                                // already names its provider, and the
                                // endpoint already hands that name to
                                // the UI - it was simply dropped on the
                                // way back, leaving an unlabelled id in
                                // a column four namespaces share (Codex
                                // sweep 7, H2). Anything we do not
                                // recognise is stored as unlabelled
                                // rather than trusted.
                                id_src: id_source(meta["provider"].as_str().unwrap_or("")),
                                overview: meta["overview"].as_str().unwrap_or(""),
                                rating: meta["rating"].as_f64().unwrap_or(0.0),
                                genres: meta["genres"].as_str().unwrap_or(""),
                                poster: &poster,
                                backdrop: &backdrop,
                                imdb: meta["imdb"].as_str().unwrap_or(""),
                                // Cast isn't in search results; a
                                // per-title Refresh re-enriches it.
                                actors: "",
                                air_date: meta["air_date"].as_str().unwrap_or(""),
                            },
                            now,
                        )
                        .ok()
                    })
                    .is_some();
                if ok {
                    for (img, backdrop) in [(poster_img, false), (backdrop_img, true)] {
                        let path = art.join(crate::wall::art_name(&key, backdrop));
                        match img {
                            Some(bytes) if std::fs::write(&path, &bytes).is_ok() => {}
                            // Absent beats stale. The row names this
                            // file, and a card whose named art is not on
                            // disk draws its placeholder (every card
                            // builder gates the URL on `is_file`), so a
                            // failed write costs a poster until the next
                            // Refresh instead of showing the wrong one.
                            _ => {
                                let _ = std::fs::remove_file(&path);
                            }
                        }
                    }
                    // The thumbnails the grid actually loads are cached
                    // per title key, so the new poster is invisible
                    // until they go.
                    crate::wall::drop_art_thumbs(&art, &key);
                }
                info!(target: "wall", "fix {key} → {title} ({year}) via candidate");
                ok
            } else if body["refetch"].as_bool() == Some(true) {
                let ok = d
                    .with_index(|ix| {
                        ix.title_set_identity_and_reset(&key, kind, &title, year)
                            .ok()
                    })
                    .is_some();
                // Only once the reset is committed. The art belongs to
                // the row's metadata, and dropping it against an edit
                // the index refused would blank a card that still holds
                // the identity that art matches.
                if ok {
                    crate::wall::drop_art(&art, &key);
                }
                info!(target: "wall", "fix {key} → {title} ({year}), re-fetching");
                ok
            } else {
                // Manual: keep id/rating/art/imdb/cast, take
                // the typed text; absent fields keep their
                // old values.
                //
                // `old` was read above, with index_read_checked
                // rather than with_index_read: this read IS the
                // "keep" half, and its `None` feeds
                // `unwrap_or_default()` straight into title_fill -
                // a zeroed row that blanks the poster, rating,
                // imdb id and cast the user was not editing. A
                // saturated read pool must stop the edit and say
                // so, never strip it silently.
                //
                // `id_src` rides with `oid` because it is the only
                // thing that makes it readable: keeping the id while
                // dropping its namespace would quietly demote the row
                // to legacy-unlabelled on every manual save.
                let (oid, osrc, orating, opost, obd, oview, ogen, oimdb, oact, oair) = old
                    .map(|t| {
                        (
                            t.tmdb_id, t.id_src, t.rating, t.poster, t.backdrop, t.overview,
                            t.genres, t.imdb, t.actors, t.air_date,
                        )
                    })
                    .unwrap_or_default();
                let overview = body["overview"]
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or(oview);
                let genres = body["genres"].as_str().map(str::to_string).unwrap_or(ogen);
                let ok = d
                    .with_index(|ix| {
                        ix.title_set_identity_and_fill(
                            &key,
                            kind,
                            &title,
                            year,
                            &nzbkit::index::TitleFill {
                                tmdb_id: oid,
                                id_src: &osrc,
                                overview: &overview,
                                rating: orating,
                                genres: &genres,
                                poster: &opost,
                                backdrop: &obd,
                                imdb: &oimdb,
                                actors: &oact,
                                air_date: &oair,
                            },
                            now,
                        )
                        .ok()
                    })
                    .is_some();
                info!(target: "wall", "fix {key} → {title} ({year}), manual");
                ok
            };
            if ok {
                json!({"status": true})
            } else {
                // One error for the whole edit, because there is no
                // longer a state between "nothing happened" and "all of
                // it did" for the user to be told about: the write was
                // refused, and pressing Save again is the whole fix.
                json!({"status": false, "error": "index unavailable"})
            }
        }
    })
}

fn m_wall_art(
    d: &Arc<Daemon>,
    req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        // Same parse the gateway used to fill `api_body` - one
        // helper, so a mixed-case `Boundary=` cannot be
        // multipart there and not here.
        let boundary = req
            .headers()
            .iter()
            .find(|h| h.field.equiv("Content-Type"))
            .and_then(|h| multipart_boundary(h.value.as_str()));
        // Slack over the 8 MB image limit for multipart framing;
        // the precise size check below still governs. The form
        // pre-read may already hold a multipart body.
        let raw = api_body.take().unwrap_or_default();
        let (key, bytes, src) = match boundary {
            Some(b) => (
                params.get("key").cloned().unwrap_or_default(),
                multipart_file(&raw, &b).map(|(_, bytes)| bytes),
                "upload",
            ),
            None => {
                let body: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
                let key = body["key"].as_str().unwrap_or("").to_string();
                let url = body["url"].as_str().unwrap_or("").trim().to_string();
                let bytes = (!url.is_empty())
                    .then(|| crate::wall::fetch_image(&url))
                    .flatten();
                (key, bytes, "url")
            }
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.as_secs() as i64)
            .unwrap_or(1);
        if key.is_empty() {
            json!({"status": false, "error": "key is required"})
        } else {
            match bytes {
                None => json!({"status": false, "error": if src == "upload" {
                    "no image file in request"
                } else {
                    "couldn't fetch an image from that URL"
                }}),
                Some(b) if b.len() > 8 * 1024 * 1024 => {
                    json!({"status": false, "error": "image too large (8 MB max)"})
                }
                Some(b) if !looks_image(&b) => {
                    json!({"status": false, "error": "that isn't an image (JPEG/PNG/GIF/WebP)"})
                }
                // index_read_checked, not with_index_read: a busy
                // read pool is not an unknown key. Flattening the
                // two would tell the user their title does not
                // exist because a scan batch happened to be
                // running, and send them off to fix the wrong
                // thing - after they already uploaded the file.
                //
                // Both halves of the seed-then-act lookup under ONE
                // pooled read: the row if it exists, and otherwise the
                // seed that would make it exist (see `seed_for_key` for
                // why a missing row is not a missing title). Only a key
                // that names no releases at all is unknown.
                Some(b) => match d.index_read_checked(|ix| {
                    Some(match ix.title_get(&key) {
                        Ok(Some(t)) => (Some(t), None),
                        Ok(None) => (None, seed_for_key(ix, &key)),
                        // A read that FAILED is not an absent row, and
                        // the difference is destructive here: seeding on
                        // it would be a no-op against the row that is
                        // really there, and the fill would then write
                        // the blank defaults over its id, rating, imdb
                        // and cast. Answered as before - the upload is
                        // refused and nothing is touched.
                        Err(_) => (None, None),
                    })
                }) {
                    Err(why) => json!({
                        "status": false,
                        "error": why.message(),
                    }),
                    // `Ok(None)` is the indexer switched off - no index
                    // to hold a title, so the key resolves to nothing
                    // exactly as an unknown one does.
                    Ok(None) | Ok(Some((None, None))) => {
                        json!({"status": false, "error": "unknown title key"})
                    }
                    Ok(Some((row, seed))) => {
                        // A row we are about to seed carries its
                        // identity and nothing else, which is precisely
                        // what `TitleRow::default()` is - so the fill
                        // below reads the same either way.
                        let t = row.unwrap_or_default();
                        let art = d.spool.join("art");
                        let _ = std::fs::create_dir_all(&art);
                        let name = crate::wall::art_name(&key, false);
                        if std::fs::write(art.join(&name), &b).is_err() {
                            json!({"status": false, "error": "couldn't write the art cache"})
                        } else {
                            let ok = d.with_index(|ix| {
                                // Seed first when the row is missing:
                                // `title_fill` is a bare UPDATE, so on a
                                // card the wall has never drawn it would
                                // match nothing, change nothing, and
                                // still report success - the poster on
                                // disk, no row naming it, and the card
                                // still wearing its placeholder.
                                //
                                // Two autocommits rather than one
                                // transaction, deliberately: a seed that
                                // lands without its fill is an ordinary
                                // pending row, which is what the next
                                // scan sweep would have written anyway.
                                if let Some(s) = &seed {
                                    ix.title_seed(&s.key, &s.kind, &s.title, s.year).ok()?;
                                }
                                ix.title_fill(
                                    &key,
                                    &nzbkit::index::TitleFill {
                                        tmdb_id: t.tmdb_id,
                                        id_src: &t.id_src,
                                        overview: &t.overview,
                                        rating: t.rating,
                                        genres: &t.genres,
                                        poster: &name,
                                        backdrop: &t.backdrop,
                                        imdb: &t.imdb,
                                        actors: &t.actors,
                                        air_date: &t.air_date,
                                    },
                                    now,
                                )
                                .ok()
                            });
                            // The grid loads `/art/thumb_<name>`, a
                            // derivative cached under a name of its own,
                            // so a hand-picked poster written over the
                            // old file is invisible on the wall until
                            // the stale thumbnail goes.
                            crate::wall::drop_art_thumbs(&art, &key);
                            info!(
                                target: "wall",
                                "custom poster for {key} ({} KB via {src})",
                                b.len() / 1024
                            );
                            json!({"status": ok.is_some()})
                        }
                    }
                },
            }
        }
    })
}

fn m_omdb_signup(
    _d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let raw = api_body.take().unwrap_or_default();
        let body: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
        let email = body["email"].as_str().unwrap_or("").trim().to_string();
        if !email.contains('@') || email.contains(char::is_whitespace) {
            json!({"status": false, "error": "a valid email address is required"})
        } else {
            match crate::wall::omdb_signup(&email) {
                Ok(()) => {
                    // The address itself stays out of the log ring: it
                    // is the user's personal data, the ring is what a
                    // support bundle ships, and "which address" is not
                    // a question the log has to answer.
                    info!(target: "wall", "OMDb key requested");
                    json!({"status": true})
                }
                Err(e) => json!({"status": false, "error": e}),
            }
        }
    })
}

fn m_wall_refresh(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let target = params.get("value").cloned().unwrap_or_default();
        let art = d.spool.join("art");
        if target == "all" {
            // `.ok()` used to fold three different answers into 0 - no
            // index, a failed UPDATE, and a genuinely empty table - and
            // the wipe below then ran regardless. Clearing `checked` is
            // the ONLY thing that requeues a title for enrichment, so on
            // a refused reset that destroyed every poster with nothing
            // left to re-fetch them, and said `"status": true`.
            let n = d.with_index(|ix| ix.titles_reset_all().ok());
            let Some(n) = n else {
                warn!(target: "wall", "metadata reset refused - the art cache is untouched");
                return Some(json!({
                    "status": false,
                    "error": "the index could not be reset"
                }));
            };
            let _ = std::fs::remove_dir_all(&art);
            let _ = std::fs::create_dir_all(&art);
            info!(target: "wall", "metadata reset for {n} titles - re-enriching");
            json!({"status": true, "reset": n})
        } else if !target.is_empty() {
            let mut ok = d
                .with_index(|ix| ix.title_reset(&target).ok())
                .unwrap_or(false);
            // A bare UPDATE matched nothing, which is the ONE case that
            // is not a verdict about the key: a card the wall has never
            // drawn has no row to reset, and refusing it told the user
            // their perfectly good title did not exist. Seed the row
            // this key deserves and the reset lands on it - a freshly
            // seeded row IS the post-reset state (checked=0, every
            // metadata column empty), so the seed and the reset are the
            // same write, and `title_seed` is INSERT OR IGNORE so a row
            // that appeared in between is reset rather than overwritten.
            //
            // Reset first and seed only on the miss: the row exists on
            // every ordinary refresh, and that path must not pay for a
            // card lookup it will throw away.
            if !ok {
                // index_read_checked for `wall_art`'s reason - a busy
                // read pool is not an unknown key, and this one would
                // otherwise report a saturated pool as a bad title.
                match d.index_read_checked(|ix| seed_for_key(ix, &target)) {
                    Err(why) => {
                        return Some(json!({"status": false, "error": why.message()}));
                    }
                    // No row and no releases either: a genuinely bad
                    // key, and still worth saying so.
                    Ok(None) => {}
                    Ok(Some(s)) => {
                        ok = d
                            .with_index(|ix| {
                                ix.title_seed(&s.key, &s.kind, &s.title, s.year).ok()?;
                                ix.title_reset(&target).ok()
                            })
                            .unwrap_or(false);
                    }
                }
            }
            // Same rule as the `all` arm: the art is the only copy, and
            // nothing re-fetches it unless `checked` was cleared.
            if ok {
                crate::wall::drop_art(&art, &target);
            }
            if ok {
                json!({"status": true})
            } else {
                json!({"status": false, "error": "unknown title key"})
            }
        } else {
            json!({"status": false, "error": "wall_refresh needs value=<key>|all"})
        }
    })
}

fn m_wall_merge(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let src = params.get("value").cloned().unwrap_or_default();
        let dst = params.get("value2").cloned().unwrap_or_default();
        if src.is_empty() || dst.is_empty() || src == dst {
            json!({"status": false, "error": "value=<from key> value2=<into key> required"})
        } else {
            let n = d
                .with_index(|ix| ix.merge_title(&src, &dst).ok())
                .unwrap_or(0);
            // Thumbnails included: the source key is gone, so nothing
            // will ever ask for its derivatives again and a file the
            // headshot eviction pass deliberately never touches would
            // sit in the cache for the life of the install.
            crate::wall::drop_art(&d.spool.join("art"), &src);
            info!(target: "wall", "merged '{src}' into '{dst}' ({n} releases)");
            json!({"status": n > 0, "moved": n})
        }
    })
}

fn m_wall_hide(
    mode: &str,
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let key = params.get("value").cloned().unwrap_or_default();
        if key.is_empty() {
            json!({"status": false, "error": "value=<title key> required"})
        } else {
            let hide = mode == "wall_hide";
            let ok = d
                .with_index(|ix| {
                    if hide {
                        ix.hide_title(&key).ok()
                    } else {
                        ix.unhide_title(&key).ok()
                    }
                })
                .is_some();
            json!({"status": ok})
        }
    })
}

fn m_wall_tip(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let since: i64 = params
            .get("since")
            .and_then(|v| v.parse().ok())
            .unwrap_or(-1);
        let initialized = since >= 0;
        // An arrival must also be a RECENT upload, or the
        // history deepen leg's finds get announced as new
        // and then cannot be found: the wall sorts by posted
        // date, so a years-old upload sits thousands of
        // cards down. A week is generous enough for slow
        // propagation and for a post whose first article
        // predates the rest of its set.
        let posted_after = epoch_secs() as i64 - 7 * 86_400;
        let tip = d.with_index_read(|ix| {
            ix.wall_tip(if initialized { since } else { i64::MAX }, posted_after, 60)
                .ok()
        });
        wall_tip_body(tip, initialized)
    })
}

fn m_title_credits(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let key = params.get("key").cloned().unwrap_or_default();
        let rows = d
            .with_index_read(|ix| ix.title_credits(&key, 40).ok())
            .unwrap_or_default();
        let art_dir = d.spool.join("art");
        json!({"credits": rows.iter().map(|c| json!({
                        "id": c.person_id, "name": c.name,
                        "role": c.role, "character": c.character,
                        "photo": person_photo_url(&art_dir, c.person_id),
                    })).collect::<Vec<_>>()})
    })
}

fn m_wall_session(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let key = params.get("key").cloned().unwrap_or_default();
        let rows = d
            .with_index_read(|ix| ix.title_session_siblings(&key, 40).ok())
            .unwrap_or_default();
        json!({"status": true, "siblings": rows.iter().map(|t| json!({
                    "id": t.sib.rel.id,
                    "name": t.sib.rel.display_name(),
                    // The raw stem rides along only when a fed name is
                    // shown, same contract as index_browse's "posted".
                    "posted": if t.sib.rel.pre_title.is_empty() { Value::Null }
                              else { Value::String(t.sib.rel.stem.clone()) },
                    "group": t.sib.rel.grp,
                    "size": t.sib.rel.total_bytes,
                    "complete": t.sib.rel.complete,
                    "link": t.sib.link.tag(),
                    "dt": t.sib.dt,
                    "anchor": t.anchor_id,
                })).collect::<Vec<_>>()})
    })
}

fn m_person(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let id: i64 = params
            .get("value")
            .and_then(|v| v.parse().ok())
            .unwrap_or(-1);
        let art_dir = d.spool.join("art");
        match d.with_index_read(|ix| {
            let p = ix.person_get(id).ok()??;
            Some((p, ix.person_titles(id).unwrap_or_default()))
        }) {
            Some((p, titles)) => json!({
                "status": true,
                "id": p.id, "name": p.name, "born": p.born, "bio": p.bio,
                "imdb": p.imdb,
                // Whether the off-index half can be fetched at
                // all - the UI hides the button rather than
                // offering one that can only come back empty.
                "tv_filmography": p.tvmaze_id > 0,
                "film_filmography": !p.wikidata_qid.is_empty(),
                "photo": person_photo_url(&art_dir, p.id),
                "titles": titles.iter().map(|t| {
                    let f = crate::wall::art_name(&t.key, false);
                    json!({
                        "key": t.key, "kind": t.kind, "title": t.title,
                        "year": t.year, "aired": t.air_date,
                        "role": t.role, "character": t.character,
                        "n": t.n_releases,
                        "poster": if art_dir.join(&f).is_file() { format!("/art/thumb_{f}") } else { Default::default() },
                    })
                }).collect::<Vec<_>>(),
            }),
            None => json!({"status": false, "error": "no such person"}),
        }
    })
}

fn m_person_more(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let id: i64 = params
            .get("value")
            .and_then(|v| v.parse().ok())
            .unwrap_or(-1);
        match d.with_index_read(|ix| ix.person_get(id).ok().flatten()) {
            Some(p) => {
                let (filmo, complete) =
                    crate::wall::person_filmography(p.tvmaze_id, &p.wikidata_qid);
                // What the user already has, so the UI can
                // mark the rest as "not in your index" - a
                // normalized title match, which is the same
                // key the wall groups cards by.
                let have: std::collections::HashSet<String> = d
                    .with_index_read(|ix| ix.person_titles(id).ok())
                    .unwrap_or_default()
                    .iter()
                    .map(|t| crate::wall::norm_title(&t.title))
                    .collect();
                json!({
                    "status": true,
                    // False when a provider declined (SPARQL
                    // is rate-limited and really does refuse
                    // one call and serve the next). Without
                    // it an empty list reads as "you already
                    // have everything", which is a lie.
                    "complete": complete,
                    "credits": filmo.iter().map(|f| json!({
                        "title": f.title, "year": f.year, "date": f.date,
                        "kind": f.kind, "character": f.character,
                        "source": f.source,
                        "have": have.contains(&crate::wall::norm_title(&f.title)),
                    })).collect::<Vec<_>>(),
                })
            }
            None => json!({"status": false, "error": "no such person"}),
        }
    })
}

fn m_people_search(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let q = params.get("q").cloned().unwrap_or_default();
        // index_read_checked, not with_index_read: the flattening
        // wrapper turns a saturated read pool or a twice-failed
        // SQLITE_SCHEMA into an empty list, and an empty list here reads
        // as "no such person" - a working index reported as one that has
        // never heard of the name the user is typing (read-only sweep 3,
        // 16 Aug 2026, L2). Both causes are transient, so say so and let
        // the next keystroke get the real answer.
        let rows = match d.index_read_checked(|ix| ix.people_search(&q, 12).ok()) {
            Err(why) => {
                return Some(json!({
                    "status": false, "busy": true, "error": why.message(),
                }));
            }
            Ok(rows) => rows.unwrap_or_default(),
        };
        let art_dir = d.spool.join("art");
        json!({"people": rows.iter().map(|p| json!({
                        "id": p.id, "name": p.name, "n": p.n_titles,
                        "photo": person_photo_url(&art_dir, p.id),
                    })).collect::<Vec<_>>()})
    })
}

fn m_wall_hidden(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let rows = d
            .with_index_read(|ix| ix.hidden_titles().ok())
            .unwrap_or_default();
        let art_dir = d.spool.join("art");
        json!({"hidden": rows.iter().map(|h| {
                        // Same thumb resolution as wall2 cards.
                        let f = crate::wall::art_name(&h.key, false);
                        let poster = if art_dir.join(&f).is_file() { format!("/art/thumb_{f}") } else { Default::default() };
                        json!({
                            "key": h.key, "title": h.title, "kind": h.kind,
                            "at": h.at, "n": h.n_releases, "poster": poster,
                        })
                    }).collect::<Vec<_>>()})
    })
}

fn m_wall_rules(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let rules = d
            .with_index_read(|ix| ix.rules_list().ok())
            .unwrap_or_default();
        json!({"rules": rules.iter().map(|r| json!({
                        "id": r.id, "field": r.field, "value": r.value,
                        "added": r.added, "auto": r.auto,
                    })).collect::<Vec<_>>()})
    })
}

fn m_wall_rule_add(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let field = params.get("name").cloned().unwrap_or_default();
        let value = params.get("value").cloned().unwrap_or_default();
        let auto = params.get("value2").map(String::as_str) == Some("auto");
        match d.with_index(|ix| Some(ix.rule_add(&field, &value, auto))) {
            Some(Ok(())) => json!({"status": true}),
            Some(Err(e)) => json!({"status": false, "error": e.to_string()}),
            None => json!({"status": false, "error": "index unavailable"}),
        }
    })
}

fn m_wall_rule_del(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let id: i64 = params
            .get("value")
            .and_then(|v| v.parse().ok())
            .unwrap_or(-1);
        let ok = d.with_index(|ix| ix.rule_delete(id).ok()).is_some();
        json!({"status": ok})
    })
}

fn m_wall_suggest(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        // Pure read - the pooled read-only connection, so the
        // suggestions panel never parks a worker behind an ingest.
        // with_index_read, not the checked form: this is a nudge
        // beside the hide list, and an empty panel for one poll is
        // the right degradation for it.
        let sug = d
            .with_index_read(|ix| ix.hide_suggestions().ok())
            .unwrap_or_default();
        json!({"suggestions": sug.iter().map(|s| json!({
                        "field": s.field, "value": s.value, "n": s.n,
                        "sample": s.sample,
                    })).collect::<Vec<_>>()})
    })
}

fn m_wall_suggest_no(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let field = params.get("name").cloned().unwrap_or_default();
        let value = params.get("value").cloned().unwrap_or_default();
        let ok = d
            .with_index(|ix| ix.suggestion_dismiss(&field, &value).ok())
            .is_some();
        json!({"status": ok})
    })
}

fn m_taste(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let tp = d.taste_profile();
        json!({
            "n_signals": tp.n_signals,
            "decade": tp.decade_center,
            "genres": tp.genres.iter()
                .map(|(name, w)| json!({"name": name, "weight": w}))
                .collect::<Vec<_>>(),
            "kinds": tp.kinds.iter()
                .map(|(name, w)| json!({"name": name, "weight": w}))
                .collect::<Vec<_>>(),
        })
    })
}

pub(in crate::serve) fn dispatch(
    d: &Arc<Daemon>,
    req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    mode: &str,
    ctx: &ApiCtx<'_>,
    api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    match mode {
        // M16 fix-match: candidate list for a re-search. Network
        // on the API thread is acceptable here (user-clicked, and
        // every provider call carries a 10 s ureq timeout - the
        // sysbench precedent).
        //
        // The PACING is not, though, and that is a different
        // thing from the timeout: `ratelimit::acquire` sleeps in
        // front of the request, for as long as the bucket says.
        // Wikidata's slots are 7.5 s apart and a 429 the
        // enricher drew penalises the lane by up to 60 s, so a
        // few clicks could park every blocking API worker and
        // take dashboard polling down with them. `try_acquire`
        // asks instead of queueing: if this search cannot start
        // within a couple of seconds we say so and return
        // immediately, which costs the lane nothing.
        "wall_search" => m_wall_search(d, req, params, ctx, api_body),
        // M16 fix-match apply. POST body {key, kind, title, year,
        // ...} in one of three shapes:
        //   meta: {...}   → apply a chosen candidate (art fetched
        //                   here, metadata written, enricher done);
        //   refetch: true → scrub identity, wipe cached metadata,
        //                   let the enricher re-look-up under the
        //                   corrected name;
        //   neither       → manual entry: identity (+ optional
        //                   overview/genres) is exactly what the
        //                   user typed; checked is stamped so the
        //                   enricher never overwrites it.
        // Release/file rows are untouched by all three.
        "wall_fix" => m_wall_fix(d, req, params, ctx, api_body),
        // M21 custom artwork: stamp a user-chosen poster onto a
        // title. Body is either JSON {key, url} (the daemon
        // fetches the image - network OUTSIDE the index lock,
        // like wall_fix) or a multipart file upload with
        // ?key=<title key> (same parser as addfile). The bytes
        // land in the .spool/art cache under the title's usual
        // art name and the row is stamped checked, so the
        // enricher never overwrites a hand-picked poster.
        "wall_art" => m_wall_art(d, req, params, ctx, api_body),
        // OMDb free-key signup, automated: POST {email} → the
        // daemon replays omdbapi.com's signup form (it only
        // wants an email). The key + activation link arrive in
        // the user's inbox; they paste the key into Settings.
        // Network on the API thread is fine here (user-clicked,
        // 15 s timeouts - the wall_search precedent).
        "omdb_signup" => m_omdb_signup(d, req, params, ctx, api_body),
        // M16: wipe cached metadata (+art) for one title
        // (value=<key>) or every title (value=all) and let the
        // enricher re-download it. Releases/files stay.
        "wall_refresh" => m_wall_refresh(d, req, params, ctx, api_body),
        // M30: merge a mis-split card into another (value=src
        // key, value2=dst key). Releases re-key; src title row
        // and art go away; dst keeps its metadata.
        "wall_merge" => m_wall_merge(d, req, params, ctx, api_body),
        // M30 wall curation: per-title "Not interested" hides,
        // hide rules (language/word/kind/group), and the
        // suggest-confirm learning loop over the user's hides.
        "wall_hide" | "wall_unhide" => m_wall_hide(mode, d, req, params, ctx, api_body),
        // The arrival poll. Runs every few seconds per open wall,
        // so it must stay far cheaper than wall2 - it answers
        // only "has anything landed?", and the expensive fetch
        // happens when the answer is yes.
        //
        // `since=-1` (a freshly-opened wall) is a special case:
        // returning "everything in the index is new" would greet
        // the user with a pill claiming 890,000 arrivals. It
        // reports the current mark and nothing new, which is what
        // "I just got here" should mean.
        "wall_tip" => m_wall_tip(d, req, params, ctx, api_body),
        // Cast and crew for one title - the detail sheet's chips.
        // Its own call rather than a field on every wall2 card:
        // this is one query for the ONE title being opened,
        // against 60 joins per grid page for something nobody
        // sees until they open a card.
        "title_credits" => m_title_credits(d, req, params, ctx, api_body),
        // Upload-session siblings for one title's newest releases -
        // posts that went up in the same run as an identified episode
        // and are very probably the rest of the season (research/
        // FINGERPRINT-next-episode-2026-08-14.md). Detail-sheet only,
        // one call per open, association evidence: rows are offered,
        // never renamed.
        "wall_session" => m_wall_session(d, req, params, ctx, api_body),
        // The person page's instant half: who they are, and every
        // title of theirs already in the index. No network.
        "person" => m_person(d, req, params, ctx, api_body),
        // The person page's off-index half: the full filmography,
        // live from TVmaze (TV) and Wikidata SPARQL (film).
        // On-demand ONLY - SPARQL is rate-limited with a query
        // timeout, so this is a per-click cost, never a backfill.
        "person_more" => m_person_more(d, req, params, ctx, api_body),
        // Name search. `search`/`wall2` index release stems only,
        // so before this a query like "tom cruise" found nothing
        // unless a filename happened to say it.
        "people_search" => m_people_search(d, req, params, ctx, api_body),
        "wall_hidden" => m_wall_hidden(d, req, params, ctx, api_body),
        "wall_rules" => m_wall_rules(d, req, params, ctx, api_body),
        "wall_rule_add" => m_wall_rule_add(d, req, params, ctx, api_body),
        "wall_rule_del" => m_wall_rule_del(d, req, params, ctx, api_body),
        "wall_suggest" => m_wall_suggest(d, req, params, ctx, api_body),
        "wall_suggest_no" => m_wall_suggest_no(d, req, params, ctx, api_body),
        // M31b "your wall": the taste profile behind the Affinity
        // sort - powers the "Because you watch …" caption and a
        // future Tune panel. n_signals==0 = cold start (the UI then
        // treats "For you" as "most posted").
        "taste" => m_taste(d, req, params, ctx, api_body),
        _ => None,
    }
}
