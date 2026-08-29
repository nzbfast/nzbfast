use super::super::*;
use super::ApiCtx;

// §106: the three subjects that are not the mode dispatch itself. The
// controls are re-exported because `crate::serve::api::queue::apply_pause`
// and its siblings are the paths sabcompat, daemon_park, sidecar and
// histstore already call - a child module must not change a caller.
mod caps;
mod controls;
mod files;
mod payload;
mod preview;

use caps::{cap_payload, planned_servers};
pub(in crate::serve) use controls::{
    apply_pause, apply_priority, note_queue_idle_unless_active, reposition_for_priority,
    stop_deleted_transfer,
};
use payload::{m_history, m_queue};

/// The `m_config` POST-body door, for the queue-family writes: accept
/// the same string fields in a JSON body as arrive in the query, body
/// winning like m_config's. A bulk selection's id list (250 ids a Show
/// more page) outgrows the 8 KB request line and 414s, and an archive
/// password or an nzblnk must stay out of access logs, history and any
/// Referer. The urlencoded form path cannot stand in - `parse_form_body`
/// caps a value at 4096 bytes, and silently drops a longer one. The GET
/// form stays for SAB parity.
fn merge_body_params(
    req: &tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    api_body: &mut Option<Vec<u8>>,
) -> std::collections::HashMap<String, String> {
    let mut merged = params.clone();
    if req.method() == &tiny_http::Method::Post
        && let Some(raw) = api_body.take()
        && let Ok(serde_json::Value::Object(map)) = serde_json::from_slice(&raw)
    {
        for (k, v) in map {
            if let Some(s) = v.as_str() {
                merged.insert(k, s.to_string());
            }
        }
    }
    merged
}

#[cfg(test)]
mod body_door_tests {
    use super::*;

    /// 27 Aug sweep findings 1/2/14: the queue-family writes accept
    /// their fields in a JSON POST body - a bulk id list outgrows the
    /// 8 KB request line, and a password must not ride it. Body wins
    /// over the query, like m_config's; a GET never reads the body.
    #[test]
    fn the_body_door_merges_json_fields_and_the_body_wins() {
        let mut params = std::collections::HashMap::new();
        params.insert("name".to_string(), "delete".to_string());
        params.insert("value".to_string(), "query-id".to_string());
        // ~10 KB: past the request line AND parse_form_body's 4096-byte
        // value cap, which is why the form path could not stand in.
        let long = "SABnzbd_nzo_nzbfast1,".repeat(500);
        let mut body =
            Some(serde_json::to_vec(&json!({"value": long, "del_files": "1", "n": 7})).unwrap());
        let req: tiny_http::Request = tiny_http::TestRequest::new()
            .with_method(tiny_http::Method::Post)
            .into();
        let m = merge_body_params(&req, &params, &mut body);
        assert_eq!(m["name"], "delete", "query fields survive the merge");
        assert_eq!(m["value"], long, "body wins over the query");
        assert_eq!(m["del_files"], "1");
        assert!(!m.contains_key("n"), "non-string JSON fields are ignored");
        assert!(body.is_none(), "the body is consumed");

        // A GET leaves the body alone and the params untouched.
        let mut body = Some(b"{\"value\":\"x\"}".to_vec());
        let req: tiny_http::Request = tiny_http::TestRequest::new().into();
        let m = merge_body_params(&req, &params, &mut body);
        assert_eq!(m["value"], "query-id");
        assert!(body.is_some(), "a GET never reads the body");
    }
}

fn m_pause(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        // pause&value=<minutes> = SAB's timed pause. value2=now
        // forces the immediate abort; default is a graceful
        // wind-down (finish in-flight, keep the queue for resume).
        let mins = params
            .get("value")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let graceful = params.get("value2").map(|v| v != "now").unwrap_or(true);
        timed_pause(d, mins, graceful);
        json!({"status": true})
    })
}

fn m_resume(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        // Deliberately does NOT clear offline any more.
        //
        // It used to, and the reasoning was sound at the time:
        // with nothing gating the download loop, leaving the flag
        // set while the queue ran would have every job fail
        // against a provider we had promised not to touch. That
        // premise is gone - the loop now refuses to start a job
        // while offline - and what was left was the last way a
        // remote client could put the operator back on their
        // provider without asking. An *arr sends resume as a
        // matter of course; going offline is a confirmed,
        // persisted act meaning "my account is free for another
        // machine". A routine resume must not undo it.
        //
        // So resume means what it says: unpause the queue. The
        // queue then sits still, visibly Offline, until someone
        // presses online. `mode=online` is the one that
        // reconnects, and it is one click.
        // Marker on the actual transition only - *arrs send resume
        // routinely, and a resume of a queue that was never paused
        // is not a moment worth marking.
        if set_paused_cancel_timer(d, false) {
            d.note_event("resume", "downloads resumed");
        }
        persist_pause(d);
        json!({"status": true})
    })
}

#[cfg(feature = "indexer")]
fn m_watch_calendar(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        use crate::watchlist as wl;
        let days = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| (t.as_secs() / 86_400) as i64)
            .unwrap_or(0);
        let civil_str = |d: i64| {
            let (y, m, dd) = civil_from_days(d);
            format!("{y:04}-{m:02}-{dd:02}")
        };
        let (today, lo, hi) = (civil_str(days), civil_str(days - 7), civil_str(days + 21));
        let items = d.watch_items();
        let st = d.watch_state.lock_ok().clone();
        let mut entries: Vec<(String, String, Value)> = Vec::new();
        for item in items.iter().filter(|i| i.enabled && i.kind == "tv") {
            let key = format!("eplist:{}", crate::wall::norm_title(&item.title));
            let eps: Vec<crate::wall::EpInfo> = d
                .with_index_read(|ix| ix.kv_get(&key))
                .and_then(|s| serde_json::from_str::<Value>(&s).ok())
                .and_then(|v| serde_json::from_value(v["episodes"].clone()).ok())
                .unwrap_or_default();
            for ep in eps {
                if ep.airdate.is_empty()
                    || ep.airdate < lo
                    || ep.airdate > hi
                    || !wl::in_range_spec(&item.seasons, ep.season)
                    || !wl::in_range_spec(&item.episodes, ep.episode)
                {
                    continue;
                }
                // A season pack covers this episode too, so
                // the calendar asks what the slot EFFECTIVELY
                // has - otherwise a season grabbed as one
                // pack drew a calendar of empty ticks.
                let have =
                    wl::covering(&st.slots, item.id, &wl::episode_slot(ep.season, ep.episode))
                        .map(|s| s.quality.clone());
                entries.push((
                    ep.airdate.clone(),
                    item.title.clone(),
                    json!({
                        "title": item.title, "season": ep.season,
                        "episode": ep.episode, "name": ep.name,
                        "airdate": ep.airdate,
                        "aired": ep.airdate <= today,
                        "have": have,
                        // TVmaze sends a synopsis for
                        // essentially every aired episode and
                        // we used to discard all of them, so
                        // "what is this one" had no answer.
                        "summary": ep.summary,
                        "runtime": ep.runtime,
                    }),
                ));
            }
        }
        entries.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
        json!({
            "today": today,
            "entries": entries.into_iter().map(|(_, _, v)| v).collect::<Vec<_>>(),
        })
    })
}

fn m_watchlist_status(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        // §151: the union, so a synced row has a status line too. Each
        // item is tagged with the source that owns it (absent for the
        // user's own), which is how the editor tells them apart.
        let items = d.watch_items();
        let owner: std::collections::HashMap<u64, u64> = d
            .lists
            .items
            .lock_ok()
            .iter()
            .map(|i| (i.item.id, i.src))
            .collect();
        let st = d.watch_state.lock_ok().clone();
        let out: Vec<Value> = items
            .iter()
            .map(|it| {
                let prefix = format!("{}:", it.id);
                let mut slots: Vec<(String, Value)> = st
                    .slots
                    .iter()
                    .filter(|(k, _)| k.starts_with(&prefix))
                    .map(|(k, s)| {
                        let slot = k[prefix.len()..].to_string();
                        let upgrading = st.pending.iter().any(|p| &p.slot == k);
                        (
                            slot.clone(),
                            json!({
                                "slot": slot, "quality": s.quality,
                                "stem": s.stem, "nzo_id": s.nzo_id,
                                "grabbed_at": s.grabbed_at,
                                "upgrading": upgrading,
                                // Bundle D: a slot whose grabs kept
                                // failing is emptied but keeps its
                                // dead stems, so "three releases
                                // tried and failed" and "nothing was
                                // ever posted" used to render
                                // identically - as nothing at all.
                                "failed": s.failed.len(),
                                "failed_last": s.failed.last().cloned().unwrap_or_default(),
                            }),
                        )
                    })
                    .collect();
                slots.sort_by(|a, b| b.0.cmp(&a.0)); // newest episode first
                json!({
                    "id": it.id,
                    // §151: which list source owns this row, when one
                    // does. The editor draws those read-only, and
                    // `saveWatchlist` must skip them - otherwise the
                    // save writes them into the user's own array and
                    // the two lists start destroying each other.
                    "src": owner.get(&it.id),
                    // ...and the whole item for a synced row, which is
                    // the only place the editor can read one from: the
                    // `watchlist` setting is the user's own array and
                    // deliberately does not contain these.
                    "item": owner
                        .get(&it.id)
                        .and_then(|_| serde_json::to_value(it).ok()),
                    "slots": slots.into_iter().map(|(_, v)| v).collect::<Vec<_>>(),
                    // §74: the last grab this item got because the
                    // release ARRIVED, not because a pass came round.
                    // Absent until one happens - the dashboard shows
                    // the line only when there is something true to
                    // say.
                    "instant": st.instant.get(&it.id.to_string()),
                    // Bundle D: why the last pass declined a
                    // candidate for this item, when it did - a
                    // given-up target, the age window, or an
                    // indexer account that could not be asked.
                    // Absent when the pass declined nothing.
                    "skipped_reason": st.skips.get(&it.id.to_string()),
                })
            })
            .collect();
        // Is the instant path armed at all right now? The badge is a
        // claim about what will happen, so it has to read the same
        // two switches the arrival hooks do: the feature's own, and
        // the indexer that produces the arrivals.
        json!({
            "items": out,
            "instant_on": d.watchlist_instant.load(Ordering::Relaxed) && !d.indexer_off(),
        })
    })
}

fn m_giveup_status(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let threshold = d.arr_giveup_threshold.load(Ordering::Relaxed).min(1000) as u32;
        json!({
            "targets": d.giveup.lock_ok().status_rows(threshold),
            "threshold": threshold,
            // 0 = the breaker is off, so nothing is given up and
            // nothing is being counted. Old counters may still sit
            // in the state file; the card says nothing about them
            // rather than implying a breaker that is not running.
            "on": threshold > 0,
        })
    })
}

fn m_giveup_reset(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let key = params.get("value").cloned().unwrap_or_default();
        if key.is_empty() {
            json!({"status": false, "error": "giveup_reset needs value=<target key>"})
        } else {
            // Scoped: save_giveup takes the same (non-reentrant)
            // lock, so the guard must be gone before it is called.
            let cleared = { d.giveup.lock_ok().clear_target(&key) };
            if cleared {
                d.save_giveup();
                info!(target: "giveup", "{key}: counters cleared - chasing it again");
            }
            json!({"status": true, "cleared": cleared})
        }
    })
}

fn m_change_cat(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let id = params.get("value").cloned().unwrap_or_default();
        let cat = params.get("value2").cloned().unwrap_or_default();
        let cat = cat.trim().trim_matches('*').trim().to_string();
        // Untrusted: a single contained path component, the
        // same guard as enqueue and the history form.
        let cat = if cat.is_empty() {
            cat
        } else {
            nzbkit::disk::sanitize_filename(&cat)
        };
        // Three phases, and they have to stay three: picking
        // the new directory goes through `dir_claim`, which
        // locks the queue itself, so computing it while
        // holding that lock deadlocks the daemon.
        //
        // Queued, stated positively. `!= Downloading` also
        // matched a job that had just finished and was still
        // in the queue waiting for `park` to file it - the
        // state flip and the queue removal are not one step.
        // Re-deriving out_dir for a job whose bytes are
        // already on disk points its history entry at a
        // directory the files were never written to, and the
        // caller is told `true` for a move nothing performed.
        // Held, deferred and duplicate jobs are all Queued,
        // so none of them lose the ability to be refiled.
        let target = d.queue.lock_ok().iter().find_map(|j| {
            let g = j.lock_ok();
            (g.nzo_id == id && g.state == JobState::Queued)
                .then(|| (j.clone(), g.name.clone(), g.category.clone()))
        });
        match target {
            // Not queued - it may already be in history. A
            // download in the wrong category used to be
            // unfixable the moment it finished, which is
            // exactly when people notice.
            None => history_change_cat(d, &id, &cat),
            // Already there: don't re-derive, or the job's own
            // directory reads as taken and the name climbs .2.
            Some((_, _, current)) if current == cat => json!({"status": true}),
            Some((job, name, _)) => match requeue_category(d, &job, &name, &cat) {
                Err(e) => {
                    return Some(json!({
                        "status": false,
                        "error": e
                    }));
                }
                // Saved with the fence still held, rolled back whole on
                // a refused store (Codex C10) - the relocation fence
                // prevents the live scheduling race, not a restart after
                // refused persistence.
                Ok(fence) => {
                    if persist_relocations(d, vec![fence]) {
                        json!({"status": true})
                    } else {
                        json!({
                            "status": false,
                            "error": "the recategorize could not be written to the \
                                      queue store - it was undone. Check free space \
                                      and write permission on the data folder",
                        })
                    }
                }
            },
        }
    })
}

/// §282 item 12. `value` is the download that cannot finish, `alt` the
/// held spare to run instead. The spare must still be in the queue and
/// must be held against that job - see `Daemon::alt_switch`, which does
/// the whole thing under one hold of the queue.
///
/// **`value` MAY BE A HISTORY ROW** since §284: a job that has already
/// failed is offered the same switch on its history drawer, and the id
/// is all that changes here. `alt_switch` resolves it against the queue
/// first and history second, so this handler needs no arm of its own -
/// which is the point, because a second door would be a second place for
/// the two roads' rules to drift apart.
///
/// The refusals come back as `error` for the toast rather than as a
/// status code: every one of them means the record moved under the tab,
/// and the sentence says what to do about it.
fn m_alt_switch(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    let id = params.get("value").cloned().unwrap_or_default();
    let alt = params.get("alt").cloned().unwrap_or_default();
    Some(match d.alt_switch(&id, &alt) {
        Some(err) => json!({"status": false, "error": err}),
        None => json!({"status": true, "nzo_id": alt}),
    })
}

/// §282 item 20. `value` is the download that cannot finish - a queue
/// row, or (§284) the history row of one that already did; the answer is
/// the ranked list of copies a person may pick from, already filtered to
/// the same release and inside the cost ceilings.
///
/// A SEARCH and nothing else: no grab is spent, nothing is enqueued and
/// nothing downloads. The pick is `mode=alt_hunt_pick` and it happens on
/// a second click.
///
/// The refusals come back as `error` for the toast rather than as a
/// status code, the way `alt_switch`'s do, because every one of them is a
/// sentence the user can act on - a setting, an *arr that owns the retry,
/// a post too young to be worth replacing.
fn m_alt_hunt(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    let id = params.get("value").cloned().unwrap_or_default();
    Some(match d.hunt_offer(&id) {
        Ok(mut v) => {
            if let Some(o) = v.as_object_mut() {
                o.insert("status".into(), json!(true));
            }
            v
        }
        Err(e) => json!({"status": false, "error": e}),
    })
}

/// §282 item 20, the second click. `value` is the download that cannot
/// finish - queue row or (§284) history row - and `alt` is the `key` of a
/// row from `mode=alt_hunt`'s list.
///
/// This is the one that spends: it fetches that copy's .nzb against the
/// indexer's daily grab budget, holds it to the same-post admission test,
/// and hands it to the EXISTING switch path - so the doomed job is failed
/// with the verdict's own sentence and both rows record what replaced
/// what. Nothing here re-spells any of that.
fn m_alt_hunt_pick(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    let id = params.get("value").cloned().unwrap_or_default();
    let alt = params.get("alt").cloned().unwrap_or_default();
    Some(match d.hunt_pick(&id, &alt) {
        Ok(nzo_id) => json!({"status": true, "nzo_id": nzo_id}),
        Err(e) => json!({"status": false, "error": e}),
    })
}

fn m_eat_volumes(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let id = params.get("value").cloned().unwrap_or_default();
        let mode = crate::eatvol::EatMode::parse(&d.unpack_eat_volumes.lock_ok().clone())
            .unwrap_or_default();
        if mode != crate::eatvol::EatMode::LowDisk {
            json!({"status": false,
                       "error": "extract-in-place is only offered while \
                                 'when the disk is too full' is selected in settings"})
        } else {
            let hit = |j: &&Arc<Mutex<Job>>| j.lock_ok().nzo_id == id;
            let found = d
                .queue
                .lock_ok()
                .iter()
                .find(hit)
                .cloned()
                .or_else(|| d.history.lock_ok().iter().find(hit).cloned());
            match found {
                None => json!({"status": false, "error": "unknown nzo_id"}),
                Some(job) => {
                    job.lock_ok().eat_volumes_ok = true;
                    // Durable before the caller's retry: the answer
                    // is given on a failed job and spent by a run
                    // that may be on the other side of a restart.
                    // Still `status: true` when the store refuses it:
                    // the consent is live and the dashboard's very next
                    // call is the retry that spends it. Answering false
                    // stops that unpack over a consent the user would
                    // at worst give again after a restart.
                    d.history_publish_change(&job, "the extract-in-place consent");
                    d.save_queue();
                    json!({"status": true, "nzo_id": id})
                }
            }
        }
    })
}

fn m_set_password(
    d: &Arc<Daemon>,
    req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        // The password must not ride the request line - see
        // `merge_body_params`.
        let params = &merge_body_params(req, params, api_body);
        let id = params.get("value").cloned().unwrap_or_default();
        let pw = params.get("password").cloned().unwrap_or_default();
        if pw.is_empty() {
            json!({"status": false, "error": "empty password"})
        } else {
            let hit = |j: &&Arc<Mutex<Job>>| j.lock_ok().nzo_id == id;
            let found = d
                .queue
                .lock_ok()
                .iter()
                .find(hit)
                .cloned()
                .or_else(|| d.history.lock_ok().iter().find(hit).cloned());
            match found {
                None => json!({"status": false, "error": "unknown nzo_id"}),
                Some(job) => {
                    // The snapshot (out_dir above all) and the
                    // `finalizing` raise are ONE job-lock
                    // acquisition: raised later, a recategorize
                    // could snapshot the flag as false, move the
                    // directory, and race the unlock's out_dir
                    // write (Codex H7). A raise that finds the
                    // flag already up refuses - a second unlock
                    // task would clear it while the first still
                    // runs.
                    let (locked, out_dir, name, cat, tv, nzb) = {
                        let mut j = job.lock_ok();
                        j.password = Some(pw.clone());
                        if j.password_required && j.finalizing {
                            return Some(json!({"status": false,
                                    "error": "an unlock is already running for this job - \
                                              try again when it settles"}));
                        }
                        if j.password_required {
                            j.finalizing = true;
                        }
                        (
                            j.password_required,
                            j.out_dir.clone(),
                            j.name.clone(),
                            j.category.clone(),
                            j.tv_sort,
                            j.nzb_path.clone(),
                        )
                    };
                    // Raise-then-check against the recategorize
                    // marker: history_change_cat inserts `moving`
                    // and THEN re-reads `finalizing`, so whichever
                    // of the two committed second sees the other
                    // and refuses - never both proceeding on one
                    // directory.
                    if locked && d.moving.lock_ok().contains(&id) {
                        job.lock_ok().finalizing = false;
                        return Some(json!({"status": false,
                                "error": "this job's files are being moved right now - \
                                          try again when it settles"}));
                    }
                    // The delete/retry interlock, closed from this
                    // side (Codex sweep 3 Aug H1): both remove the
                    // record UNDER the history lock, and this
                    // verify runs under the same lock AFTER the
                    // finalizing raise - whichever committed second
                    // sees the other. Without it, a delete or retry
                    // that read `finalizing` just before the raise
                    // could remove or re-queue the record while the
                    // unlock still ran against its directory.
                    if locked {
                        let still = d.history.lock_ok().iter().any(|j| Arc::ptr_eq(j, &job));
                        if !still {
                            job.lock_ok().finalizing = false;
                            return Some(json!({"status": false,
                                    "error": "this job was just deleted or retried - \
                                              the unlock was not started"}));
                        }
                        // Crash safety: the password (and the raised
                        // flag) reach the record's store BEFORE any
                        // filesystem mutation, so a restart still
                        // knows the password the user supplied even
                        // if power dies mid-unlock. A locked record
                        // is a HISTORY record - the store is the
                        // history store.
                        // A refusal does not stop the unlock - the
                        // password is live for the run being started
                        // here, and only the crash window's copy is
                        // lost - so it is reported through the log and
                        // the event ring, not in an answer the
                        // dashboard would read as a rejection.
                        d.history_publish_change(&job, "the archive password");
                        d.save_queue();
                    }
                    // C1: the job may be DOWNLOADING right now.
                    // Its task captured j.password once at start,
                    // so hand the live run this one through the
                    // hub cell too - the finish tail re-reads it
                    // (network drain + fallback ladder) and
                    // unlocks in THIS run instead of parking the
                    // job as password_required for a manual
                    // retry. Owner-tagged; a job that finishes
                    // between this write and the tail's read
                    // just parks exactly as it did before.
                    if d.active_stream.lock_ok().as_deref() == Some(id.as_str()) {
                        *d.hub.late_password.lock_ok() = Some((id.clone(), pw.clone()));
                        // The ask was answered - drop the live
                        // wants-a-password badge now rather than on
                        // the probe's next visit. A wrong password
                        // simply gets the flag raised again there.
                        let mut wanted = d.hub.password_wanted.lock_ok();
                        if wanted.as_deref() == Some(id.as_str()) {
                            *wanted = None;
                        }
                    }
                    if locked {
                        let d2 = d.clone();
                        let job2 = job.clone();
                        // `finalizing` is already up - raised in
                        // the snapshot acquisition above. unlock +
                        // finalize_names rewrite out_dir for many
                        // seconds on a large encrypted set, and
                        // history_change_cat's interlock is this
                        // flag - without it a category change
                        // moves the directory out from under the
                        // running extractor, and the two then race
                        // to write j.out_dir with whichever lands
                        // second winning.
                        tokio::task::spawn_blocking(move || {
                            // Cleared on EVERY exit below,
                            // including the unlock-failed path,
                            // or a wrong password would wedge the
                            // job as permanently finalizing.
                            struct ClearFinalizing(Arc<Mutex<Job>>);
                            impl Drop for ClearFinalizing {
                                fn drop(&mut self) {
                                    if let Ok(mut j) = self.0.lock() {
                                        j.finalizing = false;
                                    }
                                }
                            }
                            let _clear = ClearFinalizing(job2.clone());
                            // One password, so there is no sweep to
                            // stand down - but the same wrong blame:
                            // "the password did not unlock the archive"
                            // is what a refusal ABOUT THE DISK used to
                            // be reported as, to a user who had just
                            // typed the right one. See
                            // [`crate::smart::unlock`].
                            let unlocked = crate::smart::unlock(&out_dir, &pw);
                            if unlocked.is_ok() {
                                let post_year = match post_year_of(&nzb) {
                                    0 => crate::identify::current_year(),
                                    y => y,
                                };
                                let done = d2.finalize_names(
                                    &out_dir,
                                    &FinalizeJob {
                                        name: &name,
                                        cat: &cat,
                                        tv_sort: tv,
                                        post_year,
                                    },
                                );
                                let mut j = job2.lock_ok();
                                j.password_required = false;
                                // EVERY story the refused arm below can
                                // have written ends here - see
                                // [`crate::diag::unlock_answers`], which
                                // owns the list because that arm writes
                                // `unpack_failure` and so can carry the
                                // ladder's own reason rather than the
                                // literal beside it.
                                if crate::diag::unlock_answers(&j.fail_message) {
                                    j.clear_failure();
                                }
                                if !done.identify.is_empty() {
                                    j.identify = done.identify;
                                }
                                // C: the relocation runs on the mover
                                // worker now. Same contract as the
                                // completion path - a fresh unlock
                                // re-run starts with clean move fields
                                // and hands the move over rather than
                                // holding this tail for a NAS copy.
                                j.move_split.clear();
                                j.move_failed.clear();
                                j.move_attempts = 0;
                                j.move_pending = d2.move_destination_configured(&j.category);
                                let moved_to = done.moved.clone();
                                if let Some(dest) = done.moved {
                                    j.filed = j.tv_sort && is_season_dir(&dest);
                                    // The suffix and episode title
                                    // filing just used, kept for
                                    // the delete that will need
                                    // them later.
                                    j.filed_suffix = j.filed.then_some(done.suffix);
                                    j.filed_title = j.filed.then_some(done.filed_title);
                                    j.out_dir = dest;
                                }
                                let owes_move = j.move_pending;
                                drop(j);
                                // finalize_names may have MOVED the
                                // payload, so this is the movers'
                                // hazard on the unlock path.
                                d2.history_publish_move(&job2, &out_dir, moved_to.as_deref());
                                d2.save_queue();
                                if owes_move {
                                    d2.mover_enqueue(&job2);
                                }
                            } else {
                                let mut j = job2.lock_ok();
                                j.fail_message = crate::diag::unpack_failure(
                                    unlocked.err().flatten(),
                                    "password did not unlock the archive",
                                );
                                drop(j);
                                // Only the Reason line: the record is
                                // already parked as password_required
                                // and stays so. Log and carry on.
                                d2.history_publish_change(&job2, "the wrong-password note");
                                d2.save_queue();
                                info!(target: "unlock", "{name:?}: password did not unlock");
                            }
                        });
                        json!({"status": true, "unpacking": true})
                    } else {
                        // Nothing is running: the password is stored
                        // for whatever spends it later, a retry or a
                        // manual unlock. Same reasoning as the locked
                        // arm - the answer stays true.
                        d.history_publish_change(&job, "the archive password");
                        d.save_queue();
                        json!({"status": true})
                    }
                }
            }
        }
    })
}

/// §129 1b: the dashboard's ONE revisioned round-trip. The client hands
/// back the `queue_rev` / `history_rev` it last applied plus its events
/// cursor; an unchanged collection answers `null` instead of a payload,
/// so an idle 1 s refresh costs two atomic loads and a small stats
/// block - at ANY history size (the 1d gate). `stats` always rides (it
/// is small and changes by nature every second); the queue rides
/// whenever anything is actively transferring, because progress is a
/// continuous value no revision can honestly stand for. Lifecycle
/// events (job.completed / job.failed, seq-numbered) ride the same
/// response and replace the client's histSeen snapshot diffing.
///
/// Dashboard-only: the SAB and NZBGet facades are untouched by all of
/// this, and external clients keep their exact pre-§129 rows.
fn m_dashboard(
    d: &Arc<Daemon>,
    req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    let num = |k: &str| params.get(k).and_then(|v| v.parse::<u64>().ok());
    let (client_q, client_h) = (
        num("queue_rev").unwrap_or(0),
        num("history_rev").unwrap_or(0),
    );
    // An ABSENT events param is a fresh page priming its cursor: it
    // gets the current seq and no backlog (page loads never replay old
    // toasts). Any numeric cursor - zero included - gets everything
    // after it; treating 0 as "prime" swallowed a daemon's first-ever
    // event for a page that was already open watching.
    let since = num("events");
    // Revisions are read BEFORE the payloads are built: a mutation that
    // lands mid-build bumps past what we answer with, so the client
    // simply refetches next tick - stale-rev-with-fresh-payload is
    // harmless in that direction and impossible in the other.
    let qrev = d.queue_rev.load(Ordering::Relaxed);
    let hrev = d.history_rev.load(Ordering::Relaxed);
    let any_active = d.queue.lock_ok().iter().any(|j| {
        let g = j.lock_ok();
        matches!(g.state, JobState::Downloading | JobState::Finishing) || g.finalizing
    });
    let queue = if client_q != qrev || any_active {
        queue_json(d, params)
            .get("queue")
            .cloned()
            .unwrap_or(Value::Null)
    } else {
        Value::Null
    };
    let history = if client_h != hrev {
        let q = super::super::history::HistQuery {
            failed_only: false,
            category: params
                .get("hist_category")
                .filter(|c| !c.is_empty() && *c != "*")
                .cloned(),
            ids: None,
            search: params
                .get("hist_search")
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty()),
            bucket: params
                .get("hist_filter")
                .filter(|b| matches!(b.as_str(), "done" | "failed" | "locked"))
                .cloned(),
            start: num("hist_start").unwrap_or(0) as usize,
            // Never unbounded here: this is the per-second poll. A
            // client that wants more rows raises its window.
            limit: num("hist_limit").unwrap_or(50).clamp(1, 500) as usize,
        };
        let (slots, n, counts) = super::super::history::history_page(d, &q, true);
        json!({"slots": slots, "noofslots": n, "counts": counts})
    } else {
        Value::Null
    };
    // The cursor comes back from `life_since` itself, read under the
    // ring lock beside the batch: a separate load here could count an
    // event this answer does not carry, and the client - which adopts
    // whatever cursor it is handed - would never ask for it again.
    let (events, reset, events_seq) = match since {
        None => (Vec::new(), false, d.life_cursor()),
        Some(n) => d.life_since(n),
    };
    let stats = m_stats(d, req, params, ctx, api_body)?;
    Some(json!({
        "queue_revision": qrev,
        "queue": queue,
        "history_revision": hrev,
        "history": history,
        "stats": stats,
        "events": events,
        "events_seq": events_seq,
        "events_reset": reset,
    }))
}

fn m_stats(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        // Host resources for the dashboard's combined chart -
        // one getrusage + task_info + statvfs per poll, no
        // sampling thread. CPU% is % of ALL cores (0-100),
        // from the cpu-time delta since the previous poll;
        // sub-500 ms re-polls (a second open dashboard) reuse
        // the last reading instead of amplifying noise.
        //
        // §91: this block runs FIRST, before any of the live
        // counters below, because the disk walk can take
        // milliseconds. Sampling servers/verify/files and then
        // walking the disk shipped counters from before the walk
        // beside `downloaded` read after it - two instants in one
        // answer. Monotone snapshots come last, beside the build.
        let cpu_pct = d.cpu_pct();
        let (disk_free, disk_total) = disk_stat_walk(&d.out_dir()).unwrap_or((0, 0));
        // Phase 0(b) nested-archive prevalence (process lifetime):
        // how often nested layers appear, of what inner type, and
        // whether they streamed or demoted - real-world data for
        // future nested-format priorities.
        let nested_prevalence = {
            let np = nzbkit::extract::nested_prevalence();
            json!({
                "levels": np.levels,
                "in_stream": np.in_stream,
                "demoted": np.demoted,
                "disk": np.disk,
                "rar_store": np.rar_store,
                "rar_compressed": np.rar_compressed,
                "rar_encrypted": np.rar_encrypted,
                "sevenz": np.sevenz,
                "other": np.other,
            })
        };
        let live_servers: Vec<Value> = d
            .hub
            .pool_live
            .lock_ok()
            .as_ref()
            .map(|l| {
                l.servers
                    .iter()
                    .map(|s| {
                        json!({
                            "host": s.host,
                            "budget": s.budget.load(Ordering::Relaxed),
                            "connected": s.connected.load(Ordering::Relaxed),
                            "bytes": s.bytes.load(Ordering::Relaxed),
                            // This-run article dispatches + 430s so the UI can
                            // explain an idle provider: 0 conns with missing==tried
                            // means it doesn't have this content (430'd it all),
                            // not that it's broken.
                            "tried": s.articles_tried.load(Ordering::Relaxed),
                            "missing": s.articles_missing.load(Ordering::Relaxed),
                            // §35: why this server contributed
                            // nothing, in its own words. A user
                            // with one expired provider was
                            // paying for it on every download
                            // with nothing anywhere saying so.
                            "refused": s.refusal.lock_ok().as_ref().map(|r| {
                                json!({"permanent": r.permanent, "source_ips": r.source_ips, "line": r.line})
                            }),
                            // Granting NO sessions right now, and since
                            // when. `connected: 0` says the same about a
                            // worker mid-redial; this says it about a
                            // provider that is out, with a duration and
                            // a cause, while the job is still running.
                            // `refused` above covers only the sign-in
                            // flavour - an unreachable host produced
                            // nothing at all before this.
                            "down": s.down_secs().and_then(|secs| {
                                s.down_reason.lock_ok().as_ref().map(|r| json!({
                                    "secs": secs, "kind": r.kind, "detail": r.detail,
                                }))
                            }),
                            // Lifetime completion% (reliability
                            // ledger) for the Providers card.
                            "completion_pct": d.reliability(&s.host).map(|(t, m)| {
                                100.0 * (t.saturating_sub(m)) as f64 / t as f64
                            }),
                            // The two halves of "why did the graph
                            // dip". Sessions this server lost and
                            // redialled, against time its workers
                            // spent waiting on everything downstream
                            // of the network. One of them moving
                            // during a dip says which side to look
                            // at; neither moving says the dip was
                            // somewhere else entirely, which is also
                            // an answer and was previously
                            // unobtainable.
                            "reconnects": s.reconnects.load(Ordering::Relaxed),
                            "blocked_ms": s.blocked_ms.load(Ordering::Relaxed),
                            // Decay flag (conn-tuning design §6): the
                            // live tuner measured this host under half
                            // its usual per-connection rate on a
                            // sustained multi-stretch quorum.
                            "shaped": d.shaped_hosts.lock_ok().get(&s.host).map(|sh| json!({
                                "since": sh.since, "ref_per_conn_bps": sh.ref_per_conn_bps})),
                            // The connection ceiling this provider
                            // actually grants, when it has refused us
                            // one. `granted_hi` is the most sessions it
                            // was serving at a refusal, `capped_at` the
                            // count we were asking for then, and
                            // `since` the unix ms of the first refusal
                            // - absent entirely until a
                            // CAPACITY-classified refusal has been
                            // heard, so a row can never read a cap off
                            // an idle provider.
                            //
                            // Merged with the DAEMON's session map, not
                            // read from the pool alone: the pool is
                            // per-job, and a provider that granted 38
                            // of 100 during the last download is still
                            // granting 38 during this one. Max on both
                            // halves - either can be the fresher.
                            "capped": cap_payload(d, s),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        // The event ring, newest first. Timestamped in unix ms
        // because the dashboard's throughput trace carries wall
        // clock too - that is the whole point, laying one over the
        // other. Capped well under the ring so a long-lived daemon
        // cannot grow this payload without bound.
        let pool_events: Vec<Value> = {
            let mut evs: Vec<(u64, Value)> = d
                .hub
                .pool_live
                .lock_ok()
                .as_ref()
                .map(|l| {
                    l.recent_events(60)
                        .into_iter()
                        .map(|e| {
                            (
                                e.at_ms,
                                json!({"at_ms": e.at_ms, "host": e.host,
                                           "kind": e.kind, "detail": e.detail}),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            // The daemon's own ring - guard pauses, user actions,
            // sidecar starts, late picks. It outlives the pool
            // (pool_live is per-job), so the merged list is what
            // keeps markers on the chart between jobs. Host is
            // empty: these moments belong to the daemon, not to
            // one news server.
            evs.extend(d.recent_events(60).into_iter().map(|e| {
                (
                    e.at_ms,
                    json!({"at_ms": e.at_ms, "host": "",
                               "kind": e.kind, "detail": e.detail}),
                )
            }));
            // Newest first like each source ring, capped so the
            // payload stays bounded no matter how busy both were.
            evs.sort_by_key(|e| std::cmp::Reverse(e.0));
            evs.truncate(60);
            evs.into_iter().map(|(_, v)| v).collect()
        };
        // Idle: report the plan rather than nothing, so the card
        // stays up and the number in force is always visible.
        let servers: Vec<Value> = if live_servers.is_empty() {
            planned_servers(d, ctx.cfg_path)
        } else {
            live_servers
        };
        // §G: sorted by host so the card's rows do not reshuffle
        // between polls (a HashMap's order is not stable).
        let server_refusals: Vec<Value> = {
            let keep = d.last_refusals.lock_ok();
            let mut rows: Vec<&String> = keep.keys().collect();
            rows.sort_unstable();
            rows.into_iter()
                .filter_map(|h| {
                    keep.get(h).map(|r| {
                        json!({"host": h, "permanent": r.permanent, "source_ips": r.source_ips,
                                   "line": r.line, "at": r.at})
                    })
                })
                .collect()
        };
        let (vdone, vbad, vtotal) = d
            .hub
            .verifier
            .lock_ok()
            .as_ref()
            .map(|v| {
                let (done, bad) = v.live_counts();
                // Every adopted set (TODO 311) - the progress denominator
                // is how many blocks this job will verify, and on a
                // per-file-set post that is all of them.
                let total: u64 = v
                    .sets()
                    .iter()
                    .flat_map(|s| s.files.iter())
                    .map(|f| f.blocks.len() as u64)
                    .sum();
                (done, bad, total)
            })
            .unwrap_or((0, 0, 0));
        let files: Vec<Value> = d
            .hub
            .extractor
            .lock_ok()
            .as_ref()
            .map(|(_owner, ex)| {
                let mut ws = ex.writers_snapshot();
                ws.sort_by_key(|(_, w)| std::cmp::Reverse(w.size));
                ws.into_iter()
                    .take(12)
                    .map(|(name, w)| {
                        json!({
                            "name": name,
                            "size": w.size,
                            "written": w.written(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        // §91: the lane's two halves as one pair (active_counters).
        let (dl_done, dl_total, _) = active_counters(d);
        json!({
            "active": d.started_at.lock_ok().is_some(),
            "downloaded": dl_done,
            "total": dl_total,
            "servers": servers,
            "events": pool_events,
            // §G: the same refusals, kept past the pool that saw
            // them. `servers` above is empty whenever nothing is
            // downloading, which took the Providers card - and with
            // it the only place that said a provider had rejected
            // the sign-in - off the page at exactly the moment
            // someone would go looking for why.
            "server_refusals": server_refusals,
            "verify": {"blocks_done": vdone, "blocks_bad": vbad, "blocks_total": vtotal},
            "files": files,
            "host": {
                "cpu_pct": (cpu_pct * 10.0).round() / 10.0,
                "rss_bytes": nzbkit::mem::dashboard_rss().unwrap_or(0),
                "rss_peak_bytes": nzbkit::mem::peak_rss().unwrap_or(0),
                "rss_budget": d.mem_budget_total,
                "disk_free_bytes": disk_free,
                "disk_total_bytes": disk_total,
                // Cumulative engine disk writes - the client
                // derives a live write rate from the deltas.
                "disk_write_bytes": nzbkit::disk::bytes_written(),
            },
            "nested_prevalence": nested_prevalence,
            // Instrument-first perf counters: see api/system.rs.
            "instrumentation": super::system::instrument_counters(),
            // Status chip strip: background subsystems active right
            // now, as short tokens the page maps to chip.* phrases.
            // Queue-side states ride the slots, never this list.
            "busy": d.busy.active(),
        })
    })
}

fn m_addfile(
    d: &Arc<Daemon>,
    req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        // Multipart body: extract the first file part.
        // Same parse the gateway used to fill `api_body` - one
        // helper, so a mixed-case `Boundary=` cannot be
        // multipart there and not here.
        let boundary = req
            .headers()
            .iter()
            .find(|h| h.field.equiv("Content-Type"))
            .and_then(|h| multipart_boundary(h.value.as_str()));
        // Generous: an NZB for a 190 GB job is tens of MB.
        // The form pre-read above may already hold the body.
        let raw = api_body.take().unwrap_or_default();
        match boundary.and_then(|b| multipart_file(&raw, &b)) {
            Some((fname, bytes)) => {
                // Sonarr and Radarr send the release name in
                // `nzbname` on addfile as well as addurl, and
                // only addurl was reading it - so the job took
                // its name from the multipart filename, which
                // for a Prowlarr-proxied grab is a numeric id.
                // `origin_of` has meanwhile been treating the
                // presence of this very parameter as the "an
                // *arr sent this" signal.
                let fname = params
                    .get("nzbname")
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .unwrap_or(fname);
                let cat = params.get("cat").cloned().unwrap_or_default();
                let cat = if cat == "*" { String::new() } else { cat };
                let pw = params.get("password").map(String::as_str);
                // stream=1: watch-while-downloading add - Force
                // priority (starts next even while paused) and
                // the response carries the player-handoff links.
                let stream = params.get("stream").map(String::as_str) == Some("1");
                let prio = if stream { 2 } else { param_priority(params) };
                let origin = api_origin(ctx.ua_hdr, origin_of(params));
                // The requested pp rides into enqueue so the pre-queue
                // hook can see it (L6); record_add_params below still
                // owns recording it on the job.
                let pp = sab_pp_param(params.get("pp").map(String::as_str));
                match d.enqueue(&bytes, &fname, &cat, prio, pp, pw, &origin, false) {
                    // §129 2b: pp=/script= used to be accepted and
                    // silently dropped; now they are recorded on the
                    // job (and the pp mapping logged - decision 5).
                    //
                    // Truth-audit I: a job parked as a held
                    // ALTERNATIVE has NOT joined the queue to run,
                    // and "Added to the queue" was the reply either
                    // way. `held` carries the ids that parked, so
                    // the add flow can say which.
                    Ok(Enqueued { nzo_id: id, .. }) => {
                        d.record_add_params(
                            &id,
                            params.get("pp").map(String::as_str),
                            params.get("script").map(String::as_str),
                            ctx.via_add_only,
                        );
                        if stream {
                            json!({
                                "status": true, "nzo_ids": [id],
                                // Both links carry the JOB's own token and
                                // never the API key: `nzbfast stream` hands
                                // the m3u one to a media player as argv,
                                // which every other local account can read
                                // (TODO 23 low1, CLI half). /m3u accepts it.
                                "m3u": format!("{}/m3u/{id}?t={}", ctx.base, d.stream_token(&id)),
                                "stream": format!("{}/stream/{id}?t={}", ctx.base, d.stream_token(&id)),
                            })
                        } else {
                            json!({
                                "status": true, "nzo_ids": [id],
                                "held": if d.held_as_duplicate(&id) { vec![id] } else { vec![] },
                            })
                        }
                    }
                    Err(e) => json!({"status": false, "error": e.to_string()}),
                }
            }
            None => json!({"status": false, "error": "no nzb file in request"}),
        }
    })
}

fn m_addurl(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let url = params.get("name").cloned().unwrap_or_default();
        let cat = params.get("cat").cloned().unwrap_or_default();
        let cat = if cat == "*" { String::new() } else { cat };
        // An explicit `nzbname` wins. Without one the name has to come
        // off the fetch itself: a Prowlarr redirect grab (issue #26)
        // sends only the indexer's download URL, whose last path
        // segment is an id hash - the release name arrives in the
        // response's Content-Disposition, so naming from the URL alone
        // titled the job `chsfsd12das32da90aa3181`.
        let explicit = params
            .get("nzbname")
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let pw = params.get("password").cloned();
        let stream = params.get("stream").map(String::as_str) == Some("1");
        let prio = if stream { 2 } else { param_priority(params) };
        let origin = api_origin(ctx.ua_hdr, origin_of(params));
        match fetch_url(&url) {
            Ok(f) => {
                let name = explicit
                    .or_else(|| name_from_fetch(&f, &url))
                    .unwrap_or_else(|| "download.nzb".to_string());
                let pp = sab_pp_param(params.get("pp").map(String::as_str));
                match d.enqueue_fetched(
                    &f,
                    &name,
                    &cat,
                    prio,
                    pp,
                    pw.as_deref(),
                    0,
                    &origin,
                    DupeExempt::Nobody,
                ) {
                    // §129 2b: same pp=/script= recording as addfile.
                    Ok(Enqueued { nzo_id: id, .. }) => {
                        d.record_add_params(
                            &id,
                            params.get("pp").map(String::as_str),
                            params.get("script").map(String::as_str),
                            ctx.via_add_only,
                        );
                        if stream {
                            json!({
                                "status": true, "nzo_ids": [id],
                                // Both links carry the JOB's own token and
                                // never the API key: `nzbfast stream` hands
                                // the m3u one to a media player as argv,
                                // which every other local account can read
                                // (TODO 23 low1, CLI half). /m3u accepts it.
                                "m3u": format!("{}/m3u/{id}?t={}", ctx.base, d.stream_token(&id)),
                                "stream": format!("{}/stream/{id}?t={}", ctx.base, d.stream_token(&id)),
                            })
                        } else {
                            json!({
                                "status": true, "nzo_ids": [id],
                                "held": if d.held_as_duplicate(&id) { vec![id] } else { vec![] },
                            })
                        }
                    }
                    Err(e) => json!({"status": false, "error": e.to_string()}),
                }
            }
            Err(e) => json!({"status": false, "error": e.to_string()}),
        }
    })
}

fn m_addnzblnk(
    d: &Arc<Daemon>,
    req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        // A long article-id list outgrows the request line, and an
        // nzblnk password (p=) must not ride it - see
        // `merge_body_params`.
        let params = &merge_body_params(req, params, api_body);
        // `link` is ours; `name` is where addurl puts its
        // URL, so a caller that treats the two modes alike
        // still works.
        let raw = params
            .get("link")
            .or_else(|| params.get("name"))
            .cloned()
            .unwrap_or_default();
        match nzbkit::nzblnk::parse(&raw) {
            // `reason` is the stable, machine-readable half:
            // the dashboard says these two in the user's own
            // language rather than echoing English back.
            Err(e) => {
                json!({"status": false, "reason": "badlink", "error": e.to_string()})
            }
            Ok(l) => {
                let cat = params.get("cat").cloned().unwrap_or_default();
                let cat = if cat == "*" { String::new() } else { cat };
                let prio = param_priority(params);
                let dupe_ok = params.get("dupe_ok").map(String::as_str) == Some("1");
                let pw = (!l.password.is_empty()).then(|| l.password.clone());
                // The TRANSPORT peer, not a forwarded header: the gate
                // keys its per-peer window on this, and a header the
                // caller writes would hand a page in a loop as many
                // buckets as it cared to name.
                let peer = crate::serve::httputil::peer_ip(req);
                resolve_nzblnk(d, &l, &cat, prio, pw.as_deref(), dupe_ok, peer)
            }
        }
    })
}

fn m_watch_failed_delete(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let want = params.get("value").cloned().unwrap_or_default();
        let path = {
            let wf = d.watch_failed.lock_ok();
            wf.keys()
                .find(|p| crate::serve::tasks::watch_fail_id(p) == want)
                // Name fallback for any caller still addressing the
                // row the old way. Ambiguous by construction, which
                // is the whole finding - but refusing it outright
                // would break a script for a collision almost
                // nobody has.
                .or_else(|| {
                    wf.keys()
                        .find(|p| p.file_name().is_some_and(|f| f.to_string_lossy() == want))
                })
                .cloned()
        };
        match path {
            None => json!({"status": false, "error": "no such rejected file"}),
            Some(p) => match std::fs::remove_file(&p) {
                Ok(()) => {
                    // The bumping helper, not a bare map remove: without
                    // the queue_rev bump the deleting tab itself kept
                    // rendering the row it had just deleted (the payload
                    // skip in m_dashboard), and the retry then answered
                    // "no such rejected file".
                    d.watch_failed_remove(&p);
                    // The full path, not the basename: whose
                    // `same.nzb` this was is exactly what a reader
                    // of this line needs to know.
                    info!(target: "watch", "deleted rejected {}", p.display());
                    json!({"status": true})
                }
                Err(e) => json!({"status": false, "error": e.to_string()}),
            },
        }
    })
}

/// §188: the user has read the "history display was updated" strip.
fn m_hist_upgraded_dismiss(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some(json!({"status": d.dismiss_hist_migrate()}))
}

fn m_delete_kept_dismiss(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some(json!({"status": spend_kept_notice(d, &params.get("value").cloned().unwrap_or_default())}))
}

/// Take one kept-files notice off the ring, and with it the spooled NZB
/// it was holding for its "download it again" button.
///
/// Both ends of that notice's life go through here - dismissed by the
/// user, or spent by the retry - because the file is reachable through
/// nothing else once the notice is gone, and a delete that leaves an
/// unnamed file in the spool is the shape this whole notice exists to
/// complain about.
///
/// Being the one door is also why the `queue_rev` bump lives here. The
/// strip rides the revisioned queue payload (§129 1b), and `m_dashboard`
/// answers `queue: null` while `client_q == qrev` - so a page re-renders
/// the notice from the payload it already holds, and a removal that does
/// not move the revision clears the ring on the daemon and NOWHERE else.
/// The dismiss button fired, the daemon answered `{"status":true}`, and
/// the notice sat there until an unrelated queue mutation or a reload
/// (reported by a Windows tester, 16 Aug 2026). Only an IDLE daemon can
/// show it: `m_dashboard` re-sends the payload every second whenever
/// anything is transferring, which is why it never showed up in
/// development. Fifth instance of the payload-rider trap after the
/// update banner, `set_limit`, `watch_failed_*` and `publish_hold`.
///
/// `pub(in crate::serve)` for the daemon-side test that pins the bump -
/// the ring and its revision are serve-wide state, not this module's.
pub(in crate::serve) fn spend_kept_notice(d: &Arc<Daemon>, path: &str) -> bool {
    let gone = {
        let mut k = d.delete_kept.lock_ok();
        let before = k.len();
        for note in k.iter().filter(|n| n.path == path) {
            drop_kept_nzb(note);
        }
        k.retain(|n| n.path != path);
        k.len() < before
    };
    // Persist it, or the notice the user just cleared comes back at the
    // next restart. The bump rides with it, and only on the arm that
    // actually removed something - bumping on a no-op would re-send the
    // whole queue payload to every idle tab.
    if gone {
        d.queue_rev.fetch_add(1, Ordering::Relaxed);
        d.save_delete_kept();
    }
    gone
}

/// "Download it again" on a kept-files notice: re-add the very release
/// whose delete half-failed, from the spool copy that delete held back.
///
/// The point is where the user is standing. The notice already names the
/// release and the folder, on screen, at the moment they find out the
/// files are still there - and until now the only way to act on it was
/// to leave, find the NZB or the indexer entry again, add it by hand,
/// and then get past a duplicate hold. Every step of that is a chance to
/// give up on a download they had already asked for twice.
///
/// `allow_dupe`, deliberately: this add IS the answer to a delete, and
/// nothing about it should be parked behind an older copy of the same
/// identity. The recent-delete mark says the same thing for a re-add
/// made any other way; this path does not need to consult it, because a
/// user pressing the button on the notice is as explicit as it gets.
///
/// The notice goes when the add succeeds - it has been acted on, and a
/// row in the queue is a better handle on the download than a warning
/// strip. It stays on a failure, with the reason, because the folder is
/// still there either way.
fn m_delete_kept_retry(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some(retry_kept_notice(
        d,
        &params.get("value").cloned().unwrap_or_default(),
    ))
}

/// Test seam for [`retry_kept_notice`]: milliseconds to sit on a
/// claimed notice before admitting it. Read by nothing else, so only
/// the test that sets it can be delayed by it - and a sleep, not a
/// barrier, because a stray waiter on a two-party barrier HANGS the
/// parallel bin run rather than failing it.
#[cfg(test)]
pub(in crate::serve) static KEPT_RETRY_STALL_MS: AtomicU64 = AtomicU64::new(0);

/// The body of [`m_delete_kept_retry`], out of the handler so the suite
/// can run two of them at once - the race it guards against is the
/// whole reason the notice is CLAIMED rather than cloned.
pub(in crate::serve) fn retry_kept_notice(d: &Arc<Daemon>, path: &str) -> Value {
    // The notice is the ONLY source for the spool path. Taking one from
    // the request would let any caller hand us an arbitrary file to
    // read and enqueue.
    //
    // Taken OFF the ring here, in the same critical section that finds
    // it, and put back below if the add fails. Finding-then-cloning let
    // two calls both pass this test: http.rs runs eight worker threads
    // over the one listener, so two dashboard tabs (or a tab and a
    // scripted call, or a retried request) genuinely overlap, and the
    // notice was only removed AFTER a successful admission - a window
    // spanning a file read, a whole NZB parse and a directory claim.
    // Both adds carry allow_dupe, so nothing held the second one, and
    // `choose_out_dir` gave it its own suffixed folder: one press, two
    // complete downloads of the same release (Codex sweep 3, L3). The
    // loser now gets the ordinary "that notice is gone" answer.
    let claimed = {
        let mut k = d.delete_kept.lock_ok();
        let at = k.iter().position(|n| n.path == path && !n.nzb.is_empty());
        at.and_then(|at| k.remove(at).map(|note| (at, note)))
    };
    let Some((at, note)) = claimed else {
        return json!({"status": false,
                      "error": "that notice is gone, or it has no copy of the NZB to \
                                add again - find the release and add it as usual"});
    };
    // An unspent notice goes back where it was: the folder is still
    // sitting there, so the strip and its button have to survive a
    // failure. The revision bump rides with it for the same reason
    // `note_delete_kept` carries one - a tab that refreshed inside the
    // claim would otherwise never see the notice again.
    let restore = |note: KeptNote| {
        {
            let mut k = d.delete_kept.lock_ok();
            let at = at.min(k.len());
            k.insert(at, note);
        }
        d.queue_rev.fetch_add(1, Ordering::Relaxed);
        d.save_delete_kept();
    };
    let bytes = match std::fs::read(&note.nzb) {
        Ok(b) => b,
        Err(e) => {
            restore(note);
            return json!({"status": false, "error": e.to_string()});
        }
    };
    // Test seam: hold the window between reading the spool copy and
    // admitting it open, so the suite can run a second retry of the
    // same notice inside it. In production that window is a full NZB
    // parse plus a directory claim wide; in a test it is zero.
    #[cfg(test)]
    {
        let ms = KEPT_RETRY_STALL_MS.load(Ordering::Relaxed);
        if ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(ms));
        }
    }
    match d.enqueue(
        &bytes,
        &note.name,
        "",
        SAB_DEFAULT_PRIORITY,
        None,
        None,
        "dashboard",
        true,
    ) {
        Err(e) => {
            restore(note);
            json!({"status": false, "error": e.to_string()})
        }
        Ok(Enqueued { nzo_id, .. }) => {
            // Spent: the notice has done its job, and the spool copy it
            // was holding is now `enqueue`'s problem (it writes its
            // own). Same three steps `spend_kept_notice` takes - the
            // notice is already off the ring, so only the file and the
            // two persistence duties are left.
            drop_kept_nzb(&note);
            d.queue_rev.fetch_add(1, Ordering::Relaxed);
            d.save_delete_kept();
            info!(
                target: "queue",
                "{nzo_id}: {:?} added again from its kept-files notice",
                note.name
            );
            json!({"status": true, "nzo_id": nzo_id, "name": note.name})
        }
    }
}

fn m_queue_save(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let queue_ok = d.save_queue();
        // "Save queue" is the remedy the durability errors name, and
        // since §129 1a the history record lives in its own store - a
        // full flush has to rewrite that too, or the remedy would not
        // remedy a failed history write. Its outcome is part of the
        // answer: reporting success off save_queue alone told the user
        // the remedy had worked while the half they were being told to
        // remedy had failed again (H3, 10 Aug sweep).
        let hist_ok = d.history_compact();
        let saved = queue_ok && hist_ok;
        if saved {
            info!(target: "queue", "queue re-saved on request");
        }
        json!({"status": saved, "saved": saved,
        "error": match (queue_ok, hist_ok) {
            (true, true) => Value::Null,
            (true, false) => json!("the queue was written, but the history could \
                   not be - check free space and write permission on the data \
                   folder"),
            _ => json!("the queue still could not be written - check free space \
                   and write permission on the data folder"),
        }})
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
    Some(match mode {
        "pause" => return m_pause(d, req, params, ctx, api_body),
        "resume" => return m_resume(d, req, params, ctx, api_body),
        // The instant sibling of the idle-release timeout: hang
        // up everything now, so the account is usable from
        // another machine without waiting one out.
        "offline" | "online" => {
            let want = mode == "offline";
            d.set_offline(want);
            json!({"status": true, "offline": want})
        }
        // M23d: airdate calendar - episodes of watched shows
        // from a week back to three weeks out, joined with what
        // the watcher has grabbed. String compares work because
        // dates are ISO "YYYY-MM-DD".
        #[cfg(feature = "indexer")]
        "watch_calendar" => return m_watch_calendar(d, req, params, ctx, api_body),
        // M23: run a watchlist pass immediately (after an edit,
        // or just impatience).
        "watchlist_check_now" => {
            d.watch_now.notify_one();
            json!({"status": true})
        }
        // M23: items with what's been grabbed for each - the
        // dashboard's per-row status line.
        "watchlist_status" => return m_watchlist_status(d, req, params, ctx, api_body),
        // §151: sync every external list source now, rather than at its
        // own interval. Writes ENTRIES only - the watchlist pass still
        // decides what is grabbed, so this cannot start a download on
        // its own any more than editing the list can.
        "list_sync_now" => {
            d.lists.now.notify_one();
            json!({"status": true})
        }
        // §151: link a Plex account, without a password ever reaching
        // us. We ask plex.tv for a code, the user approves it on Plex's
        // own page, and we poll until a token appears. The token is
        // written onto the source and NEVER returned to the browser.
        "plex_link_start" | "plex_link_poll" | "plex_forget" => {
            let v = params.get("value").map(String::as_str).unwrap_or_default();
            let r = match mode {
                "plex_link_start" => v
                    .parse::<u64>()
                    .map_err(|_| "which list source?".to_string())
                    .and_then(|id| listsrc::plex_link_start(d, id)),
                "plex_link_poll" => listsrc::plex_link_poll(d, v),
                _ => v
                    .parse::<u64>()
                    .map_err(|_| "which list source?".to_string())
                    .and_then(|id| listsrc::plex_forget(d, id)),
            };
            match r {
                Ok(v) => v,
                Err(e) => json!({"status": false, "error": e}),
            }
        }
        // §96.3 bundle D: what the give-up breaker is counting, and what
        // it has already stopped chasing. The breaker used to act - it
        // unmonitors things inside the user's Sonarr - with its whole
        // state in a spool file and not one endpoint that would name it.
        //
        // Read surface, so full key like the rest of /api (the add-only
        // NZB key reaches addfile/addurl/version/status/get_cats and
        // nothing else). Reporting ONLY: listing a target changes no
        // decision, and there is still exactly one path that grabs.
        "giveup_status" => return m_giveup_status(d, req, params, ctx, api_body),
        // "Try again" on a given-up target: forget its counters, which
        // also re-arms the action latch (see GiveupState::clear_target -
        // exactly what a completed download does). The watchlist pass
        // stops skipping the target on its next round; for an *arr
        // target the user re-monitors it in the *arr, which is theirs to
        // do - we never re-monitor on our own initiative, the same way
        // we never grab on our own outside the one path.
        "giveup_reset" => return m_giveup_reset(d, req, params, ctx, api_body),
        // Recategorize a QUEUED job. The NZBGet facade has had
        // this as `GroupSetCategory` since M26 and the SAB side
        // only ever had the history-item form, so which client
        // type the user picked decided whether it worked.
        //
        // Nothing has been written yet, so unlike the history
        // form this moves no files - it re-derives the output
        // directory under the new category, which is exactly what
        // a retry does.
        "change_cat" => return m_change_cat(d, req, params, ctx, api_body),
        "retry" => {
            let id = params.get("value").cloned().unwrap_or_default();
            // The *arrs adopt the returned nzo_id as the new
            // tracking id (SAB may reissue; we keep it stable).
            json!({"status": d.retry(&id), "nzo_id": id})
        }
        // Re-attempt ONLY the move to the completed folder for a
        // Completed history job whose move failed (Job::move_failed).
        // The drawer's own retry button: `retry` above would re-queue
        // a download that is already whole on disk.
        "retry_move" => {
            let id = params.get("value").cloned().unwrap_or_default();
            json!({"status": d.retry_move_now(&id), "nzo_id": id})
        }
        // TODO 101: this job's own consent to the volume-eating unpack,
        // given in the disk-full drawer. Consent only - it starts
        // nothing; the caller retries the job afterwards, and the
        // decision is taken again there against the gates that matter
        // (mode, verified, forecast).
        //
        // Refused outright unless the mode is `low_disk`, so a stale
        // dashboard tab cannot arm a job on a daemon whose setting has
        // since gone back to `off`. `always` needs no per-job answer.
        // §282 item 12: switch a doomed download for a spare that is
        // already held for it. Nothing on this path searches, and
        // nothing on it runs without this call - the queue row draws
        // the notice and the button from `alt_offer`, and the user
        // clicks.
        "alt_switch" => return m_alt_switch(d, req, params, ctx, api_body),
        // §282 item 20: the other button item 12 described and did not
        // build. With nothing held, search for a copy of the same
        // release and show what was found, ranked, for the user to pick.
        // The search spends no grab and enqueues nothing; the pick below
        // spends one grab and goes through `alt_switch` itself.
        "alt_hunt" => return m_alt_hunt(d, req, params, ctx, api_body),
        "alt_hunt_pick" => return m_alt_hunt_pick(d, req, params, ctx, api_body),
        "eat_volumes" => return m_eat_volumes(d, req, params, ctx, api_body),
        // M24: attach an archive password to a job. Queued jobs
        // use it at completion; a history job flagged
        // password_required gets an immediate background unlock
        // attempt (+ pending TV filing once the video appears).
        "set_password" => return m_set_password(d, req, params, ctx, api_body),
        // M14h: live pool + pipeline stats of the active download -
        // the overlapping-lanes view no sequential client can draw.
        "stats" => return m_stats(d, req, params, ctx, api_body),
        "addfile" => return m_addfile(d, req, params, ctx, api_body),
        // §303: the add dialog's dry run - the §294 completable verdict
        // over POSTed NZB bytes, nothing enqueued. Full-key only, like
        // every mode not on the add-only allowlist: it spends provider
        // round trips.
        "nzb_preview" => return preview::m_nzb_preview(d, req, params, ctx, api_body),
        "addurl" => return m_addurl(d, req, params, ctx, api_body),
        // NZBLNK: a link with no NZB behind it. The German and
        // Dutch boards hand out `nzblnk:?h=…` instead of a file
        // because the posting is obfuscated - there is nothing
        // to link to until somebody has scanned the group - and
        // the client is expected to resolve the header itself.
        //
        // We own both halves already, so the ladder is short and
        // in cost order:
        //   1. our own header index, which needs no network at
        //      all and can emit the NZB from stored segment ids;
        //   2. the user's configured indexers over the M35
        //      client, under the same daily budgets and backoff
        //      every other pull search obeys.
        // Deliberately NOT in the add-only key's allowlist: rung
        // 2 spends the user's indexer quota, which an add-only
        // credential has no business doing.
        //
        // `p` becomes the job password, so the existing
        // password-chain unlock opens the archive without the
        // user pasting it anywhere; `t` becomes the job name.
        "addnzblnk" => return m_addnzblnk(d, req, params, ctx, api_body),
        // Delete a rejected watch-folder file. Only files currently in
        // the failed set can be deleted - `value` is matched against
        // tracked paths, never joined to a path, so it can't reach
        // anything else on disk.
        //
        // By IDENTITY first, name second (Codex sweep 2, 3 Aug L1). The
        // queue payload used to expose only `file_name()`, and deletion
        // took the first tracked path whose basename matched: change
        // the watch directory while a rejected `same.nzb` sits in the
        // old one and the new one, and the list shows two
        // indistinguishable rows while HashMap iteration order decides
        // which file is permanently deleted. `watch_fail_id` is an
        // opaque digest of the full tracked path - enough to name a row
        // exactly, without handing the browser the path itself.
        "watch_failed_delete" => return m_watch_failed_delete(d, req, params, ctx, api_body),
        // Dismiss one kept-files notice by PATH. Acknowledgement only -
        // it drops the entry from the ring and touches nothing on disk.
        // Deliberately not a "delete it anyway" button: that is the
        // permanent delete 70990f19 stopped us from performing on the
        // user's behalf, and a one-click version of it in a notice they
        // are trying to clear is the same mistake with a confirmation
        // step. The way to get a permanent delete is still to turn
        // "Deleted files go to the Trash" off and mean it.
        "delete_kept_dismiss" => return m_delete_kept_dismiss(d, req, params, ctx, api_body),
        "hist_upgraded_dismiss" => {
            return m_hist_upgraded_dismiss(d, req, params, ctx, api_body);
        }
        // ...and the other half of that notice: add this release again,
        // from the spool copy the refused delete kept. The one action
        // the notice can offer that is not a permanent delete - it adds
        // a download, and touches nothing that is already on disk.
        "delete_kept_retry" => return m_delete_kept_retry(d, req, params, ctx, api_body),
        // Re-attempt the queue write. For the watch-folder state where a
        // release IS live in the queue but `queue.json` could not be
        // written - so the user's .nzb was deliberately kept as the only
        // recovery copy. The strip could describe that and not act on it:
        // nothing else in the API forces the write, and the user's real
        // question ("did it stick this time?") had no way to be asked.
        "queue_save" => return m_queue_save(d, req, params, ctx, api_body),
        // TODO 274 (issue #51): per-file inspection, SAB-shaped. The
        // reporter builds one client against three backends, so the
        // surface is `get_files` where SAB puts it and the file
        // operation hangs off `mode=queue` where SAB puts its own -
        // see api/queue/files.rs.
        "get_files" => return files::m_get_files(d, req, params, ctx, api_body),
        "queue" => return m_queue(d, req, params, ctx, api_body),
        "history" => return m_history(d, req, params, ctx, api_body),
        "dashboard" => return m_dashboard(d, req, params, ctx, api_body),
        _ => return None,
    })
}

/// The queued-recategorize transaction, shared by the SAB `change_cat`
/// arm above and the NZBGet `GroupSetCategory` facade - category
/// controls filesystem routing, so relabelling without re-deriving
/// `out_dir` under `add_lock` splits the record from the download.
///
/// Choosing a directory and publishing it have to be ONE transaction,
/// under the same lock `add` uses: between the `dir_claim` probe and the
/// assignment, this job still names its OLD directory, so a concurrent
/// add reads the new one as Free and takes it - two jobs writing one
/// folder, which is the hole the 2 Aug sweep closed for `add`.
///
/// Codex H5: the caller's Queued snapshot released every lock before
/// this point, and the scheduler flips a picked job to Downloading AND
/// snapshots its out_dir in one job-lock critical section - so a job
/// that started while `refile_out_dir` walked the lists would download
/// into the OLD directory while its record names the new one.
/// Re-validate under the same job lock the write needs: either the flip
/// already happened (refuse), or this write lands first and the
/// scheduler snapshots the new path.
///
/// Taken with no queue/history/job lock held - `add_lock` sits above all
/// three, and `dir_claim` locks every job in both lists. Not reentrant
/// with `history_change_cat`, which takes `add_lock` itself.
///
/// The `save_queue` is the CALLER's, taken with the fence still held
/// and its verdict CHECKED: the SAB `change_cat` arm persists one fence
/// through `persist_relocations`, the rename doors and the NZBGet
/// category arm batch theirs (N jobs, one queue.json rewrite), and a
/// refused save rolls the whole relocation back - record and bytes -
/// so a restart restores a row that still agrees with the tree (Codex
/// C10). Not done here: both rename doors mutate again after this
/// returns - `name`, then the password - so a save here would persist a
/// half-applied record instead of the whole transaction.
///
/// Codex F-06: returns the relocation fence, and the caller decides when
/// it lifts. Every arm that only re-files gets what it wants by dropping
/// the guard at the end of its own statement - the fence then covers the
/// publish and the move, which is the whole window this call owns.
/// `rename_queued` binds it instead, because it writes `name` AFTER this
/// returns and a job started in that second gap would carry the old
/// label into `job.started` beside the new-name-derived directory. See
/// [`Job::relocating`] for what the fence is and who honours it.
#[must_use = "the relocation fence lifts when this guard drops - bind it \
              if the transaction continues past this call"]
pub(in crate::serve) fn requeue_category(
    d: &Arc<Daemon>,
    job: &Arc<Mutex<Job>>,
    name: &str,
    cat: &str,
) -> Result<Relocation, &'static str> {
    // Test hook: hold the window between the caller's Queued snapshot
    // and the publish below open, so the suite can start the job inside
    // it (the H5 race). No effect unless the suite sets it.
    if let Some(ms) = std::env::var("NZBFAST_TEST_STALL_CHANGE_CAT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
    let _publish = d.add_lock.lock_ok();
    let (dir, _) = refile_out_dir(&d.out_root.read_ok().clone(), cat, name, &|p| {
        d.dir_claim(p)
    });
    // The publish and the fence are ONE job-lock critical section, and
    // they have to be: `start_next` flips the state to Downloading and
    // snapshots `out_dir` in a critical section of its own, so anything
    // this call does in two of them can be split by a start. Either the
    // runner gets there first and the Queued check below refuses this
    // whole transaction, or this lands first and the runner reads the
    // fence. There is no third ordering (Codex F-06, extending the H5
    // refusal that shares this critical section).
    let (fence, old_dir) = {
        let mut g = job.lock_ok();
        if g.state != JobState::Queued {
            return Err("job already started");
        }
        let old_cat = std::mem::replace(&mut g.category, cat.to_string());
        let old_dir = std::mem::replace(&mut g.out_dir, dir.clone());
        g.relocating += 1;
        (
            Relocation {
                job: job.clone(),
                old_cat,
                old_dir: old_dir.clone(),
                new_dir: dir.clone(),
            },
            old_dir,
        )
    };
    d.register_cat(cat);
    // A queued job can be RUNNING in the prefetch sidecar, against the
    // directory this call has just re-pointed away from. Every further
    // byte it fetches lands in a folder the record has left, and its
    // result is void the moment the write above lands (the directory is
    // part of the sidecar's ownership stamp), so the fetch is spending
    // provider quota on nothing. Stop it - and its exit path moves what
    // it did fetch to the new directory, so the primary run resumes
    // from the journal instead of downloading the release twice
    // (read-only sweep 2, M7).
    //
    // With `add_lock` RELEASED. `spawn_sidecar` takes the sidecar slot
    // and then the job lock under it, so signalling from under the
    // publish lock would put a third mutex into that order for no
    // reason: by here the record already says where it belongs, and the
    // signal is about the fetch, not about the decision.
    let id = job.lock_ok().nzo_id.clone();
    drop(_publish);
    // Test hook: hold the FENCED window open - the destination is
    // published and the bytes behind it have not moved yet. The hook at
    // the top cannot see this window at all, because it fires before the
    // publish: it proves the H5 refusal, where a job that starts makes
    // the whole transaction fail. Here the transaction has already
    // succeeded and the question is whether the runner honours the
    // fence. No effect unless the suite sets it.
    if let Some(ms) = std::env::var("NZBFAST_TEST_STALL_RELOCATE_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
    // ...and when there is no sidecar to poke, THIS call owes the move.
    // The adoption above only ever runs on a prefetch task's exit path,
    // so a job that was prefetched and then stopped - an error, a pause,
    // an earlier poke - leaves its journal and part-files in the old
    // directory with the slot already empty. The recategorize then
    // pointed the record somewhere else and pokes nothing, so the
    // primary run started at the new directory from zero and refetched
    // the whole release, and the old folder was named by no record at
    // all (Codex sweep 3, M12). Both halves are guarded by
    // `from.exists()`, so the live case and this one cannot double-move.
    if !d.poke_sidecar(|i| i == id) && old_dir != dir && old_dir.exists() {
        match crate::smart::move_tree(&old_dir, &dir) {
            Ok(()) => info!(
                target: "queue",
                "{id}: moved the earlier progress from {} to {} - the release was \
                 re-filed while it was queued, so nothing has to be fetched twice",
                old_dir.display(),
                dir.display()
            ),
            // Not fatal to anything: the record is correct and the job
            // simply downloads again. Say where the abandoned bytes are,
            // because nothing else will.
            Err(e) => warn!(
                target: "queue",
                "{id}: could not move the earlier progress from {} to {}: {e} - \
                 the release will be downloaded again, and those files are not \
                 named by any record",
                old_dir.display(),
                dir.display()
            ),
        }
    }
    Ok(fence)
}

/// The relocation fence for one job, lifted when this drops.
///
/// A guard rather than a matching pair of writes because the move it
/// covers is bulk I/O that can fail, because `requeue_category` has four
/// doors, and because the rename wrapper keeps the fence up past that
/// call's return. A panic anywhere in the transaction lifts it too,
/// which is the behaviour to want: a fence nothing will ever clear is a
/// job that can never start again.
pub(in crate::serve) struct Relocation {
    job: Arc<Mutex<Job>>,
    // The undo set (Codex C10): what the record said before the
    // transaction, so a queue save that REFUSES after the bytes moved
    // can put record and tree back together instead of leaving the
    // durable row naming an empty directory while the partial bytes sit
    // orphaned at the new path.
    old_cat: String,
    old_dir: PathBuf,
    new_dir: PathBuf,
}

impl Relocation {
    /// Undo the transaction this fence covers, for the caller whose
    /// `save_queue` refused: restore the old category and `out_dir`,
    /// then move the tree back - record first, then bytes, mirroring
    /// the forward order. The fence stays up until this returns, so the
    /// job cannot start against either path mid-undo. Consumes the
    /// guard; the fence lifts on the way out.
    pub(in crate::serve) fn rollback(self) {
        {
            let mut g = self.job.lock_ok();
            g.category = self.old_cat.clone();
            g.out_dir = self.old_dir.clone();
        }
        if self.new_dir != self.old_dir
            && self.new_dir.exists()
            && let Err(e) = crate::smart::move_tree(&self.new_dir, &self.old_dir)
        {
            // Not fatal: the record is back on the old path and the
            // job simply downloads again. Say where the stranded
            // bytes are, because nothing else will.
            warn!(
                target: "queue",
                "could not move the earlier progress back from {} to {}: {e} - \
                 the release will be downloaded again, and those files are \
                 not named by any record",
                self.new_dir.display(),
                self.old_dir.display()
            );
        }
    }
}

/// The durability half of one or more `requeue_category` transactions:
/// ONE queue save, taken with every fence still held. On refusal every
/// relocation is rolled back - record and bytes together - so a restart
/// restores a row that still agrees with the tree (Codex C10). Returns
/// whether the store took it; a caller answering an API owes the user a
/// `status:false` on false.
#[must_use = "a refused save has already been rolled back - report it"]
pub(in crate::serve) fn persist_relocations(d: &Daemon, fences: Vec<Relocation>) -> bool {
    if d.save_queue() {
        return true;
    }
    for f in fences {
        f.rollback();
    }
    false
}

impl Drop for Relocation {
    fn drop(&mut self) {
        let mut g = self.job.lock_ok();
        // Saturating because the fence is a depth, and the only thing
        // that could take it below zero is a double-drop, which cannot
        // happen - but a wrapping panic here would be a far worse
        // answer than an already-lifted fence.
        g.relocating = g.relocating.saturating_sub(1);
    }
}

#[cfg(test)]
mod custody_tests;
