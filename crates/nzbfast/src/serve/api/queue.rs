use super::super::*;
use super::ApiCtx;

/// Is this job inside its post-network tail - verifying, repairing or
/// unpacking?
///
/// `state == Downloading` cannot answer it: the record says Downloading
/// from the first article to the last extracted byte, so every queue
/// control that refuses to act on "the active download" was in fact
/// still acting on a job whose download had finished minutes ago. The
/// pipeline's own phase word is the answer, and the queue row is now
/// rendered from the same one, so a control that refuses here is a
/// control the user could already see was not on offer.
fn finishing_tail(d: &Arc<Daemon>, g: &Job) -> bool {
    // §129: the lane gave the tail its own state, so the answer no
    // longer leans on the phase word alone - but the Downloading+phase
    // arm stays for the moment between net-drain and lane submission.
    g.state == JobState::Finishing
        || (g.state == JobState::Downloading && d.tail_phase(&g.nzo_id).is_some())
}

/// Set (or clear) one job's pause flag, with the one refusal that makes
/// the flag mean anything. Returns whether the job took it.
///
/// There is nothing left to pause once the bytes are in: the
/// verify/repair/unpack tail and the move to the destination run to
/// completion whatever this flag says. Setting it anyway labelled a job
/// "paused" in every client while its files went on moving - and left
/// the flag SET, so a later auto-retry put the job back in the queue
/// with `paused` still true and `pick_job` skipped it forever (Codex
/// sweep 2, 3 Aug M4).
///
/// Shared so the SAB/API `mode=queue&name=pause` arm and the NZBGet
/// JSON-RPC `GroupPause` cannot drift: they had drifted, and which
/// client type the user happened to configure in Sonarr decided whether
/// a paused job could ever run again.
pub(in crate::serve) fn apply_pause(d: &Arc<Daemon>, g: &mut Job, pause: bool) -> bool {
    if pause && (g.state == JobState::Completed || finishing_tail(d, g)) {
        return false;
    }
    let was = g.paused;
    g.paused = pause;
    // A resume that puts a Queued row back under the idle predicate's
    // "busy" arm is a real queue transition, and only the add and the
    // runner's pick re-arm the idle latch - neither of which can happen
    // while a global pause or a guard hold keeps `pick_job` away. So
    // pause -> resume -> pause under a global pause announced the first
    // idle edge and swallowed the second, which is the one thing the
    // latch's "once per transition" contract promises not to do (Codex
    // sweep 14 Aug L2). Both callers hold the queue lock across this,
    // which is the same serialization the add's re-arm relies on
    // (daemon_enqueue.rs) and what keeps a concurrent notifier's
    // scan-to-CAS from emitting over a row this call just made runnable.
    //
    // `state == Queued` matches the predicate exactly and is
    // load-bearing: re-arming for a Completed or Finishing row would
    // make the `note_queue_idle()` the same handler calls a moment later
    // emit a second queue.idle over a queue that never left idle.
    if was && !pause && g.state == JobState::Queued {
        d.queue_idle_latch.store(false, Ordering::Relaxed);
    }
    true
}

/// The idle edge after a delete removed rows without a park. Deleting
/// the last queued job empties the queue with no park, so park's
/// queue.idle would never fire (M3, 10 Aug sweep). Not while an active
/// download is draining: it has left the queue but its pipeline has not
/// stopped, and its own park announces the real transition a moment
/// later.
///
/// Shared so the SAB/API delete arm and the NZBGet JSON-RPC delete
/// variants cannot drift (Codex sweep 14 Aug M4): the facade is a
/// hand-copy of the REST path and this is the second REST fix it
/// missed. Call after the rows are gone and no queue lock is held.
pub(in crate::serve) fn note_queue_idle_unless_active(d: &Daemon, stopped_active: bool) {
    if !stopped_active {
        d.note_queue_idle();
    }
}

/// Stop the transfer a delete just took the record away from - and keep
/// asking until the pipeline is actually listening.
///
/// `hub.abort` / `hub.queue_ctl` are published by `install_seek` partway
/// into the fetch, and the QueueControl stays INERT after that until the
/// pool run attaches its shared state to it (`QueueControl::abort`
/// answers false while its weak reference has nothing to upgrade). A
/// single shot aimed at either window is silently swallowed: the record
/// vanishes from the queue and the download it named runs its whole
/// ladder anyway. Measured 16 Aug 2026 on a delete issued the instant the
/// row read Downloading - "active download stopped by user" in the log,
/// then `sharding 200 connections` AFTER it, then a full minute of
/// `connect failed: Connection refused` against a host nothing was
/// waiting for. The pause path has re-fired for this exact reason since
/// M23e; delete never did, and it also DISARMS pause's loop, whose
/// wind-down check ("still in the queue, still suspended") a delete makes
/// false on the next pass.
///
/// So: fire, and if the pool did not take it, keep firing on the same
/// 250 ms cadence `suspend_matching` uses until it does. Bounded at the
/// same 60 s, which is far past any launch: a job that never attaches a
/// pool has already failed on its own by then.
///
/// Only ever aimed at `active_stream` - the owner test, never
/// `state == Downloading` (see `owns_hub`): job N stays Downloading
/// through its whole disk tail while N+1 is on the wire holding these
/// handles, and this loop firing at the wrong one is the "deleted a
/// finished job, killed a healthy unrelated download" bug. While the hub
/// names anyone else the loop only WAITS - it never fires blind - so the
/// launch window (the record is Downloading, the pipeline has not
/// published yet) is covered without ever pointing the abort at a
/// stranger.
///
/// Shared so the SAB/API delete arm and the NZBGet JSON-RPC delete
/// variants cannot drift, like the two helpers above it.
pub(in crate::serve) fn stop_deleted_transfer(d: &Arc<Daemon>, stopped: Vec<String>) {
    if stopped.is_empty() {
        return;
    }
    if fire_delete_abort(d, &stopped) {
        return;
    }
    let d = d.clone();
    std::thread::spawn(move || {
        // Whether the hub has ever named one of these jobs. Before it
        // does, another job's name means "ours has not launched yet" and
        // we wait; after it has, another name means the transfer we were
        // aiming at is over and there is nothing left to stop.
        let mut was_ours = false;
        for _ in 0..240 {
            std::thread::sleep(std::time::Duration::from_millis(250));
            if d.owns_hub(|id| stopped.iter().any(|s| s == id)) {
                was_ours = true;
                if fire_delete_abort(&d, &stopped) {
                    return;
                }
            } else if was_ours {
                return;
            }
        }
        warn!(
            target: "queue",
            "{} was deleted mid-download but its pipeline never took the stop \
             signal - it will run to its own end",
            stopped.join(", ")
        );
    });
}

/// One shot of the delete abort, aimed only if the hub is still this
/// job's. Returns whether the POOL took it: the flag half is read after
/// the network phase and stops nothing by itself, so "delivered" can
/// only mean the QueueControl found a live run to abort.
fn fire_delete_abort(d: &Arc<Daemon>, stopped: &[String]) -> bool {
    if !d.owns_hub(|id| stopped.iter().any(|s| s == id)) {
        return false;
    }
    if let Some(f) = d.hub.abort.lock_ok().as_ref() {
        f.store(true, Ordering::Relaxed);
    }
    let landed = d
        .hub
        .queue_ctl
        .lock_ok()
        .as_ref()
        .is_some_and(|c| c.abort());
    if landed {
        info!(target: "queue", "active download stopped by user");
    }
    landed
}

/// Write one job's priority, releasing the states an explicit priority
/// is an instruction to release. Returns whether the job took it.
///
/// A duplicate hold is a PAUSE at priority -3, and the UI has always
/// told the user to raise the priority to download the copy anyway -
/// which did nothing at all, because `pick_job` skips a paused job
/// whatever its priority. An explicit priority write on a held
/// duplicate is that instruction, so it releases the hold here, exactly
/// as the failed-original promotion arm does (daemon.rs: paused=false,
/// priority=0). Only for -3: an ordinary paused job re-prioritised by a
/// client stays paused, which is what every SAB caller expects.
///
/// Refused on a job whose download is over for the same reason as
/// [`apply_pause`]: priority decides what starts NEXT, and clearing the
/// deferral and health waiver on a finished record is meaningless. A
/// held duplicate has never started, so that guard can never claim one.
pub(in crate::serve) fn apply_priority(d: &Arc<Daemon>, g: &mut Job, prio: i32) -> bool {
    if g.state == JobState::Completed || finishing_tail(d, g) {
        return false;
    }
    if g.priority == -3 && g.paused {
        g.paused = false;
        // The re-arm this release owes, for the same reason the resume
        // owes one (see `apply_pause`): the row is runnable again, and
        // only the add and the runner's pick clear the latch - neither
        // of which can happen while a global pause keeps `pick_job`
        // away. `state == Queued` matches the idle predicate exactly, so
        // this can never make a later `note_queue_idle` emit over a
        // queue that never left idle (Fable sweep 15 Aug).
        if g.state == JobState::Queued {
            d.queue_idle_latch.store(false, Ordering::Relaxed);
        }
    }
    g.priority = prio;
    // Explicit priority overrides a watchdog deferral - and §77's
    // health sink, which is an advisory guess and does not get to argue
    // with an order the user has just given.
    g.deferred = false;
    if let Some(h) = g.health.as_mut() {
        h.waived = true;
    }
    true
}

/// One host's observed connection ceiling, as the dashboard reads it.
fn cap_json(c: &crate::conntune::Capped) -> Value {
    json!({"granted_hi": c.granted_hi, "capped_at": c.capped_at, "since": c.since})
}

/// The running job's view of a provider's ceiling, merged with what
/// this daemon session already knew.
///
/// Both halves are high-waters of the same measurement, so the merge is
/// a max - and either half can be the fresher one. The pool's is newer
/// while a job runs and the cap tightens; the session's is newer for
/// the first seconds of a job, before this provider has been asked for
/// more than it will give, which is exactly the window the row used to
/// spend saying "using 12 of 100".
///
/// `None` until SOMETHING has heard a capacity refusal from this host.
fn cap_payload(d: &Daemon, s: &nzbkit::pool::ServerLive) -> Option<Value> {
    let live = s.capped_since.load(Ordering::Relaxed);
    // Session memory has to be retired by the same proof the pool's own
    // gauge is: holding MORE sessions than a recorded ceiling says that
    // ceiling is no longer one. `ConnGauge::up` does this for the live
    // gauge (sweep 5, L6) but can only retire a cap THAT gauge
    // recorded, and the job which disproves a ceiling is usually the
    // one AFTER the job that met it - whose gauge is empty. Without
    // this half the row went on reading "using 100 of 38" until the
    // daemon restarted, which is the wrong connection budget presented
    // as a measurement (Codex sweep 6, N4).
    let seen = {
        let mut m = d.capped_hosts.lock_ok();
        let held = s.connected.load(Ordering::Relaxed);
        if m.get(&s.host).is_some_and(|c| c.disproven_by(held)) {
            m.remove(&s.host);
        }
        m.get(&s.host).cloned()
    };
    if live == 0 {
        return seen.as_ref().map(cap_json);
    }
    let (g0, a0, t0) = seen.map_or((0, 0, u64::MAX), |c| (c.granted_hi, c.capped_at, c.since));
    Some(json!({
        "granted_hi": s.granted_hi.load(Ordering::Relaxed).max(g0),
        "capped_at": s.capped_at.load(Ordering::Relaxed).max(a0),
        "since": live.min(t0),
    }))
}

/// What the NEXT download would open on each configured server.
///
/// The live `servers` list comes from the job pool, so it is empty
/// whenever nothing is downloading - and the Providers card, the only
/// place in the product that shows a connection count, hides itself when
/// that list is empty. Turn auto-tune on, then look at an idle
/// dashboard, and there is nowhere at all that answers "how many
/// connections am I going to use". Reported by a tester on 4 Aug, who
/// had just re-enabled auto-tune and therefore most needed the answer.
///
/// So an idle daemon reports the PLAN instead of nothing: the same
/// shape, `connected: 0`, and a budget computed through the very
/// function the download path uses (`applied_connections`), so this can
/// never drift into describing a number jobs would not actually open.
/// `idle: true` marks them, because "0/16 now" and "16 next time" are
/// different sentences and the UI has to be able to tell them apart.
fn planned_servers(d: &Daemon, cfg_path: &std::path::Path) -> Vec<Value> {
    let Ok(c) = nzbkit::config::Config::load(cfg_path) else {
        return Vec::new();
    };
    let store = crate::conntune::load(cfg_path);
    let apply_knees = crate::conntune::enabled(cfg_path);
    // With the live controller on, the next download SEEDS from the
    // bucket store and the knee does not cap - report that number, not
    // the knee-capped one this install would no longer open.
    let live_tune = d.live_tune.load(Ordering::Relaxed) || crate::conntune::live_tune_on();
    let bkt = crate::conntune::bucket_of(crate::conntune::local_hour());
    let now = epoch_secs();
    let shaped = d.shaped_hosts.lock_ok();
    let capped = d.capped_hosts.lock_ok();
    let global = d.connections.load(Ordering::Relaxed).max(1);
    c.servers
        .iter()
        .filter(|s| s.enabled)
        .map(|s| {
            let base = global.min(s.connections.max(1) as usize);
            let budget = if live_tune && !s.pin_connections {
                crate::conntune::seed_connections(store.get(&s.host), bkt, now, base)
            } else {
                crate::conntune::applied_connections(
                    base,
                    s.pin_connections,
                    apply_knees.then(|| store.get(&s.host)).flatten(),
                )
            };
            json!({
                "host": s.host,
                "budget": budget,
                "connected": 0,
                "bytes": 0,
                "tried": 0,
                "missing": 0,
                "idle": true,
                // Decay flag (conn-tuning design §6): this host fell to
                // under half its usual per-connection rate.
                "shaped": shaped.get(&s.host).map(|sh| json!({
                    "since": sh.since, "ref_per_conn_bps": sh.ref_per_conn_bps})),
                // Nothing is downloading, so there is no pool half to
                // merge: this is purely what the session has already
                // seen this provider refuse.
                "capped": capped.get(&s.host).map(cap_json),
            })
        })
        .collect()
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
                Ok(()) => {
                    d.save_queue();
                    json!({"status": true})
                }
            },
        }
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
                .lock()
                .unwrap()
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
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let id = params.get("value").cloned().unwrap_or_default();
        let pw = params.get("password").cloned().unwrap_or_default();
        if pw.is_empty() {
            json!({"status": false, "error": "empty password"})
        } else {
            let hit = |j: &&Arc<Mutex<Job>>| j.lock_ok().nzo_id == id;
            let found = d
                .queue
                .lock()
                .unwrap()
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
                            if crate::smart::unlock(&out_dir, &pw) {
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
                                // BOTH password stories end here: the one this
                                // record was parked with, and the one a WRONG
                                // guess wrote over it - a tester's failed guess
                                // followed by the right password left a
                                // Completed row whose Reason still read
                                // "password did not unlock the archive".
                                if j.fail_message == "password required to unpack"
                                    || j.fail_message == "password did not unlock the archive"
                                {
                                    j.fail_message.clear();
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
                                j.fail_message = "password did not unlock the archive".into();
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
            .lock()
            .unwrap()
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
                .lock()
                .unwrap()
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
            .lock()
            .unwrap()
            .as_ref()
            .map(|v| {
                let (done, bad) = v.live_counts();
                let total: u64 = v
                    .set()
                    .map(|s| s.files.iter().map(|f| f.blocks.len() as u64).sum())
                    .unwrap_or(0);
                (done, bad, total)
            })
            .unwrap_or((0, 0, 0));
        let files: Vec<Value> = d
            .hub
            .extractor
            .lock()
            .unwrap()
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
                    Ok(id) => {
                        d.record_add_params(
                            &id,
                            params.get("pp").map(String::as_str),
                            params.get("script").map(String::as_str),
                            ctx.via_add_only,
                        );
                        if stream {
                            json!({
                                "status": true, "nzo_ids": [id],
                                "m3u": format!("{}/m3u/{id}{}", ctx.base, ctx.key_q),
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
                match d.enqueue_fetched(&f, &name, &cat, prio, pp, pw.as_deref(), 0, &origin, false)
                {
                    // §129 2b: same pp=/script= recording as addfile.
                    Ok(id) => {
                        d.record_add_params(
                            &id,
                            params.get("pp").map(String::as_str),
                            params.get("script").map(String::as_str),
                            ctx.via_add_only,
                        );
                        if stream {
                            json!({
                                "status": true, "nzo_ids": [id],
                                "m3u": format!("{}/m3u/{id}{}", ctx.base, ctx.key_q),
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
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
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
                resolve_nzblnk(d, &l, &cat, prio, pw.as_deref(), dupe_ok)
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
        Ok(nzo_id) => {
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

fn m_queue(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let value = params.get("value").cloned().unwrap_or_default();
        // Trimmed, like the delete path's busy guard: a comma list with
        // spaces in it ("nzo_1, nzo_2") otherwise matched the guard and
        // not the action, and the second id was silently ignored.
        let hit_id = |id: &str| value == "all" || value.split(',').any(|v| v.trim() == id);
        let hit = |j: &Arc<Mutex<Job>>| hit_id(&j.lock_ok().nzo_id);
        match params.get("name").map(String::as_str) {
            Some("delete") => {
                // A deleted job's prefetch sidecar must stop
                // writing to its directory.
                d.poke_sidecar(hit_id);
                // The poke is fire-and-forget, so a job the sidecar is
                // RUNNING still has live writers however queued its row
                // looks - see `remove_after_sidecar_drain`. Snapshotted
                // before the queue lock: the sidecar mutex under
                // queue+job would be a lock edge nothing else takes.
                let sidecar_owner = d.sidecar_owner();
                // §129: and its post-network tail must stop pulling
                // recovery volumes. Not covered by the hub abort below -
                // that one is scoped to the job that OWNS the hub, and a
                // Finishing job by definition does not.
                d.cancel_tail_fetches(hit_id);
                let del_files = params.get("del_files").map(String::as_str) == Some("1");
                let mut stopped_active = false;
                // Which job was on the wire, not just that one was: the
                // stop signal is aimed by nzo_id (see
                // `stop_deleted_transfer`), and a batch delete of a
                // whole category names every row in the queue.
                let mut stopped_ids: Vec<String> = Vec::new();
                // Collected under the queue lock, recorded after it -
                // the notice's own lock is a leaf and must stay one.
                let mut kept: Vec<(String, std::path::PathBuf, String)> = Vec::new();
                // The file removal goes the same way, and for a
                // sharper reason: a Trash call is bounded at 30 s per
                // route and macOS runs TWO of them (Finder, then
                // NSFileManager), so doing this inside `q.retain`
                // held the GLOBAL queue lock for up to a minute on a
                // headless mac or a share with no .Trashes. pick_job,
                // queue_json, save_queue and every *arr status poll
                // stall behind it, and the *arr marks the client
                // unhealthy. Deleting after the lock is dropped costs
                // a reservation instead: `dir_claim` consults
                // `reserved` before anything else, precisely so a
                // directory with no record naming it cannot be
                // handed to a new job - which is exactly the window
                // that opens between the record going and the files.
                let mut doomed: Vec<(String, std::path::PathBuf, bool, crate::smart::FiledTail)> =
                    Vec::new();
                // The same, for the one job whose writers are the
                // sidecar's: removed only once that has wound down.
                let mut pending_sidecar: Vec<(
                    String,
                    std::path::PathBuf,
                    bool,
                    crate::smart::FiledTail,
                )> = Vec::new();
                // The releases this request removes: stamped after the
                // lock as the user's own statement that they no longer
                // have them, so a re-add is not held as a duplicate of
                // something that is not there. It is what the stop
                // button already promises in as many words - "adding the
                // same NZB again picks up from it" - and a hold made
                // that promise false.
                let mut deleted_names: Vec<String> = Vec::new();
                // See the history arm: spool copies whose fate waits on
                // the file removal.
                let mut nzb_by_dir = std::collections::HashMap::new();
                let mut q = d.queue.lock_ok();
                let before = q.len();
                q.retain(|j| {
                    if hit(j) {
                        let mut g = j.lock_ok();
                        // ...but not the backup copy: see
                        // `is_held_alternative`.
                        if !is_held_alternative(&g) {
                            deleted_names.push(g.name.clone());
                        }
                        let active = g.state == JobState::Downloading;
                        // §129: a Finishing job's tail is running in the
                        // lane - its writers are live like `finalizing`,
                        // but the hub abort below belongs to whatever is
                        // DOWNLOADING now, so it takes the non-active
                        // arm and relies on the tombstone making its
                        // tail a no-op at park.
                        let lane = g.state == JobState::Finishing;
                        if active {
                            // The pipeline is running - mark it
                            // for silent drop and abort below.
                            // park() drops the record and removes
                            // its spooled .nzb.
                            g.tombstone = true;
                            stopped_active = true;
                            stopped_ids.push(g.nzo_id.clone());
                        } else {
                            // Non-active: the record is gone for
                            // good, so its spooled NZB is dead
                            // weight (retry only applies to
                            // history). Remove it now.
                            //
                            // Tombstoned all the same. A queued
                            // job can still be RUNNING in the
                            // prefetch sidecar, and the poke
                            // above only stops a download that
                            // has not finished: an Ok already on
                            // its way to the tail would otherwise
                            // unlock, rename, file into the TV
                            // library, move to the destination
                            // folder, run the pp-script and park
                            // the deleted job into history. The
                            // flag makes that tail a no-op.
                            g.tombstone = true;
                            // ...and its spool copy with it, unless the
                            // files half is about to be attempted: the
                            // notice's "download it again" needs that
                            // NZB when the removal is refused.
                            hold_or_drop_spool(del_files, &g.out_dir, &g.nzb_path, &mut nzb_by_dir);
                        }
                        if del_files {
                            if active || lane || g.finalizing {
                                // Writers are still live; removing
                                // now just lets the next positioned
                                // write recreate the files and
                                // orphan them. Defer to park(),
                                // which runs after the fetch drains.
                                //
                                // `finalizing` matters for the same
                                // reason and is NOT covered by
                                // `active`: a Completed job whose
                                // post-processing (unlock, rename,
                                // TV filing, NAS move) is still
                                // running has left Downloading, so
                                // this used to take the else arm and
                                // remove_dir_all the very directory
                                // the mover was reading from - half
                                // deleting a tree under it, or
                                // deleting an emptied source while
                                // the payload sat at the destination
                                // with no record left to delete it
                                // by. park() already implements the
                                // deferral and is always reached for
                                // a finalizing job (its tail holds
                                // its own Arc and parks after
                                // finalize_completed), so the files
                                // still go. Deferring on `finalizing`
                                // only, not on every non-active
                                // state: a never-run Queued job has
                                // no tail, so park would never fire
                                // and its files would never be
                                // removed at all.
                                g.del_on_drop = true;
                                // Reserve for the SAME reason the
                                // non-deferred arm below does, and
                                // for longer: the queue row goes
                                // now and the files go in `park()`,
                                // once the fetch has drained. A
                                // tombstoned job is dropped rather
                                // than filed, so in between
                                // `dir_claim` finds the directory in
                                // neither queue nor history and
                                // calls it free - and a re-add of
                                // the same release (a user retry, an
                                // *arr re-grab) can claim it and be
                                // writing there when `park()`
                                // finally removes the whole
                                // directory. `park()` releases it.
                                d.reserved.lock_ok().insert(g.out_dir.clone());
                            } else if sidecar_owner
                                .as_ref()
                                .is_some_and(|(id, _)| *id == g.nzo_id)
                            {
                                // The exception the comment above
                                // names: a never-run Queued job has no
                                // tail, but a PREFETCHING one has a
                                // whole pipeline, and removing here let
                                // the next file's first article
                                // recreate the directory and lay a
                                // fresh payload nothing names (M2).
                                // park is still the wrong destination -
                                // the abort's ordinary outcome is the
                                // sidecar's Err arm, which never parks -
                                // so the removal waits on the wind-down
                                // instead, and releases the reservation
                                // itself.
                                let tail = delete_tail(&g, || d.job_suffix(filed_stem(&g)));
                                d.reserved.lock_ok().insert(g.out_dir.clone());
                                pending_sidecar.push((
                                    filed_stem(&g).to_string(),
                                    g.out_dir.clone(),
                                    g.filed,
                                    tail,
                                ));
                            } else {
                                let tail = delete_tail(&g, || d.job_suffix(filed_stem(&g)));
                                d.reserved.lock_ok().insert(g.out_dir.clone());
                                doomed.push((
                                    filed_stem(&g).to_string(),
                                    g.out_dir.clone(),
                                    g.filed,
                                    tail,
                                ));
                            }
                        }
                        false
                    } else {
                        true
                    }
                });
                let count = before - q.len(); // counted, as history's arm is
                drop(q);
                // Now that no global lock is held: the slow half.
                //
                // Every reservation is released AFTER the whole batch,
                // never per entry. `reserved` is a set, so two entries
                // naming one directory are one member: releasing after
                // the first would unreserve a directory a later entry
                // has not reached yet, and the gap is a whole Trash
                // call wide (30 s per route, two routes on macOS).
                let reserved_dirs: Vec<std::path::PathBuf> =
                    doomed.iter().map(|(_, dir, _, _)| dir.clone()).collect();
                for (name, dir, filed, tail) in doomed {
                    let outcome = remove_job_files(&dir, &name, filed, &tail);
                    if let FilesGone::Kept(why) = outcome {
                        kept.push((name, dir, why));
                    }
                }
                {
                    let mut r = d.reserved.lock_ok();
                    for dir in &reserved_dirs {
                        r.remove(dir);
                    }
                }
                // The row is gone from the queue either way - that is
                // what was asked for and it worked. What did NOT work
                // was the files half, and with the row went the only
                // place the user could see this download named.
                note_kept_files(d, kept, &mut nzb_by_dir);
                // The sidecar's job waits for the sidecar. Its own
                // reservation is released by the drain, not by the batch
                // above - the removal is still ahead of it.
                if let Some((_, target)) = sidecar_owner {
                    for (name, dir, filed, tail) in pending_sidecar {
                        d.remove_after_sidecar_drain(target.clone(), name, dir, filed, tail);
                    }
                }
                // Only the job that OWNS the hub may fire its
                // abort. `state == Downloading` is NOT that
                // test: job N stays Downloading through its
                // whole post-network tail while job N+1 is
                // already on the wire and owns hub.abort /
                // hub.queue_ctl (they are overwritten per job
                // and carry no owner tag), so deleting N during
                // its tail aborted N+1 - a healthy, unrelated
                // download. N+1 then failed permanently (a
                // Local fail_kind is not `transient()`, so no
                // auto-retry) and fired its pp-script, failure
                // notification and failure re-grab on a good
                // release, while N was never stopped at all
                // (its abort flag was last read long before).
                // `active_stream` is the owner - the watchdog
                // was already fixed to steer by it, for exactly
                // this hazard.
                //
                // Fire-and-keep-firing rather than fire-once: the
                // helper's doc has the window that swallowed the single
                // shot.
                stop_deleted_transfer(d, stopped_ids);
                if count > 0 {
                    d.note_releases_deleted(&deleted_names);
                    d.save_queue();
                    // The rationale lives on the helper, which the
                    // JSON-RPC delete variants share.
                    note_queue_idle_unless_active(d, stopped_active);
                }
                json!({"status": count > 0, "removed": count})
            }
            Some(op @ ("pause" | "resume")) => {
                if op == "pause" {
                    // Pausing a job also stops its prefetch.
                    d.poke_sidecar(hit_id);
                }
                let mut n = 0;
                let mut finishing = 0;
                for j in d.queue.lock_ok().iter().filter(|j| hit(j)) {
                    let mut g = j.lock_ok();
                    if apply_pause(d, &mut g, op == "pause") {
                        n += 1;
                    } else {
                        finishing += 1;
                    }
                }
                // The flag alone only takes effect when a job
                // next enters the queue. Pausing the item that
                // was ACTUALLY downloading left it running at
                // full speed while this answered success and
                // the queue kept showing it as Downloading -
                // so an nzb360 tap to free bandwidth did
                // nothing at all. Wind the transfer down too.
                if op == "pause" && n > 0 {
                    d.suspend_matching(true, |g| hit_id(&g.nzo_id));
                }
                if n > 0 {
                    d.save_queue();
                    // Pausing the last runnable job is the other way the
                    // queue goes idle without a park (M3). Resume takes
                    // the same call deliberately: it never EMITS on its
                    // own (the latch keeps a still-idle queue silent),
                    // and the re-arm the resume owes lives inside
                    // `apply_pause`, under this same queue lock.
                    d.note_queue_idle();
                }
                if n == 0 && finishing > 0 {
                    json!({"status": false, "error": "this job is still finishing"})
                } else {
                    json!({"status": n > 0})
                }
            }
            // SAB parity: mode=queue&name=switch&value=<nzo_id>
            // &value2=<index> moves the item to that queue
            // position (the dashboard's drag-to-reorder). Order
            // only breaks ties within a priority - pick_job
            // still runs Force/High first - and the active
            // download can't be moved.
            Some("switch") => {
                let pos: usize = params
                    .get("value2")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                let mut q = d.queue.lock_ok();
                let from = q.iter().position(|j| j.lock_ok().nzo_id == value);
                match from {
                    Some(i) if q[i].lock_ok().state != JobState::Downloading => {
                        let job = q.remove(i).unwrap();
                        // A manual reorder reasserts the
                        // user's order - the watchdog's
                        // deferral no longer applies, and
                        // neither does §77's health sink. The
                        // health VERDICT stays: it is what the
                        // servers said, and the row goes on
                        // saying it.
                        {
                            let mut g = job.lock_ok();
                            g.deferred = false;
                            if let Some(h) = g.health.as_mut() {
                                h.waived = true;
                            }
                        }
                        let to = pos.min(q.len());
                        // §96 (AltMount audit, item 6): a move to the FRONT
                        // means "run this next" - nzb360 sends value2=0
                        // expecting exactly that. Position alone only breaks
                        // ties within a priority, so a Normal job dragged
                        // above a High one would still run second. Adopt the
                        // highest priority present among the other runnable
                        // jobs, capped at High: Force is never minted by a
                        // reorder, because Force also runs through a queue
                        // pause - a side effect no drag asked for.
                        if to == 0 {
                            let top = q
                                .iter()
                                .map(|o| o.lock_ok())
                                .filter(|g| g.state == JobState::Queued && !g.tombstone)
                                .map(|g| g.priority)
                                .max()
                                .unwrap_or(0)
                                .min(1);
                            let mut g = job.lock_ok();
                            if top > g.priority {
                                g.priority = top;
                            }
                        }
                        q.insert(to, job);
                        drop(q);
                        d.save_queue();
                        json!({"status": true, "position": to})
                    }
                    Some(_) => json!({
                        "status": false,
                        "error": "cannot move the active download"
                    }),
                    None => {
                        json!({"status": false, "error": "unknown nzo_id"})
                    }
                }
            }
            // The two remote-app arms live in remote.rs (§18): rename
            // (which is also how SAB spells set-password, value3) and
            // whole-queue sort. LunaSea sends both.
            Some("rename") => super::remote::rename_arm(d, params),
            Some("sort") => super::remote::sort_arm(d, params),
            Some("change_complete_action") => super::remote::complete_action_arm(params),
            Some("priority") => {
                // SAB's priority dropdown has a "Default" entry
                // and sends the -100 sentinel for it, so it has
                // to be resolved here too - storing the sentinel
                // would sort the job below Low while every
                // client labelled it Normal. (-2, "add paused",
                // is only meaningful on an ADD and is left
                // exactly as it was.)
                let prio: i32 = match params
                    .get("value2")
                    .and_then(|v| super::super::sabcompat::parse_priority_token(v))
                    .unwrap_or(0)
                {
                    SAB_DEFAULT_PRIORITY => 0,
                    p => p,
                };
                let mut n = 0;
                let mut finishing = 0;
                for j in d.queue.lock_ok().iter().filter(|j| hit(j)) {
                    let mut g = j.lock_ok();
                    if apply_priority(d, &mut g, prio) {
                        n += 1;
                    } else {
                        finishing += 1;
                    }
                }
                if n > 0 {
                    d.save_queue();
                }
                if n == 0 && finishing > 0 {
                    json!({"status": false, "error": "this job is still finishing"})
                } else {
                    json!({"status": n > 0, "position": -1})
                }
            }
            _ => queue_json(d, params),
        }
    })
}

fn m_history(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let value = params.get("value").cloned().unwrap_or_default();
        let find = |id: &str| {
            d.history
                .lock()
                .unwrap()
                .iter()
                .find(|j| j.lock_ok().nzo_id == id)
                .cloned()
        };
        match params.get("name").map(String::as_str) {
            // Open the finished item on the DAEMON's machine
            // (the normal local setup): value2 "folder" reveals
            // the download dir, "file" opens the largest media
            // file in the OS default player.
            Some("open") => {
                let what = params.get("value2").map(String::as_str).unwrap_or("folder");
                match find(&value) {
                    None => json!({"status": false, "error": "unknown nzo_id"}),
                    Some(job) => {
                        let dir = job.lock_ok().out_dir.clone();
                        let target = if what == "file" {
                            largest_media_file(&dir).unwrap_or_else(|| dir.clone())
                        } else {
                            dir.clone()
                        };
                        json!({"status": os_open(&target), "path": target.to_string_lossy()})
                    }
                }
            }
            // Re-categorize: move the files to the new
            // category's folder and update the record.
            Some("set_cat") => {
                let cat = params.get("value2").cloned().unwrap_or_default();
                let cat = cat.trim().trim_matches('*').trim().to_string();
                // Untrusted: keep it a single contained path
                // component so the rename target can't escape
                // out_root (bug sweep - same class as enqueue).
                let cat = if cat.is_empty() {
                    cat
                } else {
                    nzbkit::disk::sanitize_filename(&cat)
                };
                // One implementation with change_cat's history
                // leg. This used to rename under the download
                // root only - ignoring the completed-move
                // destinations, failing across filesystems
                // (fs::rename cannot cross onto a NAS), and
                // never persisting - so a recategorized job
                // forgot its category on restart.
                history_change_cat(d, &value, &cat)
            }
            Some("delete") => {
                let del_files = params.get("del_files").map(String::as_str) == Some("1");
                // Snapshot the queue's directories BEFORE the
                // history lock: they are claimants too, and
                // taking the two locks in this order everywhere
                // is what keeps them from deadlocking.
                let queue_dirs: Vec<PathBuf> = d
                    .queue
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|j| j.lock_ok().out_dir.clone())
                    .collect();
                let mut h = d.history.lock_ok();
                // A recategorize is moving one of these payloads on
                // disk right now. It snapshotted the record before
                // the move and writes `out_dir` back afterwards, so
                // deleting the record (and its files) underneath
                // leaves the moved data orphaned at a destination
                // nothing names, or half-deleted across both
                // folders. Refuse for the whole request rather than
                // silently skipping one id of a batch. Checked
                // UNDER the history lock: a recategorize raises its
                // marker and then re-verifies the record is still
                // present, so a check outside this lock could pass
                // just before the marker went up while the move
                // still proceeded (Codex H7).
                let busy: Vec<String> = {
                    let m = d.moving.lock_ok();
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|s| m.contains(*s))
                        .map(str::to_string)
                        .collect()
                };
                if !busy.is_empty() {
                    return Some(json!({"status": false,
                            "error": format!(
                                "{} is having its files moved right now - try again when it settles",
                                busy.join(", "))}));
                }
                let before = h.len();
                let records: Vec<DeleteRecord> = h
                    .iter()
                    .map(|j| {
                        let g = j.lock_ok();
                        DeleteRecord {
                            nzo_id: g.nzo_id.clone(),
                            state: g.state,
                            out_dir: g.out_dir.clone(),
                            filed: g.filed,
                            locked: g.password_required,
                        }
                    })
                    .collect();
                // Decided in one pass over the WHOLE list, so
                // the "somebody else still lives here" test sees
                // the records that survive rather than the ones
                // about to go (see plan_history_delete).
                let plan = plan_history_delete(&records, &value, &queue_dirs);
                // A doomed record whose unlock task is `finalizing`
                // is mid-extraction/rename/move on disk right now
                // (Codex sweep 3 Aug H1) - same refusal as `moving`
                // above, but checked against the PLAN rather than
                // the value string, so the `all`/`failed`/
                // `completed` sweeps hit it too (and a bulk sweep
                // catching a mid-move id is refused here as well).
                let busy: Vec<String> = {
                    let m = d.moving.lock_ok();
                    h.iter()
                        .zip(&plan)
                        .filter(|(_, p)| p.doomed)
                        .filter_map(|(j, _)| {
                            let g = j.lock_ok();
                            (g.finalizing || m.contains(&g.nzo_id)).then(|| g.nzo_id.clone())
                        })
                        .collect()
                };
                if !busy.is_empty() {
                    return Some(json!({"status": false,
                            "error": format!(
                                "{} is being unlocked or moved right now - \
                                 try again when it settles",
                                busy.join(", "))}));
                }
                // Recorded after the history lock is dropped, below.
                let mut kept: Vec<(String, std::path::PathBuf, String)> = Vec::new();
                // Spooled NZBs whose fate waits on the removal: kept for
                // the notice's "download it again" when the files stay,
                // removed with the record when they go.
                let mut nzb_by_dir = std::collections::HashMap::new();
                // And so is the removal itself - see the queue-delete
                // arm above for why a bounded Trash call must not run
                // under a global lock, and why the directory is
                // reserved across the gap.
                let mut to_remove: Vec<(
                    String,
                    std::path::PathBuf,
                    bool,
                    crate::smart::FiledTail,
                )> = Vec::new();
                for (j, p) in h.iter().zip(&plan) {
                    if !p.doomed {
                        continue;
                    }
                    let g = j.lock_ok();
                    // The record is being deleted for good - its spooled
                    // .nzb (kept until now for retry) is now dead
                    // weight. Unless the files half is about to be
                    // attempted: a REFUSED removal leaves the user
                    // holding a folder and a notice, and that NZB is the
                    // only thing that can offer them the download again
                    // from where they are standing. Held back and
                    // decided after the outcome is known, below.
                    hold_or_drop_spool(
                        del_files && p.may_remove_files,
                        &g.out_dir,
                        &g.nzb_path,
                        &mut nzb_by_dir,
                    );
                    if del_files {
                        if p.may_remove_files {
                            let tail = delete_tail(&g, || d.job_suffix(filed_stem(&g)));
                            d.reserved.lock_ok().insert(g.out_dir.clone());
                            to_remove.push((
                                filed_stem(&g).to_string(),
                                g.out_dir.clone(),
                                g.filed,
                                tail,
                            ));
                            // UX §18: a move-completed (or
                            // recategorize) that failed part way
                            // left half the payload at the SOURCE,
                            // and `out_dir` followed the bytes that
                            // did move. Only `move_split` names the
                            // other half - so a delete-with-files
                            // that removes just `out_dir` takes the
                            // record away and orphans those files,
                            // with no row left to reach them by and
                            // no kept-files note either. Both
                            // locations, or neither promise is kept.
                            //
                            // `g.filed` carries over to the source,
                            // and it MUST: for a TV-filed job the
                            // folder `relocate_completed` moves FROM
                            // is the shared season folder (see its
                            // `same_place` comment), so `move_split`
                            // can name a directory full of the
                            // user's other episodes. Hardcoding
                            // `false` here - "the source is always a
                            // job-owned folder" - would have handed
                            // a whole season to `remove_user_dir` on
                            // a single episode's delete. With the
                            // flag it takes the narrow per-episode
                            // path, exactly as the destination side
                            // above already does.
                            let src = std::path::PathBuf::from(&g.move_split);
                            let claimed = || {
                                queue_dirs.contains(&src)
                                    || records
                                        .iter()
                                        .zip(&plan)
                                        .any(|(o, op)| !op.doomed && o.out_dir == src)
                            };
                            if !g.move_split.is_empty() && src != g.out_dir && !claimed() {
                                d.reserved.lock_ok().insert(src.clone());
                                to_remove.push((
                                    filed_stem(&g).to_string(),
                                    src,
                                    g.filed,
                                    delete_tail(&g, || d.job_suffix(filed_stem(&g))),
                                ));
                            }
                        } else {
                            // A verified re-download published
                            // over this record's directory and
                            // lives there now. Removing the
                            // record is right; removing the
                            // files would destroy the newer job.
                            info!(
                                target: "history",
                                "{}: record removed, files kept - {} \
                                         belongs to another job now",
                                g.nzo_id,
                                g.out_dir.display()
                            );
                        }
                    }
                }
                // What the user just told us they no longer have. Taken
                // from the plan rather than from `value`, so the bulk
                // words (`all`, `failed`, `completed`) and an id list
                // stamp exactly the records that are leaving - see
                // `Daemon::note_releases_deleted`.
                let deleted_names: Vec<String> = h
                    .iter()
                    .zip(&plan)
                    .filter(|(_, p)| p.doomed)
                    .map(|(j, _)| j.lock_ok().name.clone())
                    .collect();
                // By id, not by position: nzo_ids are unique,
                // and a positional retain would be one refactor
                // away from deleting the wrong record.
                let doomed: std::collections::HashSet<&str> = records
                    .iter()
                    .zip(&plan)
                    .filter(|(_, p)| p.doomed)
                    .map(|(r, _)| r.nzo_id.as_str())
                    .collect();
                h.retain(|j| !doomed.contains(j.lock_ok().nzo_id.as_str()));
                // §129 1a: the store forgets them too, once the lock is
                // down (below, beside save_queue).
                let doomed_ids: Vec<String> = doomed.iter().map(|s| s.to_string()).collect();
                // A bulk sweep needs to say how much it swept:
                // "Cleared." over a list that still has rows in
                // it is indistinguishable from a no-op. `status`
                // keeps its old meaning for every existing
                // caller (SAB clients included).
                let count = before - h.len();
                drop(h);
                // Now that no global lock is held: the slow half.
                // Released after the whole batch - see the queue arm
                // above. It matters more here: `plan_history_delete`
                // counts only SURVIVORS as a claimant, so two doomed
                // records sharing one out_dir both earn
                // `may_remove_files`, and a set holds that directory
                // once.
                let reserved_dirs: Vec<std::path::PathBuf> =
                    to_remove.iter().map(|(_, dir, _, _)| dir.clone()).collect();
                for (name, dir, filed, tail) in to_remove {
                    let outcome = remove_job_files(&dir, &name, filed, &tail);
                    if let FilesGone::Kept(why) = outcome {
                        kept.push((name, dir, why));
                    }
                }
                {
                    let mut r = d.reserved.lock_ok();
                    for dir in &reserved_dirs {
                        r.remove(dir);
                    }
                }
                // "Delete + files" is two promises, and only the
                // record half is guaranteed. A row the user deleted
                // to reclaim the disk space, whose files are still
                // taking it up, is the case this exists for: the row
                // was their handle on that folder and it has just
                // gone, so the path has to be handed back.
                note_kept_files(d, kept, &mut nzb_by_dir);
                if count > 0 {
                    d.note_releases_deleted(&deleted_names);
                    d.history_tombstone(&doomed_ids);
                    d.save_queue();
                }
                // A class sweep (all/completed/failed) is idempotent:
                // asking for a state the history is already in is
                // success, and LunaSea's clear-history dialog reads
                // false as an error toast (§18). A per-id delete keeps
                // reporting the miss - an unknown id is diagnosable.
                let class_sweep = matches!(value.as_str(), "all" | "completed" | "failed");
                json!({"status": count > 0 || class_sweep, "removed": count})
            }
            _ => history_json(d, params),
        }
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
pub(in crate::serve) fn requeue_category(
    d: &Arc<Daemon>,
    job: &Arc<Mutex<Job>>,
    name: &str,
    cat: &str,
) -> Result<(), &'static str> {
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
    let old_dir = {
        let mut g = job.lock_ok();
        if g.state != JobState::Queued {
            return Err("job already started");
        }
        g.category = cat.to_string();
        std::mem::replace(&mut g.out_dir, dir.clone())
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
    Ok(())
}

#[cfg(test)]
#[path = "queue_cap_tests.rs"]
mod cap_payload_tests;

#[cfg(test)]
mod queue_custody_tests {
    use super::*;
    use crate::serve::testutil::test_daemon;

    const NZB: &[u8] = br#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb"><file poster="x" date="0" subject="&quot;a.bin&quot; yEnc (1/1)"><groups><group>g</group></groups><segments><segment bytes="1000" number="1">one@x</segment></segments></file></nzb>"#;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("nzbfast-qcust-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("temp dir");
        d
    }

    /// "Download it again" pressed twice at once adds the release ONCE.
    ///
    /// http.rs runs eight worker threads over the one listener, so two
    /// dashboard tabs (or a tab and a scripted call) genuinely overlap.
    /// The notice used to be cloned and only removed after a successful
    /// admission, so both calls passed the find, both read the spool
    /// copy and both enqueued - with `allow_dupe` set, so nothing held
    /// the second, and `choose_out_dir` gave it a suffixed folder of its
    /// own: one press, two complete downloads (Codex sweep 3, L3).
    #[test]
    fn two_overlapping_retries_of_one_notice_add_the_release_once() {
        let dir = tmp("keptrace");
        let d = test_daemon(&dir);
        let nzb = d.spool.join("Raced.Release.nzb");
        std::fs::write(&nzb, NZB).expect("spool copy");
        let out = d.out_dir().join("Raced.Release");
        d.note_delete_kept("Raced.Release", &out, "the Trash refused it", Some(&nzb));
        let path = out.display().to_string();

        KEPT_RETRY_STALL_MS.store(600, Ordering::Relaxed);
        let d2 = d.clone();
        let p2 = path.clone();
        let first = std::thread::spawn(move || retry_kept_notice(&d2, &p2));
        // Well inside the stall: the second call lands while the first
        // is holding the notice and has already read its bytes.
        std::thread::sleep(std::time::Duration::from_millis(150));
        let second = retry_kept_notice(&d, &path);
        let first = first.join().expect("first retry");
        KEPT_RETRY_STALL_MS.store(0, Ordering::Relaxed);

        let admitted = [&first, &second]
            .iter()
            .filter(|v| v["status"] == serde_json::Value::Bool(true))
            .count();
        assert_eq!(
            admitted, 1,
            "both presses were admitted: {first} / {second}"
        );
        assert_eq!(
            d.queue.lock_ok().len(),
            1,
            "one press on the notice, one download"
        );
        assert!(
            d.delete_kept.lock_ok().is_empty(),
            "the spent notice must not come back"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A failed add puts the notice BACK: the folder is still there, so
    /// the strip and its button have to survive it.
    #[test]
    fn a_failed_retry_leaves_the_notice_where_it_was() {
        let dir = tmp("keptback");
        let d = test_daemon(&dir);
        // Two notices, so the restore has to land in the right slot.
        let first = d.out_dir().join("First.Release");
        let nzb1 = d.spool.join("First.Release.nzb");
        std::fs::write(&nzb1, NZB).expect("spool copy");
        d.note_delete_kept("First.Release", &first, "refused", Some(&nzb1));
        let second = d.out_dir().join("Second.Release");
        let nzb2 = d.spool.join("Second.Release.nzb");
        // Not an NZB at all, so `enqueue` refuses it.
        std::fs::write(&nzb2, b"not xml").expect("spool copy");
        d.note_delete_kept("Second.Release", &second, "refused", Some(&nzb2));

        let answer = retry_kept_notice(&d, &second.display().to_string());
        assert_eq!(
            answer["status"],
            serde_json::Value::Bool(false),
            "a spool copy that does not parse cannot be admitted"
        );
        let ring = d.delete_kept.lock_ok().clone();
        assert_eq!(ring.len(), 2, "the unspent notice was dropped");
        assert_eq!(
            ring[1].path,
            second.display().to_string(),
            "restored out of order"
        );
        assert!(nzb2.exists(), "an unspent notice keeps its spool copy");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A recategorize with NO sidecar live still takes the job's
    /// part-downloaded files with it.
    ///
    /// The adoption that moves them runs on the prefetch task's exit
    /// path and nowhere else, so a job that was prefetched and then
    /// stopped - an error, a pause, an earlier poke - has its journal
    /// and part-files sitting in the old directory with the slot already
    /// empty. The recategorize then re-pointed the record and poked
    /// nothing, so the primary run started at the new directory from
    /// zero and refetched the whole release over the same provider
    /// quota, and the old folder was named by no record at all (Codex
    /// sweep 3, M12).
    #[test]
    fn a_recategorize_with_no_sidecar_moves_the_partial_files() {
        let dir = tmp("recat");
        let d = test_daemon(&dir);
        let old = d.out_dir().join("Repointed.Release");
        std::fs::create_dir_all(&old).expect("old dir");
        std::fs::write(old.join(".nzbfast.journal"), b"journal").expect("journal");
        std::fs::write(old.join("part01.rar"), b"landed bytes").expect("part file");

        let job = Arc::new(Mutex::new(
            job_from_json(&serde_json::json!({
                "nzo_id": "nzo-recat-1",
                "name": "Repointed.Release",
                "nzb_path": "/tmp/x.nzb",
                "out_dir": old.to_string_lossy(),
                "state": "Queued",
            }))
            .expect("job"),
        ));
        d.queue.lock_ok().push_back(job.clone());
        assert!(
            d.sidecar.lock_ok().is_none(),
            "the shape under test is the one with no sidecar live"
        );

        requeue_category(&d, &job, "Repointed.Release", "movies").expect("recategorize");
        let now = job.lock_ok().out_dir.clone();
        assert_ne!(now, old, "the whole point of the call is a new directory");
        assert!(
            now.join("part01.rar").exists() && now.join(".nzbfast.journal").exists(),
            "the part-downloaded release stayed behind, so the job refetches it all"
        );
        assert!(
            !old.exists(),
            "the old directory is named by no record now and must not survive"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
