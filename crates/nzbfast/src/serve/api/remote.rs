//! Phone-remote parity arms (§18): the SAB calls LunaSea and nzb360
//! send that fall outside the *arr-certified surface, plus the helpers
//! the /jsonrpc facade shares for the same operations (rename, sort).
//! Kept out of queue.rs deliberately - that file is close to the size
//! gate's ceiling, and these arms are a client-compat appendix rather
//! than core queue behaviour.

use super::*;

pub(in crate::serve) fn dispatch(
    d: &Arc<Daemon>,
    req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    mode: &str,
    ctx: &ApiCtx<'_>,
    api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some(match mode {
        // Real SAB's top-level move: mode=switch&value=<nzo>&value2=<pos>.
        // The queue arm (mode=queue&name=switch) has carried the same
        // logic since §96; this spelling is the one LunaSea uses, and
        // its parser requires the answer wrapped as {"result":
        // {"position": N}} - SAB's own shape - where the queue arm
        // answers {"status", "position"}.
        "switch" => {
            let mut p = params.clone();
            p.insert("name".into(), "switch".into());
            let inner = queue::dispatch(d, req, &p, "queue", ctx, api_body)?;
            match inner.get("position").and_then(Value::as_i64) {
                Some(pos) if inner.get("status").and_then(Value::as_bool) == Some(true) => {
                    json!({"result": {"position": pos, "priority": 0}})
                }
                _ => inner,
            }
        }
        _ => return None,
    })
}

/// NZBGet's `editqueue GroupMoveOffset`: Param is a signed count of
/// positions, as a string. LunaSea's queue reorder sends ONLY this
/// form, never MoveTop/MoveBottom.
pub(in crate::serve) fn move_by_offset(d: &Arc<Daemon>, ids: &[i64], offset: i64) -> bool {
    let nzo_int = crate::serve::sabcompat::nzo_int;
    let mut ok = false;
    let mut q = d.queue.lock_ok();
    // One id per call is what the clients send; a multi-id move
    // applies the offset to each in a stable order.
    for id in ids {
        if let Some(from) = q.iter().position(|j| nzo_int(&j.lock_ok().nzo_id) == *id) {
            // `offset` is parsed straight off the JSON-RPC parameter, so
            // it can be any i64: a plain `+` overflows (a debug-build
            // panic, and in release a wrap that clamps to the WRONG end
            // - i64::MAX sends the job to the top instead of the bottom).
            // Saturate, then clamp.
            let to = (from as i64)
                .saturating_add(offset)
                .clamp(0, q.len() as i64 - 1) as usize;
            if let Some(j) = q.remove(from) {
                q.insert(to, j);
                ok = true;
            }
        }
    }
    ok
}

/// NZBGet's `editqueue GroupPause`/`GroupResume`, by the ids' numeric
/// half. Moved verbatim out of jr_editqueue (§18 pushed that fn past
/// the size gate); the history on each step:
///
/// - Pausing a job also stops its prefetch (same as the /api handler):
///   the sidecar is the one part of a "paused" job that would keep
///   downloading.
/// - Through the shared transition, not a bare flag write (Codex sweep
///   2, 3 Aug M4). Setting `paused` on a job in its verify/repair/
///   unpack tail changes nothing about the tail - it runs to
///   completion - but the flag STAYS, and an auto-retry then requeued
///   the job with `paused` still true, where `pick_job` skips it
///   forever. The /api arm has refused that since the tail guard
///   landed; the jsonrpc copy had its own and never got it.
/// - The flag alone only bites when the job next enters the queue, so
///   pausing the item that is actually downloading did nothing while
///   answering success - hence `suspend_matching`.
/// - Pausing the last runnable job idles the queue with no park, and
///   this facade answered true without saying so while the REST arm
///   has announced it since the 10 Aug sweep (Codex sweep 14 Aug M4).
///   Resume takes the same call, deliberately: it never EMITS on its
///   own (the latch keeps a still-idle queue silent), and the re-arm a
///   resume owes lives inside `apply_pause`, under the queue lock the
///   loop holds.
pub(in crate::serve) fn pause_by_ids(d: &Arc<Daemon>, ids: &[i64], pause: bool) -> bool {
    let nzo_int = crate::serve::sabcompat::nzo_int;
    if pause {
        d.poke_sidecar(|id| ids.contains(&nzo_int(id)));
    }
    let mut ok = false;
    for j in d.queue.lock_ok().iter() {
        let mut g = j.lock_ok();
        if ids.contains(&nzo_int(&g.nzo_id)) && queue::apply_pause(d, &mut g, pause) {
            ok = true;
        }
    }
    if pause {
        d.suspend_matching(true, |g| ids.contains(&nzo_int(&g.nzo_id)));
    }
    if ok {
        d.note_queue_idle();
    }
    ok
}

/// NZBGet's `editqueue GroupSetName`, by the ids' numeric half.
pub(in crate::serve) fn rename_by_ids(d: &Arc<Daemon>, ids: &[i64], newname: &str) -> bool {
    let nzo_int = crate::serve::sabcompat::nzo_int;
    if newname.is_empty() {
        return false;
    }
    // Collect first, act after the queue lock is gone: the rename
    // takes add_lock and the job's own lock, the same order the
    // recategorize arm keeps.
    let targets: Vec<Arc<Mutex<Job>>> = d
        .queue
        .lock_ok()
        .iter()
        .filter(|j| ids.contains(&nzo_int(&j.lock_ok().nzo_id)))
        .cloned()
        .collect();
    let mut ok = false;
    for j in targets {
        ok |= rename_queued(d, &j, newname).is_ok();
    }
    ok
}

/// NZBGet's `editqueue GroupSetParameter`. The one parameter clients
/// send on their own is *Unpack:Password (LunaSea's set-password
/// action); it maps onto the same per-job password the SAB facade's
/// rename value3 sets. Anything else is recorded in pp_params, where
/// the *arrs' drone GUID already lives.
pub(in crate::serve) fn set_parameter(d: &Arc<Daemon>, ids: &[i64], param: &str) -> bool {
    let nzo_int = crate::serve::sabcompat::nzo_int;
    let (pname, pval) = param.split_once('=').unwrap_or((param, ""));
    let mut ok = false;
    for j in d.queue.lock_ok().iter() {
        let mut g = j.lock_ok();
        if !ids.contains(&nzo_int(&g.nzo_id)) {
            continue;
        }
        if pname.eq_ignore_ascii_case("*Unpack:Password") {
            g.password = Some(pval.to_string()).filter(|p| !p.is_empty());
        } else {
            g.pp_params.retain(|(n, _)| n != pname);
            g.pp_params.push((pname.to_string(), pval.to_string()));
        }
        ok = true;
    }
    ok
}

/// Rename a queued job, re-deriving its output directory from the new
/// name through the same queued-recategorize transaction change_cat
/// runs - a rename controls filesystem routing exactly as a category
/// does, so writing the label alone would leave the record saying one
/// folder while the job downloads into another. Serves both fronts:
/// SAB's `mode=queue&name=rename` and NZBGet's `GroupSetName`.
///
/// Persisting the result is the CALLER's, as it is for the
/// `requeue_category` this wraps - and both fronts do it, `rename_arm`
/// directly and `rename_by_ids` through the tail `save_queue` every
/// `jr_editqueue` subcommand gets. That second one is a save several
/// arms away from the verb that earned it, so it reads as absent: it
/// was reported on 20 Aug 2026 as a rename lost across a restart, which
/// it is not. It stays a caller's job because the two doors keep
/// writing after this returns (the password, on the SAB side), and one
/// save at the end of the request stores the whole edit rather than a
/// half-applied record - and renames N jobs in one queue.json rewrite
/// rather than N. `remote_compat.rs` pins the NZBGet door end to end.
pub(in crate::serve) fn rename_queued(
    d: &Arc<Daemon>,
    job: &Arc<Mutex<Job>>,
    newname: &str,
) -> Result<(), &'static str> {
    // Untrusted: a single contained path component, like enqueue - the
    // name is joined under out_root when the directory is derived.
    let newname = nzbkit::disk::sanitize_filename(newname.trim());
    if newname.is_empty() {
        return Err("empty name");
    }
    let cat = job.lock_ok().category.clone();
    queue::requeue_category(d, job, &newname, &cat)?;
    // The label follows the directory swap; requeue_category has
    // already refused non-queued jobs, and a job that starts in this
    // gap still downloads into the directory just derived from the
    // new name, so the two can never disagree.
    job.lock_ok().name = newname;
    // The name is a queue payload rider AND, since N12, an input to the
    // cached owned-title set, so the store above owes the revision a
    // bump. `rename_arm` follows with a `save_queue` that bumps anyway;
    // `rename_by_ids` (NZBGet's GroupSetName) does not itself - its
    // store is `jr_editqueue`'s tail save - so without this the
    // store-before-bump rule the caches rely on would sit outside the
    // function that knows a rename happened. Bumping here covers both
    // doors from one place, and the second bump on the SAB path costs
    // an idle poll one payload.
    d.queue_rev.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

/// SAB's `mode=queue&name=rename&value=<nzo>&value2=<name>[&value3=<pw>]`.
/// value3 is how SAB spells "set this job's password" - LunaSea's
/// set-password dialog sends the CURRENT name in value2 plus the
/// password in value3, so a same-name rename must succeed for the
/// password half to land. Queued jobs only, like SAB.
pub(in crate::serve) fn rename_arm(
    d: &Arc<Daemon>,
    params: &std::collections::HashMap<String, String>,
) -> Value {
    let value = params.get("value").cloned().unwrap_or_default();
    let hit_id = |id: &str| value.split(',').any(|v| v.trim() == id);
    let newname = params.get("value2").map(String::as_str).unwrap_or("");
    let pw = params
        .get("value3")
        .map(String::as_str)
        .filter(|p| !p.is_empty());
    let targets: Vec<Arc<Mutex<Job>>> = d
        .queue
        .lock_ok()
        .iter()
        .filter(|j| hit_id(&j.lock_ok().nzo_id))
        .cloned()
        .collect();
    let mut n = 0;
    for j in &targets {
        if rename_queued(d, j, newname).is_ok() {
            if let Some(pw) = pw {
                j.lock_ok().password = Some(pw.to_string());
            }
            n += 1;
        }
    }
    if n > 0 {
        d.save_queue();
    }
    json!({"status": n > 0})
}

/// SAB's `mode=queue&name=change_complete_action&value=<action>`.
/// The machine actions (shutdown_pc, hibernate_pc, standby_pc,
/// shutdown_program) have no machinery here. "none" clears a thing
/// that is already clear - success. For the rest the honest answer is
/// a refusal: answering true while executing nothing would strand a
/// user waiting on a shutdown that never comes.
pub(in crate::serve) fn complete_action_arm(
    params: &std::collections::HashMap<String, String>,
) -> Value {
    let v = params.get("value").map(String::as_str).unwrap_or("none");
    if v == "none" || v.is_empty() {
        json!({"status": true})
    } else {
        json!({"status": false,
               "error": "queue-complete actions are not supported here"})
    }
}

/// SAB's `mode=queue&name=sort&sort=<key>&dir=<asc|desc>`.
pub(in crate::serve) fn sort_arm(
    d: &Arc<Daemon>,
    params: &std::collections::HashMap<String, String>,
) -> Value {
    let key = params.get("sort").map(String::as_str).unwrap_or("");
    let asc = params.get("dir").map(String::as_str) != Some("desc");
    json!({"status": sort_queue(d, key, asc)})
}

/// Sort the whole queue by one key. Serves SAB's
/// `mode=queue&name=sort&sort=<key>&dir=<asc|desc>` (keys avg_age,
/// name, size) and NZBGet's `editqueue GroupSort` (name, size, left,
/// priority, category, age - sent as "<key>+"/"<key>-"). False for a
/// key neither client defines, so a typo is visible instead of a
/// silent success over an unsorted queue.
pub(in crate::serve) fn sort_queue(d: &Arc<Daemon>, key: &str, asc: bool) -> bool {
    #[expect(clippy::type_complexity)]
    let keyfn: Box<dyn Fn(&Job) -> (i64, String)> = match key {
        "name" => Box::new(|g| (0, g.name.to_lowercase())),
        "size" | "mb" => Box::new(|g| (g.total_bytes as i64, String::new())),
        "left" | "mbleft" => Box::new(|g| {
            (
                g.total_bytes.saturating_sub(g.downloaded_bytes) as i64,
                String::new(),
            )
        }),
        "priority" => Box::new(|g| (g.priority as i64, String::new())),
        "category" | "cat" => Box::new(|g| (0, g.category.to_lowercase())),
        // SAB's avg_age sorts oldest-post-first; the add time is the
        // closest thing a one-pass queue records per job.
        "avg_age" | "age" => Box::new(|g| (g.queued_unix.unwrap_or(0), String::new())),
        _ => return false,
    };
    let mut q = d.queue.lock_ok();
    let mut v: Vec<_> = q.drain(..).collect();
    v.sort_by_cached_key(|j| {
        let g = j.lock_ok();
        keyfn(&g)
    });
    if !asc {
        v.reverse();
    }
    *q = v.into();
    drop(q);
    d.save_queue();
    true
}

// Clippy's `items_after_test_module` wants this last in the file; it is.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::serve::testutil::test_daemon;

    /// A rename moves `queue_rev`, on BOTH front doors.
    ///
    /// The name rides the revisioned queue payload and, since N12, is an
    /// input to the cached owned-title set that the Affinity sort and
    /// the index eviction pass both read. `rename_arm` (SAB) ends with a
    /// `save_queue` that bumps; `rename_by_ids` (NZBGet's GroupSetName)
    /// does not itself (its store is `jr_editqueue`'s tail save), so the
    /// bump belongs to `rename_queued` or the two doors disagree about
    /// whether a rename happened.
    #[test]
    fn a_rename_moves_the_queue_revision() {
        let dir = std::env::temp_dir().join(format!("nzbfast-renrev-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let d = test_daemon(&dir);
        let job = Arc::new(Mutex::new(
            job_from_json(&json!({
                "nzo_id": "SABnzbd_nzo_r1", "name": "Before.Rename",
                "nzb_path": "/tmp/x.nzb", "out_dir": d.out_dir().join("Before.Rename"),
                "state": "Queued",
            }))
            .expect("job_from_json"),
        ));
        d.queue.lock_ok().push_back(job.clone());

        let rev = d.queue_rev.load(Ordering::Relaxed);
        rename_queued(&d, &job, "After.Rename").expect("rename a queued job");
        assert_eq!(job.lock_ok().name, "After.Rename");
        assert!(
            d.queue_rev.load(Ordering::Relaxed) > rev,
            "the rename has to move the revision the payload and the \
             owned-key cache are gated on"
        );

        // ...and a REFUSED rename must not: the payload is unchanged, so
        // a bump there would re-send it to every idle tab for nothing.
        job.lock_ok().state = JobState::Downloading;
        let rev = d.queue_rev.load(Ordering::Relaxed);
        assert!(
            rename_queued(&d, &job, "Too.Late").is_err(),
            "a started job cannot be renamed"
        );
        assert_eq!(job.lock_ok().name, "After.Rename");
        assert_eq!(d.queue_rev.load(Ordering::Relaxed), rev);

        drop(d);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
