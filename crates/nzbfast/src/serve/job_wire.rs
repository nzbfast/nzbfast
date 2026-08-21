//! `Job` <-> JSON wire form: the pair that queue.json round-trips through
//! (TODO 106 code motion out of job.rs).
//!
//! One writer and one reader for the same key set - they are only correct
//! together, so they live together. A child module of `job`, re-exported by
//! it, so `job_json` / `job_from_json` stay the same paths to every caller.

use super::*;

pub(in crate::serve) fn job_json(j: &Job) -> Value {
    json!({
        "nzo_id": j.nzo_id,
        "name": j.name,
        "nzb_path": j.nzb_path.to_string_lossy(),
        "origin": j.origin,
        "category": j.category,
        "state": format!("{:?}", j.state),
        "total_bytes": j.total_bytes,
        "out_dir": j.out_dir.to_string_lossy(),
        "fail_message": j.fail_message,
        "fail_detail": j.fail_detail,
        "delete_status": j.delete_status,
        "priority": j.priority,
        "paused": j.paused,
        "retries": j.retries,
        "dupe_key": j.dupe_key,
        "held_for": j.held_for,
        "library": j.library,
        "fetched": j.fetched,
        "downloaded_bytes": j.downloaded_bytes,
        "elapsed_secs": j.elapsed_secs,
        // Wall clock, so history ages survive a restart.
        "finished_unix": j.finished_unix,
        "postproc_secs": j.postproc_secs,
        // The other wall clock, for the same reason: `queued_at` is a
        // monotonic Instant that cannot cross a process (and is taken at
        // pick), so every restored queue row answered SAB's numeric
        // `time_added` with null and a strict client stopped parsing the
        // queue there (M10, 10 Aug sweep).
        "queued_unix": j.queued_unix,
        "nzb_sha": j.nzb_sha,
        "finalizing": j.finalizing,
        "deferred": j.deferred,
        "defer_reason": j.defer_reason,
        "defer_count": j.defer_count,
        "password": j.password,
        "bad_blocks": j.bad_blocks,
        "verify_blocks": j.verify_blocks,
        "tv_sort": j.tv_sort,
        "smart_rule": j.smart_rule,
        // Whether out_dir is the shared season folder. Persisted: a
        // restart that forgot it would let a delete-with-files remove a
        // whole season (see Job::filed).
        "filed": j.filed,
        // What filing appended to the episode files. Persisted because
        // the naming settings are live and this is history: recomputing
        // it later answers about today, not about the files on disk.
        "filed_suffix": j.filed_suffix,
        "filed_title": j.filed_title,
        "filed_base": j.filed_base,
        "password_required": j.password_required,
        "eat_volumes_ok": j.eat_volumes_ok,
        "zip_packed": j.zip_packed,
        "unpack_blocked_by": j.unpack_blocked_by,
        // Persisted because it is the only record that the payload is
        // in two places: nothing can work that out after the fact once
        // the move's own log line has rolled out of the ring.
        "move_split": j.move_split,
        "move_failed": j.move_failed,
        // Persisted for the same reason as the two above: the retry
        // ladder has to survive a restart, or a daemon that restarts
        // daily is back to retrying an unreachable NAS forever.
        "move_attempts": j.move_attempts,
        "move_pending": j.move_pending,
        // §158 item 1: which cross-store move this copy belongs to. The
        // ONE field both stores write for the same nzo_id, and the only
        // thing that tells a half-written park from a half-written retry
        // at restore - see `serve/moveseq.rs`.
        "move_seq": j.move_seq,
        "archive_shape": j.archive_shape,
        // The identity facts an oracle supplied. Persisted rather than
        // recomputed: every one of them cost a third-party request, and
        // the headers the CRC came from are long gone by restart.
        "inner_crc": j.inner_crc,
        "identity_name": j.identity_name,
        "identity_imdb": j.identity_imdb,
        "identity_src": j.identity_src,
        "auto_retry_at": j.auto_retry_at,
        "auto_retry_why": j.auto_retry_why,
        "pp_params": j.pp_params,
        "sab_pp": j.sab_pp,
        "script_override": j.script_override,
        "replaces": j.replaces.as_ref().map(|p| p.to_string_lossy()),
        // Survives a restart: a job the daemon was killed mid-download
        // still knows where to report its failure when it eventually
        // does fail, and how deep the replacement chain already is.
        "failure_link": j.failure_link,
        "failure_host": j.failure_host,
        "failure_https": j.failure_https,
        "failure_depth": j.failure_depth,
        "identify": j.identify,
        // §77 pre-flight verdict. Persisted rather than recomputed: the
        // probe cost a round of STATs against every server, and after a
        // restart the answer to "was it already missing when you added
        // it?" cannot be obtained any other way - the post has moved on.
        "health": j.health.as_ref().map(crate::health::health_json),
        // §76. Persisted, not recomputed: the live writer it was read
        // from is gone, and re-probing every history row at load would
        // wake a disk full of finished downloads to learn what we
        // already knew.
        "media": j.media,
        // What the post-processing sweeps removed (history drawer's
        // cleanup line). Persisted: the sweeps ran once, at completion,
        // and nothing can re-count them after the files are gone.
        "cleaned_files": j.cleaned_files,
        "cleaned_par2": j.cleaned_par2,
        "cleaned_trash": j.cleaned_trash,
    })
}

pub(in crate::serve) fn job_from_json(v: &Value) -> Option<Job> {
    let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
    let out_dir = PathBuf::from(s("out_dir")?);
    let tv_sort = v.get("tv_sort").and_then(Value::as_bool).unwrap_or(false);
    // Records written before `filed` existed have to answer the question
    // somehow, and the shape of `out_dir` is the whole answer: a season
    // folder is shared no matter what state the job is sitting in.
    //
    // Emphatically NOT gated on `state == "Completed"`. The pre-upgrade
    // `retry` re-queued a filed job without moving it off the season
    // folder and then persisted it, so a legacy record can read `Queued`
    // while `out_dir` is still `Show/Season NN` - and migrating that as
    // `filed = false` is what hands the next delete-with-files a
    // `remove_dir_all` of the season.
    let filed = v
        .get("filed")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| tv_sort && is_season_dir(&out_dir));
    Some(Job {
        nzo_id: s("nzo_id")?,
        name: s("name")?,
        nzb_path: PathBuf::from(s("nzb_path")?),
        // Absent on records written before jobs carried an origin.
        origin: s("origin").unwrap_or_default(),
        category: s("category").unwrap_or_default(),
        state: match v.get("state").and_then(Value::as_str)? {
            "Completed" => JobState::Completed,
            "Failed" => JobState::Failed,
            // Queued - including a job caught mid-Downloading by the
            // shutdown: it goes back through the scheduler and resumes.
            _ => JobState::Queued,
        },
        total_bytes: v.get("total_bytes").and_then(Value::as_u64).unwrap_or(0),
        out_dir,
        fail_message: s("fail_message").unwrap_or_default(),
        fail_detail: s("fail_detail").unwrap_or_default(),
        // Monotonic clock cannot survive a process, so this stays None;
        // `finished_unix` is the one that carries the age across.
        finished_at: None,
        finished_unix: v.get("finished_unix").and_then(Value::as_i64),
        // Absent on every record written before the tail was timed;
        // 0.0 is exactly what those rows can truthfully say, and the
        // drawer renders no line for it.
        postproc_secs: v
            .get("postproc_secs")
            .and_then(Value::as_f64)
            .unwrap_or(0.0),
        // Never written, so never read: these index a log ring this
        // process has not filled. See `Job::log_mark`.
        log_mark: 0,
        log_end: 0,
        nzb_sha: s("nzb_sha").unwrap_or_default(),
        finalizing: v
            .get("finalizing")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        priority: v.get("priority").and_then(Value::as_i64).unwrap_or(0) as i32,
        paused: v.get("paused").and_then(Value::as_bool).unwrap_or(false),
        // Monotonic like finished_at, so a restart clears it - the
        // late-pick marker measures THIS process's reaction time.
        queued_at: None,
        // ...and the wall-clock twin that does survive, which is what
        // the SAB facade reports as `time_added`.
        queued_unix: v.get("queued_unix").and_then(Value::as_i64),
        idle_at_add: false,
        retries: v.get("retries").and_then(Value::as_u64).unwrap_or(0) as u32,
        dupe_key: s("dupe_key"),
        held_for: s("held_for").unwrap_or_default(),
        library: v.get("library").and_then(Value::as_bool).unwrap_or(false),
        fetched: v.get("fetched").and_then(Value::as_bool).unwrap_or(false),
        tombstone: false,
        del_on_drop: false,
        delete_status: s("delete_status").unwrap_or_default(),
        suspended: false,
        downloaded_bytes: v
            .get("downloaded_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        elapsed_secs: v.get("elapsed_secs").and_then(Value::as_f64).unwrap_or(0.0),
        deferred: v.get("deferred").and_then(Value::as_bool).unwrap_or(false),
        defer_reason: s("defer_reason").unwrap_or_default(),
        defer_count: v.get("defer_count").and_then(Value::as_u64).unwrap_or(0) as u32,
        demote: false,
        password: s("password"),
        // Records written before verification became nullable stored 0
        // for BOTH "nothing verified this" and "verified, nothing bad",
        // and nothing else on the record tells them apart. A non-zero
        // count is proof a verifier ran, so it survives as a verdict; a
        // zero without the companion block count is unknowable and reads
        // as "not verified" rather than claiming a check that may never
        // have happened. New records carry `verify_blocks` and are
        // exact.
        bad_blocks: match (
            v.get("bad_blocks").and_then(Value::as_u64),
            v.get("verify_blocks").and_then(Value::as_u64),
        ) {
            (Some(bad), _) if bad > 0 => Some(bad),
            (Some(bad), Some(checked)) if checked > 0 => Some(bad),
            _ => None,
        },
        verify_blocks: v.get("verify_blocks").and_then(Value::as_u64).unwrap_or(0),
        smart_rule: s("smart_rule").unwrap_or_default(),
        tv_sort,
        filed,
        // Absent on records written before filing recorded its suffix.
        // NOT `unwrap_or_default()`: an empty suffix is a real value that
        // means "auto-rename was off, the files are bare {base}.{ext}",
        // and as a match pattern it takes every quality of the episode.
        // Legacy records say None and fall back to a recompute, which is
        // what all of them did before this field existed.
        filed_suffix: v
            .get("filed_suffix")
            .and_then(Value::as_str)
            .map(str::to_string),
        // Absent on every record written before episode titles existed,
        // and `delete_tail` reads that absence as "no title on disk" -
        // which for those records is a fact, not a fallback.
        filed_title: v
            .get("filed_title")
            .and_then(Value::as_str)
            .map(str::to_string),
        filed_base: v
            .get("filed_base")
            .and_then(Value::as_str)
            .map(str::to_string),
        password_required: v
            .get("password_required")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        eat_volumes_ok: v
            .get("eat_volumes_ok")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        zip_packed: v
            .get("zip_packed")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        unpack_blocked_by: s("unpack_blocked_by").unwrap_or_default(),
        move_split: s("move_split").unwrap_or_default(),
        move_failed: s("move_failed").unwrap_or_default(),
        move_attempts: v.get("move_attempts").and_then(Value::as_u64).unwrap_or(0) as u32,
        move_pending: v
            .get("move_pending")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        // Absent on every record written before §158 item 1. Zero is the
        // right reading of that absence: BOTH copies of a pre-upgrade
        // split-brain id read 0, the comparison ties, and the tie falls
        // back to the §158 rule those records were written under -
        // history wins. Nothing about an old store changes meaning.
        move_seq: v.get("move_seq").and_then(Value::as_u64).unwrap_or(0),
        archive_shape: s("archive_shape").unwrap_or_default(),
        inner_crc: v.get("inner_crc").and_then(Value::as_u64).unwrap_or(0) as u32,
        identity_name: s("identity_name").unwrap_or_default(),
        identity_imdb: s("identity_imdb").unwrap_or_default(),
        identity_src: s("identity_src").unwrap_or_default(),
        auto_retry_at: v.get("auto_retry_at").and_then(Value::as_u64),
        auto_retry_why: s("auto_retry_why").filter(|w| !w.is_empty()),
        pp_params: v
            .get("pp_params")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|p| {
                        let pair = p.as_array()?;
                        Some((
                            pair.first()?.as_str()?.to_string(),
                            pair.get(1)?.as_str()?.to_string(),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default(),
        sab_pp: v.get("sab_pp").and_then(Value::as_i64),
        script_override: s("script_override").unwrap_or_default(),
        replaces: s("replaces").filter(|v| !v.is_empty()).map(PathBuf::from),
        failure_link: s("failure_link").unwrap_or_default(),
        // Absent in records written before the origin check existed. An
        // empty host fails the match, so such a job reports nowhere -
        // the safe direction, and only until its next fetch.
        failure_host: s("failure_host").unwrap_or_default(),
        // Absent in records written before the scheme was kept. `false`
        // means "http origin", which only ever permits MORE than the
        // truth would - and only until the job's next fetch restamps it.
        failure_https: v
            .get("failure_https")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        failure_depth: v.get("failure_depth").and_then(Value::as_u64).unwrap_or(0) as u8,
        identify: s("identify").unwrap_or_default(),
        // Absent on every record written before §77, and on any record
        // whose verdict no longer parses: both mean "not sampled", which
        // renders no badge and sinks nothing.
        health: v.get("health").and_then(crate::health::health_from_json),
        // Absent on every record written before §76, and on any that a
        // future field addition cannot deserialize - both mean "nothing
        // known about the bytes", which is what an unprobed job is.
        media: v
            .get("media")
            .cloned()
            .and_then(|m| serde_json::from_value(m).ok()),
        media_rejudge: false,
        // Absent on records written before the cleanup line existed:
        // zero renders no drawer row, which is all those records can
        // truthfully say.
        cleaned_files: v.get("cleaned_files").and_then(Value::as_u64).unwrap_or(0) as u32,
        cleaned_par2: v.get("cleaned_par2").and_then(Value::as_u64).unwrap_or(0) as u32,
        cleaned_trash: v
            .get("cleaned_trash")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}
