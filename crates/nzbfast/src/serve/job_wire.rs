//! `Job` <-> JSON wire form: the pair that queue.json round-trips through
//! (TODO 106 code motion out of job.rs).
//!
//! One writer and one reader for the same key set - they are only correct
//! together, so they live together. A child module of `job`, re-exported by
//! it, so `job_json` / `job_from_json` stay the same paths to every caller.

use super::*;

/// The persisted job record's schema generation. Stamped on every record
/// [`job_json`] writes, checked by [`job_from_json`].
///
/// **Absence is generation 1.** Every record on every disk today was
/// written before this field existed, and the reader treats a record with
/// no `schema_version` exactly as it treats one stamped `1` - which is
/// what makes adding the field a no-op for an existing store. That
/// equivalence is permanent, not a migration window: nothing rewrites an
/// old record to add the stamp, so version-less records will keep
/// arriving for as long as anyone has a spool directory.
///
/// **When to bump it, and when emphatically not to.** Same contract as
/// [`super::histstore::LIFE_SCHEMA_VERSION`]: adding a key never bumps
/// it, because a reader that has never heard of a key already ignores
/// it and every field in [`job_from_json`] documents what its own
/// absence means. It bumps only when an older reader would MISREAD a
/// record it can still parse - a key renamed, removed, or given a new
/// meaning.
///
/// **What a reader does with a version above its own: it refuses the
/// record, loudly.** That follows from the paragraph above rather than
/// from caution - by that contract a higher number is precisely the case
/// where a best-effort parse is known to be wrong, and the fields this
/// record decides are not cosmetic (`filed` gates whether a
/// delete-with-files may `remove_dir_all` a shared season folder;
/// `move_seq` is the only thing that tells a half-written park from a
/// half-written retry). Guessing there is worse than not loading.
///
/// **The cost of that, stated rather than buried, because it is the one
/// thing a future bump has to price in.** A refusal is a silent skip at
/// both production call sites (`job::restore_records` and
/// `histstore`'s replay `continue` past a `None`), and `queue.json` is
/// rewritten from whatever loaded - so a downgrade to a binary that
/// predates the bump does not merely fail to show the queue, it deletes
/// it on the next save. Two thin nets survive that: `persist`'s `.bak`
/// still holds the pre-downgrade file for one more load cycle, and
/// `history.jsonl` is append-only, so its rows outlive the refusal until
/// a compaction rewrite. Neither is a reason to bump this casually. A
/// bump is a one-way door for every binary already in the field.
pub(in crate::serve) const JOB_SCHEMA_VERSION: u64 = 1;

/// A persisted count read back into a field NARROWER than the JSON
/// number that carries it, saturating instead of wrapping.
///
/// Our own serializer can only ever emit a value that fits - the field
/// it came from is a `u32`/`u8`/`i32` - so a number that does not fit is
/// by construction corrupt or foreign, and the only question is which
/// wrong answer to give. `as` gives the worst one available: it WRAPS,
/// and the direction it wraps in is the dangerous one. Four of the eight
/// fields read through here are ladder counters compared against a small
/// give-up constant - `defer_count` (`stall`'s `>= 3`), `move_attempts`
/// (`MOVE_RETRY_GIVE_UP`), `failure_depth` (`FAILURE_REGRAB_MAX`) and
/// `refeed_depth` (`refeed::REFEED_MAX_DEPTH`) - and `2^32 as u32` is 0,
/// a RESET that hands the ladder back its whole budget. That is not
/// hypothetical damage: `Job::move_attempts` exists because an
/// unreachable destination with nothing counting the failures logged the
/// same EACCES 45 times across 15 hours.
///
/// Saturating moves such a counter PAST its give-up bound instead, which
/// stops the ladder - the safe direction, and the one this module
/// already reaches for elsewhere (a legacy record's empty
/// `failure_host` "fails the match, so such a job reports nowhere").
///
/// The other four are not ladders and the rule is applied to them
/// anyway, deliberately: `inner_crc` is a lookup key, where a saturated
/// value can only fail to match (and 0 would be WORSE, because 0 is that
/// field's documented sentinel for "no CRC" - laundering corruption into
/// a clean answer); `cleaned_files` and `cleaned_par2` render one
/// history-drawer line and gate nothing; `priority` is signed and gets
/// [`nar_i32`]. One rule with no per-field exceptions is the point - a
/// table of which corrupt values are safe to wrap is a table that goes
/// stale the first time a field grows a consumer.
///
/// **One hazard this introduces, stated rather than left to be found.**
/// A field saturated to `u32::MAX` that is later INCREMENTED overflows:
/// `Job::retries` is `+= 1`'d on a manual retry, so a hand-edited
/// `retries` of 2^32 now panics there in a debug build where wrapping to
/// 0 did not. Release is unaffected (`overflow-checks` is off there),
/// and 0 is the worse answer in release anyway - `retries` doubles as
/// the generation token `sidecar` and `hooks` compare against `gen0` to
/// tell "this job was retried under me" from "it was not", and a silent
/// reset makes that comparison lie. A loud debug panic on input nobody
/// can produce except by hand is the better half of that trade.
///
/// It is NOT a rejection, and that is the deliberate half. A rejected
/// record vanishes: both production readers skip a `None` and the next
/// save drops it. Losing a user's history row over a cosmetic
/// `cleaned_files` counter - which renders one drawer line and gates
/// nothing - would be a far larger fault than the corrupt number it was
/// reacting to. Only the schema version above is worth a whole record.
///
/// The wrong TYPE (a string, a float, a negative in a `u64` field) still
/// reads as the field's documented default, unchanged from before this
/// existed: `as_u64` already answered `None` there, and every one of
/// these fields documents what its own absence means. Pinned by test so
/// it is a decision rather than an accident.
fn nar_u32(v: &Value, key: &str) -> u32 {
    v.get(key)
        .and_then(Value::as_u64)
        .map_or(0, |n| u32::try_from(n).unwrap_or(u32::MAX))
}

/// [`nar_u32`] for a `u8` field. Same rule, same reasons.
fn nar_u8(v: &Value, key: &str) -> u8 {
    v.get(key)
        .and_then(Value::as_u64)
        .map_or(0, |n| u8::try_from(n).unwrap_or(u8::MAX))
}

/// [`nar_u32`] for the one SIGNED narrowed field, `priority`. Saturates
/// at both ends, so a corrupt value keeps its sign and therefore its
/// ordering against the documented range (2 Force .. -100 Default)
/// rather than wrapping across it - a wrap is what turns a garbage
/// negative into a job that outranks Force.
fn nar_i32(v: &Value, key: &str) -> i32 {
    v.get(key).and_then(Value::as_i64).map_or(0, |n| {
        i32::try_from(n).unwrap_or(if n < 0 { i32::MIN } else { i32::MAX })
    })
}

pub(in crate::serve) fn job_json(j: &Job) -> Value {
    json!({
        // First key on the record, so `head -c` on a spool file answers
        // which generation wrote it. See `JOB_SCHEMA_VERSION` for what
        // bumping it costs.
        "schema_version": JOB_SCHEMA_VERSION,
        "nzo_id": j.nzo_id,
        "name": j.name,
        "nzb_path": j.nzb_path.to_string_lossy(),
        "origin": j.origin,
        "category": j.category,
        "state": format!("{:?}", j.state),
        "total_bytes": j.total_bytes,
        "out_dir": j.out_dir.to_string_lossy(),
        // §282 item 14: which release replaced which, and why. Persisted
        // because the clause is a history clause - it has to survive the
        // restart between the switch and the user reading the row.
        "alt_from": j.alt_from,
        "alt_from_name": j.alt_from_name,
        "alt_why": j.alt_why,
        "alt_to_name": j.alt_to_name,
        "fail_message": j.fail_message,
        // TODO 307 item 1's job-level carry, as the token
        // `fail_kind_token` already publishes to `history_json` rather
        // than a second spelling of the same six values. ADDITIVE, so it
        // does NOT bump `JOB_SCHEMA_VERSION` - see that constant for the
        // rule and for what a bump would cost. `null` for a job nothing
        // classified, which is what every record written before this
        // field existed reads as and is the correct answer for them:
        // the sentence is genuinely all the evidence such a record has.
        "fail_code": j.fail_code.map(crate::failkind::fail_kind_token),
        "fail_detail": j.fail_detail,
        "delete_status": j.delete_status,
        "priority": j.priority,
        "paused": j.paused,
        "retries": j.retries,
        "dupe_key": j.dupe_key,
        "held_for": j.held_for,
        "library": j.library,
        "insurance": j.insurance,
        "fetched": j.fetched,
        "downloaded_bytes": j.downloaded_bytes,
        "elapsed_secs": j.elapsed_secs,
        // Wall clock, so history ages survive a restart.
        "finished_unix": j.finished_unix,
        "postproc_secs": j.postproc_secs,
        // TODO 207: the shortfall verdict for this job's network leg,
        // null for anything nothing judged. The log marks below are
        // deliberately absent from this list and this one deliberately
        // is not: a mark indexes a process-global ring, a verdict is a
        // statement about the download. See `Job::whyslow`.
        "whyslow": j.whyslow.as_ref().map(super::whyslow::verdict_json),
        // TODO 309: which route this job's last run took through the
        // §94 A resume gate. Same rule as `whyslow` above and for the
        // same reason - it is a statement about the download, and the
        // engine's log line about it is gone by the time anybody asks.
        "resume_route": j.resume_route.as_ref().map(resume_route_json),
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
        "defer_at": j.defer_at,
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
        // §296. Persisted for the reason the field's own comment gives:
        // it is the only record of which files are ALREADY at the
        // destination, and a move that forgets publishes them twice.
        "early_published": j.early_published.iter().map(|e| json!({
            "name": e.name, "len": e.len, "mtime_ns": e.mtime_ns,
            "nzf_id": e.nzf_id,
            "dest": e.dest.as_ref().map(|p| p.to_string_lossy()),
        })).collect::<Vec<_>>(),
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
        // TODO 280. Persisted for the reason the field's own comment
        // gives: forgetting it re-opens a child's payload to a refeed.
        "refeed_depth": j.refeed_depth,
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
    // The generation gate. Absent is generation 1 (every record written
    // before the stamp existed), anything at or below ours is readable,
    // and anything above it is refused rather than guessed at - the
    // whole argument, including what a refusal costs a downgrade, is at
    // `JOB_SCHEMA_VERSION`.
    //
    // A stamp that is PRESENT but not a number is refused too. Our
    // writer emits `json!(u64)` and nothing else, so a string or a null
    // there is not a generation this reader can place, and treating an
    // unreadable stamp as absence would let exactly the record the gate
    // exists for walk straight through it.
    match v.get("schema_version") {
        None => {}
        Some(Value::Number(n)) if n.as_u64().is_some_and(|g| g <= JOB_SCHEMA_VERSION) => {}
        Some(other) => {
            // One line per refused record, matching what the history
            // store already prints for a line it cannot read. A whole
            // store at a future generation is loud, and it should be:
            // the alternative is a queue that empties with nothing
            // anywhere saying why.
            //
            // It says where the bytes go, because "skipped" would be a
            // half-truth that matters here. `history.jsonl` is
            // append-only, so a refused history row really does survive
            // - until a compaction rewrite, which drops every line that
            // did not load. `queue.json` is rewritten from whatever
            // loaded, so a refused queue row is GONE at the next save;
            // only `persist`'s `.bak` still has it, and only until the
            // load after this one refreshes that too.
            warn!(
                target: "queue",
                "not loading a persisted job record stamped schema_version \
                 {other}: this build reads up to {JOB_SCHEMA_VERSION}, so the \
                 record was written by a later nzbfast (or is corrupt) and \
                 cannot be read safely. Run that version to load it - the next \
                 queue save drops it from queue.json, and a history compaction \
                 drops it from history.jsonl"
            );
            return None;
        }
    }
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
        alt_from: s("alt_from").unwrap_or_default(),
        alt_from_name: s("alt_from_name").unwrap_or_default(),
        alt_why: s("alt_why").unwrap_or_default(),
        alt_to_name: s("alt_to_name").unwrap_or_default(),
        fail_message: s("fail_message").unwrap_or_default(),
        // Absent on every record written before TODO 307 item 1, and
        // `None` is exactly what those records can truthfully say - the
        // reader then falls back to the string classifier, which is what
        // it did for all of them anyway. An UNKNOWN token reads `None`
        // too rather than refusing the record: a kind this build has not
        // heard of can only come from a newer one, and the schema rule
        // above is explicit that an additive key must never cost a
        // record. See `failkind::kind_from_token`.
        fail_code: v
            .get("fail_code")
            .and_then(Value::as_str)
            .and_then(crate::failkind::kind_from_token),
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
        // Absent on every record written before TODO 207, and that is
        // what those records get: None. NOT `unknown` and NOT `line` -
        // both are verdicts, and a record from before the field existed
        // carries none. Same trap as `bad_blocks` below, where a stored
        // 0 meant both "verified, nothing bad" and "never verified".
        // All of the reading is in `verdict_from_json`, so the token
        // set has one home.
        whyslow: super::whyslow::verdict_from_json(v.get("whyslow")),
        resume_route: resume_route_from_json(v.get("resume_route")),
        // Never written, so never read: these index a log ring this
        // process has not filled. See `Job::log_mark`.
        log_mark: 0,
        log_end: 0,
        nzb_sha: s("nzb_sha").unwrap_or_default(),
        finalizing: v
            .get("finalizing")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        priority: nar_i32(v, "priority"),
        paused: v.get("paused").and_then(Value::as_bool).unwrap_or(false),
        // Monotonic like finished_at, so a restart clears it - the
        // late-pick marker measures THIS process's reaction time.
        queued_at: None,
        // ...and the wall-clock twin that does survive, which is what
        // the SAB facade reports as `time_added`.
        queued_unix: v.get("queued_unix").and_then(Value::as_i64),
        idle_at_add: false,
        retries: nar_u32(v, "retries"),
        dupe_key: s("dupe_key"),
        held_for: s("held_for").unwrap_or_default(),
        library: v.get("library").and_then(Value::as_bool).unwrap_or(false),
        // Deferred rows are exactly the kind that sit across restarts,
        // so the flag survives; the attempt ladder does not (see
        // `Job::insurance_attempts` - a restart is a new day).
        insurance: v.get("insurance").and_then(Value::as_bool).unwrap_or(false),
        insurance_attempts: 0,
        insurance_note: String::new(),
        fetched: v.get("fetched").and_then(Value::as_bool).unwrap_or(false),
        tombstone: false,
        // Never persisted: a relocation cannot outlive the process
        // that was running it. See `Job::relocating`.
        relocating: 0,
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
        defer_at: v.get("defer_at").and_then(Value::as_u64).unwrap_or(0),
        defer_count: nar_u32(v, "defer_count"),
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
        move_attempts: nar_u32(v, "move_attempts"),
        move_pending: v
            .get("move_pending")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        // Absent on every record written before §296, which reads as
        // "nothing was published early" - true of all of them.
        early_published: v
            .get("early_published")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|e| {
                        Some(crate::serve::earlyfile::EarlyFile {
                            name: e.get("name").and_then(Value::as_str)?.to_string(),
                            len: e.get("len").and_then(Value::as_u64)?,
                            mtime_ns: e.get("mtime_ns").and_then(Value::as_u64).unwrap_or(0),
                            nzf_id: e
                                .get("nzf_id")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string(),
                            // Absent on a record written before the
                            // destination was recorded (sweep S6). None
                            // reads as "re-derive at spend time", which
                            // is what those records always did.
                            dest: e
                                .get("dest")
                                .and_then(Value::as_str)
                                .map(std::path::PathBuf::from),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default(),
        // Not on the wire at all: the refusal is re-derived from the
        // same `exists()` test on the next publish pass.
        early_refused: Default::default(),
        // Absent on every record written before §158 item 1. Zero is the
        // right reading of that absence: BOTH copies of a pre-upgrade
        // split-brain id read 0, the comparison ties, and the tie falls
        // back to the §158 rule those records were written under -
        // history wins. Nothing about an old store changes meaning.
        move_seq: v.get("move_seq").and_then(Value::as_u64).unwrap_or(0),
        archive_shape: s("archive_shape").unwrap_or_default(),
        inner_crc: nar_u32(v, "inner_crc"),
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
        failure_depth: nar_u8(v, "failure_depth"),
        // Absent on every record written before TODO 280, where 0 - "a
        // job nobody refed" - is the truth for all of them.
        refeed_depth: nar_u8(v, "refeed_depth"),
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
        cleaned_files: nar_u32(v, "cleaned_files"),
        cleaned_par2: nar_u32(v, "cleaned_par2"),
        cleaned_trash: v
            .get("cleaned_trash")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

/// TODO 309: [`crate::streamhub::ResumeRoute`] onto the wire.
///
/// Beside the record rather than beside the type, in the file that owns
/// every other field's round trip - the type belongs to the engine and
/// the daemon's persistence format is not its business.
fn resume_route_json(r: &crate::streamhub::ResumeRoute) -> Value {
    json!({
        "mapped": r.mapped,
        "restored_bytes": r.restored_bytes,
        "budget_bytes": r.budget_bytes,
        "widest_slot_bytes": r.widest_slot_bytes,
        "seatable_bytes": r.seatable_bytes,
    })
}

/// ...and back, defensively, on `whyslow`'s rule: every record written
/// before this field existed must read as ABSENT.
///
/// `mapped` is the discriminator and it has no default. A route with a
/// missing verdict is not a route that took the cheap path, it is a
/// record that never carried one, and defaulting it either way would
/// print a claim about a run nobody measured. The four FIGURES do
/// default to 0, because `line()` in the report prints no clause for a
/// zero and a route whose numbers were lost still knows which way it
/// went.
fn resume_route_from_json(v: Option<&Value>) -> Option<crate::streamhub::ResumeRoute> {
    let v = v?;
    let n = |k: &str| v.get(k).and_then(Value::as_u64).unwrap_or(0);
    Some(crate::streamhub::ResumeRoute {
        mapped: v.get("mapped")?.as_bool()?,
        restored_bytes: n("restored_bytes"),
        budget_bytes: n("budget_bytes"),
        widest_slot_bytes: n("widest_slot_bytes"),
        seatable_bytes: n("seatable_bytes"),
    })
}
