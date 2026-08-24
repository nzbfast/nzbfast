use super::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum JobState {
    Queued,
    Downloading,
    /// §129: the tail runs in the postproc lane. Set at ticket
    /// submission, left only via `park`; `job_from_json` maps it back
    /// to Queued on restart, exactly like mid-Downloading.
    Finishing,
    Completed,
    Failed,
}

/// TODO 207: the verdict a finished download carries into history.
///
/// The LONGEST-HELD layer of the run, not the last one: a job that was
/// provider-bound for eleven minutes and spent its final seconds on the
/// disk was a provider problem, and the last verdict before it left the
/// wire says the opposite. The two seconds counts travel with it for
/// the same reason every live verdict travels with its numbers - "for
/// 640s of 900s" carries its own weight, where a bare layer token
/// invites the reader to assume the whole run.
///
/// The samples behind it are NOT persisted and cannot be: they come
/// from a process-global ring that means nothing after a restart. This
/// is the conclusion drawn from them, which does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WhyVerdict {
    /// The layer token, exactly as `whyslow::Layer::token` spells it -
    /// never `unknown`, which is the absence of a verdict and is stored
    /// as the absence of this whole record.
    pub layer: String,
    /// The verdict's detail (a hostname, or the `missing` case), empty
    /// when the layer carries none.
    pub detail: String,
    /// Seconds the layer above was the published verdict.
    pub held_secs: u64,
    /// Seconds this job was observed at all, so the claim above can be
    /// read as the fraction of the run it actually is.
    pub total_secs: u64,
}

pub struct Job {
    pub nzo_id: String,
    pub name: String,
    pub nzb_path: PathBuf,
    /// Where this job came from: "dashboard", "watch" (watch folder),
    /// "rss", "arr", "watchlist", "url", "wall", "indexer" (M35 pull
    /// search). Shown in the queue and history drawers, because "why is
    /// this downloading?" was unanswerable from the UI - the record
    /// simply had no such field, though it was assumed to.
    pub origin: String,
    pub category: String,
    pub state: JobState,
    pub total_bytes: u64,
    pub out_dir: PathBuf,
    pub fail_message: String,
    /// The console block behind `fail_message`, captured when the job
    /// failed. Empty for everything that did not fail (and on platforms
    /// where the log tee does not run). See `fail_detail_snapshot`.
    pub fail_detail: String,
    pub finished_at: Option<Instant>,
    /// Is post-processing in flight for this job right now?
    ///
    /// `finalize_completed` writes the job's new `out_dir` only as its
    /// LAST statement, so for the whole of post-processing - the A6
    /// hand-over, unlock, cleanup, rename, TV filing and the move to a
    /// NAS, which is minutes on a large release - the durable record says
    /// "Completed, payload is at X" while the payload is on its way to Y.
    /// Nothing recorded that the work was in flight, so a restart in that
    /// window filed the job to history as a clean success over a
    /// half-moved directory, and Sonarr either imported a partial file or
    /// stalled on a path that no longer held anything.
    ///
    /// Writing the intent down first is what makes the two cases
    /// distinguishable at all: cleared means post-processing finished,
    /// set means it did not. Nothing can tell them apart after the fact,
    /// which is why neither "re-run it" nor "call it failed" was a safe
    /// blind fix - a payload that finished moving leaves `out_dir`
    /// pointing at a directory that no longer exists, and a re-run finds
    /// nothing to do.
    pub finalizing: bool,
    /// SHA-256 of the NZB this job was created from, so "is this exact
    /// NZB already queued?" survives a restart.
    ///
    /// The watch folder's only durable "I consumed this" marker was
    /// deleting the file, and its in-memory `watch_failed` map is gone
    /// after a restart. So whenever the delete could not happen - a share
    /// that refuses it (the code explicitly anticipates that), a crash
    /// between the queue write and the unlink, or an ENOSPC that made the
    /// poller keep the file on purpose - the next start re-ingested the
    /// surviving .nzb and downloaded the whole release a second time. For
    /// a name with no SxxEyy or year there is no dupe_key either, so
    /// nothing caught it, on every restart, forever.
    pub nzb_sha: String,
    /// When the job finished, in unix seconds, for anything that has to
    /// survive a restart. `finished_at` is an `Instant` - monotonic,
    /// process-local, and NOT persisted - so after a restart every
    /// history row reported an age of zero and clients (nzb360,
    /// LunaSea) showed a week of history as finished seconds ago,
    /// re-sorted it wrongly, and re-notified every old item as new.
    pub finished_unix: Option<i64>,
    /// Wall-clock seconds this job spent in the post-network tail: from
    /// the moment the lane took custody (the record turns `Finishing`)
    /// to the moment `park` files it. 0.0 until a tail has run.
    ///
    /// The number exists because its absence cost a triage round. A
    /// tester reported a 389 MB download sitting on "unpacking" for four
    /// to five minutes with the daemon's own CPU, disk-write and network
    /// gauges all reading near zero, and nothing anywhere recorded which
    /// stage had eaten the time - the SAB-facing `postproc_time` was a
    /// hardcoded 0, and `elapsed_secs` covers the network leg alone. The
    /// tail is where the unlock probes, the identity oracles' two
    /// third-party requests, the sweeps, the rename and the index fold
    /// live, and any of them can be slow on someone else's machine.
    /// Recording it is what makes the next such report answerable from
    /// a history row instead of from a `sample` of the process.
    pub postproc_secs: f64,
    /// TODO 207: the shortfall verdict this run earned, or None for a
    /// job nothing ever judged.
    ///
    /// PERSISTED, unlike the log marks below, and the difference is the
    /// same rule read from the other end: a mark indexes a
    /// process-global ring that a restart re-creates from zero, so it
    /// cannot mean anything in another process - while a verdict is a
    /// statement ABOUT this download that stays true however many
    /// restarts later it is read. See `whyslow::WhySlow::capture` for
    /// when it is taken and `whyslow::verdict_json` for the wire form.
    pub whyslow: Option<WhyVerdict>,
    /// The captured-output cursors bracketing this run, for
    /// `mode=report`. Both 0 = nothing to slice.
    ///
    /// DELIBERATELY NOT PERSISTED (see `job_wire`). They index the
    /// process-global log ring, which a restart re-creates from zero -
    /// so a mark restored from `history.jsonl` would name a span of
    /// somebody else's output. `logtee::between` refuses a mark it
    /// cannot have issued, and dropping them at the boundary means it
    /// never has to. The cost of not persisting is that a report for a
    /// job from before the last restart carries no log, which it says.
    pub log_mark: u64,
    pub log_end: u64,
    /// SABnzbd priority: 2 Force, 1 High, 0 Normal, -1 Low, -100 Default.
    /// Force jobs start even while the queue is paused.
    pub priority: i32,
    pub paused: bool,
    /// When this job entered the queue. Process-local and not
    /// persisted - a restart restores it as None and the late-pick
    /// marker simply doesn't fire. Consumed (taken) at pick, so a job
    /// that goes back to Queued later can never replay a stale stamp.
    pub queued_at: Option<Instant>,
    /// When this job entered the queue, in unix seconds - the wall-clock
    /// twin of `queued_at`, and unlike it PERSISTED and never taken. The
    /// monotonic one is process-local and is consumed at pick, so the
    /// SAB facade's numeric `time_added` went null for every restored
    /// row (and for every row that had already started), which is a
    /// shape a strict client refuses to parse - the same class as the
    /// `finished_unix` fix above.
    pub queued_unix: Option<i64>,
    /// Snapshot at add time: was the runner free to take this job at
    /// once (nothing downloading, queue not paused, no runnable job
    /// ahead)? Only then is a slow pick evidence the runner itself was
    /// starved - the fixed inline-SQLite starvation held picks back
    /// 38 s - rather than ordinary waiting in line.
    pub idle_at_add: bool,
    /// Times this job was sent back from history via mode=retry. The
    /// article journal in out_dir makes each retry fetch only what's
    /// still missing.
    pub retries: u32,
    /// M14f: normalized release identity ("show/s1e2", "movie/2026").
    /// Jobs sharing a key are duplicates; later arrivals are held as
    /// ALTERNATIVEs and auto-promoted if the original fails.
    pub dupe_key: Option<String>,
    /// The nzo_id of the row THIS job was held as an alternative of, or
    /// empty for anything that was not held.
    ///
    /// The promotion in `park` used to find its alternatives by
    /// `dupe_key` alone, which is the same-title identity, not the one
    /// admission actually judged on. Under `dupe_scope = "exact"` a
    /// different release of the same episode is admitted and runs, so
    /// when IT fails it promoted a row that had been held against a
    /// still-COMPLETED original - the user got a second copy of
    /// something they already had (Codex sweep K, 13 Aug 2026). An
    /// empty value (a queue written before this field existed) keeps
    /// the old dupe_key-only behaviour, which is right for `smart`,
    /// where the two identities agree.
    pub held_for: String,
    /// M14i metadata-only mode: availability-check instead of downloading;
    /// the NZB in the spool is the library entry, a .strm file the pointer.
    pub library: bool,
    /// A real download of this job has completed (bytes are on disk).
    pub fetched: bool,
    /// User deleted this job while it was DOWNLOADING: the pipeline is
    /// being aborted; park() drops the record instead of filing it in
    /// history (the user said remove, not fail).
    pub tombstone: bool,
    /// The delete that tombstoned this active job also asked for its files
    /// (del_files=1). We must NOT remove them from the delete handler - the
    /// pipeline is still writing and would recreate them right after - so
    /// park() removes them once the fetch has drained and the writers are
    /// gone. Not persisted (only ever true for the moment between abort and
    /// park).
    pub del_on_drop: bool,
    /// The NZBGet delete verb that removed this job asked for a history
    /// record: "MANUAL" (GroupDelete / GroupParkDelete) or "DUPE"
    /// (GroupDupeDelete), empty for everything else. A non-empty value
    /// changes three things: park() files a tombstoned job into history
    /// instead of dropping it, the spooled .nzb is kept (the history row
    /// is retryable, like NZBGet's HistoryReturn), and the JSON-RPC
    /// history reports the row as DELETED/<value> rather than a
    /// download verdict. Persisted: the row keeps saying "you deleted
    /// this" across a restart.
    pub delete_status: String,
    /// M23e: queue pause aborted this job mid-download. The tail handler
    /// re-queues it (the article journal resumes it later) instead of
    /// failing it into history.
    pub suspended: bool,
    /// History stats: decoded bytes + wall-clock seconds of the network
    /// phase (stamped at network-drain; tail/repair time excluded so
    /// bytes÷seconds IS the average download speed).
    pub downloaded_bytes: u64,
    pub elapsed_secs: f64,
    /// Slow-job watchdog: this job was demoted for being single-server-
    /// bound and slow while other jobs waited. pick_job runs deferred
    /// jobs only when nothing else is runnable; any user priority change
    /// or drag-reorder clears the flag.
    pub deferred: bool,
    /// Why the watchdog deferred it (shown in the dashboard drawer).
    pub defer_reason: String,
    /// Times deferred - bounded so a job can't churn forever.
    pub defer_count: u32,
    /// Set by the watchdog just before aborting the pipeline: park()
    /// must requeue this job (deferred, back of the queue) instead of
    /// filing it in history as Failed.
    pub demote: bool,
    /// Archive password for encrypted RAR sets: the SAB API `password`
    /// parameter, a `{{password}}` suffix on the submitted name, or the
    /// NZB's `<meta type="password">`. Never exposed through the API -
    /// only its existence is (has_password).
    pub password: Option<String>,
    /// In-stream verify: PAR2 blocks that hashed bad during this job's
    /// download (0 = clean; feeds the dashboard's verify-health timeline).
    ///
    /// `None` means verification never RAN - a par2-less post, or a
    /// resume that mapped no block to a recovery set. That case used to
    /// store 0, which every reader downstream read as "verified clean":
    /// the health tile counted un-verified downloads as clean
    /// verifications and the timeline drew them as green ticks. Zero is
    /// evidence only when something did the checking, so the absence of
    /// checking is its own value.
    pub bad_blocks: Option<u64>,
    /// PAR2 blocks this job's in-stream verifier actually hashed (ok +
    /// bad). What makes `bad_blocks: Some(0)` a claim rather than an
    /// assertion - "0 bad in 12,847 blocks" is checkable, "verified
    /// clean" alone is not. 0 whenever `bad_blocks` is None.
    pub verify_blocks: u64,
    /// M23: the Smart Folder rule that matched at enqueue asked for TV
    /// filing ([Show]/Season NN/ + rename) at completion.
    pub tv_sort: bool,
    /// The name of the Smart Folder rule that chose this job's category
    /// and/or TV filing, empty when nothing matched. Provenance only, and
    /// the reason it is stored rather than recomputed: the rules are live
    /// and editable, so re-running them later answers "which rule would
    /// match today", not "which rule put this download in Films". A user
    /// looking at a job in an unexpected category is asking the second
    /// question.
    pub smart_rule: String,
    /// TV filing actually RAN: `out_dir` is the SHARED `Show/Season NN`
    /// library folder, not this job's private directory. Every operation
    /// that treats out_dir as "this job's stuff" (delete-with-files,
    /// recategorize, a retry's re-download) has to know, and it cannot be
    /// re-derived from `state`: a retry re-queues the job, and the shape
    /// test `tv_sort && Completed && "Season NN"` would then say "not
    /// filed" about a directory that still holds the whole season.
    /// Persisted for the same reason - a restart must not forget it.
    pub filed: bool,
    /// The quality suffix TV filing actually appended to this job's
    /// episode files, as [`Daemon::finalize_names`] computed it under the
    /// naming settings that stood at the time. `Some("")` is a real
    /// answer - with auto-rename off, filing writes a bare
    /// `{base}.{ext}` - and `None` means "not filed, or filed before this
    /// was recorded".
    ///
    /// Persisted, and deliberately NOT recomputed when a delete needs it.
    /// The rename settings are live: an install that turned auto-rename
    /// off after an episode was filed recomputed an EMPTY suffix, and an
    /// empty suffix matches the episode base plus ANY rename tail. A
    /// watchlist upgrade then deleted both the copy it superseded and the
    /// replacement it had just filed beside it, and the slot still
    /// recorded the new release as owned, so it was never re-grabbed.
    /// See [`delete_tail`].
    pub filed_suffix: Option<String>,
    /// The episode-title segment TV filing appended to this job's episode
    /// base (" - Children"), when `rename_episode_titles` was on and the
    /// cached episode list knew the title. Empty means the file on disk
    /// carries no title, which is every job filed before TODO 78 and
    /// every job filed with the setting off.
    ///
    /// Persisted, and matched LITERALLY rather than recomputed, for a
    /// sharper version of [`Job::filed_suffix`]'s reason: the episode
    /// list behind it is refreshed from a third party every 12 hours.
    /// A provider that re-spells an episode, or a user who turns the
    /// setting off, would recompute a name that is not the one on disk -
    /// and a name that is not on disk is at best a no-op delete and at
    /// worst a match on a neighbouring file. `None` on an unfiled job,
    /// and on records written before this field existed.
    pub filed_title: Option<String>,
    /// The STEM TV filing keyed on, when it was not this job's own name.
    ///
    /// Filing derives `Show/Season NN/Show - S01E02` from a release
    /// stem, and since the identity ladder landed that stem is not
    /// always `name`: an obfuscated post identified by an oracle is
    /// filed under the name the oracle gave, because "a4f9c2e1" is not
    /// a show. Every later operation on a filed job - delete this
    /// episode without its siblings, play this episode out of a shared
    /// season folder - has to look for the files that were actually
    /// written, so it needs the same stem back.
    ///
    /// Persisted for exactly the reason [`Job::filed_suffix`] is: the
    /// oracle's answer is not reproducible from the record, and a
    /// restart that forgot it would leave a filed episode findable by
    /// nothing. `None` on an unfiled job, and on any record written
    /// before this existed - both of which mean "the name".
    pub filed_base: Option<String>,
    /// M24: completion found password-protected volumes and no (or a
    /// wrong) password - the dashboard offers "unlock" on this job.
    pub password_required: bool,
    /// TODO 101: this job's own consent to the volume-eating unpack,
    /// given in the disk-full drawer ("extract in place by deleting the
    /// archive parts as they are used").
    ///
    /// Per JOB, not a setting, because it forfeits the
    /// retry-without-refetch property for THIS download and nothing
    /// else. Read only in `low_disk` mode - `always` is its own consent
    /// and `off` ignores it - and never sufficient on its own: the set
    /// must still have verified. Persisted, because the answer is given
    /// on a failed job in history and spent by the retry that follows,
    /// which may be on the other side of a restart.
    pub eat_volumes_ok: bool,
    /// The NZB's own file list is zip-shaped, spotted at enqueue. Warns
    /// in the queue before the download spends an hour arriving at a
    /// format we cannot unpack. Name-based, so an obfuscated container
    /// is invisible here and only [`Job::unpack_blocked_by`] catches it.
    pub zip_packed: bool,
    /// Name of an archive a COMPLETED job left packed because we have no
    /// unpacker for it (today: any zip). Empty for a clean unpack.
    ///
    /// Sidecars only - a `Subs/subs.zip` beside a feature that unpacked
    /// fine. A zip that IS the payload fails the job instead and reports
    /// through `fail_message`, because Completed on an unusable release
    /// is a conclusion an *arr acts on: it stops looking, and the series
    /// sits stuck forever.
    ///
    /// Stored as the bare NAME, not a sentence: the dashboard has to
    /// compose the message in the user's own language.
    pub unpack_blocked_by: String,
    /// §282 item 14: the job this one REPLACED, when an alternate
    /// candidate was switched to. The nzo_id, so history can link the
    /// two rows; empty on every job that replaced nothing, which is
    /// almost all of them.
    pub alt_from: String,
    /// ...and its release NAME, which is the half the user actually
    /// needs. Kept separately rather than looked up: the abandoned row
    /// can be deleted, or aged out of history by retention, and the
    /// sentence "this replaced X" must still read.
    pub alt_from_name: String,
    /// Why the abandoned job was abandoned, in the words the user was
    /// shown when they were offered the switch. Item 14's whole point is
    /// that a file with a release name nobody clicked is a bug report
    /// waiting to happen, and "what replaced it" without "why" only
    /// answers half of it.
    pub alt_why: String,
    /// The mirror on the ABANDONED row: the name that replaced it. Both
    /// directions are stored because either row can be the one the user
    /// opens, and a history record that knows only its own half sends
    /// them looking for the other.
    pub alt_to_name: String,
    /// UX §18: the move to `move_completed` failed part way and left the
    /// payload split. This is the SOURCE directory that still holds
    /// files; `out_dir` has already followed the bytes that did move,
    /// because those exist nowhere else. Empty when the job never moved
    /// or moved whole.
    ///
    /// A path, not a sentence - the same rule as `unpack_blocked_by`
    /// above, and for the same reason: the dashboard composes the
    /// warning in the user's own language. It is also the only durable
    /// record that the payload is in two places, since the mover's own
    /// log line rolls out of the memory-only ring.
    pub move_split: String,
    /// The move to `move_completed` failed OUTRIGHT - nothing moved and
    /// the payload is still whole at `out_dir`. Holds the destination
    /// that could not be reached plus the OS error, because by the time
    /// anyone reads this the log line is usually gone. Empty when no
    /// move was owed or the move succeeded.
    ///
    /// This is the field that ends the silent-green era: a completed
    /// job whose files never reached the completed folder used to be
    /// indistinguishable from one whose files did (7 Aug 2026 - five
    /// finished jobs sat in the download folder for hours). The row
    /// paints amber from it, the drawer names the destination, and the
    /// M32 auto-retry machinery re-drives the move off it.
    pub move_failed: String,
    /// How many times in a row the move to `move_completed` has failed
    /// for this job. Zero whenever the move succeeded, was never owed,
    /// or the user asked for a fresh attempt by hand.
    ///
    /// The ladder in [`move_retry_delay`] reads it, and
    /// [`MOVE_RETRY_GIVE_UP`] ends it. Before this existed the redrive
    /// re-armed a FLAT cooldown on every failure with nothing counting
    /// them, so a destination that could not be reached at all was
    /// retried every 20 minutes forever: an unmounted destination
    /// volume (8 Aug 2026) had one job log the same EACCES 45 times
    /// across 15 hours, each one indistinguishable from the last. A
    /// count is what lets the delay grow and the daemon stop.
    pub move_attempts: u32,
    /// The move to `move_completed` is OWED but has not settled yet:
    /// the mover worker holds it (C: the relocation left the finalize
    /// tail, so a NAS copy no longer stalls the next download). The
    /// row shows a "moving" note off this; `out_dir` still names the
    /// source, which is where the files verifiably are - staging means
    /// a mid-move kill never strands them elsewhere. Persisted so a
    /// restart re-queues the move instead of forgetting it.
    pub move_pending: bool,
    /// How many times this record has crossed between the queue store
    /// and the history store, counting from 0 for a job that has never
    /// crossed. Bumped by [`stamp_move`](super::moveseq::stamp_move) on
    /// the way OUT, before the destination store's durable write, so the
    /// destination's copy always carries the higher number.
    ///
    /// This is what tells the two half-written moves apart at restore.
    /// Both directions tear into the SAME shape - a nonterminal queue row
    /// plus a terminal history row for one nzo_id - so precedence alone
    /// cannot say whether it was a park that half-finished or a retry;
    /// §158 resolved both as "history wins", which is right for the park
    /// and silently reverts the retry. The counter makes the direction of
    /// the last INTENDED move recoverable rather than inferred: whichever
    /// store holds the higher `move_seq` is the one the move was heading
    /// for. See `serve/moveseq.rs` for the whole protocol.
    ///
    /// Absent on every record written before this field existed, which
    /// reads as 0 on both copies and falls back to the §158 rule.
    pub move_seq: u64,
    /// What the extractor found this set to be: the space-separated
    /// `ArchiveShape` tokens (`rar5 store one-pass`, `rar4 compressed
    /// on-disk`, ...). Empty while nothing archive-shaped has parsed yet,
    /// and on jobs that predate the field.
    ///
    /// Tokens, not a sentence, for the same reason as
    /// [`Job::unpack_blocked_by`]: the dashboard composes the badge in
    /// the user's own language. A downloading job's badge comes from the
    /// live extractor instead (see `queue_json`) - this field is the
    /// latched copy that survives into history.
    pub archive_shape: String,
    /// CRC32 of the first inner file this job's RAR headers named, as
    /// the extractor latched it (see `Extractor::inner_crc`). 0 = the
    /// headers were encrypted, or the set was not RAR-wrapped at all.
    ///
    /// Kept because it is an exact key into the open release databases
    /// and the headers it came from do not survive the download: the
    /// volumes are usually never written to disk. Persisted so a
    /// restart does not have to re-derive it, and so a job whose lookup
    /// failed offline can be asked about later.
    pub inner_crc: u32,
    /// What an identity oracle said this release actually is: the
    /// canonical name, and the IMDb id that came with it. Empty when
    /// nothing was asked or nothing answered.
    ///
    /// This is a SECOND opinion beside `name`, never a replacement for
    /// it: `name` is what the user (or the *arr) submitted and every
    /// client matches on it, so overwriting it would break the round
    /// trip. Rename reads this; the API reports both.
    pub identity_name: String,
    pub identity_imdb: String,
    /// Which oracle answered ("srrdb", "xrel", "par-hash", "mkv-title").
    /// Shown beside the name, because "srrdb says" and "the container
    /// says" are different degrees of confidence and the user is
    /// entitled to tell them apart.
    pub identity_src: String,
    /// M32: a first failure with missing articles
    /// schedules ONE automatic retry - propagation lag often fills the
    /// gaps in. Unix seconds when the retry is due; the article journal
    /// makes the rerun fetch only what's still missing.
    pub auto_retry_at: Option<u64>,
    /// WHAT the armed retry is waiting for, as a token: `"transport"` (a
    /// link or pool fault on this machine, short cooldown) or
    /// `"propagation"` (articles the servers may still receive, full
    /// cooldown). Recorded beside the stamp rather than re-derived from
    /// `fail_message` later, because the decision that picked the DELAY
    /// was taken here: a row that says "retrying in 2 minutes" has to be
    /// able to say why it is 2 and not 20. `None` when no retry is armed.
    pub auto_retry_why: Option<String>,
    /// M26 nzbget facade: post-processing parameters attached by the
    /// jsonrpc `append` (name/value pairs). Sonarr/Radarr tag every add
    /// with a `drone` GUID and match queue/history items ONLY by that
    /// parameter - it must round-trip through listgroups/history.
    pub pp_params: Vec<(String, String)>,
    /// §129 2b: the SAB `pp=` level the add requested (0-3), recorded
    /// so the drawer can show the one-pass mapping (repair and unpack
    /// are integral; 0/1 is recorded intent, not a behavior change).
    /// None = the add named no pp level.
    pub sab_pp: Option<i64>,
    /// §129 2b: the add's `script=` param. Empty = none given (the
    /// category's script, then the global one, applies); "None" =
    /// explicitly no script for this job.
    pub script_override: String,
    /// This job was given its own directory because a previously
    /// COMPLETED job of the same name still had its payload on disk; on
    /// success it takes over that canonical directory (see
    /// `publish_over_previous`). `None` for the ordinary case where the
    /// job already owns the canonical name.
    pub replaces: Option<PathBuf>,
    /// `X-DNZB-Failure` from the fetch that produced this NZB: the
    /// indexer's own "this one was bad, here is another" endpoint. Empty
    /// for an uploaded file, and for indexers that don't send it.
    pub failure_link: String,
    /// Host of the URL the NZB was fetched FROM - the only host this
    /// job's failure link is allowed to point at. Without it the header
    /// is an arbitrary URL, supplied by whatever server answered the
    /// fetch, that the daemon later GETs from inside the user's network
    /// (the SSRF guard deliberately permits LAN indexers). An indexer
    /// may report a dead post to itself and nowhere else.
    pub failure_host: String,
    /// Was that fetch over TLS? Host equality alone would let an
    /// `https://indexer/...` NZB hand back an `http://indexer/...` link
    /// and quietly move a relationship the user had encrypted onto
    /// plaintext - where the query string (which carries their indexer
    /// apikey) is readable by anything on the path.
    pub failure_https: bool,
    /// How many failure-link replacements deep this job already is. A
    /// replacement that also fails asks for another, and an indexer with
    /// a long list of dead posts would otherwise walk the whole list
    /// unattended. See `FAILURE_REGRAB_MAX`.
    pub failure_depth: u8,
    /// TODO 280: how many refeed generations deep this job is. 0 for
    /// every job a person or an app added; 1 for one queued out of a
    /// finished download's own payload. Persisted, because a restart
    /// that forgot it would make a child's output eligible all over
    /// again and turn a one-level rule into no rule at all. See
    /// `refeed::REFEED_MAX_DEPTH`.
    pub refeed_depth: u8,
    /// What post-download synthesised naming concluded about an
    /// obfuscated payload: the container facts on the first line, then
    /// one candidate film per line. Empty for every job the ladder did
    /// not run on, which is nearly all of them.
    ///
    /// Recorded on the DECLINING outcomes above all, because that is
    /// where it earns its place: the gate refuses to rename unless one
    /// film survives, so the usual answer is "here is what your file is,
    /// and here is the shortlist" and the user finishes the job. On the
    /// accepting outcome the filename already says it, and this is the
    /// audit trail for why.
    ///
    /// Free text in ENGLISH, unlike [`Job::unpack_blocked_by`]: it is
    /// evidence (runtimes, codecs, film titles), not a status the
    /// dashboard composes a sentence from, and the film titles inside it
    /// are not ours to translate.
    pub identify: String,
    /// TODO §77: what a STAT sample of this post's articles across every
    /// configured server said when the job was added. `None` until the
    /// prober has run (and forever, if the operator turned it off).
    ///
    /// ADVISORY. Nothing may fail, block or remove a job because of what
    /// is in here - see [`crate::health`] for why a post missing on
    /// every server is not proof of anything. Persisted so a restart
    /// keeps the badge (and the failure-time evidence) instead of
    /// re-probing every queued job on every start.
    /// `pub(crate)` unlike its siblings: [`crate::health::PostHealth`]
    /// is crate-private, and this field is the narrower surface (Q5 -
    /// nothing outside the crate reads it, and rustdoc warned on the
    /// exposure).
    pub(crate) health: Option<crate::health::PostHealth>,
    /// §76: what the main video actually IS, read from its own container
    /// header, plus anything the release name claims that those bytes
    /// deny. `None` until the prober has an answer - which for most jobs
    /// is a few seconds after the download starts, and for an archive
    /// shape that only writes its payload at unpack time is the final
    /// on-disk pass after post-processing.
    ///
    /// Latched onto the job rather than recomputed per request for the
    /// same reason [`Job::archive_shape`] is: the queue and history are
    /// polled every second by every open dashboard, and the writers this
    /// came from are gone by the time history shows it.
    pub media: Option<nzbkit::mediaprobe::MediaFacts>,
    /// The chip in [`Job::media`] was judged against a claim name that
    /// has since CHANGED - an identity oracle answered after pass 1
    /// settled, and an obfuscated stem that claimed nothing must now be
    /// judged against the canonical name that claims everything. Read
    /// by `media_settled`, so the prober's final pass runs once more.
    /// Deliberately not persisted: a restart just keeps the chip as
    /// judged, which is the pre-§76 behaviour, never a wrong verdict.
    pub media_rejudge: bool,
    /// How many files post-processing's sweeps removed from this job's
    /// finished directory: the cleanup-rule extensions (including the
    /// `par_cleanup`-forced `.par2`), plus the junk sweep or
    /// keep-media-only pass inside `finalize_names`. Zero for a job with
    /// nothing to sweep, and for every record written before the field
    /// existed. The counts used to be computed and dropped on the floor,
    /// so files vanished from a finished download with no line anywhere
    /// saying so - the history drawer now renders one from these.
    pub cleaned_files: u32,
    /// The `.par2` recovery files among [`Job::cleaned_files`]. Named
    /// separately because they are deleted by a DEFAULT most users never
    /// chose, and "where did my recovery data go" deserves its own half
    /// of the answer.
    pub cleaned_par2: u32,
    /// Whether those deletes were recoverable when they ran - the
    /// delete_to_trash setting stood and the Trash was answering. It is
    /// the difference between "moved to the Trash" and "removed" in the
    /// drawer line, recorded AT SWEEP TIME because the setting is live
    /// and the drawer renders arbitrarily later.
    pub cleaned_trash: bool,
}

impl Job {
    /// Fields that describe ONE network attempt and must not outlive it.
    /// Every path that sends a job back through the queue (retry, demote,
    /// pause requeue, disk-full requeue) calls this, because `whyslow`
    /// is stamped at network-drain on EVERY exit including the aborts,
    /// and `postproc_secs` is only written at the tail a parked retry
    /// never reaches (bug sweep 22 Aug 2026, F-16/F-17). `fail_message`
    /// is deliberately not here: the retry and demote paths own it.
    pub(in crate::serve) fn clear_attempt_verdicts(&mut self) {
        self.whyslow = None;
        self.fail_detail.clear();
        self.finished_at = None;
        self.finished_unix = None;
        self.postproc_secs = 0.0;
    }
}

/// What [`Daemon::finalize_names`] needs to know about the job it is
/// filing. A struct rather than more positional parameters because the
/// list had reached four same-typed strings and bools, and a caller
/// swapping `name` and `cat` would have compiled.
pub struct FinalizeJob<'a> {
    pub name: &'a str,
    pub cat: &'a str,
    pub tv_sort: bool,
    /// The year this release was POSTED, which bounds an identified
    /// film's release year from above. From the NZB's own article dates
    /// (see [`post_year_of`]), not from the clock: a back-catalogue grab
    /// of a 2019 film downloaded today is a 2019 post.
    pub post_year: u32,
}

/// Everything post-processing learned that the durable job record has to
/// keep. Replaced a tuple when the third field arrived - see the field
/// docs for why each one can only be known here.
pub struct Finalized {
    /// The job's new directory, when renaming or the move-completed
    /// destination changed it.
    pub moved: Option<PathBuf>,
    /// The quality suffix filing actually wrote. See [`Job::filed_suffix`].
    pub suffix: String,
    /// The episode-title segment filing actually wrote (" - Children"),
    /// empty when titles were off or the cache did not know this one.
    /// See [`Job::filed_title`].
    pub filed_title: String,
    /// What synthesised naming concluded, for [`Job::identify`]. Empty
    /// when the ladder did not run.
    pub identify: String,
    /// Files the junk sweep or keep-media-only pass removed. Only this
    /// moment knows the number - the sweeps run inside finalize_names -
    /// and it used to be discarded, so the deletes were invisible to the
    /// job record. Feeds [`Job::cleaned_files`].
    pub swept: usize,
}

/// The year a release was posted, from the newest article date in its
/// NZB. Zero when the NZB is unreadable or carries no dates - callers
/// fall back to the current year, which is right for a fresh grab and is
/// the only guess available.
///
/// NEWEST rather than oldest: a repost or a fill tops up an old NZB with
/// recent articles, and it is the most recent posting that bounds how
/// new the film can be.
pub fn post_year_of(nzb_path: &std::path::Path) -> u32 {
    let Ok(bytes) = std::fs::read(nzb_path) else {
        return 0;
    };
    let Ok(nzb) = nzbkit::nzb::Nzb::parse(&bytes) else {
        return 0;
    };
    let newest = nzb.files.iter().map(|f| f.date).max().unwrap_or(0);
    if newest <= 0 {
        return 0;
    }
    // Same epoch-to-civil-year arithmetic the identifier uses; there is
    // no chrono in the tree.
    crate::identify::year_of_unix(newest)
}

/// Keeps the index paused for the entire lifetime of a foreground job,
/// including verification/repair/extraction after its network phase.
/// Tails may overlap the next job, so this is a counter rather than a
/// boolean.
pub(super) struct IndexJobGuard(
    pub(super) Arc<AtomicUsize>,
    /// Weak so the guard can mark "indexing resumed" on the 1 -> 0
    /// edge without keeping the daemon alive at shutdown.
    pub(super) std::sync::Weak<Daemon>,
);

impl Drop for IndexJobGuard {
    fn drop(&mut self) {
        if self.0.fetch_sub(1, Ordering::Release) == 1
            && let Some(d) = self.1.upgrade()
            && d.index_pause_on_download.load(Ordering::Relaxed)
            && d.index_enabled.load(Ordering::Relaxed)
        {
            d.note_event("indexer", "downloads done - indexing picks back up");
        }
    }
}

/// A job FAILED holding what may be a locked archive: find it, and spend
/// every password we already hold before the failure is filed.
///
/// Returns true when one of them worked - the job record is Completed by
/// then and its tail still owes the sweep, rename and move.
///
/// Detection alone was half the story. The 11 Aug fix taught this path to
/// SEE a locked archive on a failed job (so the drawer offers the 🔑
/// rather than "show the folder"), but deliberately did no unlocking,
/// because unlocking belonged to jobs that COMPLETE. The result: with the
/// right line sitting in the operator's passwords file we raised a prompt
/// for a password we had already read, while SABnzbd - which tries its
/// `password_file` here - simply delivered the payload (advQ, the
/// four-way correctness round, 12 Aug).
///
/// The ladder is the completed path's, in §99 order: the job's own
/// password first, then the file's candidates, read fresh so a line added
/// while the job ran still counts.
///
/// `was_unpack_failure` decides how far a hit may go. The probe runs for
/// any local, hint-less failure - the gate the 11 Aug fix already vetted
/// for raising the 🔑 - but only a job that failed BECAUSE something
/// could not be unpacked has had its stated reason answered by the
/// unlock, and only that one may be called a completion. Any other local
/// failure keeps its verdict: the payload is out and the password is
/// recorded, and whatever really went wrong still gets to say so.
///
/// `gen0` fences every write below, under the write's own hold: both
/// blocking calls this awaits are unbounded, and a delete plus a Retry
/// inside either one hands the record to a live download. Stamping
/// `Completed` then leaves a QUEUED row terminal - `pick_job` never
/// picks it, and only a second retry clears it (sweep 3, H2).
#[expect(clippy::too_many_arguments)]
async fn settle_locked_failure(
    d: &Arc<Daemon>,
    job: &Arc<Mutex<Job>>,
    out: &std::path::Path,
    name: &str,
    nzb: &std::path::Path,
    site: &str,
    job_pw: Option<&str>,
    was_unpack_failure: bool,
    gen0: Option<(u32, u64)>,
) -> bool {
    // Header-parses every RAR volume, 7z and zip container in the folder:
    // blocking file IO, off the runtime worker, exactly as the completed
    // path runs it.
    let probe_dir = out.to_path_buf();
    let locked = tokio::task::spawn_blocking(move || crate::smart::encrypted_archive(&probe_dir))
        .await
        .unwrap_or(None);
    let Some(locked) = locked else {
        return false;
    };
    let locked_name = locked
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let poster = crate::smart::nzb_poster(nzb);
    let cands: Vec<String> = job_pw
        .map(str::to_string)
        .into_iter()
        .chain(d.read_unpack_passwords_for(site, &poster))
        .collect();
    let unlock_dir = out.to_path_buf();
    // The same stand-down the completed path takes (`job_finalize`): a
    // refusal that named itself is about the DISK, so every candidate
    // below it would meet the same one, and none of them has been
    // tested against the archive. See [`crate::smart::unlock`].
    let (winner, refused) = tokio::task::spawn_blocking(move || {
        let mut refused: Option<String> = None;
        let mut winner: Option<String> = None;
        for pw in cands {
            match crate::smart::unlock(&unlock_dir, &pw) {
                Ok(()) => {
                    winner = Some(pw);
                    break;
                }
                Err(None) => {}
                Err(Some(why)) => {
                    refused = Some(why);
                    break;
                }
            }
        }
        (winner, refused)
    })
    .await
    .unwrap_or((None, None));
    if let Some(why) = refused {
        // This job has ALREADY failed - the probe runs over a local,
        // hint-less failure - and its own message is very likely this
        // same verdict, raised by the ladder that failed it. What must
        // not happen is the `password_required` below: the archive is
        // locked, but nothing here established that a password is what
        // it is missing, and raising the 🔑 sends the user to buy a key
        // for a door that is not the one shut.
        warn!(target: "unlock", "{name:?}: the unlock was refused - {why}");
        return false;
    }
    match winner {
        Some(pw) => {
            info!(
                target: "unlock",
                "{name:?}: {locked_name} unlocked with a password we already held - \
                 the job is a completion after all"
            );
            d.record_unlock_password(site, &poster, &pw);
            // The password is the site's and is kept either way; the
            // RECORD may no longer be this tail's - see `gen0`.
            {
                let mut j = job.lock_ok();
                if !Daemon::same_generation(&j, gen0) || j.tombstone {
                    info!(target: "unlock", "{name:?}: the record left this tail's custody while the ladder ran");
                    return false;
                }
                j.password = Some(pw);
                j.password_required = false;
                if was_unpack_failure {
                    j.fail_message.clear();
                    j.state = JobState::Completed;
                }
            }
            d.save_queue();
            was_unpack_failure
        }
        None => {
            info!(
                target: "unlock",
                "{name:?}: {locked_name} is password-protected - set a password and retry to unpack it"
            );
            // Same fence: `auto_retry_eligible` refuses a job carrying
            // this flag, so a record queued again would lose its retry.
            {
                let mut j = job.lock_ok();
                if !Daemon::same_generation(&j, gen0) || j.tombstone {
                    return false;
                }
                j.password_required = true;
            }
            d.save_queue();
            false
        }
    }
}

/// M23/M24 post-download work on a SUCCESSFUL job, in order: passworded
/// volumes (unlock with the job's password, or flag for the dashboard),
/// cleanup-rule deletes (don't move junk), then TV filing if the
/// enqueue-time rule asked for it. File ops run on the blocking pool;
/// out_dir/password_required update before the pp-script and history
/// see them. A no-op on a job that did not complete.
///
/// Every completion that produced FILES goes through here, not just the
/// runner's tail: the idle-server sidecar finishes a job outright whenever
/// the idle servers happen to hold all of it, and such a job used to be
/// parked raw - no canonical-directory hand-over, no unlock, no junk
/// sweep, no rename, no move to the destination folder. The one completion
/// that does not come through here is the M14i library metadata-only pick,
/// which writes a .strm pointer and has nothing to unlock, rename or move.
///
/// The unfenced spelling. Every caller in the daemon now names the
/// round it started on, so this is the tests' entry point only - they
/// call the tail directly, with no lane and no prefetch behind it.
///
/// Gated `all(test, unix)`, matching `job_finalize_marker_tests` - its
/// only callers. Under a bare `cfg(test)` the function outlived them on
/// Windows, where that module is cfg'd out, and `dead_code` turned the
/// windows-unit clippy gate red for a target no test here even runs.
#[cfg(all(test, unix))]
pub(super) async fn finalize_completed(d: &Arc<Daemon>, job: &Arc<Mutex<Job>>) {
    finalize_completed_gen(d, job, None).await
}

/// [`finalize_completed`], fenced to the round of the record's life the
/// caller started on (`Daemon::record_generation`).
///
/// Both callers that matter are long-running tails - the post-processing
/// lane and the prefetch sidecar's detached completion - and both can be
/// overtaken: a delete verb files their job into history and a retry of
/// that row re-queues the SAME Arc one generation on. Everything below
/// then belongs to the retry, and running it is not a stale write to a
/// dead record but a live one to somebody else's: the marker, the
/// unlock, the rename, the TV filing and the move to the destination
/// folder all land on the round that is about to download again
/// (read-only sweep 2, H1 and M5). `None` keeps the old behaviour
/// exactly, which is what the tests and the metadata-only pick want.
pub(super) async fn finalize_completed_gen(
    d: &Arc<Daemon>,
    job: &Arc<Mutex<Job>>,
    gen0: Option<(u32, u64)>,
) {
    // The key the activity map is stamped with while this tail runs. A
    // record's nzo_id never changes, so one read outside every fence is
    // enough and it costs no place in the snapshot tuple below.
    let nzo = job.lock_ok().nzo_id.clone();
    let snapshot = {
        let j = job.lock_ok();
        if !Daemon::same_generation(&j, gen0) {
            None
        } else {
            Some((
                // A tombstoned job was deleted by the user while it ran. If
                // the fetch happened to return Ok in the window before the
                // abort landed, none of this should follow: park() is about
                // to drop the record (and, on delete-with-files, the payload
                // too), so unpacking it, filing it into the TV library and
                // moving it onto a NAS would publish a result nobody asked
                // to keep.
                j.state == JobState::Completed && !j.tombstone,
                j.state == JobState::Failed && !j.tombstone,
                j.fail_message.clone(),
                j.out_dir.clone(),
                j.name.clone(),
                j.category.clone(),
                j.tv_sort,
                j.password.clone(),
                j.replaces.clone(),
                j.inner_crc,
                j.nzb_path.clone(),
                // §99 try-order key: the indexer host the NZB was fetched
                // from (empty for an uploaded file).
                j.failure_host.clone(),
            ))
        }
    };
    let Some((done_ok, failed, fail2, out2, name2, cat2, tv2, pw2, repl2, crc2, nzb2, site2)) =
        snapshot
    else {
        return;
    };
    let exts = {
        let mut e = d.cleanup_exts.lock_ok().clone();
        // Spent recovery files go with the sidecar junk by default. Added
        // here rather than swept separately so it inherits the sweep's
        // ordering guarantees - in particular that the identity rungs
        // read the .par2 sidecars BEFORE anything deletes them.
        if d.par_cleanup.load(Ordering::Relaxed) && !e.iter().any(|x| x == "par2") {
            e.push("par2".to_string());
        }
        e
    };
    // A job can FAIL because something in its output is locked, and the
    // tail below runs for completions only - so the one question a
    // locked failure turns on was never asked. An encrypted RAR set
    // completes (the volumes are left for the unlock step), which is why
    // this went unnoticed; a header-encrypted 7z instead reports
    // `PasswordRequired` as an ordinary unpack failure, so the job ended
    // Failed with "an archive in the output directory could not be
    // unpacked" and the drawer offered "show the folder" for a job whose
    // entire remedy is a password (soak round 3, 11 Aug, advQ).
    //
    // Detection ONLY: no unlock, no sweep, no move, no marker. Those
    // belong to a successful job - and to the Retry that this flag is
    // what enables, since `fail_action` returns "password" for any
    // failure carrying it.
    //
    // Asked only of a failure that could BE a locked archive: `Local`,
    // with no other remedy already named. The flag is not cosmetic -
    // `auto_retry_eligible` refuses a job carrying it and `post_job_plan`
    // then calls the failure final - so raising it on every failed job
    // that happens to hold an encrypted volume took the automatic retry
    // away from the ordinary encrypted release whose download hit a
    // connection blip, and reported a live post to the indexer as failed.
    // The disk-full and damaged-article failures are `Local` too and
    // already carry their own remedy; a password answers neither.
    let locked_probe = failed
        && fail_kind(&fail2) == FailKind::Local
        && fail_hint(&fail2).is_empty()
        && !disk_full_failure(&fail2);
    if locked_probe
        && settle_locked_failure(
            d,
            job,
            &out2,
            &name2,
            &nzb2,
            &site2,
            pw2.as_deref(),
            // The one failure an unlock actually answers. Every unpack
            // verdict in `get::tail` names itself this way.
            fail2.contains("could not be unpacked"),
            gen0,
        )
        .await
    {
        // Unlocked, so the record now says Completed: the payload is
        // unpacked but nothing else has run - no sweep, no rename, no
        // move - so hand the job back to the completed tail rather than
        // half-finishing it here. Exactly one re-entry is possible, since
        // `locked_probe` asks `state == Failed`.
        Box::pin(finalize_completed_gen(d, job, gen0)).await;
        return;
    }
    if done_ok {
        // Write the intent down BEFORE touching anything. Everything
        // below can move the payload out from under the recorded
        // out_dir, and the record is not corrected until the very end -
        // so without this marker a restart in between could not tell a
        // finished job from one caught mid-move, and filed the latter to
        // history as a clean success. Saved immediately: the flag is
        // worth nothing if it only exists in memory.
        // Same check, same hold as the write - and the last one this
        // function needs: `retry` refuses a record carrying the marker,
        // so from here to the write-back that clears it no new
        // generation can appear.
        {
            let mut j = job.lock_ok();
            if !Daemon::same_generation(&j, gen0) {
                return;
            }
            j.finalizing = true;
        }
        if !d.save_queue() {
            // The comment above is literal: the marker is worth nothing
            // if it only exists in memory. Every step below can move
            // the payload out from under the recorded out_dir, insured
            // only by that marker - running them uninsured means a
            // crash mid-move restores a clean Completed record over a
            // half-moved payload (Codex sweep 5 Aug M6). Leave the
            // finished files exactly where the record says they are,
            // and say why on the row; an unlock/retry re-runs this
            // whole tail once the disk is writable again.
            error!(
                target: "queue",
                "{name2:?}: the finalize marker could not be written - \
                 post-processing skipped, the finished files are untouched at {}. \
                 Check free space and write permission on the data folder, then \
                 retry the job to unpack and move them",
                out2.display()
            );
            let mut j = job.lock_ok();
            j.finalizing = false;
            j.unpack_blocked_by =
                "post-processing skipped: the queue file could not be written".to_string();
            return;
        }
        // Cloned handle for the blocking finalize (the caller still
        // needs its own for park()/script).
        let d3 = d.clone();
        // For the crashed-tail arm below: the closure consumes the
        // originals.
        let name_log = name2.clone();
        let out_log = out2.clone();
        // For the §99 association record on the in-stream probe's
        // winner, which lands after the closure returns.
        let site3 = site2.clone();
        let nzo3 = nzo.clone();
        let nzb3 = nzb2.clone();
        let FinalizeOutcome {
            needs_pw,
            unlock_refused,
            pw_used,
            blocked_by,
            moved,
            filed_sfx,
            filed_ttl,
            ident,
            identified,
            cleaned,
        } = tokio::task::spawn_blocking(move || {
            job_finalize::finalize_payload(
                d3, nzo3, out2, repl2, pw2, nzb2, site2, name2, crc2, exts, cat2, tv2,
            )
        })
        .await
        .unwrap_or_else(|e| {
            // A PANIC in the tail, not a result. This used to be
            // swallowed whole: the job parked green with the defaults
            // below and not one line said the unlock, sweeps, rename
            // and move had never run. The files are untouched - the
            // panic aborted the closure before or during them - so say
            // so, and leave an amber note on the row (the still-packed
            // surface) pointing at Retry, which re-runs this whole
            // tail.
            error!(
                target: "queue",
                "{name_log:?}: post-processing crashed ({e}) - the downloaded files are \
                 untouched at {}; retry the job to re-run unpack, rename and move",
                out_log.display()
            );
            FinalizeOutcome::crashed()
        });
        // The probe winner taken below, held past the job lock so the
        // §99 association write (file IO) never runs under it.
        let mut probe_pw: Option<String> = None;
        {
            let mut j = job.lock_ok();
            j.password_required = needs_pw;
            // The candidate that worked becomes the job's password: a
            // retry unlocks without consulting the list again, and the
            // history row reports has_password.
            if pw_used.is_some() {
                j.password = pw_used;
            }
            // The in-stream probe's verified winner (the set decrypted
            // one-pass, so the disk ladder above never ran). Owner-
            // checked and taken, so the next job can never inherit it.
            if j.password.is_none() {
                let mut g = d.hub.password_found.lock_ok();
                if g.as_ref().is_some_and(|(o, _)| *o == j.nzo_id) {
                    j.password = g.take().map(|(_, pw)| pw);
                    probe_pw = j.password.clone();
                }
            }
            // The unlock ladder refused for a reason of its own -
            // today a bomb verdict, which is the disk and not the
            // password. It is written like the sentence below and not
            // over it: `needs_pw` is false on this path, so the two
            // never both have something to say. Guarded on an empty
            // message for the same reason every other writer here is -
            // a failure the download itself already recorded outranks
            // anything post-processing has to add.
            if let Some(why) = unlock_refused
                && j.fail_message.is_empty()
            {
                j.fail_message = why;
            }
            // In "never ask" mode the locked outcome is not presented
            // as a failure: the still-packed note (blocked_by above)
            // says what happened, password_required keeps the 🔑
            // available for whenever the user does have the password,
            // and no text or sound nags for one.
            if needs_pw
                && j.fail_message.is_empty()
                && d.password_prompt.lock_ok().as_str() != "never"
            {
                j.fail_message = "password required to unpack".into();
            }
            j.unpack_blocked_by = blocked_by;
            // C: the relocation now happens on the mover worker, off
            // this tail. A fresh completion starts with clean move
            // fields, and `move_pending` is what park() hands the
            // mover - gated exactly as the inline move used to be: a
            // still-locked job has no settled payload to move.
            j.move_split.clear();
            j.move_failed.clear();
            // A fresh completion is a fresh ladder: whatever the last
            // attempt on this job cost, this one starts at the first
            // rung rather than inheriting a spent retry budget.
            j.move_attempts = 0;
            j.move_pending = !needs_pw && d.move_destination_configured(&j.category);
            // Recorded even when it changed no filename: an IMDb id with
            // no better name is still the thing that lets the history
            // row link to what it actually is.
            if !ident.is_empty() {
                // A settled chip was judged against the OLD claim name
                // (an obfuscated stem claims nothing, so nothing could
                // contradict it). The canonical name the oracle handed
                // back claims everything - owe the job one more final
                // pass so the bytes are judged against it.
                let old_claim = if j.identity_name.is_empty() {
                    j.name.clone()
                } else {
                    j.identity_name.clone()
                };
                if ident.name != old_claim
                    && j.media.as_ref().is_some_and(|m| m.complete && m.any())
                {
                    j.media_rejudge = true;
                    d.media_final_owed.lock_ok().push(j.nzo_id.clone());
                }
                j.identity_name = ident.name;
                j.identity_imdb = ident.imdb;
                j.identity_src = ident.src.to_string();
            }
            // Only ever SET, never cleared: a job whose ladder did not
            // run this time (unlock re-runs post-processing) must not
            // lose the note the first pass wrote.
            if !identified.is_empty() {
                j.identify = identified;
            }
            // ACCUMULATED, not assigned: an unlock re-runs this whole
            // tail, and its second sweep only sees what the first left
            // behind - overwriting would forget the first pass's count.
            if cleaned.0 > 0 {
                j.cleaned_files = j.cleaned_files.saturating_add(cleaned.0 as u32);
                j.cleaned_par2 = j.cleaned_par2.saturating_add(cleaned.1 as u32);
                j.cleaned_trash = cleaned.2;
            }
            if let Some(dest) = moved {
                // Record whether the new home is the SHARED season folder, so
                // every later "delete this job's files" knows not to take the
                // siblings with it. See Job::filed.
                j.filed = j.tv_sort && is_season_dir(&dest);
                // ...and, with it, the suffix and episode title those
                // files now carry. Only an actually-filed job has them
                // to remember.
                j.filed_suffix = if j.filed { filed_sfx } else { None };
                j.filed_title = if j.filed { filed_ttl } else { None };
                // Only when it is NOT the job's own name: `filed_stem`
                // falls back to `name`, so storing a copy of it would
                // just be a second thing to keep in step.
                j.filed_base = j
                    .filed
                    .then(|| j.identity_name.clone())
                    .filter(|n| !n.is_empty());
                j.out_dir = dest;
            }
            // Cleared in the same breath as the corrected out_dir: from
            // here the record describes where the payload actually is.
            j.finalizing = false;
        }
        // §99: the in-stream probe's winner is an unlock like any other
        // - remember which site / poster it belongs to. Off the async
        // tail (NZB re-parse plus a small file write).
        if let Some(pw) = probe_pw {
            let d4 = d.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let poster = crate::smart::nzb_poster(&nzb3);
                d4.record_unlock_password(&site3, &poster, &pw);
            })
            .await;
        }
        // TODO 280: the payload is settled where the record says it is
        // - unpacked, swept and renamed, and the destination move has
        // not started - so this is the moment a container post's inner
        // .nzb is on disk and findable. Off by default, and never on the
        // failure path: a job that did not complete has no payload to
        // read. Blocking (a folder walk, whole-file reads and an
        // enqueue), so it goes to the pool rather than onto this tail's
        // worker; a panic in it must not cost the job its history row.
        if d.refeed_nzb.load(Ordering::Relaxed) {
            let (d5, j5) = (d.clone(), job.clone());
            if let Err(e) =
                tokio::task::spawn_blocking(move || d5.refeed_completed(&j5, gen0)).await
            {
                warn!(target: "refeed", "looking for NZB files in the output did not finish: {e}");
            }
        }
        // Outside the job lock - save_queue locks every job in turn.
        // The identity/cleanup stamps land on a record that may already
        // be parked (an unlock re-run) - keep its store line current.
        d.history_publish_change(job, "the post-processing stamps and folder");
        d.save_queue_soon();
    }
}

/// An equivalent release the user already has, as reported to the UI
/// before a hand-picked grab is added. `where_` is "queue" (still
/// coming) or "history" (already downloaded), which is the difference
/// between "you are about to queue this twice" and "you already have
/// this, do you want to play that copy instead".
pub(crate) struct DupeCollision {
    pub where_: &'static str,
    pub name: String,
    pub nzo_id: String,
}

/// One "the record went, the files did not" notice.
///
/// A struct rather than the 4-tuple this was, because it grew a fifth
/// field that has to be right: `nzb` is the spooled NZB the delete would
/// normally have thrown away, kept alive precisely because the removal
/// was REFUSED. It is what lets the notice offer the download again
/// where the user is already standing, instead of sending them off to
/// find the release and re-add it by hand.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct KeptNote {
    pub name: String,
    /// The folder still on disk. Also the notice's IDENTITY: dismiss and
    /// retry both address it by this.
    pub path: String,
    pub why: String,
    pub at: i64,
    /// Path to the spooled NZB, or empty when there is none to offer.
    /// Empty is ordinary, not a fault: a job deleted before it was ever
    /// spooled, a record restored from an older version's notice file,
    /// or a spool the user has since cleaned out.
    #[serde(default)]
    pub nzb: String,
}

/// Read a notice list written by either shape.
///
/// The pre-struct file is an array of `[name, path, why, at]` arrays,
/// and it names folders that are still sitting on the user's disk with
/// no record anywhere else pointing at them - dropping those on upgrade
/// would lose the one handle the notice exists to keep.
pub(crate) fn kept_notes_from_json(v: &Value) -> Option<VecDeque<KeptNote>> {
    if let Ok(k) = serde_json::from_value::<VecDeque<KeptNote>>(v.clone()) {
        return Some(k);
    }
    let legacy: VecDeque<(String, String, String, i64)> = serde_json::from_value(v.clone()).ok()?;
    Some(
        legacy
            .into_iter()
            .map(|(name, path, why, at)| KeptNote {
                name,
                path,
                why,
                at,
                nzb: String::new(),
            })
            .collect(),
    )
}

/// Throw away the spooled NZB a kept-files notice was holding for its
/// "download it again" button.
///
/// Called when the notice goes - dismissed, retried, or pushed off the
/// end of the ring - because the file is reachable through nothing else
/// once that happens. Best-effort: an empty path means there was never
/// one, and a failed removal costs a small file in the spool, not
/// correctness.
pub(crate) fn drop_kept_nzb(note: &KeptNote) {
    if !note.nzb.is_empty() {
        let _ = std::fs::remove_file(&note.nzb);
    }
}

/// Is this row a HELD ALTERNATIVE - a copy parked at Duplicate priority
/// behind another one?
///
/// It matters to what a delete MEANS. Deleting an ordinary row says "I
/// do not have this release any more"; deleting the backup copy says
/// only "I do not want a second copy of it", because the row it was held
/// for is still there. Stamping the second as a delete of the identity
/// would let the next add of that identity run alongside the original -
/// a double download, which is the thing the hold exists to prevent.
///
/// The same test `held_as_duplicate` reads back to tell an adder what
/// happened to its job, so the two cannot disagree about what a hold
/// looks like.
pub(crate) fn is_held_alternative(g: &Job) -> bool {
    g.paused && g.priority == DUPE_PRIORITY
}

/// Rename a spool copy out of the shape `recover_orphaned_spool`
/// adopts, returning the new path.
///
/// The matcher takes only `SABnzbd_nzo_nzbfast*.nzb`, so the suffix is
/// enough to make a file unadoptable. A copy under any other name was
/// never adoptable, so it is left alone rather than renamed for nothing
/// (`None`), as is one whose rename is refused - that one is warned
/// about, because it stays adoptable.
pub(crate) fn mask_spool_path(nzb: &Path, suffix: &str) -> Option<PathBuf> {
    let adoptable = nzb
        .file_name()
        .and_then(|f| f.to_str())
        .is_some_and(|f| f.starts_with("SABnzbd_nzo_nzbfast") && f.ends_with(".nzb"));
    if !adoptable {
        return None;
    }
    let mut masked = nzb.to_path_buf().into_os_string();
    masked.push(suffix);
    let masked = PathBuf::from(masked);
    match std::fs::rename(nzb, &masked) {
        Ok(()) => Some(masked),
        Err(e) => {
            warn!(
                target: "queue",
                "{}: could not set the deleted job's spool copy aside: {e}",
                nzb.display()
            );
            None
        }
    }
}

/// Remove a deleted record's spool copy - and if the unlink is REFUSED,
/// rename it out of the shape `recover_orphaned_spool` adopts.
///
/// The record is gone durably by the time this runs, so a survivor
/// under the adoptable name is re-enqueued as "recovered" at the next
/// start: the release the user (or an *arr) deliberately cancelled
/// downloads again, un-held, because the delete's own
/// `note_releases_deleted` mark clears the duplicate hold. The unlink
/// is refused rarely and only from outside - a Windows sharing
/// violation from an AV or indexer holding the just-written file, a
/// macOS `uchg` flag, a spool directory that lost write permission -
/// which is exactly why swallowing the error was invisible for as long
/// as it was.
pub(crate) fn drop_spool(nzb: &Path) {
    match std::fs::remove_file(nzb) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            // A read-only spool DIRECTORY refuses the rename for the
            // same reason it refused the unlink, so there is a third
            // resort: emptying the file needs write permission on the
            // file alone. An empty spool copy holds no articles and
            // `recover_orphaned_spool` skips it, which is the property
            // this is for.
            let set_aside =
                mask_spool_path(nzb, ".deleted").is_some() || std::fs::write(nzb, b"").is_ok();
            warn!(
                target: "queue",
                "{}: the deleted job's spool copy could not be removed: {e} (set aside: {set_aside})",
                nzb.display()
            );
        }
    }
}

/// Hold a deleted record's spooled NZB back for a kept-files notice, or
/// throw it away now.
///
/// `keep` is "this delete is about to try the files half": only then can
/// the removal be REFUSED, and only a refusal has anything to offer the
/// NZB back for. Everywhere else the spool copy dies with the record it
/// belonged to, exactly as it always did.
///
/// Shared by the three delete arms rather than hand-copied a third time.
/// This file's own history is the argument: the JSON-RPC facade was a
/// hand-copy of the REST delete that never got the active-job fix, so
/// which client type the user configured decided whether the bug was
/// reachable.
///
/// A QUEUE of NZBs per directory, not one slot. Records legitimately
/// share an out_dir - a TV-filed job's `out_dir` IS the season folder
/// (`j.filed = j.tv_sort && is_season_dir(&dest)`), and
/// `plan_history_delete` grants `may_remove_files` to every filed record
/// without a claimant test, so a bulk history sweep over one season
/// passes several records through here for the same key. A single slot
/// dropped the earlier PathBuf on the floor: the spool file it named was
/// never removed and no longer reachable by the final drain (a permanent
/// leak from the delete whose whole promise is to leave nothing behind),
/// and the notice for the FIRST record was then handed the LAST record's
/// NZB - so "download it again" re-fetched the wrong episode under the
/// first one's name. Insert order equals kept order, so a FIFO pairs
/// each notice with its own record's copy.
pub(crate) fn hold_or_drop_spool(
    keep: bool,
    out_dir: &Path,
    nzb: &Path,
    held: &mut std::collections::HashMap<PathBuf, Vec<PathBuf>>,
) {
    if keep {
        held.entry(out_dir.to_path_buf())
            .or_default()
            .push(nzb.to_path_buf());
    } else {
        drop_spool(nzb);
    }
}

/// File the kept-files notices a delete owes, and settle the spool
/// copies `hold_or_drop_spool` was holding for them.
///
/// A directory that refused gets its NZB attached to the notice - that
/// is the notice's "download it again". Anything still held afterwards
/// belongs to a directory that went cleanly, so nothing names it now and
/// it goes.
pub(crate) fn note_kept_files(
    d: &Daemon,
    kept: Vec<(String, PathBuf, String)>,
    held: &mut std::collections::HashMap<PathBuf, Vec<PathBuf>>,
) {
    for (name, dir, why) in kept {
        // Take this directory's OLDEST remaining copy: `kept` preserves
        // the order the records were held in, so each notice gets the
        // NZB of the record it is actually about.
        let nzb = held
            .get_mut(&dir)
            .filter(|q| !q.is_empty())
            .map(|q| q.remove(0));
        if held.get(&dir).is_some_and(Vec::is_empty) {
            held.remove(&dir);
        }
        d.note_delete_kept(&name, &dir, &why, nzb.as_deref());
    }
    // Everything still held belongs to a directory that went cleanly (or
    // to a second refusal the notice dedupe folded away): nothing names
    // it now, so it goes - every copy, not just one per directory.
    for (_, nzbs) in held.drain() {
        for nzb in nzbs {
            drop_spool(&nzb);
        }
    }
}

pub(super) fn priority_name(p: i32) -> &'static str {
    match p {
        2 => "Force",
        1 => "High",
        -1 => "Low",
        -3 => "Duplicate",
        _ => "Normal",
    }
}

/// SABnzbd's DEFAULT_PRIORITY sentinel: "whatever the default is", not a
/// priority of its own. It is what every client sends when the user did
/// not choose one, and it is the default of our own `priority=` parsing.
pub(crate) const SAB_DEFAULT_PRIORITY: i32 = -100;

/// The priority a job actually gets on the way into the queue.
///
/// The sentinel has to be resolved HERE, not left on the record. `pick_job`
/// orders by the stored number, so a stored -100 sorted BELOW Low (-1) and
/// even below a held Duplicate (-3) - while `priority_name` (the dashboard,
/// the SAB queue API, the *arrs) labelled that same job "Normal". A job the
/// user had explicitly demoted to Low therefore ran before the jobs the UI
/// said were Normal, which is precisely backwards.
///
/// -2 is SAB's "add paused" flag rather than a priority; the caller sets
/// `paused` from it and the job itself is Normal. There is no per-category
/// default priority in this daemon (the categories API reports -100 for
/// every category), so the default is Normal.
/// M14f alternative: held below everything until the original fails. Its
/// own priority rather than a flag, so ordering and the API's priority
/// vocabulary both keep working; `Daemon::held_as_duplicate` reads it back
/// to tell an adder what actually happened to their job.
pub(crate) const DUPE_PRIORITY: i32 = -3;

/// A SAB `pp=` request param, validated: 0-3, anything else (junk, out
/// of range, absent) = the add named none. One parse shared by the add
/// handlers (which pass it to `enqueue` for the pre-queue hook) and
/// `record_add_params` (which records it on the job afterwards), so the
/// hook and the record can never disagree about what was asked.
pub(crate) fn sab_pp_param(pp: Option<&str>) -> Option<i64> {
    pp.and_then(|p| p.trim().parse::<i64>().ok())
        .filter(|p| (0..=3).contains(p))
}

pub(crate) fn enqueue_priority(requested: i32, duplicate: bool) -> i32 {
    if duplicate {
        DUPE_PRIORITY
    } else if requested == -2 || requested == SAB_DEFAULT_PRIORITY {
        0
    } else {
        requested
    }
}

/// May `park` act on a watchdog demotion by sending the job back through
/// the queue?
///
/// Only when the demotion's abort actually took the download down
/// (`failed`). The watchdog decides from a rate window and fires an abort
/// that can lose the race with the finish line - on 31 Jul it read a
/// DRAINED pool ("100% of the last 10s from one host at 0.2 MB/s") while
/// the job sat Downloading behind the previous job's stalled tail, so the
/// flag landed on a job that then completed cleanly. Post-processing had
/// renamed its directory by the time park ran, and the re-queue downloaded
/// the whole release a second time into the renamed folder. A completed
/// job files to history whatever the flag says; `park` scrubs the stale
/// flag so a later retry cycle cannot trip over it either.
///
/// A free function so the queue soak's invariant - a finished job never
/// re-queues itself - is pinned by a test that cannot drift from the code.
pub(super) fn demote_requeues(demote: bool, tombstone: bool, failed: bool) -> bool {
    demote && !tombstone && failed
}

/// A finished job as NZBGet's own `(Status, ParStatus, UnpackStatus)`.
///
/// Everything that was not Completed used to report `FAILURE/PAR` with
/// `ParStatus: FAILURE` - one bit, so "needs a password", "the disk
/// filled up" and "the post is missing articles" were indistinguishable
/// to a client, and all three were blamed on a repair that in two of the
/// three cases never ran. NZBGet has vocabulary for each of them and the
/// *arrs surface it, so the mapping only has to be honest.
///
/// `SUCCESS/UNPACK` is kept verbatim on the success path: it is what the
/// M26 certification round proved against Sonarr and Radarr, and it says
/// the same thing `SUCCESS/ALL` would.
pub(crate) fn nzbget_status(j: &Job) -> (&'static str, &'static str, &'static str) {
    if j.state == JobState::Completed {
        return ("SUCCESS/UNPACK", "SUCCESS", "SUCCESS");
    }
    let msg = j.fail_message.to_ascii_lowercase();
    // Both of these are unpack-stage verdicts with a dedicated NZBGet
    // status, and neither is the release's fault - a client that showed
    // "repair failed" for them sent the user looking in the wrong place.
    if msg.contains("password") {
        return ("FAILURE/UNPACK", "SUCCESS", "PASSWORD");
    }
    if disk_full_failure(&msg) {
        return ("FAILURE/UNPACK", "SUCCESS", "SPACE");
    }
    match fail_kind(&j.fail_message) {
        // The one case that really is a failed repair.
        FailKind::Unrepairable => ("FAILURE/PAR", "FAILURE", "NONE"),
        // The post could not be fetched whole. NZBGet calls that health,
        // and reports no par verdict because par never got to run.
        // Transport joins them for the *arr's purposes (grab another
        // release); the indexer dead-post report is gated separately by
        // post_unavailable, which excludes it.
        FailKind::MissingArticles
        | FailKind::PreflightImpossible
        | FailKind::Gone
        | FailKind::Transport => ("FAILURE/HEALTH", "NONE", "NONE"),
        // Anything on this machine. Says nothing about the release.
        FailKind::Local => ("FAILURE/UNPACK", "SUCCESS", "FAILURE"),
    }
}

/// Does this archive shape need room for the volumes AND the extracted
/// payload at the same time? True for the shapes that materialize their
/// parts on disk and unpack afterwards, which is what makes a disk that
/// fits the download alone fail at the very end.
pub(crate) fn shape_unpacks_on_disk(shape: &str) -> bool {
    shape
        .split_whitespace()
        .any(|t| matches!(t, "on-disk" | "mixed-pass" | "unlock-at-end"))
}

/// Bytes the output directory must be able to take before this job can
/// finish: what is still to fetch, plus the room the extraction needs.
///
/// The extracted payload is approximated by the set size - archives on
/// Usenet are near-incompressible media - and it sits beside the parts,
/// hence the second copy.
///
/// An ENCRYPTED set used to need a THIRD, because the finish decrypt did
/// not work in place: it wrote the plaintext into a temp beside the
/// ciphertext and renamed it over the top, so both existed at the peak.
/// Counting only twice told a user with a 15.6 GB disk that a 13.85 GB
/// encrypted job needed ~12 GB freed when the true figure was past 25,
/// so they would have freed what we asked and failed at 96% a second
/// time. TODO 27 phase 3 deleted that pass - an encrypted set decrypts
/// as its bytes arrive, and one that cannot simply demotes to volumes +
/// payload like any other - so the third copy went with it. Forecasting
/// it anyway would now name a figure a third too high, which is the
/// same defect pointing the other way.
pub(crate) fn unpack_space_needed(to_fetch: u64, total_bytes: u64, shape: &str) -> u64 {
    let mut needed = to_fetch.saturating_add(total_bytes);
    let has = |want: &str| shape.split_whitespace().any(|t| t == want);
    // A NESTED set peaks one payload higher than it looks: the outer
    // volumes stay on disk (the nested pass deliberately keeps what it
    // cannot prove spent), level 0's output IS the inner archive, and
    // level 1's output is the real payload - three copies at the peak
    // where this said two. Exactly the defect the `encrypted` arm was
    // added for, one shape over, and it fails identically: no
    // `space_short` amber, then ENOSPC at the second nesting level after
    // the entire download has been paid for, and a drawer that names a
    // figure the user can free and still fail at.
    if has("inner-7z") || has("inner-rar") {
        needed = needed.saturating_add(total_bytes);
    }
    needed
}

/// NZBGet's priority scale onto ours.
///
/// They are not the same numbers: NZBGet uses -100/-50/0/50/100 with 900
/// for force, SAB (and our stored `priority`) uses -1/0/1 with 2 for
/// force. Passing one through as the other made "high" in an *arr land
/// as a priority far above Force.
pub(crate) fn nzbget_priority(p: i64) -> i32 {
    match p {
        900.. => 2,
        50..=899 => 1,
        i64::MIN..=-50 => -1,
        _ => 0,
    }
}

/// Cooldown ceiling for a `Transport` failure - a stalled pool, a flaky
/// link, a server that never connected.
///
/// The configured `auto_retry_secs` is sized for propagation: articles
/// genuinely absent from a server may appear in twenty minutes, so
/// waiting is the remedy. Nothing about a stall gets better by waiting,
/// so this caps it - the user is otherwise made to sit out a cooldown
/// for a cause that was never in play. Still a cooldown and not zero: a
/// link that just wedged deserves a moment, and an immediate retry into
/// a still-broken pool would spin.
pub(super) const SHORT_RETRY_SECS: u64 = 120;

/// Ceiling on the backed-off move cooldown, however many attempts have
/// failed. Six hours: long enough that a destination which is simply
/// gone stops filling the log, short enough that a NAS which came back
/// overnight is picked up by morning without anybody pressing anything.
pub(super) const MOVE_RETRY_MAX_SECS: u64 = 6 * 3600;

/// How many consecutive failed move attempts before the daemon stops
/// re-arming and leaves the job parked for a human.
///
/// Eight, which with the doubling ladder below is a little over a day
/// of trying from the default 20-minute base. The move retry is not the
/// download retry (ONE attempt, see `auto_retry_eligible`): the thing it
/// waits for is usually a volume that will be back, so it is worth
/// several tries. What it must not do is try forever - past a day the
/// answer is not "wait longer", it is "tell the user", and the amber
/// row plus its `Try the move now` button are already there to be told
/// through.
pub(super) const MOVE_RETRY_GIVE_UP: u32 = 8;

/// The cooldown owed before the `attempts`-th consecutive move retry,
/// given the configured base. `attempts` counts the failures SO FAR
/// (1 after the first), so the first retry waits the plain base.
///
/// Doubling, capped: 20m, 40m, 80m, 2h40, 5h20, then 6h flat. A move
/// destination fails for one of two reasons and the ladder has to suit
/// both - a share that dropped for a moment wants the short first rung,
/// and a volume nobody has plugged in wants the daemon to shut up about
/// it. Flat-20-minutes served the first and failed the second.
pub(super) fn move_retry_delay(base: u64, attempts: u32) -> u64 {
    // Saturating both ways: `base` is user-configured (minutes, up to a
    // week) and the shift count grows without bound, so the arithmetic
    // must not be the thing that panics a mover.
    let steps = attempts.saturating_sub(1).min(u32::BITS - 1);
    base.checked_shl(steps)
        .unwrap_or(MOVE_RETRY_MAX_SECS)
        .min(MOVE_RETRY_MAX_SECS.max(base))
}

/// Is this path a TV-filing `Season NN` folder - i.e. a SHARED library
/// directory holding every episode of a season, not one job's private
/// output? The one place the shape is spelled out; `Job::filed` records
/// the answer at the moment filing ran, and everything downstream reads
/// the flag rather than re-testing.
pub(crate) fn is_season_dir(p: &std::path::Path) -> bool {
    p.file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_prefix("Season "))
        .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
}

/// Delete a finished job's downloaded content safely.
///
/// Normally `out_dir` is the job's own private folder, so we remove it
/// wholesale. But once a job has been TV-filed (M23 tv_sort) `out_dir` is
/// the SHARED `Show/Season NN` directory - recursively removing it would
/// take every other episode of the season with it (bug sweep: a watchlist
/// "replace old" upgrade, and a history "delete + files", both wiped whole
/// seasons). For a filed job we delete only this episode's files; the rest
/// of the season is left intact.
///
/// `tail` is what this release's filed files carry after the episode base
/// (see [`delete_tail`]). Its quality-suffix half is what makes the filed
/// delete release-SPECIFIC rather than merely episode-specific: an upgrade
/// files the better copy into the same season folder under the same
/// `Show - S03E05` base, so without it the delete of the superseded copy
/// also took the replacement that had just landed beside it and the user
/// was left with neither. Ignored for an unfiled job, whose directory is
/// private either way.
///
/// Returns whether the files actually went, and why not when they didn't
/// (see [`FilesGone`]). A recoverable delete that the Trash refuses now
/// LEAVES them (see `smart::remove_user_dir` - the fallback used to be a
/// permanent delete), so callers that tell the user what happened have to
/// ask rather than assume.
pub(super) fn remove_job_files(
    out_dir: &std::path::Path,
    name: &str,
    filed: bool,
    tail: &crate::smart::FiledTail,
) -> FilesGone {
    // `filed` is the job's own persisted flag (Job::filed), NOT a shape
    // test on the current state. Deriving it from `state == Completed`
    // meant a re-queued job (retry) claimed its shared season folder as
    // private and a later delete-with-files took the whole season.
    if filed {
        let d = crate::smart::delete_filed_episode(out_dir, name, tail);
        info!(
            target: "files",
            "{name}: TV-filed - removed {} file(s) from {}, siblings left intact",
            d.removed,
            out_dir.display()
        );
        // A refusal here leaves the episode sitting in the user's own
        // library, which is the half of this they are most likely to
        // find later and least likely to explain. Removing nothing at
        // all is NOT a refusal: the matcher is deliberately conservative
        // (a season pack, a name the rename never touched) and reporting
        // "your files are still there" for a delete that never had a
        // target to hit would cry wolf on every one of those.
        match d.kept {
            Some(why) => FilesGone::Kept(why),
            None => FilesGone::Yes(d.removed_as),
        }
    } else {
        // Trash-aware, like every other delete of a user's downloaded
        // content: this is the arm behind history "delete + files", a
        // queue delete with files, and the watchlist delete_old upgrade,
        // and it was a bare remove_dir_all - the one delete the
        // "Deleted files go to the Trash" setting most obviously
        // promises to soften, permanently removing whole releases while
        // the settings hint said a wrong guess could be undone. The
        // whole private folder goes as ONE recoverable item (a single
        // bounded Trash call), so restoring "the download I deleted" is
        // one drag rather than a thousand files. Read the flag here, at
        // the delete's entry, per remove_user_file's contract.
        let recoverable = crate::smart::delete_to_trash();
        match crate::smart::remove_user_dir(out_dir, recoverable) {
            Ok(how) => FilesGone::Yes(how),
            Err(e) => {
                warn!(
                    target: "files",
                    "{name}: could not remove {}: {e}",
                    out_dir.display()
                );
                FilesGone::Kept(e.to_string())
            }
        }
    }
}

/// What a delete-with-files actually managed to do on disk.
///
/// A plain `bool` was enough while "not removed" could only mean an error
/// nobody could act on. It cannot carry the case this exists for: a
/// recoverable delete the Trash refuses leaves the download exactly where
/// it was, and the record the user was holding it by is removed anyway.
/// The reason has to reach a surface a person actually looks at (see
/// `Daemon::note_delete_kept`), so it travels back with the verdict rather
/// than dying in a `warn!`.
pub(super) enum FilesGone {
    /// Nothing this job put on disk is left - or there was nothing there
    /// to remove in the first place.
    /// Carries what actually happened, because "went to the Trash" is a
    /// promise of recoverability and only the removal itself knows
    /// whether it can be kept. Reconstructing it from the setting told a
    /// user their 14 GB download was restorable when it had been
    /// destroyed - see `smart::Removed`.
    Yes(crate::smart::Removed),
    /// The files are STILL on disk, and this is why.
    Kept(String),
}

/// What a filed job's files really carry after the episode base, and so
/// what [`remove_job_files`] (and the play path) has to match them with.
///
/// [`Job::filed_suffix`] is what filing itself used, and it is the answer.
/// The naming settings are LIVE, so recomputing here asked today's
/// settings about a name written weeks ago: turn auto-rename off and the
/// recomputed suffix is empty, which does not mean "no suffix on disk" but
/// "match the episode base plus any rename tail at all" - every quality of
/// the episode, including the upgrade filed beside it a second ago.
///
/// `legacy` is [`Daemon::job_suffix`], and runs only for records written
/// before the suffix was persisted: recomputing is what we did for all of
/// them anyway, and a suffix that no longer matches is a leftover rather
/// than a destroyed episode. What it must never be is a bare `""` default,
/// which is the wildcard the bug was made of.
///
/// The episode title has NO legacy arm, and does not need one: a record
/// old enough to be missing it was written before titles could be in a
/// filename at all, so the empty string is not a guess about it - it is
/// the fact.
pub(super) fn delete_tail(j: &Job, legacy: impl FnOnce() -> String) -> crate::smart::FiledTail {
    crate::smart::FiledTail {
        title: j.filed_title.clone().unwrap_or_default(),
        suffix: j.filed_suffix.clone().unwrap_or_else(legacy),
    }
}

/// The stem a filed job's episode files on disk were built from, which
/// is [`Job::filed_base`] when an identity oracle renamed the release
/// and the job's own name otherwise.
///
/// Every filed-job lookup goes through here rather than reaching for
/// `name` directly: an obfuscated post filed under an oracle's name has
/// no file anywhere called after its hash, so a `name`-keyed delete
/// leaves the episode behind and a `name`-keyed play cannot find it.
pub(super) fn filed_stem(j: &Job) -> &str {
    j.filed_base
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or(&j.name)
}

/// One history record as `plan_history_delete` needs to see it.
///
/// A struct rather than the tuple this was: with `filed` and `locked`
/// adjacent, a positional record is one careless swap away from deciding
/// the wrong record owns its files, and that decision reaches
/// `remove_dir_all`.
pub(crate) struct DeleteRecord {
    pub nzo_id: String,
    pub state: JobState,
    pub out_dir: PathBuf,
    /// TV-filed: `out_dir` is the shared season folder, claimed by every
    /// episode in it.
    pub filed: bool,
    /// Waiting for the user's password. Complete on paper - every byte
    /// arrived, so `state` is Completed - but the payload is still packed
    /// and only this record carries the 🔑 that unlocks it. A
    /// "clear the finished ones" sweep must leave it where it is.
    pub locked: bool,
}

/// One history record's fate under a `mode=history&name=delete` call.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct HistoryDelete {
    /// This record is leaving history.
    pub doomed: bool,
    /// ...and its `out_dir` is genuinely its alone, so `del_files=1` may
    /// remove it. False when somebody else still lives there.
    pub may_remove_files: bool,
}

/// Plan a history delete before any of it happens: which records go, and
/// which of them own their output directory outright.
///
/// A completed job's directory is not necessarily its own to delete.
/// `publish_over_previous` (A6) hands the CANONICAL directory to a verified
/// re-download and leaves the superseded job's history record pointing at
/// that same path, so a delete-with-files on the OLDER record used to
/// `remove_dir_all` the NEWER job's payload - the record deleted was not
/// the data destroyed. A directory with a second live claimant is not this
/// record's to remove; the leftover record can always be deleted again
/// without files.
///
/// The claimant test runs against the records that will SURVIVE, never the
/// pre-delete list - `value=all` dooms every history record, so testing
/// against the list as it stands would find each record's own directory
/// "claimed" by a doomed sibling and silently stop deleting anything.
///
/// TV-filed records are exempt: their `out_dir` IS the shared season
/// folder, so every episode of the season claims it, and the per-episode
/// delete is already narrow by construction (`remove_job_files`).
///
/// `value` selects: an nzo_id, a comma list of them, or one of the bulk
/// words - `all`, `failed`, or `completed`. `completed` is the dashboard's
/// one-click "Clear completed": it is deliberately NARROWER than the
/// history card's Completed filter chip, which counts password-locked
/// records too (they finish downloading, so their state IS Completed).
/// Sweeping those away would take the only 🔑 the user has with them, so
/// they stay, exactly as failures do.
///
/// `queue_dirs` is every live queue job's directory (all of them survive a
/// history delete).
pub(crate) fn plan_history_delete(
    records: &[DeleteRecord],
    value: &str,
    queue_dirs: &[PathBuf],
) -> Vec<HistoryDelete> {
    let doomed: Vec<bool> = records
        .iter()
        .map(|r| {
            value == "all"
                || (value == "failed" && r.state == JobState::Failed)
                || (value == "completed" && r.state == JobState::Completed && !r.locked)
                // Trimmed: the caller's busy guard trims the same list,
                // so an untrimmed match here left " nzo_2" passing the
                // guard and then deleting nothing.
                || value.split(',').any(|v| v.trim() == r.nzo_id)
        })
        .collect();
    records
        .iter()
        .zip(&doomed)
        .map(|(rec, &is_doomed)| {
            let (dir, filed) = (&rec.out_dir, rec.filed);
            // Survivors only: every queue job survives, and so does every
            // history record this call is not deleting.
            let other_claimant = queue_dirs.iter().any(|p| p == dir)
                || records
                    .iter()
                    .zip(&doomed)
                    .any(|(other, &other_doomed)| !other_doomed && &other.out_dir == dir);
            HistoryDelete {
                doomed: is_doomed,
                may_remove_files: is_doomed && (filed || !other_claimant),
            }
        })
        .collect()
}

/// Files under `dir`, recursively; 0 when it cannot be read (which is
/// also what a directory that has been moved away answers). Symlinks
/// count as the one file they are - never walked - matching how
/// `move_tree` treats them.
pub(super) fn file_count(dir: &std::path::Path) -> usize {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    rd.flatten()
        .map(|e| {
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                file_count(&e.path())
            } else {
                1
            }
        })
        .sum()
}

/// Split the two persisted record arrays into the queue and the history
/// the daemon comes back with. Returns `(queue, history)` in file order.
///
/// A record's ARRAY is not on its own the answer. A job goes Completed (or
/// Failed) the moment its download ends, and only reaches history when
/// `park` files it - between those two points sits the whole of
/// post-processing: repair, unpack, unlock, junk sweep, rename, Season
/// filing, the move to a NAS. Any `save_queue` during that window - and
/// every queue mutation on the box calls one - persists a TERMINAL record
/// inside the "queue" array. Restoring it there made it a permanent
/// zombie: `pick_job` only ever picks a `Queued` job, nothing else
/// reconciles the two arrays, so it sat in the queue forever, never ran,
/// never appeared in history, and never reached the *arrs that were
/// waiting on its outcome.
///
/// Such a record is routed to history instead, which is where `park` was
/// about to put it and is the outcome the rest of the system is built
/// around: visible, retryable, and reported. What it does not get is the
/// hooks - the pp-script and the notifications fire from the runner, which
/// died with the daemon.
///
/// Emphatically NOT a state rewrite: `job_from_json` maps a Downloading
/// record to `Queued`, and that record stays in the QUEUE so the scheduler
/// restarts it and its article journal resumes the transfer from what
/// already landed.
///
/// De-duplicated by nzo_id. `park` retains-then-pushes before its single
/// save, so a well-formed file never holds one job twice; a torn or
/// hand-edited one must not be turned into two history entries by this.
pub(super) fn restore_records(queue_arr: &[Value], hist_arr: &[Value]) -> (Vec<Job>, Vec<Job>) {
    let mut queued: Vec<Job> = Vec::new();
    let mut interrupted: Vec<Job> = Vec::new();
    for j in queue_arr {
        let Some(mut job) = job_from_json(j) else {
            continue;
        };
        if matches!(job.state, JobState::Completed | JobState::Failed) {
            // `finalizing` is the difference between "post-processing
            // finished, only the hooks were lost" and "the payload was
            // being moved when the daemon died". The second used to be
            // filed as a clean success with a storage path that could be
            // a half-copied directory - or one the move had already
            // emptied - and the *arrs act on that: import the partial
            // file, or stall on a release with no Failed state to
            // trigger a re-grab.
            //
            // Reported Failed so a re-grab happens. A re-download costs
            // bandwidth; importing half a file quietly corrupts a
            // library, and there is no way after the fact to tell which
            // of the two a given directory is. The bytes are left on
            // disk, and the message says where, so nothing is lost that
            // the user cannot pick up by hand.
            if job.finalizing && job.state == JobState::Completed {
                info!(
                    target: "queue",
                    "{} ({}) was interrupted DURING post-processing - \
                     reporting it as failed so it is re-grabbed rather than \
                     imported half-moved. Its files are under {}",
                    job.nzo_id,
                    job.name,
                    job.out_dir.display()
                );
                job.state = JobState::Failed;
                if job.fail_message.is_empty() {
                    job.fail_message = format!(
                        "post-processing was interrupted by a restart; the download \
                         itself completed and its files are under {}",
                        job.out_dir.display()
                    );
                }
            } else {
                info!(
                    target: "queue",
                    "{} ({}) was still in post-processing at shutdown - \
                     filing it to history as {:?}",
                    job.nzo_id, job.name, job.state
                );
            }
            job.finalizing = false;
            interrupted.push(job);
        } else {
            job.finalizing = false;
            queued.push(job);
        }
    }
    // Consumed on restore for the history array too, not only the queue
    // arms above. The set_password unlock task saves while its
    // ClearFinalizing guard is still in scope, so a history record can
    // reach queue.json with `finalizing: true` and the guard's Drop then
    // clears it in memory only. Carried back across a hard stop (docker
    // stop, reboot, pkill - there is no SIGTERM handler), that stale
    // flag made history_change_cat refuse the job FOREVER with
    // "post-processing is still running", through both the dashboard and
    // SAB editqueue set_cat, with no way to reset it. The flag has no
    // consumer for a history record - the Completed->Failed conversion
    // above applies only to the queue array - so clearing it here is the
    // whole fix, whichever write path persisted the stale true.
    let mut history: Vec<Job> = hist_arr
        .iter()
        .filter_map(job_from_json)
        .map(|mut j| {
            j.finalizing = false;
            j
        })
        .collect();
    // After the history array, not before: these finished last, and
    // history reads newest-first off the end.
    for job in interrupted {
        if !history.iter().any(|h| h.nzo_id == job.nzo_id) {
            history.push(job);
        }
    }
    (queued, history)
}

/// Claim one of the EXTRA episode slots a multi-episode release covers.
///
/// A `S01E01E02` double owns both episodes, which is why it claims them:
/// otherwise a standalone E02 gets grabbed again on the next pass. But
/// the claim used to be a bare insert with no look at what was already
/// there, so a 1080p double could take a slot that already held a
/// standalone 2160p grab. The user's better copy stopped being tracked by
/// any slot, and the very release they already had scored as an upgrade
/// next pass and was re-downloaded with the duplicate hold bypassed.
///
/// Take the slot only when it is free, when we are at least as good as
/// whoever holds it, or when it is our own record being refreshed.
pub(super) fn claim_extra_slot(
    slots: &mut std::collections::HashMap<String, crate::watchlist::Slot>,
    key: String,
    val: &crate::watchlist::Slot,
) {
    if let Some(prev) = slots.get(&key)
        && prev.stem != val.stem
        && prev.rank > val.rank
    {
        info!(
            target: "watch",
            "not taking the slot held by {} (better than {}) for its extra episode",
            prev.stem, val.stem
        );
        return;
    }
    slots.insert(key, val.clone());
}

/// Content fingerprint of an NZB, so "already queued" can be answered
/// after a restart from the persisted queue rather than from memory.
pub(super) fn nzb_sha(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(bytes))
}

/// The suffix `publish_over_previous` parks a superseded download under
/// while it swaps the new one into place.
pub(super) const REPLACED_SUFFIX: &str = ".nzbfast-replaced-";

/// What both reference clients mean by "MB" in their APIs.
///
/// MEASURED, not assumed. An NZB whose segments sum to exactly
/// 104857600 bytes was added to SABnzbd 5.0.4 and to NZBGet on the bench
/// box, and both reported 100:
///
///   SAB    `mode=queue`  -> "mb": "100.00", "size": "100.0 MB"
///   NZBGet `listgroups`  -> FileSizeMB: 100, from FileSizeLo/Hi 104857600
///
/// That is 1048576 bytes per MB in both. We divided by 1_000_000, which
/// overstated every size by 4.9% - Sonarr multiplies the field back by
/// 1024*1024, so its queue sizes and its free-space thresholds were both
/// skewed. Anything feeding a client-facing *MB field goes through here.
pub(super) const API_MB: f64 = 1024.0 * 1024.0;

/// Integer form of [`API_MB`], for the NZBGet fields that are whole MB.
pub(super) const API_MB_U: u64 = 1024 * 1024;

/// Wall-clock seconds. Distinct from `Instant`, which is monotonic and
/// process-local: anything that has to mean the same thing after a
/// restart has to be stamped with this.
pub(super) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_secs() as i64)
        .unwrap_or(0)
}

// The JSON wire form of a Job, moved out bodily (TODO 106) and re-exported
// so `job_json` / `job_from_json` remain the same paths they always were.
#[path = "job_wire.rs"]
mod job_wire;
pub(super) use job_wire::{job_from_json, job_json};

// How a job fails and what happens next, moved out bodily (TODO 106) and
// re-exported so every caller still names `job::fail_kind` and friends.
//
// The classifier half now lives at `crate::failkind` (TODO 276 item 3)
// and is re-exported from HERE rather than imported at each use site, so
// the ~90 callers inside `serve` that reach these names through this
// module's glob are untouched by the move.
#[path = "job_fail.rs"]
mod job_fail;
pub(crate) use crate::failkind::{
    FailKind, RETRY_WHY_PROPAGATION, RETRY_WHY_TRANSPORT, disk_full_failure,
    disk_full_mid_download, fail_action, fail_hint, fail_kind, fail_kind_token,
};
pub(super) use job_fail::{auto_retry_eligible, merge_notify_tokens, post_job_plan};
// `post_job_duties` has no production caller outside `job_fail` itself - it is
// the inner half of `post_job_plan` - but `serve::tests_grabs` pins its
// three-way policy by name through `serve`'s glob of this module.
#[cfg(test)]
pub(super) use job_fail::post_job_duties;

// The duplicate-detection keys, moved out bodily (TODO 106) and re-exported:
// `serve` reaches them through its own glob of this module.
//
// `flatten_name` is NOT in this list any more. It moved to `crate::smart`
// in TODO 276 item 3 - `newznab::release_ident` was its one caller outside
// `serve`, and reaching in here for it was the last of the sixteen
// references that held `serve` inside a 146,591-line dependency cycle.
// `job_dupe` re-exports it from its new home, so the keys below still read
// as one unit.
#[path = "job_dupe.rs"]
mod job_dupe;
pub(super) use job_dupe::{dupe_key, exact_dupe_key, is_proper};
// Same shape: `dated_key` is only called by `dupe_key` beside it, and by the
// dated-post cases in `job_tests`.
#[cfg(test)]
pub(super) use job_dupe::dated_key;

// Where a finished job's files land, moved out bodily (TODO 106) and
// re-exported so daemon_persist / settings_setters / the api keep their paths.
#[path = "job_publish.rs"]
mod job_publish;
pub(crate) use job_publish::{DirClaim, choose_out_dir, publish_over_previous, refile_out_dir};
pub(super) use job_publish::{recover_interrupted_publishes, same_dir};

#[cfg(test)]
#[path = "job_tests.rs"]
mod job_tests;

#[cfg(all(test, unix))]
#[path = "job_finalize_marker_tests.rs"]
mod job_finalize_marker_tests;

/// What `Daemon::enqueue` hands back: the job's id, and whether the
/// record that names it reached disk (TODO 16g / A12).
///
/// `enqueue` used to return the bare id and persist best-effort, so every
/// caller was told the job was durable when it may not have been - and
/// the watch poller deleted the user's .nzb on that word. The job is live
/// in memory either way; `durable: false` means the write of queue.json
/// (or of history.jsonl, for the arms that file straight to history)
/// failed, and a restart before the next successful save will not find
/// the record. `enqueue` logs that itself, once, so a caller with nothing
/// of its own to protect may ignore the flag: the spooled .nzb it wrote
/// survives, and `Daemon::recover_orphaned_spool` re-adopts it at the next
/// start under the SAME id. A caller that DESTROYS its source on success
/// (the watch folder deleting the user's file) must check the flag and
/// keep the source when it is false.
#[derive(Debug, Clone)]
pub(super) struct Enqueued {
    pub nzo_id: String,
    pub durable: bool,
}
