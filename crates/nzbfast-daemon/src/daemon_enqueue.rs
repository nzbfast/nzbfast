//! `Daemon::enqueue` - the whole add path from NZB bytes to a queued (or
//! parked) job - moved out bodily under the size gate (TODO 106). A child
//! module of `daemon`, same shape as daemon_index, so `Daemon`'s private
//! fields and daemon.rs's private types stay in scope exactly as they
//! were inline. `super` now means `daemon`, not `serve`, so the method's
//! old pub(super) is spelled pub(crate) to keep its original
//! visibility.

use super::*;

/// Test seam: `enqueue` trips it once a duplicate collision has been
/// SELECTED and before the add publishes - the window a concurrent
/// delete of the chosen original lands in. `add_lock` serializes adds
/// against each other but not against deletion, so in production the
/// window is the whole job build; in a test without a seam it is zero
/// width. Same two-stage shape as `daemon_park::PARK_GEN_BARRIER`:
/// first barrier says the window is open, second says the test has
/// staged its delete and releases it.
///
/// Keyed by stem, unlike the other seams, and that is load-bearing:
/// `cargo test` runs this binary's tests in parallel and EVERY add
/// reaches this point, so an unkeyed barrier is tripped by whatever
/// unrelated test happens to be adding a duplicate at the time - a
/// third waiter on a `Barrier::new(2)`, which is a hang, not a
/// failure. Only the add whose stem contains the key waits.
#[cfg(test)]
pub(crate) static DUPE_ADMIT_BARRIER: Mutex<
    Option<(String, Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,
> = Mutex::new(None);

/// What `Daemon::resolve_add_identity` settles. Fields are the locals
/// `enqueue` used to declare inline and still uses under the same names.
struct AddIdentity {
    stem: String,
    password: Option<String>,
    category: String,
    total_bytes: u64,
    zip_packed: bool,
    tv_sort: bool,
    smart_rule: String,
}

/// What `Daemon::consult_pre_queue` answers that the caller cannot derive.
/// The name, category and priority it also rewrites are amended in place.
struct HookVerdict {
    pp: Option<i64>,
    script: String,
    reject: Option<String>,
}

/// What `enqueue_as` has settled about an add that its own body no longer
/// owns by the time the row is built - the stem, the spool path, the
/// out dir and the dupe key have all moved onto the [`Job`] - but that
/// [`Daemon::publish_or_refuse`] still needs.
///
/// A struct rather than twelve more parameters, and that is a
/// correctness argument rather than a tidiness one: positionally these
/// are three adjacent `String`s (`nzo_id`, `pairing_name`, `category`),
/// two adjacent `Option`s of borrowed text and a `bool` next to two
/// integers, so any two of several pairs would swap and still compile.
/// Named fields at the call site cannot.
pub struct AddPending<'a> {
    /// The id the add was accepted under. Logged, announced, returned.
    nzo_id: String,
    /// `job.name`, taken before the row owns the stem, for the lifecycle
    /// event emitted while that row is behind the queue lock.
    pairing_name: String,
    category: String,
    origin: &'a str,
    /// The priority the CALLER asked for, NOT the row's: the duplicate
    /// ladder derives the row's from it with [`enqueue_priority`], and
    /// re-derives it under the queue lock if the collision has gone.
    priority: i32,
    total_bytes: u64,
    /// Whether the row was BUILT as a held ALTERNATIVE. Not final on the
    /// way in - the queue critical section can still clear it, which is
    /// why the destructure below rebinds it `mut`.
    duplicate: bool,
    /// TODO 282 item 5: the job this add is a spare OF, when it is one.
    hold_for: Option<&'a str>,
    /// The spare's spool copy, cloned before `spool_path` moved onto the
    /// row, because the arms that refuse a spare have to unlink it.
    spare_spool: Option<PathBuf>,
    /// The original this add collided with, as chosen before the queue
    /// lock. Re-checked there and nowhere else.
    collision: Option<DupeCollision>,
    /// §129 4a: the pre-queue script's refusal, if it gave one.
    hook_reject: Option<String>,
    /// §129 2d: what the user's duplicates setting says to do.
    dupe_action: String,
    /// This add's own message-id set, hashed from the NZB `enqueue_as`
    /// parsed. Carried here only to PRIME the §292 memo at the publish -
    /// a row admitted with its ids already known never costs a later add
    /// the spool read that used to make the add path quadratic.
    post_ids: Arc<spare::PostIds>,
}

impl Daemon {
    /// `pp` is the post-processing mode the CALLER requested (0-3, None
    /// = none named). The pre-queue hook receives it - SAB's contract
    /// hands the script the requested pp - but it is RECORDED on the
    /// job afterwards by `record_add_params`, which fills only what the
    /// hook did not already answer.
    #[expect(clippy::too_many_arguments)]
    pub fn enqueue(
        &self,
        nzb_bytes: &[u8],
        name: &str,
        category: &str,
        priority: i32,
        pp: Option<i64>,
        password: Option<&str>,
        origin: &str,
        allow_dupe: bool,
    ) -> Result<Enqueued> {
        self.enqueue_as(
            None,
            nzb_bytes,
            name,
            category,
            priority,
            pp,
            password,
            origin,
            DupeExempt::asked(allow_dupe),
            None,
        )
    }

    /// The queue id for a new add: the caller's own when it gave one,
    /// else the next off the counter. Minted `SABnzbd_nzo_nzbfast{n}`
    /// from a plain counter, so one id is routinely a strict PREFIX of
    /// another - the reason a test must never substring-search a payload
    /// for one (`tools/payload-id-gate.py` holds that rule).
    pub fn mint_nzo_id(&self, id: Option<&str>) -> String {
        match id {
            Some(id) => id.to_string(),
            None => format!(
                "SABnzbd_nzo_nzbfast{}",
                self.next_id.fetch_add(1, Ordering::Relaxed)
            ),
        }
    }

    /// `enqueue` with the id chosen by the caller, and with the option of
    /// parking it as a HELD SPARE of another job.
    ///
    /// `hold_for` is TODO 282 item 5, and it is an explicit instruction
    /// rather than the duplicate ladder happening to fire: the caller has
    /// already decided this NZB is a backup for that job, so the whole
    /// `dupe_collision` question is skipped and the row lands paused at
    /// [`DUPE_PRIORITY`] with `held_for` naming the target. It has to be
    /// explicit, because none of the three settings that decide a
    /// duplicate's fate is a statement about a spare: `dupe_scope =
    /// "exact"` would let a different release of the same episode QUEUE
    /// and download payload, `dupe_action = "discard"`/`"fail"` would
    /// refuse or fail it, and a recent delete mark would release the
    /// hold. A spare that downloads payload is the one outcome §282
    /// forbids outright.
    ///
    /// `id` is the id chosen by the caller. Only
    /// `recover_orphaned_spool` passes `Some`: an orphaned spool file is
    /// named by the id its job was accepted under, and re-adopting it
    /// under that id keeps an *arr's handle and the job's stream token
    /// valid across the restart, and makes "recovered exactly once" a
    /// plain id lookup. A recovered id is always below the restored
    /// allocator (the wall-clock floor in `load_queue`), so it can never
    /// be handed out again.
    #[expect(clippy::too_many_arguments)]
    pub fn enqueue_as(
        &self,
        id: Option<&str>,
        nzb_bytes: &[u8],
        name: &str,
        category: &str,
        priority: i32,
        pp: Option<i64>,
        password: Option<&str>,
        origin: &str,
        exempt: DupeExempt<'_>,
        hold_for: Option<&str>,
    ) -> Result<Enqueued> {
        let nzo_id = self.mint_nzo_id(id);
        let nzb = nzbkit::nzb::Nzb::parse(nzb_bytes)?;
        let AddIdentity {
            mut stem,
            password,
            mut category,
            total_bytes,
            zip_packed,
            tv_sort,
            smart_rule,
        } = self.resolve_add_identity(&nzb, &nzo_id, name, category, password);
        let mut priority = priority;
        let HookVerdict {
            pp: hook_pp,
            script: hook_script,
            reject: hook_reject,
        } = self.consult_pre_queue(
            &nzb,
            &nzo_id,
            origin,
            pp,
            total_bytes,
            &mut stem,
            &mut category,
            &mut priority,
        );
        // Named after the release as well as the job id. A folder of
        // SABnzbd_nzo_nzbfast<n>.nzb files could not be matched to
        // anything a user had ever seen; the id stays first so the name
        // is still unique and sortable, and old jobs are unaffected
        // because nzb_path is persisted per job.
        let spool_path = self
            .spool
            .join(format!("{nzo_id}-{}.nzb", safe_spool_stem(&stem)));
        // Atomic: a resume re-parses this file; it must never be torn.
        // The category is settled by here and is recorded beside it.
        write_spool_copy(&spool_path, nzb_bytes, &category)?;
        // §129 2b: the category's default priority fills an add that
        // did not name one (-100, SAB's "default"). An explicit
        // priority - including -2 add-paused - always wins.
        if priority == SAB_DEFAULT_PRIORITY
            && let Some(p) = self
                .cat_meta
                .lock_ok()
                .get(&category)
                .and_then(|m| m.priority)
        {
            priority = p;
        }
        // CAPPED, and `refile_out_dir` must spell it the SAME way.
        let dir_stem = nzbkit::disk::sanitize_filename_capped(&stem);
        // TODO 317 (GitHub #67): when this category writes through, the
        // job downloads INTO its destination rather than being moved
        // there once it finishes - so there is no copy-then-delete
        // across filesystems at the end and no window in which the
        // payload has to exist on two drives at once.
        //
        // The destination is decided HERE and recorded on the job
        // (`write_through` below), which is TODO 317's own rule: fixed
        // at job start, a later settings or category change applies
        // from the next job. Recomputing it at completion instead
        // would mean a job that started under the setting and finished
        // without it owes a move from a directory the mover cannot
        // derive a relative path for.
        let write_through_root = self.write_through_root(&category);
        let base_out_dir = match &write_through_root {
            Some(root) => root.join(&dir_stem),
            None => self.base_out_dir(&category, &dir_stem),
        };
        // Two DIFFERENT NZBs whose names sanitize to the same stem and carry
        // no dupe_key (no SxxEyy/year marker - e.g. software or music posts)
        // are not caught by the M14f duplicate hold below, so they would
        // share one out_dir. Their pipelines deliberately overlap (A's tail
        // repairs/extracts while B's net leg runs), so B's journal + volume
        // writers truncate the files A is still reading → both corrupt. Give
        // a colliding job its own directory.
        //
        // A COMPLETED job's payload claims its directory too. Treating it as
        // inert meant a re-add reused the folder and the very first decoded
        // span truncated the previous, good result - which was then gone for
        // nothing if the replacement failed on missing articles, a password
        // or ENOSPC. The re-add downloads under its own name and takes over
        // the canonical directory only once it has verified (`replaces`,
        // published by `publish_over_previous`). A FAILED job's leftovers are
        // junk and are still reused in place, so retrying a flaky post does
        // not climb .2, .3, .4.
        //
        // And a directory that holds files which NO record of ours names
        // claims it as well - but WITHOUT a `replaces`. The two halves are
        // separate: refusing to download into it is what keeps the first
        // decoded span from truncating somebody's files, and recording no
        // replace is what keeps `publish_over_previous` from renaming that
        // directory aside and deleting it on success. `replaces` is only
        // ever OUR OWN completed result of the same release; a hand-made
        // folder that happens to share the release stem, or a payload whose
        // history row the user cleared, is not that and is never touched.
        // The add just lives at .2 for good, which is the price of not
        // knowing whose the folder is.
        // From here to the queue push - which is in `publish_or_refuse`,
        // the guard being MOVED there rather than dropped here - is one
        // transaction. Choosing a directory and deciding "not a
        // duplicate" are both reads of state this job is about to
        // change, and neither is published until the push, so without
        // the lock two concurrent adds of one release agree on
        // everything and then collide.
        let publish = self.add_lock.lock_ok();
        // dir_claim stats the output volume (`p.exists()`, plus one
        // `read_dir` for the fresh-add arm), which can be a network
        // share, and enqueue is reachable from tokio tasks (watchlist
        // watcher, RSS poller) - demote the worker around it.
        //
        // `dir_claim_for_add` and not the bare `dir_claim`: this is a
        // FRESH placement, so a directory holding files that no record
        // names is somebody else's - a completed result whose history
        // row the user cleared with the files kept, or a folder the
        // user made themselves - and downloading into it truncates
        // those files at the first decoded article. It answers
        // `Occupied`, which climbs and records no replace. The retry
        // path deliberately keeps the bare claim; the full argument is
        // on `dir_claim_for_add`.
        let (out_dir, replaces) = crate::persist::blocking_db(|| {
            choose_out_dir(&base_out_dir, &dir_stem, &|p| self.dir_claim_for_add(p))
        });
        self.register_cat(&category);
        // M14f duplicate check: same identity already queued, running, or
        // successfully completed → hold this one as an ALTERNATIVE
        // (paused, Duplicate priority). It auto-promotes if the original
        // fails; PROPERs always download.
        //
        // WHICH rows this add may be a duplicate OF is `exempt`, whose
        // three answers - and why the narrow one exists (§290, Codex
        // F-09) - are set out on [`DupeExempt`]. A `hold_for` spare
        // forgives everything: the caller has settled that row's fate.
        let key = dupe_key(&stem);
        let exempt = exempt.or_anybody(hold_for.is_some());
        // Hashed ONCE per add: the §292 arm compares against it, and the
        // publish stores it as this row's memo entry.
        let post_ids = Arc::new(spare::post_ids(&nzb));
        let collision = self.add_collision(&stem, &post_ids, total_bytes, exempt);
        // The user's delete has now been answered: this release is back.
        // Spending the mark here, rather than letting it sit out its
        // window, is what keeps the identity protected afterwards - a
        // SECOND copy added behind this one is an ordinary duplicate of
        // the row we are about to publish, and must be held like one.
        // Unconditional: a delete followed by an add that was never
        // going to be held has still been answered. Except for a spare,
        // which this daemon added and the user did not - spending their
        // mark on it would leave the identity unprotected for the rest of
        // the window against an add they DID make.
        if hold_for.is_none() {
            self.clear_delete_mark(&stem);
        }
        #[cfg(test)]
        if collision.is_some() {
            let seam = DUPE_ADMIT_BARRIER.lock_ok().clone();
            if let Some((key, open, release)) = seam
                && stem.contains(&key)
            {
                open.wait();
                release.wait();
            }
        }
        // Not final: the original can be deleted between here and the
        // publish, and the queue critical section in
        // `publish_or_refuse` re-asks. An explicit `hold_for` is a
        // duplicate by instruction, and the same critical section
        // re-asks whether its target is still there.
        let duplicate = collision.is_some() || hold_for.is_some();
        // §129 2d: what a duplicate add becomes is the user's call now.
        // "pause" is the M14f hold; "discard" refuses the add outright;
        // "fail" files it straight to history as Failed (the *arr
        // contract: a failed grab triggers their own search for a
        // different release, where a silently held one just sits).
        let dupe_action = self.dupe_action.lock_ok().clone();
        if let Some(c) = &collision
            && dupe_action == "discard"
            // A hook REJECT outranks the duplicates setting: the job is
            // about to file to history with the hook's reason.
            && hook_reject.is_none()
            // And the original still has to be there. Refusing an add
            // outright against a record that was deleted while this one
            // was being admitted loses the download for nothing - the
            // caller is told "duplicate" and there is nothing left for
            // it to be a duplicate OF.
            && self.dupe_collision_stands(c)
        {
            drop(publish);
            // The spool copy was written above; a refused add must not
            // leave it behind - and a refused UNLINK must not either,
            // which is why this is `drop_spool` and not a swallowed
            // `remove_file` (Codex sweep 24 Aug, F-04): the survivor is
            // adoptable, so the discarded duplicate would download at
            // the next start.
            drop_spool(&spool_path);
            info!(
                target: "queue",
                "refused {stem:?} - duplicate of {} ({}, {}), and duplicates \
                 are set to be discarded",
                c.name, c.nzo_id, c.where_
            );
            anyhow::bail!(
                "duplicate of {:?} ({}) - discarded; the duplicates setting \
                 decides this",
                c.name,
                c.where_
            );
        }
        // Late-pick groundwork: was the runner free to take this job the
        // moment it lands? Only then does a slow pick mean the runner was
        // starved (the fixed inline-SQLite bug held picks back 38 s)
        // rather than the job simply waiting its turn.
        let runner_idle = self.started_at.lock_ok().is_none()
            && !self.paused.load(std::sync::atomic::Ordering::Relaxed)
            && !self.queue.lock_ok().iter().any(|j| {
                let g = j.lock_ok();
                g.state == JobState::Queued && !g.paused
            });
        // The lifecycle event below still needs the display name after
        // the row takes ownership of `stem`. The seed worker reads the
        // same name back from the durable row rather than this clone.
        let pairing_name = stem.clone();
        // The two arms that refuse a SPARE have to unlink its spool copy,
        // and by then `spool_path` has moved onto the job. Cloned only
        // when there is a spare in the first place, so an ordinary add
        // pays nothing for it.
        let spare_spool = hold_for.map(|_| spool_path.clone());
        let library = self.library_cats.lock_ok().contains(&category);
        let job = Arc::new(Mutex::new(Job {
            origin: origin.to_string(),
            nzo_id: nzo_id.clone(),
            name: stem,
            nzb_sha: nzb_sha(nzb_bytes),
            finalizing: false,
            nzb_path: spool_path,
            category: category.clone(),
            state: JobState::Queued,
            total_bytes,
            out_dir,
            // TODO 317: recorded, never re-derived. See `Job::write_through`.
            write_through: write_through_root.is_some(),
            fail_message: String::new(),
            fail_code: None,
            fail_detail: String::new(),
            finished_at: None,
            finished_unix: None,
            // SAB priority -2 means "add paused", -100 means "the default".
            priority: enqueue_priority(priority, duplicate),
            paused: duplicate || priority == -2,
            queued_at: Some(Instant::now()),
            queued_unix: Some(unix_now()),
            idle_at_add: runner_idle,
            // Stamped by `enqueue_fetched` when the NZB came from a URL
            // and the indexer sent an X-DNZB-Failure header.
            failure_link: String::new(),
            failure_host: String::new(),
            failure_https: false,
            failure_depth: 0,
            // TODO 280: every add starts at 0. The refeed path stamps
            // the child's depth after this returns, exactly as
            // `enqueue_fetched` stamps a failure-link replacement's.
            refeed_depth: 0,
            identify: String::new(),
            media: None,
            postproc_secs: 0.0,
            whyslow: None,
            log_mark: 0,
            log_end: 0,
            media_rejudge: false,
            retries: 0,
            dupe_key: key,
            held_for: held_for_of(collision.as_ref(), hold_for),
            library,
            insurance: self.insurance_at_add(priority, duplicate || hold_for.is_some(), library),
            insurance_attempts: 0,
            insurance_note: String::new(),
            fetched: false,
            tombstone: false,
            hidden: false,
            relocating: 0,
            del_on_drop: false,
            delete_status: String::new(),
            suspended: false,
            downloaded_bytes: 0,
            elapsed_secs: 0.0,
            deferred: false,
            defer_reason: String::new(),
            defer_at: 0,
            defer_count: 0,
            demote: false,
            bad_blocks: None,
            verify_blocks: 0,
            tv_sort,
            smart_rule,
            filed: false,
            filed_suffix: None,
            filed_title: None,
            filed_base: None,
            password,
            password_required: false,
            eat_volumes_ok: false,
            zip_packed,
            unpack_blocked_by: String::new(),
            alt_from: String::new(),
            alt_from_name: String::new(),
            alt_why: String::new(),
            alt_to_name: String::new(),
            // §310: the heal road stamps this after the add - see
            // `heal::Daemon::heal_start`.
            heal_dir: PathBuf::new(),
            move_split: String::new(),
            move_failed: String::new(),
            move_attempts: 0,
            move_pending: false,
            early_published: Vec::new(),
            early_refused: Default::default(),
            // A fresh job has never crossed between the two stores.
            move_seq: 0,
            archive_shape: String::new(),
            resume_route: None,
            inner_crc: 0,
            identity_name: String::new(),
            identity_imdb: String::new(),
            identity_src: String::new(),
            auto_retry_at: None,
            auto_retry_why: None,
            pp_params: Vec::new(),
            sab_pp: hook_pp,
            script_override: hook_script,
            replaces,
            // §77: filled in by the health prober on its next idle tick.
            // Deliberately not probed inline here - enqueue is called
            // from the HTTP handler, the watch folder and the RSS
            // poller, and none of them may block on a network round trip
            // to every configured server.
            health: None,
            // Counted at completion by the post-processing sweeps.
            cleaned_files: 0,
            cleaned_par2: 0,
            cleaned_trash: false,
        }));
        // The row exists; the only question left is its fate, and the
        // transaction guard goes with it. Every arm from here either
        // hands `publish` to `file_never_queued` or drops it after the
        // queue push, so `enqueue_as` cannot hold it past this call.
        self.publish_or_refuse(
            job,
            publish,
            AddPending {
                nzo_id,
                pairing_name,
                category,
                origin,
                priority,
                total_bytes,
                duplicate,
                hold_for,
                spare_spool,
                collision,
                hook_reject,
                dupe_action,
                post_ids,
            },
        )
    }

    /// The fate of a row that has been BUILT but not yet published: file
    /// it to history as Failed, refuse it outright, or push it onto the
    /// queue. Lifted out of `enqueue_as` under the size gate (TODO 106),
    /// and the seam is where it is because the `add_lock` guard changes
    /// hands there: every arm below either hands `publish` to
    /// `file_never_queued` or drops it after the queue push, so the
    /// guard can be MOVED into this method and the borrow checker holds
    /// the "one transaction, one owner" rule that used to be a comment.
    ///
    /// What may cross the seam, in both directions:
    ///
    /// * Nothing above it may depend on the outcome - `enqueue_as` has
    ///   settled the identity, the directory, the duplicate question and
    ///   the row itself, and its last statement is this call.
    /// * Nothing here may RE-DECIDE any of that. The one thing it does
    ///   re-ask is whether the chosen collision (and a spare's target)
    ///   still exists, and that is deliberate: those are the two reads
    ///   `add_lock` does not serialize against, so they are re-asked
    ///   under the queue lock and nowhere else.
    /// * The two refusal arms must stay ABOVE the queue critical
    ///   section. Both are "this row never queues", and a row that has
    ///   been pushed cannot be filed to history without going through
    ///   the delete path instead.
    ///
    pub fn publish_or_refuse(
        &self,
        job: Arc<Mutex<Job>>,
        publish: std::sync::MutexGuard<'_, ()>,
        pending: AddPending<'_>,
    ) -> Result<Enqueued> {
        let AddPending {
            nzo_id,
            pairing_name,
            category,
            origin,
            priority,
            total_bytes,
            mut duplicate,
            hold_for,
            spare_spool,
            collision,
            hook_reject,
            dupe_action,
            post_ids,
        } = pending;
        // §129 4a: a pre-queue REJECT files to history as Failed with
        // the reason - the dupe_action="fail" shape verbatim, so the
        // *arr contract (a failed grab means "search for another
        // release") and retry-from-history both hold. The spool .nzb
        // stays; a retry does not re-run the hook (SAB semantics).
        //
        // A SPARE files nothing at all - see the `hold_for` arm below,
        // and `spare::Daemon::hold_spares_with` for why §4b's junk-queue
        // class is the thing §282 must not resurrect by a new road.
        if let Some(why) = hook_reject {
            if hold_for.is_some() {
                drop(publish);
                if let Some(p) = &spare_spool {
                    // `drop_spool`, not a swallowed `remove_file`: the
                    // refused spare has no record anywhere, so a copy
                    // whose unlink fails is re-adopted at the next start
                    // (Codex sweep 24 Aug, F-04).
                    drop_spool(p);
                }
                anyhow::bail!("the pre-queue script refused this spare: {why}");
            }
            info!(
                target: "prequeue",
                "{nzo_id} filed to history as FAILED - rejected by the pre-queue \
                 script"
            );
            return Ok(self.file_never_queued(&job, nzo_id, why, publish));
        }
        // §129 2d, dupe_action = "fail": the job never queues - it files
        // straight to history as Failed, through the same seam every
        // history mutation uses (history_upsert beside save_queue), and
        // emits the job.failed lifecycle event a real failure would.
        // Retry from history remains the escape hatch: the spool .nzb
        // is in place and retry asks the duplicates question afresh.
        if let Some(c) = &collision
            && dupe_action == "fail"
            // Same as the discard arm: filing a valid add to history as
            // Failed against a vanished original tells the *arr that
            // submitted it to go and find another release, for a title
            // nothing is downloading.
            && self.dupe_collision_stands(c)
        {
            let why = format!(
                "duplicate of {:?} ({}) - failed; the duplicates setting decides this",
                c.name, c.where_
            );
            info!(
                target: "queue",
                "{nzo_id} filed to history as FAILED - duplicate of {} ({}), and \
                 duplicates are set to fail",
                c.name, c.nzo_id
            );
            return Ok(self.file_never_queued(&job, nzo_id, why, publish));
        }
        // §129 4a: the add joins the event ring and the queue in one
        // step, announced BEFORE the job is visible to anything that
        // could start it. Every add path funnels through here, so this
        // one emit covers all fourteen of them.
        //
        // The queue lock is what makes the ordering a guarantee rather
        // than a race: `pick_job` scans under this same lock, so a
        // runner that sees this job necessarily acquired the lock after
        // we released it, and its job.started is therefore behind our
        // job.added on the ring. Emitting AFTER the push instead let a
        // fast pick outrun a slow `save_queue` - a 16-way-loaded box put
        // job.started on the ring at seq 1, 54 ms ahead of the job.added
        // for the same nzo_id, which is a webhook consumer watching a
        // job start before it exists. The idle latch re-arms inside the
        // same critical section for the same reason - and it must be
        // INSIDE, not merely before it (Codex sweep 14 Aug M3): stored
        // ahead of the lock, a notifier that had already scanned the
        // empty queue could take its false-to-true CAS after this add
        // published, emitting queue.idle over a runnable job and
        // leaving the latch set - so if a global pause kept the job
        // from the pick re-arm, its own genuine idle edge was
        // swallowed too. Under the lock, the notifier either finishes
        // before this add (its idle predates the job, correctly) or
        // scans after it and sees the job.
        //
        // Deadlock-safe by lock order: the ring, the webhook channel and
        // the target list are leaves taken under the queue lock, and no
        // path takes them the other way round. The cost is that the
        // event now precedes `save_queue` rather than following it, so a
        // crash in that window loses a job a consumer was told about -
        // the same window every other reader of the add already had,
        // since the queue was live to the API at exactly this point.
        let mut orphan_spare = false;
        // §7a: the row this add publishes, for the O(1) durable write
        // below. `None` when the add bailed as an orphan spare and
        // nothing was queued at all.
        let mut published_row: Option<Arc<Mutex<Job>>> = None;
        {
            let mut q = self.queue.lock_ok();
            // TODO 282 item 5: a spare's target must still be here, and
            // the answer when it is not is to REFUSE the add - not to
            // queue it normally, which is what the collision arm below
            // does. The two differ because the outcomes differ: an add
            // that stopped being a duplicate is a download the user
            // asked for, while a spare whose job is gone is a download
            // NOBODY asked for, and letting it queue is the one thing a
            // spare may never do (see `spare::Daemon::hold_spares_with`).
            // ...or (§284) a history record still being offered another
            // copy - see `Daemon::parked_spare_owner`, which carries the
            // argument and the lock note.
            if let Some(target) = hold_for {
                orphan_spare = !q.iter().any(|j| j.lock_ok().nzo_id == target)
                    && !self.parked_spare_owner(target);
            }
            // Last look at the collision, under the very lock this add
            // publishes with. `add_lock` serializes adds against each
            // other, but a delete takes only the queue (or history)
            // lock, so the original chosen above can be gone by now -
            // and a hold outlives its original: `held_for` is released
            // by park promotion, which runs when the original FAILS, so
            // a job that no longer exists never releases anything. The
            // alternative would sit paused at Duplicate priority for
            // good, pointing at an id nothing will ever park.
            //
            // Deliberately NOT a re-run of `dupe_collision`: its alias
            // arm parses release names and asks the index for show ids,
            // and running that under the queue lock stalls every API
            // request behind it (the #38 follow-up). Only the CHOSEN
            // original is re-checked. If a second, still-live original
            // existed and this one was the one deleted, the add queues
            // normally - the pre-M14f outcome, and the mild direction
            // to be wrong in next to holding a job against nothing.
            //
            // A deleted original does NOT release a hold that was
            // already published: that stays deliberate (`park` refuses
            // to promote a tombstone - the user cancelled that title on
            // purpose). This is only about an add that was never a
            // duplicate by the time it landed.
            if let Some(c) = &collision {
                let stands = if c.where_ == "queue" {
                    q.iter().any(|j| j.lock_ok().nzo_id == c.nzo_id)
                } else {
                    // The one nested acquisition here, and only on
                    // the history arm: a scan of a few ids, no I/O. No
                    // path in serve/ takes the history lock and then
                    // the queue lock - every reader of both takes them
                    // one at a time - so queue -> history cannot ABBA.
                    self.history.lock_ok().iter().any(|j| {
                        let g = j.lock_ok();
                        g.nzo_id == c.nzo_id && g.state == JobState::Completed
                    })
                };
                if !stands {
                    duplicate = false;
                    {
                        let mut g = job.lock_ok();
                        g.priority = enqueue_priority(priority, false);
                        g.paused = priority == -2;
                        g.held_for.clear();
                        // No longer held: the add-time insurance stamp applies.
                        g.insurance = self.insurance_at_add(priority, false, g.library);
                    }
                    info!(
                        target: "queue",
                        "{nzo_id}: {} ({}) is gone - it was deleted while this add \
                         was being admitted, so the add queues normally rather \
                         than holding against a record nothing can fail",
                        c.name, c.nzo_id
                    );
                }
            }
            if !orphan_spare {
                self.queue_idle_latch.store(false, Ordering::Relaxed);
                self.life_emit(
                    "job.added",
                    json!({
                        "nzo_id": nzo_id,
                        "name": pairing_name,
                        "category": category,
                        "priority": enqueue_priority(priority, duplicate),
                        "origin": origin,
                        "total_bytes": total_bytes,
                        "duplicate": duplicate,
                        "paused": duplicate || priority == -2,
                    }),
                );
                // The memo §292's arm reads, primed from the NZB this
                // add already parsed: a row admitted here never costs a
                // later add a spool read. Under the queue lock, which is
                // the order that arm takes the two in.
                self.post_ids
                    .lock_ok()
                    .insert(nzo_id.clone(), Arc::clone(&post_ids));
                published_row = Some(Arc::clone(&job));
                q.push_back(job);
            }
        }
        // Published: the directory and the identity are now visible to
        // every other adder.
        drop(publish);
        if orphan_spare {
            // Never queued, so nothing names the spool copy - and
            // `recover_orphaned_spool` adopts exactly that shape at the
            // next start. `drop_spool` so a refused unlink is masked
            // rather than left adoptable (Codex sweep 24 Aug, F-04).
            if let Some(p) = &spare_spool {
                drop_spool(p);
            }
            anyhow::bail!(
                "the job this spare was held for is gone - it was deleted while the \
                 spare was being admitted"
            );
        }
        if duplicate {
            info!(target: "queue", "added {nzo_id} as ALTERNATIVE (duplicate held)");
        } else {
            info!(target: "queue", "added {nzo_id}");
        }
        // §7a: ONE appended line plus its fsync, at any queue size - the
        // add mutates the job it is adding and nothing else, so there is
        // nothing for the full diff scan to find. Still synchronous and
        // still durable-before-return: `Enqueued::durable` is what the
        // watch poller reads before it deletes the user's original .nzb
        // (the 27 Aug C09 fix), and nothing here moves onto the debounce.
        // See `Daemon::save_queue_row` for what makes naming the row safe
        // and what happens when a later edit here stops being true.
        let durable = match &published_row {
            Some(j) => self.save_queue_row(j),
            None => self.save_queue(),
        };
        // The notification is O(1) and may coalesce. The worker scans
        // retained records, so no XML parse or index wait belongs here.
        #[cfg(feature = "indexer")]
        self.seed_harvest_wake.notify_one();
        Ok(self.enqueued(nzo_id, durable))
    }

    /// File an add that never reached the queue into history as Failed,
    /// and answer its caller.
    ///
    /// Shared by the two arms that do this - a pre-queue REJECT (§129 4a)
    /// and `dupe_action = "fail"` (§129 2d) - because the ORDER of the
    /// two writes is the whole subject, and an invariant written out
    /// twice is one that drifts on the copy nobody edited.
    ///
    /// §158.7: the DESTINATION store first, then the queue snapshot.
    /// This job was never queued, so `save_queue` writes a queue.json
    /// that does not carry it either way - which is exactly what made the
    /// old order lossy rather than merely odd. A kill (or an ENOSPC)
    /// between the two writes left the record in NEITHER file: queue.json
    /// never had it and history.jsonl did not have it yet, so the spooled
    /// .nzb sat on disk named by no record anywhere and the *arr that
    /// submitted it was never told the grab failed. Ordered this way the
    /// torn state is "in history only", which is the whole truth for a
    /// job that never reached the queue. Nothing here depends on the
    /// queue write running first; all it carries of this job is the
    /// id-allocator bump, and the restore's wall-clock floor already
    /// covers an allocator bump that never landed.
    ///
    /// Takes the `add_lock` guard by value: the history push belongs
    /// inside the add transaction and the two store writes deliberately
    /// do not, so the drop point is part of what this method is for.
    pub fn file_never_queued(
        &self,
        job: &Arc<Mutex<Job>>,
        nzo_id: String,
        why: String,
        publish: std::sync::MutexGuard<'_, ()>,
    ) -> Enqueued {
        {
            let mut g = job.lock_ok();
            g.state = JobState::Failed;
            g.paused = false;
            g.priority = 0;
            g.fail_message = why;
            g.finished_at = Some(Instant::now());
            g.finished_unix = Some(unix_now());
        }
        self.history.lock_ok().push(job.clone());
        drop(publish);
        let durable = self.history_upsert(std::slice::from_ref(job));
        self.save_queue();
        #[cfg(feature = "indexer")]
        self.seed_harvest_wake.notify_one();
        self.life_emit_parked(job);
        self.history_enforce_retention();
        self.enqueued(nzo_id, durable)
    }

    /// The one place an undurable accept is said out loud, so a caller
    /// that has nothing to do about it need not repeat the warning.
    pub fn enqueued(&self, nzo_id: String, durable: bool) -> Enqueued {
        if !durable {
            warn!(
                target: "queue",
                "{nzo_id} accepted, but its record could not be saved to {} - the job \
                 runs from memory, and its spooled .nzb will be re-adopted at the \
                 next start if the queue is never saved again before then",
                self.spool.display()
            );
        }
        Enqueued { nzo_id, durable }
    }
}

impl Daemon {
    /// TODO 218: pick a category for an add that named none, from what
    /// the NZB carries. Two sources, in order:
    ///
    /// 1. `<meta type="category">` equal (case-insensitively) to a known
    ///    category's name - zero configuration, the common case for the
    ///    indexers that write the tag at all.
    /// 2. Each category's `groups` patterns (`CatMeta::groups`,
    ///    SABnzbd's "Indexer Categories / Groups"), tried against every
    ///    meta category value and then every newsgroup, in the
    ///    configured category order so the answer is stable.
    ///
    /// Returns the category and a short reason for the log. None when
    /// nothing matches - the add then lands uncategorised, exactly as
    /// before this existed.
    pub(crate) fn infer_category(&self, nzb: &nzbkit::nzb::Nzb) -> Option<(String, String)> {
        let metas: Vec<&str> = nzb
            .meta
            .iter()
            .filter(|(k, _)| k == "category")
            .map(|(_, v)| v.trim())
            .filter(|v| !v.is_empty())
            .collect();
        let cats: Vec<String> = self
            .cats
            .lock_ok()
            .iter()
            .filter(|c| *c != "*")
            .cloned()
            .collect();
        for m in &metas {
            if let Some(c) = cats.iter().find(|c| c.eq_ignore_ascii_case(m)) {
                return Some((c.clone(), format!("NZB meta category {m:?}")));
            }
        }
        let mut groups: Vec<&str> = Vec::new();
        for f in &nzb.files {
            for g in &f.groups {
                if !groups.contains(&g.as_str()) {
                    groups.push(g);
                }
            }
        }
        let meta = self.cat_meta.lock_ok();
        for c in &cats {
            let Some(m) = meta.get(c) else { continue };
            for pat in m.groups.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                if let Some(v) = metas.iter().find(|v| nzbkit::categories::pat_match(pat, v)) {
                    return Some((c.clone(), format!("pattern {pat:?} on meta category {v:?}")));
                }
                if let Some(g) = groups
                    .iter()
                    .find(|g| nzbkit::categories::pat_match(pat, g))
                {
                    return Some((c.clone(), format!("pattern {pat:?} on group {g:?}")));
                }
            }
        }
        None
    }

    /// Everything an add settles about ITSELF, before a byte is spooled
    /// and before the add lock: the display name, the archive password
    /// carried in it, the category, and the two Smart Folders answers
    /// that ride with them. Out of `enqueue` bodily under the size gate
    /// (TODO 106) - nothing in here touches the queue, the spool or the
    /// add lock, which is why it comes out whole.
    fn resolve_add_identity(
        &self,
        nzb: &nzbkit::nzb::Nzb,
        nzo_id: &str,
        name: &str,
        category: &str,
        password: Option<&str>,
    ) -> AddIdentity {
        let mut stem = name.trim_end_matches(".nzb").to_string();
        // Archive password: an explicit param (SAB API) wins; the
        // `Name{{password}}` convention comes OFF the display name either
        // way (and the output folder - never leak a password into the
        // filesystem); the NZB's own <meta type="password"> is the
        // fallback (the engine would find it again at download time -
        // capturing it here surfaces has_password to the UI).
        let mut password: Option<String> = password.filter(|p| !p.is_empty()).map(str::to_string);
        // All three name conventions - {{pw}}, password=pw, {pw} - are
        // recognized and stripped (crate::smart::name_password).
        if let Some((pw, clean)) = crate::smart::name_password(&stem) {
            password.get_or_insert(pw);
            stem = clean;
        }
        if password.is_none() {
            password = nzb.password().map(str::to_string);
        }
        // Zip-packed post, spotted from the NZB's own file list before a
        // single byte is fetched. We cannot unpack one, so saying it here
        // costs the user a click instead of a download. Name-shaped
        // evidence only - an obfuscated container has no name to read, and
        // guessing from a subject line would cry wolf on ordinary posts.
        let zip_packed = nzb
            .files
            .iter()
            .filter_map(|f| f.filename_hint())
            .any(nzbkit::zip::name_is_zip_shaped);
        if zip_packed {
            info!(
                target: "queue",
                "{nzo_id} looks zip-packed - store and deflate zips unpack \
                 natively, an encrypted one too when the job has a password; an \
                 exotic codec will arrive packed"
            );
        }
        let total_bytes = nzb.eager_bytes();
        // TODO 218: an add that names no category takes one from the NZB
        // itself - its `<meta type="category">` or its newsgroups -
        // before Smart Folders get a say. An explicit `cat=` is never
        // second-guessed, and a Smart Folder rule still overrides both.
        let mut category = category.to_string();
        if category.trim().is_empty()
            && let Some((c, how)) = self.infer_category(nzb)
        {
            info!(target: "smart", "{stem:?} → category {c:?} ({how})");
            category = c;
        }
        // M23 Smart Folders: the first matching rule can retarget the
        // category (= out_root subfolder) and request TV filing.
        let mut tv_sort = false;
        let mut smart_rule = String::new();
        // Scoped so the rule-list lock is dropped the moment the two
        // reads below are done with it, as it was before the F5 note
        // joined them under one guard.
        {
            let rules = self.smart_folders.lock_ok();
            // F5: `total_bytes` is `Nzb::eager_bytes`, which is 0 when the
            // manifest declared no `bytes=` at all - a shape this repo
            // accepts on purpose, and whose own parser comment says "0
            // posted bytes means unknown, not zero". `Rule::matches` cannot
            // tell that 0 from a measurement, so every `min_size` rule
            // declines the job and every `max_size` rule waves it through,
            // and the row then files under whatever is left with nothing
            // anywhere saying why. Say it here. NOT a refusal and not a
            // substituted figure: which answer a size-gated rule SHOULD
            // give when the size is unknown is the open product question
            // written up in the zero-declared-bytes handoff (claim
            // `nzb-zero-bytes-downstream`), and guessing it in passing is
            // how a routing rule starts lying.
            // Conditional on there BEING such a rule, because on the common
            // list (no size bounds anywhere) the unknown costs the routing
            // nothing and a line per add would be noise.
            let gated = crate::smart::size_gated(&rules);
            if total_bytes == 0 && gated > 0 {
                warn!(
                    target: "smart",
                    "{stem:?} declares no byte counts, so its size is unknown rather \
                     than zero - the {gated} Smart Folder rule(s) with a size bound \
                     are judged against that 0 and will not do what you meant"
                );
            }
            if let Some(r) = crate::smart::first_match(&rules, &stem, total_bytes) {
                if !r.category.is_empty() {
                    category = r.category.clone();
                }
                tv_sort = r.tv_sort;
                // Kept on the job: "why is this in Films?" is answerable only
                // by the rule that decided it, and the rule list is editable.
                smart_rule = r.name.clone();
                info!(
                    target: "smart",
                    "rule {:?} matched {stem:?} → category {:?}{}",
                    r.name,
                    category,
                    if tv_sort { " + TV filing" } else { "" }
                );
            }
        }
        // `category` (the `cat=` request param) and `stem` (from the NZB
        // name / `nzbname`) are untrusted and must never escape out_root:
        // an absolute component replaces the base, and `..` is resolved by
        // the OS at create/remove time - a crafted name plus a delete call
        // could otherwise write to, or recursively delete, an arbitrary
        // directory (bug sweep). Force each to a single contained path
        // component before it ever touches the filesystem.
        if !category.is_empty() {
            category = nzbkit::disk::sanitize_filename(&category);
        }
        AddIdentity {
            stem,
            password,
            category,
            total_bytes,
            zip_packed,
            tv_sort,
            smart_rule,
        }
    }

    /// §129 4a: what the pre-queue hook answered. `stem`, `category` and
    /// `priority` are amended IN PLACE because rewriting them is the
    /// hook's whole contract; the three fields the caller cannot derive
    /// come back in the verdict. Out of `enqueue` under the size gate
    /// (TODO 106).
    fn consult_pre_queue(
        &self,
        nzb: &nzbkit::nzb::Nzb,
        nzo_id: &str,
        origin: &str,
        pp: Option<i64>,
        total_bytes: u64,
        stem: &mut String,
        category: &mut String,
        priority: &mut i32,
    ) -> HookVerdict {
        // §129 4a: consult the pre-queue hook - rename, recategorize,
        // reprioritize, pick pp/script, or reject - before anything is
        // published. Before the spool write (a rename names the spool
        // file), before the add lock (a slow script must never
        // serialize concurrent adds), and demoted via blocking_db
        // (enqueue is reachable from tokio tasks). Fail-open by
        // contract - see prequeue.rs.
        let mut hook_pp: Option<i64> = None;
        let mut hook_script = String::new();
        let mut hook_reject: Option<String> = None;
        if self.pre_queue_script.lock_ok().is_some() {
            let mut groups: Vec<String> = Vec::new();
            for f in &nzb.files {
                for g in &f.groups {
                    if !groups.contains(g) {
                        groups.push(g.clone());
                    }
                }
            }
            let verdict = crate::persist::blocking_db(|| {
                self.run_pre_queue(
                    nzo_id,
                    origin,
                    stem,
                    pp,
                    category,
                    *priority,
                    total_bytes,
                    &groups,
                )
            });
            if let Some(v) = verdict {
                if !v.accept {
                    hook_reject = Some("rejected by the pre-queue script".to_string());
                }
                if let Some(n) = v.name {
                    *stem = n;
                }
                if let Some(c) = v.category {
                    *category = nzbkit::disk::sanitize_filename(&c);
                }
                if let Some(p) = v.priority {
                    // The hook's priority is an EXPLICIT one: it also
                    // suppresses the category default fill below.
                    *priority = p;
                }
                hook_pp = v.pp;
                hook_script = v.script.unwrap_or_default();
            }
        }
        HookVerdict {
            pp: hook_pp,
            script: hook_script,
            reject: hook_reject,
        }
    }
}

/// WHICH row a new job is an alternative OF - see `Job::held_for`.
///
/// A free function only because `enqueue_as` was at 496 of the size
/// gate's 500-line ceiling on 26 Aug 2026, and this is the one part of
/// its Job literal with a body rather than a value. The collision the dupe check just found wins;
/// an explicit `hold_for=` on the add is the fallback.
fn held_for_of(collision: Option<&DupeCollision>, hold_for: Option<&str>) -> String {
    collision
        .map(|c| c.nzo_id.clone())
        .or_else(|| hold_for.map(str::to_string))
        .unwrap_or_default()
}
