//! `Daemon::enqueue` - the whole add path from NZB bytes to a queued (or
//! parked) job - moved out bodily under the size gate (TODO 106). A child
//! module of `daemon`, same shape as daemon_index, so `Daemon`'s private
//! fields and daemon.rs's private types stay in scope exactly as they
//! were inline. `super` now means `daemon`, not `serve`, so the method's
//! old pub(super) is spelled pub(in crate::serve) to keep its original
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
pub(in crate::serve) static DUPE_ADMIT_BARRIER: Mutex<
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

impl Daemon {
    /// `pp` is the post-processing mode the CALLER requested (0-3, None
    /// = none named). The pre-queue hook receives it - SAB's contract
    /// hands the script the requested pp - but it is RECORDED on the
    /// job afterwards by `record_add_params`, which fills only what the
    /// hook did not already answer.
    #[expect(clippy::too_many_arguments)]
    pub(in crate::serve) fn enqueue(
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
            None, nzb_bytes, name, category, priority, pp, password, origin, allow_dupe, None,
        )
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
    pub(in crate::serve) fn enqueue_as(
        &self,
        id: Option<&str>,
        nzb_bytes: &[u8],
        name: &str,
        category: &str,
        priority: i32,
        pp: Option<i64>,
        password: Option<&str>,
        origin: &str,
        allow_dupe: bool,
        hold_for: Option<&str>,
    ) -> Result<Enqueued> {
        let nzo_id = match id {
            Some(id) => id.to_string(),
            None => format!(
                "SABnzbd_nzo_nzbfast{}",
                self.next_id.fetch_add(1, Ordering::Relaxed)
            ),
        };
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
        crate::persist::write_atomic(&spool_path, nzb_bytes)?;
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
        let dir_stem = nzbkit::disk::sanitize_filename(&stem);
        let base_out_dir = self.base_out_dir(&category, &dir_stem);
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
        // From here to the queue push is one transaction. Choosing a
        // directory and deciding "not a duplicate" are both reads of
        // state this job is about to change, and neither is published
        // until the push, so without the lock two concurrent adds of one
        // release agree on everything and then collide.
        let publish = self.add_lock.lock_ok();
        // dir_claim stats the output volume (`p.exists()`), which can be
        // a network share, and enqueue is reachable from tokio tasks
        // (watchlist watcher, RSS poller) - demote the worker around it.
        let (out_dir, replaces) = crate::persist::blocking_db(|| {
            choose_out_dir(&base_out_dir, &dir_stem, &|p| self.dir_claim(p))
        });
        self.register_cat(&category);
        // M14f duplicate check: same identity already queued, running, or
        // successfully completed → hold this one as an ALTERNATIVE
        // (paused, Duplicate priority). It auto-promotes if the original
        // fails; PROPERs always download.
        //
        // `allow_dupe` is the user having been ASKED and said yes (the
        // wall's confirmation). It suppresses the hold, not the key: the
        // job still carries its identity, so everything downstream that
        // reasons about duplicates keeps working.
        let key = dupe_key(&stem);
        let collision = if allow_dupe || hold_for.is_some() {
            None
        } else {
            self.dupe_collision(&stem)
        };
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
        // publish, and the queue critical section below re-asks. An
        // explicit `hold_for` is a duplicate by instruction, and the same
        // critical section re-asks whether its target is still there.
        let mut duplicate = collision.is_some() || hold_for.is_some();
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
            // leave it behind.
            let _ = std::fs::remove_file(&spool_path);
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
        // C4-4: the accepted NZB is a (name, payload message-id set)
        // pairing for the identity substrate - recorded after the job
        // publishes, below.
        let pairing_name = stem.clone();
        // The two arms that refuse a SPARE have to unlink its spool copy,
        // and by then `spool_path` has moved onto the job. Cloned only
        // when there is a spare in the first place, so an ordinary add
        // pays nothing for it.
        let spare_spool = hold_for.map(|_| spool_path.clone());
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
            fail_message: String::new(),
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
            // WHICH row this one is an alternative OF - see `Job::held_for`.
            held_for: collision
                .as_ref()
                .map(|c| c.nzo_id.clone())
                .or_else(|| hold_for.map(str::to_string))
                .unwrap_or_default(),
            library: self.library_cats.lock_ok().contains(&category),
            fetched: false,
            tombstone: false,
            del_on_drop: false,
            delete_status: String::new(),
            suspended: false,
            downloaded_bytes: 0,
            elapsed_secs: 0.0,
            deferred: false,
            defer_reason: String::new(),
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
            move_split: String::new(),
            move_failed: String::new(),
            move_attempts: 0,
            move_pending: false,
            // A fresh job has never crossed between the two stores.
            move_seq: 0,
            archive_shape: String::new(),
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
                    let _ = std::fs::remove_file(p);
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
            if let Some(target) = hold_for {
                orphan_spare = !q.iter().any(|j| j.lock_ok().nzo_id == target);
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
                q.push_back(job);
            }
        }
        // Published: the directory and the identity are now visible to
        // every other adder.
        drop(publish);
        if orphan_spare {
            // Never queued, so nothing names the spool copy - and
            // `recover_orphaned_spool` adopts exactly that shape at the
            // next start.
            if let Some(p) = &spare_spool {
                let _ = std::fs::remove_file(p);
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
        let durable = self.save_queue();
        // After the add is published and saved, never on its critical
        // path: a contended index costs this pairing, not the add.
        self.record_nzb_pairing(&pairing_name, origin, &nzb);
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
    fn file_never_queued(
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
        self.life_emit_parked(job);
        self.history_enforce_retention();
        self.enqueued(nzo_id, durable)
    }

    /// The one place an undurable accept is said out loud, so a caller
    /// that has nothing to do about it need not repeat the warning.
    fn enqueued(&self, nzo_id: String, durable: bool) -> Enqueued {
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
    pub(in crate::serve) fn infer_category(
        &self,
        nzb: &nzbkit::nzb::Nzb,
    ) -> Option<(String, String)> {
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
        if let Some(r) =
            crate::smart::first_match(&self.smart_folders.lock_ok(), &stem, total_bytes)
        {
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
        // contract - see serve/prequeue.rs.
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
