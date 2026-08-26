//! The download runner's own preamble and postamble (TODO 106 code motion
//! out of `spawn_download_worker`).
//!
//! Three self-contained stretches of that loop, in the order it runs them:
//! `download_guards` decides whether a pick may happen at all (and sleeps
//! on the caller's behalf when it may not), `reset_hub_for_job` hands the
//! shared hub over from the previous job to this one, and `settle_job_tail`
//! reads the final per-job figures at network-drain, before the next
//! iteration is free to zero them.
//!
//! A child of `tasks`, so `Daemon`'s and the module's private items stay
//! in scope; `pub(super)` here means "pub in tasks", which is every call
//! site there is.

use super::*;

/// Everything the loop still needs after the fetch has drained, read
/// while the figures are still THIS job's.
pub(super) struct JobTail {
    pub(super) dl_bytes: u64,
    pub(super) on_disk_bytes: u64,
    pub(super) verifier: Option<Arc<nzbkit::live::LiveVerifier>>,
    pub(super) shaper: Option<Arc<nzbkit::extract::Extractor>>,
    /// M29 oracle samples, drained here and ingested on the lane. The
    /// DRAIN has to happen on the runner (the hub's sink belongs to
    /// this job, and the next job installs a fresh one); the INGEST
    /// must not, because it takes the index write mutex and this loop
    /// is the runner - see `settle_job_tail`.
    #[cfg(feature = "indexer")]
    pub(super) oracle_samples: Vec<nzbkit::oracle::Sample>,
}

/// TODO §156 item 7: the no-servers guard's config read, kept off the
/// runner.
///
/// `Config::load` is a `std::fs::read`, and this loop IS the runner, so
/// reading it inline made the guard the very hazard the disk probe below
/// documents and defends against, about twice a second forever: a config
/// on a dropped SMB or NFS mount blocked every pick with no hold
/// published, which is the worst shape there is - stalled and silent.
///
/// Three fixes were on the table; this is the disk probe's, for the
/// disk probe's reasons. Caching against mtime does not fix it (`stat`
/// hangs on a dead mount exactly as `read` does, so the runner still
/// blocks), and having the config layer publish its own changes is a
/// watcher on every config reader in the daemon, which is a different
/// piece of work with a much wider blast radius than one guard. Reading
/// on the blocking pool under a timeout is what the neighbour already
/// does, is local to this guard, and turns the hang into the answer the
/// ladder already knows how to handle.
#[derive(Default)]
pub(super) struct ServerProbe {
    /// At most one outstanding read, re-awaited next pass rather than
    /// stacking a fresh blocked thread per pass - the disk probe's rule,
    /// for the disk probe's reason.
    inflight: Option<tokio::task::JoinHandle<(ServerVerdict, Option<nzbkit::config::Config>)>>,
    /// The last answer that actually came back.
    last: ServerVerdict,
    /// …and the config that answer was read from, kept so the pick that
    /// follows never takes a SECOND, unbounded read on the runner. See
    /// `server_verdict` for what that read cost.
    cfg: Option<Arc<nzbkit::config::Config>>,
}

impl ServerProbe {
    /// The freshest verdict there is, without ever blocking the runner.
    ///
    /// A probe that does not answer within the timeout leaves `last`
    /// ALONE rather than reporting `Unknown`: "we did not hear back" is
    /// not news about the config, and treating it as news would take a
    /// live hold down and announce a server that nobody has added. The
    /// hold therefore survives a config mount dying under it, which is
    /// the honest reading - the queue is still not going anywhere.
    ///
    /// Before any probe has answered `last` is `Unknown`, so a daemon
    /// whose config hangs from the first pass stands the guard down and
    /// lets the download report the real error, rather than holding the
    /// queue on a guess. On a healthy filesystem the read lands in
    /// microseconds and the first pass has its answer, so the hold's
    /// timing is what it always was.
    pub(super) async fn verdict(&mut self, config: &std::path::Path) -> ServerVerdict {
        let mut probe = self.inflight.take().unwrap_or_else(|| {
            let path = config.to_path_buf();
            tokio::task::spawn_blocking(move || server_verdict(&path))
        });
        match tokio::time::timeout(std::time::Duration::from_secs(2), &mut probe).await {
            Ok(Ok((v, cfg))) => {
                self.last = v;
                // A read that came back but could not be parsed leaves
                // the last GOOD snapshot alone, exactly as it leaves the
                // last good verdict alone: "we could not read it" is not
                // news about the server list.
                if let Some(cfg) = cfg {
                    self.cfg = Some(Arc::new(cfg));
                }
            }
            // A panicked probe is no answer either; drop the handle and
            // start a fresh read next pass.
            Ok(Err(_)) => {}
            Err(_) => self.inflight = Some(probe),
        }
        self.last
    }

    /// The config behind the freshest verdict, for the pick that
    /// follows. `None` until a probe has answered once.
    pub(super) fn config(&self) -> Option<Arc<nzbkit::config::Config>> {
        self.cfg.clone()
    }
}

/// Publish a queue hold - the store first, the revision second.
///
/// §156 item 6: under a hold nothing is transferring, so the revision
/// is the ONLY thing that can move the §129 1b poll's payload, and
/// without a bump an open dashboard never draws the banner. On the
/// TRANSITION only (`fresh`): the hold row refreshes every pass and
/// bumping there would put the whole queue back on the wire every few
/// seconds.
///
/// The ORDER is the load-bearing part (Codex sweep I, 13 Aug 2026). A
/// poll landing between a bump and the store sees the new revision with
/// the old hold, adopts that revision, and - because the later store
/// carries no second bump - every matching poll after it omits the
/// queue payload until some other state change moves the revision. The
/// banner the bump exists to draw is then never drawn at all. Storing
/// first makes the revision a promise the state has already kept.
fn publish_hold(d: &Arc<Daemon>, kind: &str, a: f64, b: f64, fresh: bool) {
    *d.queue_hold.lock_ok() = Some((kind.into(), a, b));
    if fresh {
        d.queue_rev.fetch_add(1, Ordering::Relaxed);
    }
}

/// The M14g guard ladder, run once per pass before anything is picked.
///
/// `None` means the runner must not pick this pass - the hold has already
/// been recorded and slept on, so the caller just `continue`s. `Some` is
/// the `only_force` verdict to pick with: a spent quota still lets Force
/// jobs through (SAB semantics), a full disk lets nothing through, and
/// the no-servers hold and offline do not return at all.
///
/// `quick`: the cross-job hand-over path (`tasks/worker.rs`), where the
/// caller has a draining run to watch and a held guard must return at
/// once instead of sleeping on the caller's behalf. Every hold is still
/// recorded and published exactly as on the ordinary pass.
#[expect(clippy::too_many_arguments)]
pub(super) async fn download_guards(
    d: &Arc<Daemon>,
    config: &std::path::Path,
    lane: &PostprocLane,
    guard_reason: &mut Option<String>,
    ledger: &mut Option<QuotaLedger>,
    disk_probe: &mut Option<tokio::task::JoinHandle<Option<u64>>>,
    server_probe: &mut ServerProbe,
    quick: bool,
) -> Option<bool> {
    let hold = |secs: u64| async move {
        if !quick {
            tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
        }
    };
    // §129 2g: a scheduled quota_reset zeroes the window here,
    // where the ledger lives - checked before every guard so a
    // disk hold or offline spell cannot defer it. Opened if
    // need be so the reset also lands on disk for a quota that
    // is currently off but has spend recorded (re-enabling
    // must not resurrect it).
    if d.quota_reset.swap(false, Ordering::Relaxed) {
        let period = d.quota_period.load(Ordering::Relaxed) as char;
        let mut led = ledger
            .take()
            .unwrap_or_else(|| QuotaLedger::open(&d.spool, period));
        led.bytes = 0;
        led.save();
        info!(
            target: "guard",
            "quota ledger reset by schedule - the period's spend starts from zero"
        );
        *ledger = Some(led);
    }
    // M14g guards. Low disk stops everything (a Force job
    // can't write to a full disk either); a spent quota still
    // lets Force jobs through (SAB semantics).
    //
    // statfs on an external or network volume can hang without
    // bound (a NAS share that dropped, a sleeping USB disk), and
    // this loop IS the runner - a hung probe here stops every
    // pick. Probe on the blocking pool with a timeout; a timeout
    // means "unknown", which must not block the pick (None
    // already means the guard stands down, same as a missing
    // directory). Keep the ONE stuck probe and re-await it next
    // pass rather than stacking a new blocked thread per pass.
    let min = d.min_free.load(Ordering::Relaxed);
    let mut free_now: Option<u64> = None;
    if min > 0 {
        let mut probe = disk_probe.take().unwrap_or_else(|| {
            let out = d.out_dir();
            tokio::task::spawn_blocking(move || free_bytes(&out))
        });
        match tokio::time::timeout(std::time::Duration::from_secs(2), &mut probe).await {
            Ok(res) => free_now = res.ok().flatten(),
            Err(_) => *disk_probe = Some(probe),
        }
    }
    if min > 0
        && let Some(free) = free_now
        && free < min
    {
        let fresh = guard_reason.as_deref() != Some("disk");
        if fresh {
            info!(
                target: "guard",
                "pausing: {:.1} GB free < {:.1} GB min",
                free as f64 / 1e9,
                min as f64 / 1e9
            );
            *guard_reason = Some("disk".into());
            // Marker on the transition only - this loop re-checks
            // every 5 s and the row strip carries the live figure.
            let msg = format!(
                "downloads paused - {:.1} GB free is under the {:.1} GB minimum",
                free as f64 / 1e9,
                min as f64 / 1e9
            );
            // §129 2e: targets routed onto "disk" hear about it
            // too - the same transition-only edge as the marker.
            d.notify_event("disk", &msg);
            // §129 4a: the schema's disk.low, same edge.
            // event-arm-gate: a STATE, not a moment - the #qspace
            // banner draws it from the queue payload's own hold
            // (`hold.kind === 'disk'`), with the live free/minimum
            // figures and a button onto the setting that decided it.
            // §129 1b finding (b) is the rule.
            d.life_emit(
                "disk.low",
                json!({
                    "message": msg,
                    "free_bytes": free,
                    "min_bytes": min,
                }),
            );
            d.note_event("disk", msg);
        }
        // Refreshed every pass, not just on entry: the free
        // figure moves while the user clears space, and the row
        // strip shows it live. See `publish_hold` for why the
        // revision bump rides WITH the store rather than above it.
        publish_hold(d, "disk", free as f64 / 1e9, min as f64 / 1e9, fresh);
        hold(5).await;
        return None;
    }
    // §129 backpressure: tails piling up faster than they
    // drain must not fill the disk with undone unpacks - same
    // "pause with a reason" doctrine as the §108 storage pause.
    if lane.saturated() {
        if guard_reason.as_deref() != Some("postproc") {
            let (n, cap) = (lane.backlog(), lane.cap());
            info!(target: "guard", "pausing picks: {n} finishing job(s) at the lane bound {cap}");
            *guard_reason = Some("postproc".into());
            d.note_event(
                "postproc",
                "waiting for post-processing to catch up - the next \
                 download starts when a finishing job completes",
            );
        }
        // No bump, on either edge: this hold's jobs are Finishing, so
        // `any_active` already carries the payload (see the clear edge
        // at the bottom of this function).
        publish_hold(
            d,
            "postproc",
            lane.backlog() as f64,
            lane.cap() as f64,
            false,
        );
        hold(1).await;
        return None;
    }
    if guard_reason.as_deref() == Some("postproc") {
        *guard_reason = None;
        *d.queue_hold.lock_ok() = None;
        d.note_event("clear", "post-processing caught up - downloads resume");
    }
    // TODO §154: nothing to dial. With no enabled server the
    // pick used to go ahead anyway, `get_with_progress` died
    // with "config has no servers" inside ~500 ms, and the job
    // filed to history Failed - `FailKind::Local`, which is
    // correct and is also what makes it terminal, so no retry
    // ladder ever looks at it again. On the SAB facade that
    // Failed row is failed-download handling to an *arr:
    // blocklist the release, search for another. "This box has
    // no servers right now" says nothing about the post, so a
    // setup-order mistake (Sonarr wired up before the servers
    // are) silently burns a healthy release per poll. Hold the
    // queue instead, and let it clear itself - the config is
    // re-read here every tick, so adding a server starts the
    // queue with no restart and no retry click.
    //
    // FORCE DOES NOT BYPASS THIS, which is the one place this
    // hold differs from the quota hold below. Force means "run
    // this even though the scheduler says wait"; a spent quota
    // is a scheduling decision, and a Force job on a spent
    // quota downloads fine. With no server there is nothing to
    // dial, so letting Force through would only reproduce the
    // instant fail this guard exists to prevent. Hence a
    // `continue` gate rather than a term in `only_force`.
    //
    // The condition itself, and why it is narrower than "the
    // config did not load", is `server_verdict` above; why the read
    // is not on this thread is `ServerProbe`.
    let servers = server_probe.verdict(config).await;
    if servers == ServerVerdict::NoneEnabled {
        let fresh = guard_reason.as_deref() != Some("noservers");
        if fresh {
            info!(
                target: "guard",
                "holding the queue: no enabled server is configured"
            );
            *guard_reason = Some("noservers".into());
            d.note_event(
                "servers",
                "no servers configured - downloads wait until one is added",
            );
        }
        // The §129 1b poll answers `"queue": null` for a client whose
        // revision matches unless something is actively transferring,
        // and under this hold every job sits Queued - so the revision
        // is the ONLY thing that can move the payload, exactly as
        // `slowstore::bump` documents for the storage pause.
        publish_hold(d, "noservers", 0.0, 0.0, fresh);
        hold(1).await;
        return None;
    }
    if guard_reason.as_deref() == Some("noservers") {
        *guard_reason = None;
        *d.queue_hold.lock_ok() = None;
        d.note_event(
            "clear",
            match servers {
                ServerVerdict::Dialable => "a server is configured - downloads resume",
                // The other way off this hold: the config stopped
                // being readable, so the guard stands down and the
                // download it releases is what reports the real
                // error. Saying "a server is configured" here would
                // be a plain untruth on the event list.
                _ => "the config cannot be read - downloads resume so the error is reported",
            },
        );
        // The clear edge needs the bump for the same reason the
        // set edge does: nothing is transferring yet, so a
        // matching revision would leave the banner on screen.
        d.queue_rev.fetch_add(1, Ordering::Relaxed);
    }
    // Offline outranks everything below, INCLUDING Force.
    //
    // It has to be its own gate rather than a term in
    // `only_force`, because Force is defined as the thing that
    // walks past a paused queue - and offline only ever reached
    // this loop as a pause it set on the way through. So a
    // priority-2 job started while the header said Offline, the
    // fleet reopened, and the operator's OTHER machine was
    // refused at the account's connection cap with no reason to
    // suspect this daemon (TODO 65). Force is not even reliably
    // the user's own choice: the retry/start path hard-codes
    // `priority = 2` on its behalf.
    //
    // Offline is not a scheduling state like pause; it is a
    // promise about the network, made in absolute terms - the
    // confirm dialog says every connection is closed "so you can
    // use the account from another machine", and startup logs
    // "touching no provider". Coming back online is the only act
    // that releases it, which is one click and is what the
    // button already says.
    if d.offline.load(Ordering::Relaxed) {
        hold(1).await;
        return None;
    }
    let mut only_force = d.paused.load(Ordering::Relaxed);
    let quota = d.quota.load(Ordering::Relaxed);
    let period = d.quota_period.load(Ordering::Relaxed) as char;
    if quota > 0 || ledger.is_some() {
        // (Re)open on first use or a live period change; keep
        // billing an open ledger even if the cap is lifted so
        // re-enabling sees the true window usage.
        if ledger.as_ref().is_none_or(|l| l.period != period) {
            *ledger = Some(QuotaLedger::open(&d.spool, period));
        }
    }
    // Publish what the period has cost so far, whether or not a
    // cap is set: the facade's `left_quota` needs the running
    // total, not just the exhausted case (L5).
    d.quota_spent.store(
        ledger.as_mut().map(|l| l.spent()).unwrap_or(0),
        Ordering::Relaxed,
    );
    if let (Some(led), true) = (ledger.as_mut(), quota > 0)
        && led.spent() >= quota
    {
        let fresh = guard_reason.as_deref() != Some("quota");
        if fresh {
            info!(
                target: "guard",
                "quota spent ({:.1} of {:.1} GB) - only Force jobs until the period rolls over",
                led.bytes as f64 / 1e9,
                quota as f64 / 1e9
            );
            *guard_reason = Some("quota".into());
            let msg = format!(
                "download quota spent ({:.1} of {:.1} GB) - only Force \
                 jobs run until the period rolls over",
                led.bytes as f64 / 1e9,
                quota as f64 / 1e9
            );
            // §129 2e: same transition-only edge as the marker.
            d.notify_event("quota", &msg);
            // §129 4a: the schema's quota.reached, same edge.
            // event-arm-gate: a STATE, not a moment - the same #qspace
            // banner draws it from the queue payload's hold
            // (`hold.kind === 'quota'`), with the live spent/cap figures
            // and the note that Force still runs. §129 1b finding (b).
            d.life_emit(
                "quota.reached",
                json!({
                    "message": msg,
                    "spent_bytes": led.bytes,
                    "quota_bytes": quota,
                }),
            );
            d.note_event("quota", msg);
        }
        publish_hold(
            d,
            "quota",
            led.spent() as f64 / 1e9,
            quota as f64 / 1e9,
            fresh,
        );
        only_force = true;
    }
    if guard_reason.is_some() && !only_force {
        info!(target: "guard", "cleared");
        *guard_reason = None;
        d.note_event(
            "clear",
            "the space and quota guards cleared - downloads resume",
        );
    }
    if guard_reason.is_none() {
        let mut h = d.queue_hold.lock_ok();
        if h.is_some() {
            *h = None;
            // The clear edge of the disk and quota holds. It needs the
            // bump for the same reason their set edges do: nothing is
            // transferring yet, so a matching revision would leave the
            // banner on screen after the hold lifted. (The postproc
            // hold clears on its own path above and stays bump-free:
            // its jobs are Finishing, so `any_active` already carries
            // the payload.)
            d.queue_rev.fetch_add(1, Ordering::Relaxed);
        }
    }
    Some(only_force)
}

/// Hand the shared hub over from the previous job to this one.
///
/// Two halves. First the block-account economics for this job's pool:
/// hosts whose block spend is used up are ruled out, and every host with
/// bytes LEFT is handed its remaining budget so the pool releases it
/// mid-run if this job spends the rest (§96.5 - the exclusion alone only
/// helps the next job). Then every per-job hub slot is REPLACED rather
/// than merely left, because the tail of job N-1 and the queue payload
/// both read these while job N runs: a slot still holding the previous
/// job's value is a double-billed byte, a stale extractor served down
/// /stream, or a password matched against the wrong record. Each `= None`
/// below carries the specific hazard it closes.
pub(super) fn reset_hub_for_job(
    d: &Arc<Daemon>,
    cfg_now: Option<Arc<nzbkit::config::Config>>,
    nzo_id: &str,
    failure_host: String,
) {
    // Block accounts: rule exhausted hosts out of this job's
    // pool (block spend ≥ the configured block size), and hand
    // every host with bytes LEFT its remaining budget, so the
    // pool releases it mid-run if this job spends the rest
    // (§96.5 - the exclusion alone only helps the next job).
    //
    // The snapshot comes from the bounded no-servers probe rather than
    // from a fresh `Config::load` here: this function runs ON the
    // runner with the job already marked Downloading and no fetch task
    // to cancel yet, so a config path that stopped answering wedged the
    // queue silently (Codex sweep H).
    {
        let mut excluded: Vec<String> = Vec::new();
        let mut budgets: std::collections::HashMap<String, u64> = Default::default();
        for s in cfg_now
            .as_ref()
            .map(|c| c.servers.as_slice())
            .unwrap_or(&[])
        {
            let Some(b) = s.block_bytes.filter(|b| *b > 0) else {
                continue;
            };
            let spent = d.block_spent(&s.host);
            if spent >= b {
                excluded.push(s.host.clone());
            } else {
                budgets.insert(s.host.clone(), b - spent);
            }
        }
        *d.hub.excluded_hosts.lock_ok() = excluded;
        *d.hub.host_byte_budgets.lock_ok() = budgets;
    }
    // TODO 208 item 1: the link anchor the fleet build caps the seed
    // from. Read here, at job start, so the second job on a fresh
    // install already has the first job's measured peak.
    d.hub.line_anchor_bps.store(
        d.link_peak
            .effective(d.line_speed.load(Ordering::Relaxed))
            .0,
        Ordering::Relaxed,
    );
    // M2c.5: allow the engine's speculative recovery prefetch
    // for the main job unless a period quota is configured -
    // same reasoning as the sidecar guard: opportunistic
    // fetches must not race a metered budget.
    d.hub
        .spec_prefetch
        .store(d.quota.load(Ordering::Relaxed) == 0, Ordering::Relaxed);
    *d.active_stream.lock_ok() = Some(nzo_id.to_string());
    // Queue-row sub-line: fetching, from here until the pipeline
    // itself advances the token at its section transitions.
    d.hub
        .activity
        .lock_ok()
        .insert(nzo_id.to_string(), "fetching");
    // Clear the hub's per-job slots BEFORE the fetch spawns: if
    // get_with_progress errors before repopulating them (bad
    // NZB, config error), net_rx resolves by drop and the
    // net-drain accounting below would otherwise re-read the
    // PREVIOUS job's pool/verifier - double-billing its bytes
    // and article counts and stamping its bad blocks here.
    *d.hub.pool_live.lock_ok() = None;
    *d.hub.verifier.lock_ok() = None;
    // §96.5: same double-billing hazard as the two slots above,
    // through the OTHER door - the periodic usage flush is
    // delta-billed against this map, so a leftover high-water
    // mark from the previous job would swallow the first bytes
    // of this one. Cleared while pool_live is None, so a flush
    // tick between the two stores sees no pool and bills
    // nothing.
    d.run_usage_flushed.lock_ok().clear();
    // Same reason, for the resume credit: a leftover figure from
    // the previous job would be subtracted from THIS job's
    // network bytes, under-billing its quota and under-reporting
    // its speed.
    d.hub.resume_seeded.store(0, Ordering::Relaxed);
    // M29 oracle: fresh per-job sink - the pool records each
    // article's hit/430 into it; drained to the ledger below.
    *d.hub.oracle.lock_ok() = Some(Arc::new(nzbkit::oracle::OracleSink::default()));
    // M29 opt-in routing: install a ledger snapshot for this
    // job only when `oracle_route` is on, so get_with_progress
    // can DEMOTE providers confidently gone for the release's
    // (family, age-bucket) to the bottom of the level ladder.
    // Off → cleared, so a plain job never consults it. A wrong
    // verdict costs only latency, and that is now literally
    // true: no server is removed, so however many backbones the
    // ledger writes off (it wrote off 5 of 6 on 14 Aug 2026),
    // each demoted one still gets every article once the
    // undemoted servers have 430'd it.
    //
    // Read-only path, never `with_index`: this is the LAST thing
    // between a queued job and its first byte, and the write
    // mutex is held for a tip pass's whole ingest transaction.
    // Measured 14 Aug 2026: an NZB dropped in the watch folder
    // mid-pass sat 40 s here - queued and durable at 16:13:43,
    // first byte at 16:14:23, the exact second the pass logged
    // its headers - because the runner's 1 s poll had nothing to
    // acquire. That is the same starvation the `with_index`
    // comment records at 38 s on 5 Aug; demoting the call off
    // the async workers never addressed the mutex wait itself.
    // A saturated read pool answers None, which is precisely the
    // `oracle_route` off case above: routing is an optimisation
    // and skipping it costs latency, never correctness.
    #[cfg(feature = "indexer")]
    {
        *d.hub.route_gone.lock_ok() = if d.oracle_route.load(Ordering::Relaxed) {
            d.with_index_read(|ix| ix.oracle_snapshot().ok())
        } else {
            None
        };
    }
    // Slim build: no availability ledger, so no snapshot to route by.
    #[cfg(not(feature = "indexer"))]
    {
        *d.hub.route_gone.lock_ok() = None;
    }
    // Also drop the previous job's extractor. It is otherwise
    // left installed for post-completion streaming, but now that
    // active_stream points at THIS job, a /stream/<this id>
    // request passes the owner check while the fetch is still
    // parsing the NZB / restoring the journal (or forever, if it
    // errors first) - and pick_media would map the request onto
    // the stale extractor and serve the PREVIOUS job's file. With
    // it cleared, the stream blocks until this job installs its
    // own extractor (main.rs), which is the correct wait.
    *d.hub.extractor.lock_ok() = None;
    // And the previous job's late-attached password (C1): the
    // owner tag already keeps a stale entry from ever matching
    // this job's reads, so this is hygiene, not correctness.
    *d.hub.late_password.lock_ok() = None;
    // Same owner-tag hygiene for the live wants-a-password
    // signal and the probe's verified winner - a stale tag
    // never matches this job's slot or record.
    *d.hub.password_wanted.lock_ok() = None;
    *d.hub.password_found.lock_ok() = None;
    // §99: this job's NZB source host, so the probe tries the
    // password last known to work for that site first.
    // Replaces (never merely clears) the previous job's hint.
    *d.hub.pw_assoc_site.lock_ok() = Some((nzo_id.to_string(), failure_host));
    // And the seek handle with it: SeekCtl holds a STRONG
    // extractor reference, so a stale one would pin the
    // previous job's whole extractor graph until this job
    // happens to overwrite it - or forever, if the fetch
    // errors first or the daemon idles.
    *d.hub.seek.lock_ok() = None;
    // TODO 274: and the per-file table, for the same reason twice over -
    // it holds a strong SeekCtl (so the extractor graph again) and a
    // strong Arc per FileSlot, which would pin the previous job's whole
    // slot array. The owner tag already keeps a stale table from ever
    // being READ against this job.
    //
    // TODO 274 (e): it is RETIRED rather than dropped. Job N's tail
    // overlaps this download by design, and a listing is the question
    // that tail is worth asking - so the counters are read out into a
    // frozen copy, which pins none of the above, and N's `get_files`
    // answers from that until N parks. Dropping it outright is what had
    // `mode=get_files` fall through to parsing N's spooled `.nzb` and
    // report every file of a fully downloaded job as never started.
    d.hub.retire_job_files();
}

/// The pool-facing figures of a job, taken off the hub while the hub is
/// still that job's.
///
/// Two callers, one instant each. On the plain path `settle_job_tail`
/// detaches at network-drain, exactly where it always read them. On the
/// cross-job hand-over path (`tasks/worker.rs`) the runner detaches at
/// the moment the NEXT job claims the hub, which can be seconds before
/// this job drains - and `pool_live` is an `Arc` the pool keeps
/// updating, so the per-server figures read at settle are still the
/// final ones. Only the whyslow stamp and the cap/refusal banks are
/// taken as of the hand-over: the core only ever judges whoever owns
/// the wire, and from that instant that is the next job.
pub(super) struct DetachedTail {
    pub(super) pool_live: Option<Arc<nzbkit::pool::LiveStats>>,
    /// The run's stop handles, so the slow-job watchdog can still defer
    /// a predecessor that is draining behind the active job (the queue
    /// waits on it, so it is still the job worth judging).
    pub(super) abort: Option<Arc<std::sync::atomic::AtomicBool>>,
    pub(super) queue_ctl: Option<Arc<nzbkit::pool::QueueControl>>,
    /// Per-host bytes already billed to the usage ledger when this was
    /// taken; what the pool adds after that is billed at settle.
    usage_flushed: std::collections::HashMap<String, u64>,
    pub(super) resume_seeded: u64,
    verifier: Option<Arc<nzbkit::live::LiveVerifier>>,
    shaper: Option<Arc<nzbkit::extract::Extractor>>,
    #[cfg(feature = "indexer")]
    oracle_samples: Vec<nzbkit::oracle::Sample>,
}

/// Take [`DetachedTail`] for `nzo_id` off the hub, which must still be
/// that job's. Bills the per-server usage up to now (delta-billed, so
/// the periodic mid-job flush and this never double-bill) and banks
/// the job's connection ceilings and refusal line.
pub(super) fn detach_job_tail(d: &Arc<Daemon>, nzo_id: &str) -> DetachedTail {
    // TODO 207: the shortfall verdict is final here too, and for a
    // stronger reason than the counters below - the core only ever
    // judges whoever owns the wire, so from this instant on there is
    // nothing left to judge and the next job's first tick wipes the
    // window. `whyslow::stamp` has the whole of the WHEN argument.
    super::super::whyslow::stamp(d, nzo_id);
    // §96.5: delta-billed against the flush task's high-water
    // map, so bytes the periodic mid-job flush already billed
    // are not billed twice here.
    d.flush_run_usage();
    let usage_flushed = d.run_usage_flushed.lock_ok().clone();
    // ...and this job's connection ceilings, in the same window and for
    // the same reason: `pool_live` is still THIS job's. Banking was
    // watchdog-only, so a job shorter than one 1-5 s tick could be
    // refused and leave nothing at all in the lifetime ledger (Codex
    // sweep 6, N8). One episode banks once, whichever caller reaches it
    // first.
    super::stall::fold_and_bank_caps(d);
    // ...and the refusal LINE, which rode the same tick and was left
    // behind by that fix. The retained pool covers the ordinary case,
    // since `pool_live` is not cleared when a job ends - but a refusal
    // seen only inside a sub-tick job whose pool a later job replaces,
    // or one on the last job before a queue-finished shutdown action
    // ends the process, was banked nowhere (Codex sweep 7, L2).
    super::stall::bank_refusals(d);
    // M29 oracle: take this job's per-article outcomes off the hub
    // before the next job installs its own sink. The FOLD into the
    // ledger rides on the ticket and happens on the lane.
    //
    // It used to happen right here, and that is how a slow index
    // stopped the queue dead. `with_index` takes the index write
    // mutex under `block_in_place`, so this loop - the runner - parked
    // on it: on 15 Aug an unbudgeted retention reap held that mutex for
    // six hours, and the finished job never reached `lane.submit`, so
    // its record stayed `Downloading`, its row read "Extracting" at
    // 100% for as long as the daemon lived, no history row was ever
    // filed, and its `IndexJobGuard` never dropped - which left the
    // indexer paused on a download that had ended. Everything the
    // runner does between net-drain and the lane belongs to the same
    // rule as the config read below: keep it off the runner.
    #[cfg(feature = "indexer")]
    let oracle_samples = d
        .hub
        .oracle
        .lock_ok()
        .take()
        .map(|sink| sink.drain())
        .unwrap_or_default();
    DetachedTail {
        pool_live: d.hub.pool_live.lock_ok().clone(),
        abort: d.hub.abort.lock_ok().clone(),
        queue_ctl: d.hub.queue_ctl.lock_ok().clone(),
        usage_flushed,
        resume_seeded: d.hub.resume_seeded.load(Ordering::Relaxed),
        // The verifier is still THIS job's too - keep the Arc so
        // the tail task reads the final in-stream bad-block count
        // even after the next job swaps the hub's slot.
        verifier: d.hub.verifier.lock_ok().clone(),
        // Same reason for the extractor: the shape is only final
        // once the tail has settled (a late demote in
        // finish/verify flips a set to "partly on disk"), and by
        // then the next job may own the hub slot.
        shaper: d.hub.extractor_for(Some(nzo_id)),
        #[cfg(feature = "indexer")]
        oracle_samples,
    }
}

/// Read this job's final figures at network-drain and bill what is
/// already final.
///
/// The quota is billed here because the decoded-byte count is final at
/// network-drain (the consumers are joined before the signal fires);
/// `progress` is the job's OWN counter, so it does not matter whether
/// the next job has re-pointed the daemon's cell by now. The per-server
/// usage and reliability ledgers come from `detached` - taken here if
/// the hub is still this job's, or at the hand-over if it is not.
pub(super) fn settle_job_tail(
    d: &Arc<Daemon>,
    nzo_id: &str,
    ledger: &mut Option<QuotaLedger>,
    progress: &AtomicU64,
    detached: Option<DetachedTail>,
) -> JobTail {
    let detached = detached.unwrap_or_else(|| detach_job_tail(d, nzo_id));
    if let Some(led) = ledger.as_mut() {
        led.add(progress.load(Ordering::Relaxed));
    }
    // History stats: decoded bytes + network wall time, final
    // at net-drain.
    let dl_bytes = progress.load(Ordering::Relaxed);
    // ...and the same figure plus whatever a resume already had
    // on disk, which is what a paused row needs to report.
    let on_disk_bytes = dl_bytes.saturating_add(detached.resume_seeded);
    // Bill this job's per-server bytes to the usage history - what the
    // pool moved after the detach, which is nothing on the plain path
    // and the drain's bytes on the hand-over path - and its article
    // tries/430s to the reliability ledger.
    let mut residual: Vec<(String, u64)> = Vec::new();
    let mut per_server_rel: Vec<(String, u64, u64)> = Vec::new();
    if let Some(l) = &detached.pool_live {
        for s in &l.servers {
            let bytes = s.bytes.load(Ordering::Relaxed);
            let billed = detached.usage_flushed.get(&s.host).copied().unwrap_or(0);
            if bytes > billed {
                residual.push((s.host.clone(), bytes - billed));
            }
            per_server_rel.push((
                s.host.clone(),
                s.articles_tried.load(Ordering::Relaxed),
                s.articles_missing.load(Ordering::Relaxed),
            ));
        }
    }
    if !residual.is_empty() {
        d.add_usage(&residual);
    }
    d.add_reliability(&per_server_rel);
    JobTail {
        dl_bytes,
        on_disk_bytes,
        verifier: detached.verifier,
        shaper: detached.shaper,
        #[cfg(feature = "indexer")]
        oracle_samples: detached.oracle_samples,
    }
}
