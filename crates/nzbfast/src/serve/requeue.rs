//! What a job's rerun will COST, and the two callers that ask.
//!
//! One question - "if this job goes back to the queue now, what does the
//! next run pay that an uninterrupted run would not?" - asked from two
//! places that could not be further apart in the daemon:
//!
//! * the slow-job watchdog ([`crate::serve::tasks`]), at a demotion it
//!   is about to fire, so the `defer_reason` the queue drawer prints
//!   names what the trip back cost (TODO 309(d));
//! * the queue payload ([`Daemon::pause_cost`]), on the poll path, so
//!   the dashboard can warn BEFORE the user presses Pause rather than
//!   after. The moment was ruled on 28 Aug 2026 and it is PRE-COMMIT:
//!   for a compressed set there is no post-hoc remedy at all, so a note
//!   after the click is an obituary.
//!
//! It lives here rather than in the watchdog that wrote it because the
//! second caller arrived, and a sentence about what a rerun costs copied
//! into two hand-maintained siblings is this repository's most
//! documented defect class (CLAUDE.md's TENTH, ELEVENTH and FOURTEENTH
//! gates are each one instance of it). Nothing here is new: the enum,
//! both constants and [`requeue_cost`] are the watchdog's own, moved
//! verbatim with their doc comments, plus the caching entry point the
//! poll path needs and the wire shape the payload carries.

use super::*;
/// TODO 309(d): what the requeue a demotion causes will COST this job,
/// when the answer is "more than an uninterrupted run would have".
///
/// A demoted job is requeued `deferred` and reruns from its journal, and
/// that rerun goes through `get::plan::resume_map_admitted`, which
/// declines to map the replay in-stream once the journal's placed bytes
/// exceed the held-span budget. Over that line the rerun materializes
/// volumes and extracts from disk instead, priced by TODO 94 A at **2.53x
/// payload of device I/O against 1.02x** for the mapped route.
///
/// `None` when the requeue is on the ordinary cheap route - which is the
/// common case, and the case this costs nothing to answer.
///
/// Two arms, answering two different questions about the same rerun:
/// what it will cost the DISK, and what it will cost the WIRE. They are
/// mutually exclusive by construction - `Disk` needs a journal holding
/// more placed bytes than the budget, `Refetch` needs one shielding
/// almost nothing of what the wire moved - and each is priced from the
/// source that is honest for its question (the journal for disk, the
/// live wire counters for bandwidth; [`requeue_cost`] says why neither
/// source can answer the other's question).
#[derive(Clone, Copy)]
pub(in crate::serve) enum RequeueCost {
    /// The rerun extracts from volumes on disk (TODO 94 A's 2.53x
    /// payload of device I/O against 1.02x mapped).
    Disk {
        /// Bytes the journal has already placed on disk for this job.
        /// The same quantity `resume_map_admitted` reads, from the same
        /// file, through the same parser.
        restored: u64,
        /// The in-stream replay budget they are measured against:
        /// `MemBudget::holds_cap`, 45% of the process budget.
        cap: u64,
    },
    /// The rerun refetches what this run already downloaded (TODO
    /// 309(b)): a compressed set's output bytes are decoded bytes, so no
    /// fragment of any RAR article can be described as sitting on disk,
    /// the journal shields nothing, and every byte of wire spend is
    /// spent again. Measured 27 Aug 2026 (RESUME-ONEPASS-EDGES section
    /// 7.5): a 2.1 GB compressed set SIGKILLed mid-run left a 72-byte
    /// journal and the rerun refetched 100% of the set.
    Refetch {
        /// Wire bytes this run has fetched that the journal cannot
        /// shield - the bytes a rerun downloads a second time.
        refetch: u64,
    },
}

/// The bandwidth arm's noise floor: a refetch under a gigabyte is
/// seconds of wire time at the rates the single-server-bound arm deals
/// in (its session-best gate alone demands 1 MB/s), so a defer line
/// alarming about megabytes would be noise. A taste threshold, not a
/// measurement - nothing else reads it.
pub(in crate::serve) const REFETCH_FLOOR_BYTES: u64 = 1_000_000_000;

/// How far the wire's byte count must outrun the journal's placed bytes
/// before the gap is read as "this set journals nothing" rather than as
/// bookkeeping lag. `placement_bytes` legitimately trails the wire - it
/// excludes par2-main articles, held spans and in-flight plaintext, and
/// decoded bytes undercount the wire by the yEnc framing - so a factor
/// of 8 asks for seven-eighths of everything fetched to be unshielded,
/// which no store set reaches (its held spans are bounded by the same
/// `holds_cap` the [`RequeueCost::Refetch`] arm's absolute guard uses)
/// while a compressed set's placements never grow at all.
pub(in crate::serve) const REFETCH_SHIELD_FACTOR: u64 = 8;

/// Read [`RequeueCost`] off the judged job's journal and wire counters.
///
/// **Why the DISK arm reads the journal and not a live counter.** The
/// daemon knows this job's byte progress to the megabyte
/// (`Daemon::wire_counters`), and for this arm it is the wrong number by
/// construction: what the gate compares is
/// `ResumeState::placement_bytes`, which counts PLACED fragments and so
/// excludes par2-main articles (journaled the v1 way), held spans and
/// in-flight plaintext (journaled not at all). Near the boundary - which
/// is the only place this answer changes anything - those differences are
/// the answer. So the honest reading is the file, and the file is read
/// exactly as the rerun will read it.
///
/// **Why the REFETCH arm reads the wire counters and not the journal.**
/// Its question is the mirror image: not "what will the rerun replay
/// from disk" but "what will it fetch AGAIN", and the journal cannot
/// answer that because not recording those bytes is the very defect
/// being priced - a compressed set's journal is ~72 bytes however much
/// the wire moved (TODO 309(b)). The wire counter is the only record
/// that those bytes were ever paid for. The two sources divide the
/// ground cleanly: the journal is authoritative for what is on disk,
/// the wire counters for what came down the line.
///
/// The disk arm is held to the SAME admission rule the rerun will apply
/// ([`crate::get::resume_map_admits`], widened by TODO 309(a)): a set
/// whose widest volume fits the margin maps in-stream at ~1.02x however
/// large its total, so there is no disk cost to report and nothing to
/// veto with - before this call shared the rule, the drawer told the
/// user a 64 MB-volume set "will unpack from volumes on disk" when the
/// rerun was going to map it. `seatable` is passed as the raw cap;
/// the doc on `resume_map_admits` says why that is the right
/// prediction-time reading.
///
/// It is affordable because a demotion is RARE: at most three per job,
/// each one already tearing a pipeline down. `blocking_db` is what keeps
/// the parse off the reactor; the wire counters are two atomic loads.
pub(in crate::serve) fn requeue_cost(
    d: &Daemon,
    id: &str,
    out_dir: &std::path::Path,
    budget: nzbkit::mem::MemBudget,
) -> Option<RequeueCost> {
    if std::env::var("NZBFAST_DEFER_IGNORE_RESUME_COST").is_ok_and(|v| v == "1") {
        return None;
    }
    let cap = budget.holds_cap() as u64;
    let resume = crate::persist::blocking_db(|| nzbkit::journal::Journal::peek(out_dir));
    let restored = resume.as_ref().map_or(0, |r| r.placement_bytes());
    if restored > cap {
        let widest = resume.as_ref().map_or(0, |r| r.largest_slot_bytes());
        return (!crate::get::resume_map_admits(restored, widest, cap, cap))
            .then_some(RequeueCost::Disk { restored, cap });
    }
    // The bandwidth arm. Both guards are load-bearing and each covers
    // the other's blind spot: the ratio alone passes a huge store set
    // whose 2% yEnc framing gap tops the floor, and the absolute guard
    // alone passes a store set with a large held-span backlog (bounded
    // by `holds_cap`, which is why `cap` is the other operand).
    //
    // DO NOT DROP `cap` FROM THAT `max` - the arithmetic, not taste.
    // Two sweeps have now read `cap.max(REFETCH_FLOOR_BYTES)` as a bug
    // on the grounds that the cap dominates the 1 GB floor on every real
    // box (~1.93 GB on a 16 GB machine's budget, up to ~7.7 GB at the
    // budget ceiling), so the floor constant looks dead. The mechanism
    // is real and the conclusion is backwards. A store set - the only
    // shape that shields anything - reaches this line with its wire
    // count ahead of its placements by exactly the three things
    // `placement_bytes` excludes, and the largest of those, the
    // held-span backlog, is bounded by `holds_cap`, which IS `cap`. So
    // for a store set `done - restored <= cap` plus small terms, and
    // with the shield factor (`restored * 8 < done` gives
    // `done <= cap * 8/7`) the same bound falls out of the ratio guard
    // itself: `refetch` cannot exceed the cap. `refetch > cap` is
    // therefore what makes a trip PROOF that the set is not shielding,
    // i.e. a SOUNDNESS condition. `REFETCH_FLOOR_BYTES` is the taste
    // threshold sitting on top of it, and it only binds on a box under
    // ~8 GB of RAM, where the cap is below a gigabyte. Take the cap out
    // and the guard becomes `refetch > 1 GB`, which a perfectly healthy
    // store set with a 1.93 GB held-span backlog clears - reintroducing
    // the false positive this guard exists for, and only on the
    // big-memory boxes the complaint is about.
    let (done, _, _) = d.wire_counters(id)?;
    let refetch = done.saturating_sub(restored);
    (restored.saturating_mul(REFETCH_SHIELD_FACTOR) < done
        && refetch > cap.max(REFETCH_FLOOR_BYTES))
    .then_some(RequeueCost::Refetch { refetch })
}

/// The jobs on the wire and the last thing [`Daemon::pause_cost`] said
/// about each.
///
/// TWO SLOTS, and the second one is the whole of this type's history.
/// It was one slot until 28 Aug 2026, on the reasoning that
/// [`requeue_cost`]'s bandwidth arm needs [`Daemon::wire_counters`] and
/// the daemon runs one job at a time - which stopped being true when
/// the cross-job hand-over landed. During a queue-dry hand-over the
/// successor claims the wire while the PREDECESSOR is still
/// `Downloading` and still moving bytes it would lose
/// ([`Daemon::drain_dl`], and `wire_counters` answers for both), so
/// overwriting on the claim published the successor and silenced the
/// predecessor's row from that instant. Both dashboard pause doors then
/// went quiet: the whole-queue door found only the successor, which is
/// under the screen's own floor for the whole early overlap, and the
/// per-row door on the predecessor read its own null. The cost of that
/// silence is the entire point of the feature - a compressed set
/// shields nothing, so the pause throws away everything the wire moved.
///
/// Two is the bound rather than a map, and it is `wire_counters`'
/// bound: the active hub and the one job that may still be draining
/// behind it. A third would need a third live wire slot.
#[derive(Default)]
pub(in crate::serve) struct PauseCostCache(Mutex<PauseCostState>);

/// One job the runner put on the wire, and what was last said about it.
struct WireOwner {
    /// The row this answer belongs to.
    id: String,
    /// Where its journal lives.
    ///
    /// The out_dir is why this record exists at all. The journal lives
    /// in it, and the payload path must not reach into the queue to
    /// find it - `sabcompat::prelock` is built so that every read it
    /// takes provably happens before the queue lock, which is the issue
    /// #38 deadlock invariant turned into structure. So the runner
    /// leaves the pair here when it claims the progress counters
    /// (`tasks::worker`), in the same lock section that publishes
    /// `active_dl` and installs the drain slot, and the payload reads it
    /// without touching the queue.
    out_dir: PathBuf,
    /// `(when, answer)` - the last answer for THIS job, for
    /// [`PAUSE_COST_TTL`].
    ///
    /// It rides with the owner rather than sitting in a cache of its
    /// own, which is what makes the two-slot cache fall out of the
    /// two-slot owner record with no second eviction rule to get wrong.
    /// A single slot would have been worse than useless here: the poll
    /// path now asks about both owners in one pass, so two ids would
    /// thrash it and put a journal parse on EVERY poll, which is the
    /// cost [`PAUSE_COST_TTL`] exists to prevent.
    answer: Option<(Instant, Option<RequeueCost>)>,
}

#[derive(Default)]
struct PauseCostState {
    /// `[the job that last claimed the wire, the one it displaced]`.
    ///
    /// Neither is ever cleared when a job ENDS, deliberately: the answer
    /// is gated on [`Daemon::wire_counters`], which stops answering for
    /// a job the moment it leaves the wire, so a stale owner reports no
    /// cost. One writer and no teardown beats two writers and a window,
    /// and that argument is what lets the second slot cost nothing - it
    /// needs no lifecycle of its own, only somewhere to fall.
    owners: [Option<WireOwner>; 2],
}

/// How long a [`Daemon::pause_cost`] answer is reused before the journal
/// is read again.
///
/// The dashboard polls the queue about once a second and a store set's
/// journal is tens of thousands of records, so an uncached read would
/// put a full journal parse on the poll path once a second for the whole
/// of a large download. Five seconds is far shorter than the thing being
/// reported changes over - a cost measured in gigabytes, moving at line
/// rate - and far longer than a poll.
const PAUSE_COST_TTL: std::time::Duration = std::time::Duration::from_secs(5);

impl RequeueCost {
    /// The queue row's `pause_cost` object.
    ///
    /// `kind` and not a bare number, because the two arms are different
    /// KINDS of loss and no surface may blur them. `refetch` is wire
    /// spend the next run pays again and is the case that earns a
    /// confirm; `disk` is the same download arriving by a slower route,
    /// which costs time and no data at all, and must never get a modal.
    /// The byte figures go out raw so each surface formats them in its
    /// own units, and the page writes the sentence - a daemon shipping
    /// English here is a string the 27 catalogues cannot translate.
    pub(in crate::serve) fn wire_json(&self) -> Value {
        match *self {
            RequeueCost::Disk { restored, cap } => {
                json!({"kind": "disk", "bytes": restored, "budget": cap})
            }
            RequeueCost::Refetch { refetch } => json!({"kind": "refetch", "bytes": refetch}),
        }
    }
}

impl Daemon {
    /// The runner claiming the wire for `id`: remember where its journal
    /// lives, for [`Daemon::pause_cost`], and push the job it displaced
    /// into the second slot rather than over the edge. See
    /// [`PauseCostState::owners`] for why that second slot exists.
    ///
    /// Idempotent for the job already holding the wire, which is what
    /// keeps a repeated claim from shifting a live drainer out from
    /// behind it. The only way a duplicate id could reach both slots is
    /// through that repeat, so the early return is also what makes the
    /// pair distinct by construction.
    pub(in crate::serve) fn note_wire_owner(&self, id: &str, out_dir: &std::path::Path) {
        let mut g = self.pause_cost.0.lock_ok();
        if g.owners[0].as_ref().is_some_and(|o| o.id == id) {
            return;
        }
        g.owners[1] = g.owners[0].take();
        g.owners[0] = Some(WireOwner {
            id: id.to_string(),
            out_dir: out_dir.to_path_buf(),
            answer: None,
        });
    }

    /// What pausing each job on the wire right now would cost its next
    /// run - the same question the demotion watchdog asks at a verdict,
    /// asked at the one moment the USER can still act on the answer
    /// (TODO 309(b), 28 Aug 2026: warn before the click, not after).
    ///
    /// Each entry names the row its answer belongs to, so the payload
    /// matches it to its slot the way it already matches `live_shape`
    /// and the sidecar. Empty means pausing is free, which is the answer
    /// for every job that is not on the wire and for every job on it
    /// that has not yet moved enough bytes to matter.
    ///
    /// AT MOST TWO ENTRIES, AND TWO IS NOT A CORNER. It answered for one
    /// row until 28 Aug 2026 and the hand-over is why that was wrong:
    /// the successor claims the wire while the predecessor is still
    /// downloading behind it, and pausing stops BOTH, so an answer for
    /// one of them is silence about the other's whole loss. The page
    /// takes the worst of what it is given; this hands over everything
    /// that has something to lose. [`PauseCostState::owners`] carries
    /// the incident.
    ///
    /// Two things stand between this and a journal parse on every poll,
    /// and the first is the one that carries the weight.
    ///
    /// **The cheap screen.** Neither arm of [`requeue_cost`] can fire
    /// until the wire has moved more than `cap.max(REFETCH_FLOOR_BYTES)`.
    /// The bandwidth arm says so outright - `refetch > cap.max(FLOOR)`,
    /// and `refetch` is `done` minus something - and the disk arm needs
    /// `restored > cap`, where `restored` counts DECODED bytes of what
    /// the wire delivered and so is bounded by `done` too. A job under
    /// that line has no cost to report and its journal is never opened.
    /// It is applied PER OWNER, which is what keeps the second slot free
    /// on the ordinary poll: a successor seconds into its run is under
    /// the floor, so the extra owner costs two atomic loads.
    ///
    /// That threshold is **the held-span cap or 1 GB, whichever is
    /// larger**, and on any ordinary box it is the cap: `holds_cap` is
    /// 45% of the process memory budget, so ~1.93 GB where the budget is
    /// 4 GB (a 16 GB machine's RAM/4 default) and up to ~7.7 GB at the
    /// 16 GB budget ceiling. The 1 GB constant only binds below about
    /// 8 GB of RAM, where 45% of RAM/4 is under a gigabyte. This comment
    /// said "for their first gigabyte" until 28 Aug 2026, which
    /// understated the real threshold by up to nearly eight times and was
    /// read as a bug by two separate sweeps - the cap in that `max` is a
    /// soundness condition and [`requeue_cost`] carries the derivation
    /// at the guard. Do not restate the threshold as a constant here.
    ///
    /// **The cache**, for what gets past it: [`PAUSE_COST_TTL`], one
    /// entry per owner ([`WireOwner::answer`]). The journal read happens
    /// with the lock DOWN - it is `blocking_db` I/O on an HTTP worker's
    /// path, and holding a daemon mutex across it is how the queue
    /// drawer once wedged the whole worker pool. Two polls racing past a
    /// stale entry both parse, which costs one duplicate read and cannot
    /// produce a wrong answer.
    pub(in crate::serve) fn pause_cost(&self) -> Vec<(String, RequeueCost)> {
        self.pause_cost_under(nzbkit::mem::process_budget())
    }

    /// [`Daemon::pause_cost`] against an explicit budget.
    ///
    /// Split so the tests can drive a known budget without publishing
    /// one: `nzbkit::mem::set_process_budget` writes a process-wide
    /// atomic, and a test that moved it would be moving it under every
    /// other test sharing the process (`tools/test-global-gate.py`).
    /// The one-line wrapper above is the only site that reads the
    /// global, and it has nothing left to get wrong.
    fn pause_cost_under(&self, budget: nzbkit::mem::MemBudget) -> Vec<(String, RequeueCost)> {
        let cap = budget.holds_cap() as u64;
        // Snapshot both owners and drop the lock: everything below can
        // block, and none of it may run under this mutex.
        let owners: Vec<(String, PathBuf, Option<(Instant, Option<RequeueCost>)>)> = {
            let g = self.pause_cost.0.lock_ok();
            g.owners
                .iter()
                .flatten()
                .map(|o| (o.id.clone(), o.out_dir.clone(), o.answer))
                .collect()
        };
        let mut out = Vec::new();
        for (id, out_dir, cached) in owners {
            // `wire_counters` is what makes a stale owner free: it stops
            // answering the moment the job leaves the wire, which is why
            // neither slot is ever torn down.
            let Some((done, _, _)) = self.wire_counters(&id) else {
                continue;
            };
            if done <= cap.max(REFETCH_FLOOR_BYTES) {
                continue;
            }
            if let Some((at, cost)) = cached
                && at.elapsed() < PAUSE_COST_TTL
            {
                out.extend(cost.map(|c| (id, c)));
                continue;
            }
            let cost = requeue_cost(self, &id, &out_dir, budget);
            // Store against the owner it was asked about, by id: the
            // hand-over can have shifted the slots while the journal was
            // being parsed, and an answer written to a slot index would
            // then land on the wrong job.
            if let Some(o) = self
                .pause_cost
                .0
                .lock_ok()
                .owners
                .iter_mut()
                .flatten()
                .find(|o| o.id == id)
            {
                o.answer = Some((Instant::now(), cost));
            }
            out.extend(cost.map(|c| (id, c)));
        }
        out
    }
}

/// TODO 309(b): the pause-cost answer the queue payload publishes.
///
/// [`requeue_cost`] itself is pinned by `tasks::stall`'s
/// `requeue_cost_tests`, which came with it and is unchanged. What is
/// new here, and what these pin, is everything AROUND it: the ownership
/// record the runner leaves, the screen that keeps the journal shut, and
/// the cache. Each of the three can fail silently - a lost owner, a
/// screen that lets everything through, a cache that never expires - and
/// none of the three would fail a build.
#[cfg(test)]
mod pause_cost_tests {
    use super::*;
    use nzbkit::extract::Frag;

    /// The smallest budget the process will take, so `holds_cap` is a
    /// known ~30 MB and the screen's floor is the 1 GB constant.
    fn budget() -> nzbkit::mem::MemBudget {
        nzbkit::mem::MemBudget::with_total(nzbkit::mem::MemBudget::MIN)
    }

    fn scratch(name: &str) -> crate::testscratch::ScratchDir {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-pausecost-{}-{name}", std::process::id()));
        crate::testscratch::ScratchDir::attach(&dir)
    }

    /// Put `id` on the wire having fetched `done` bytes of `total`.
    fn on_the_wire(d: &Arc<Daemon>, id: &str, done: u64, total: u64) {
        *d.active_dl.lock_ok() = Some(id.to_string());
        d.progress.reset().store(done, Ordering::Relaxed);
        d.active_total.store(total, Ordering::Relaxed);
    }

    /// Hand the wire from `id` to `next`, exactly as `tasks::worker`
    /// does it: the predecessor moves into the drain slot with its own
    /// counters and keeps fetching, the successor takes `active_dl`, and
    /// both claim the pause-cost owner record in that order.
    fn hand_over(d: &Arc<Daemon>, id: &str, done: u64, total: u64, next: &str, next_dir: &Path) {
        *d.drain_dl.lock_ok() = Some(DrainSlot {
            nzo_id: id.to_string(),
            t_start: Instant::now(),
            progress: Arc::new(AtomicU64::new(done)),
            // Default counters have no published plan, so `left()`
            // declines and the slot's own arithmetic answers - the same
            // fallback a run before its first plan publish takes.
            counters: Arc::new(crate::streamhub::FetchCounters::default()),
            total,
            resume_seeded: 0,
            pool_live: None,
            abort: None,
            queue_ctl: None,
        });
        *d.active_dl.lock_ok() = Some(next.to_string());
        d.progress.reset();
        d.active_total.store(total, Ordering::Relaxed);
        d.note_wire_owner(next, next_dir);
    }

    /// The one answer a single-job fixture expects, with the COUNT
    /// pinned. Every case that uses it puts one job on the wire, so a
    /// second entry is a defect, and an `expect` on the list would let
    /// one through unread.
    #[track_caller]
    fn only(v: Vec<(String, RequeueCost)>, why: &str) -> (String, RequeueCost) {
        assert_eq!(
            v.len(),
            1,
            "{why}: one job on the wire, {} answers",
            v.len()
        );
        v.into_iter().next().unwrap()
    }

    /// A journal placing `n` articles of `len` bytes into one volume -
    /// the shape a STORE set leaves, and the only shape that shields
    /// anything at all.
    fn journal_of(dir: &Path, n: usize, len: u64) {
        let (j, _) = nzbkit::journal::Journal::open(dir, b"<nzb/>").unwrap();
        for i in 0..n {
            j.record_placed(
                0,
                &format!("<a{i}@x>"),
                None,
                "vol.part01.rar",
                n as u64 * len,
                &[Frag::identity("vol.part01.rar", i as u64 * len, len)],
                // No payload on disk behind these records, so there is
                // no honest X5-02 commitment to record. Nothing here
                // runs a restore - these helpers weigh `placement_bytes`
                // - so `None` costs the assertions nothing and is the
                // truthful value.
                None,
            );
        }
        j.flush();
    }

    /// The case the whole feature exists for: a COMPRESSED set, which
    /// journals nothing however much the wire moved, so a pause throws
    /// away every byte of it (RESUME-ONEPASS-EDGES section 7.5 - a
    /// 2.1 GB set left a 72-byte journal and the rerun refetched 100%).
    #[test]
    fn a_compressed_set_on_the_wire_prices_its_pause_as_a_refetch() {
        let dir = scratch("refetch");
        let d = crate::serve::testutil::test_daemon(&dir);
        // A journal with records but no PLACEMENTS is what a compressed
        // set leaves: `Journal::open` writes the v1 header and nothing
        // else follows it, so `placement_bytes` is 0.
        let (j, _) = nzbkit::journal::Journal::open(&dir, b"<nzb/>").unwrap();
        j.flush();
        d.note_wire_owner("SABnzbd_nzo_nzbfast1", &dir);
        on_the_wire(&d, "SABnzbd_nzo_nzbfast1", 3_000_000_000, 4_000_000_000);
        let (id, cost) = only(
            d.pause_cost_under(budget()),
            "3 GB fetched and nothing shielded is a refetch",
        );
        assert_eq!(id, "SABnzbd_nzo_nzbfast1");
        let RequeueCost::Refetch { refetch } = cost else {
            panic!("a journal shielding no placed payload is the Refetch arm");
        };
        assert_eq!(refetch, 3_000_000_000);
        // ...and the payload shape the dashboard branches on. `kind` is
        // the field that keeps a confirm off the `disk` arm.
        assert_eq!(cost.wire_json()["kind"], "refetch");
    }

    /// The other arm, and the one that must NOT get a modal: a store set
    /// whose placed bytes are over the replay budget pays a slower
    /// route, not a re-download.
    #[test]
    fn a_store_set_over_the_replay_budget_prices_its_pause_as_disk() {
        let dir = scratch("disk");
        let d = crate::serve::testutil::test_daemon(&dir);
        // 2 GB placed in ONE volume: over a ~30 MB budget, and a single
        // volume that wide can never map, so `resume_map_admits` says no.
        journal_of(&dir, 2000, 1_000_000);
        d.note_wire_owner("SABnzbd_nzo_nzbfast1", &dir);
        on_the_wire(&d, "SABnzbd_nzo_nzbfast1", 2_100_000_000, 4_000_000_000);
        let (_, cost) = only(d.pause_cost_under(budget()), "2 GB placed is over");
        let RequeueCost::Disk { restored, .. } = cost else {
            panic!("a 2 GB volume cannot map under a ~30 MB budget");
        };
        assert_eq!(restored, 2_000_000_000);
        assert_eq!(cost.wire_json()["kind"], "disk");
    }

    /// The screen, which is what keeps this off the journal on the poll
    /// path - and it is pinned by CONSEQUENCE rather than by watching
    /// the file: the fixture leaves a journal that would price as a
    /// refetch, and the answer is still `None`, which it can only be if
    /// the screen returned before reading it.
    #[test]
    fn a_job_under_the_floor_is_free_and_its_journal_is_never_read() {
        let dir = scratch("screen");
        let d = crate::serve::testutil::test_daemon(&dir);
        let (j, _) = nzbkit::journal::Journal::open(&dir, b"<nzb/>").unwrap();
        j.flush();
        d.note_wire_owner("SABnzbd_nzo_nzbfast1", &dir);
        // A gigabyte exactly: the floor is `>`, so this is under it.
        on_the_wire(
            &d,
            "SABnzbd_nzo_nzbfast1",
            REFETCH_FLOOR_BYTES,
            4_000_000_000,
        );
        assert!(
            d.pause_cost_under(budget()).is_empty(),
            "under the floor there is no cost to report and no journal to read"
        );
        // One byte past it, the same journal prices.
        on_the_wire(
            &d,
            "SABnzbd_nzo_nzbfast1",
            REFETCH_FLOOR_BYTES + 1,
            4_000_000_000,
        );
        assert!(
            !d.pause_cost_under(budget()).is_empty(),
            "past the floor it prices"
        );
    }

    /// The same screen at a PRODUCTION budget, which is the threshold
    /// every real box actually runs: `budget()` above is
    /// `MemBudget::MIN`, so its `holds_cap` is ~30 MB and every other
    /// test in this module only ever exercises the 1 GB floor. On a
    /// 16 GB machine the default budget is 4 GB and the cap is ~1.93 GB,
    /// so `cap.max(REFETCH_FLOOR_BYTES)` is the CAP and the constant is
    /// dead weight - which is exactly why two sweeps read the `max` as a
    /// bug. Dropping `cap` from it leaves `refetch > 1 GB`, which a
    /// healthy store set with a 1.93 GB held-span backlog clears, and
    /// the "free at the screen" assertion below is what dies when
    /// somebody does it. [`requeue_cost`] carries the derivation.
    ///
    /// WHICH ARM OF THAT `max` BINDS IS A PROPERTY OF THE TARGET, and
    /// this test asserted the 64-bit answer unconditionally for its
    /// first two days. That took `armv7-cross` red in nightly from
    /// 28 Aug 2026, deterministically, on both attempts and in both
    /// test binaries nextest built for it - the only failing test in
    /// 8,094 - and nothing reported it, so it sat there. The cause is arithmetic and not a
    /// `usize` narrowing: [`nzbkit::mem::MemBudget::with_total`] clamps
    /// every budget to [`nzbkit::mem::MemBudget::max_total`], which is
    /// 1 GiB on a 32-bit target for the two address-space reasons its
    /// own comment carries, so the 4 GiB asked for below IS 1 GiB there
    /// and 45% of it is 483,183,810 bytes - under half the floor. The
    /// cap arm does not exist on armv7 and no bigger number reaches it.
    ///
    /// So the fixture drives the SCREEN, which is what this test is
    /// named for and is well defined on both targets, and each target
    /// pins which arm it is getting. Deliberately not one portable
    /// assertion: `cap.max(FLOOR) >= FLOOR` is true whatever the 45%
    /// becomes, so it would pass with the cap arm dropped entirely,
    /// which is the exact edit this test exists to refuse. And
    /// deliberately not `#[cfg]`-ed off the target where it failed -
    /// that would leave armv7's own screen pinned by nothing, on the one
    /// platform where the floor is the whole of it.
    #[test]
    fn at_a_production_budget_the_screen_is_the_held_span_cap() {
        // membudget-ceiling-gate: with_total() clamps any input safely on
        // every target, so the literal itself needs no guard; the 32-bit
        // split lives in the two cfg-gated asserts below, which read the
        // clamped result via `cap` rather than trusting this figure raw.
        let big = nzbkit::mem::MemBudget::with_total(4u64 << 30);
        let cap = big.holds_cap() as u64;
        let screen = cap.max(REFETCH_FLOOR_BYTES);
        #[cfg(target_pointer_width = "64")]
        assert!(
            cap > REFETCH_FLOOR_BYTES,
            "45% of a 4 GB budget must be over a gigabyte, or this test \
             pins the floor a second time instead of the cap: cap={cap}"
        );
        #[cfg(not(target_pointer_width = "64"))]
        assert!(
            cap < REFETCH_FLOOR_BYTES,
            "a narrower target clamps every budget to \
             MemBudget::max_total(), so 45% of one cannot reach the \
             floor - if it now can, the ceiling moved and this arm is \
             the wrong one to be taking: cap={cap}"
        );
        let dir = scratch("prodscreen");
        let d = crate::serve::testutil::test_daemon(&dir);
        // The compressed-set journal again: it shields nothing, so the
        // only thing keeping the answer at `None` is the screen.
        let (j, _) = nzbkit::journal::Journal::open(&dir, b"<nzb/>").unwrap();
        j.flush();
        d.note_wire_owner("SABnzbd_nzo_nzbfast1", &dir);
        // At the screen exactly - nearly two gigabytes of wire on a
        // 64-bit box, the bare floor on a 32-bit one - and still free.
        on_the_wire(&d, "SABnzbd_nzo_nzbfast1", screen, 8_000_000_000);
        assert!(
            d.pause_cost_under(big).is_empty(),
            "at the screen there is nothing a rerun cannot shield"
        );
        // One byte past it it prices, and prices as a refetch.
        on_the_wire(&d, "SABnzbd_nzo_nzbfast1", screen + 1, 8_000_000_000);
        let (_, cost) = only(
            d.pause_cost_under(big),
            "past the screen an unshielded set costs a refetch",
        );
        let RequeueCost::Refetch { refetch } = cost else {
            panic!("a journal shielding no placed payload is the Refetch arm");
        };
        assert_eq!(refetch, screen + 1);
    }

    /// armv7's production screen, pinned FROM A 64-BIT BOX - which is
    /// the whole reason this test exists rather than being left to the
    /// nightly qemu job.
    ///
    /// A 1 GiB budget is the one figure both targets agree on to the
    /// byte: it sits exactly ON the 32-bit
    /// [`nzbkit::mem::MemBudget::max_total`] ceiling and is untouched on
    /// 64-bit, so `holds_cap` here is 483,183,810 on EVERY target - the
    /// same number `armv7-cross` printed for ten nights - and the screen
    /// is the 1 GB floor either way. That makes this a faithful host-run
    /// of what a 32-bit install actually gets, and the one thing above
    /// that a 64-bit box otherwise cannot execute.
    ///
    /// The floor arm is what binds on EVERY armv7 install, not a corner:
    /// 45% of the largest budget the target can address is under half of
    /// `REFETCH_FLOOR_BYTES`, so `cap` can never win that `max` there.
    /// That is the constant doing exactly the job [`requeue_cost`]
    /// describes - "it only binds on a box under ~8 GB of RAM" - and it
    /// stays SOUND, because the floor it screens on is the larger of the
    /// two, so `refetch > FLOOR` still implies `refetch > cap`.
    #[test]
    fn a_32_bit_sized_budget_screens_on_the_floor_and_still_implies_the_cap() {
        let small = nzbkit::mem::MemBudget::with_total(1u64 << 30);
        assert_eq!(
            small.total,
            1 << 30,
            "a 1 GiB budget is at the 32-bit ceiling and under every \
             other one, so no target may clamp it"
        );
        let cap = small.holds_cap() as u64;
        assert_eq!(cap, 483_183_810, "45% of a gigabyte, on every target");
        assert!(
            cap < REFETCH_FLOOR_BYTES,
            "the floor is what screens a 32-bit install"
        );
        let dir = scratch("armv7screen");
        let d = crate::serve::testutil::test_daemon(&dir);
        let (j, _) = nzbkit::journal::Journal::open(&dir, b"<nzb/>").unwrap();
        j.flush();
        d.note_wire_owner("SABnzbd_nzo_nzbfast1", &dir);
        // Past the cap and under the floor: free, because the screen
        // takes the LARGER of the two and the floor is it here.
        on_the_wire(
            &d,
            "SABnzbd_nzo_nzbfast1",
            REFETCH_FLOOR_BYTES,
            8_000_000_000,
        );
        assert!(
            d.pause_cost_under(small).is_empty(),
            "over the held-span cap but under the floor is still free"
        );
        on_the_wire(
            &d,
            "SABnzbd_nzo_nzbfast1",
            REFETCH_FLOOR_BYTES + 1,
            8_000_000_000,
        );
        let (_, cost) = only(
            d.pause_cost_under(small),
            "past the floor an unshielded set costs a refetch",
        );
        let RequeueCost::Refetch { refetch } = cost else {
            panic!("a journal shielding no placed payload is the Refetch arm");
        };
        assert_eq!(refetch, REFETCH_FLOOR_BYTES + 1);
    }

    /// A job that is not on the wire has nothing in flight to lose, and
    /// that is what makes it safe never to clear the owner: the answer
    /// is gated on `wire_counters`, which stops answering the moment the
    /// job leaves.
    #[test]
    fn a_stale_owner_reports_no_cost_once_the_job_leaves_the_wire() {
        let dir = scratch("stale");
        let d = crate::serve::testutil::test_daemon(&dir);
        let (j, _) = nzbkit::journal::Journal::open(&dir, b"<nzb/>").unwrap();
        j.flush();
        d.note_wire_owner("SABnzbd_nzo_nzbfast1", &dir);
        on_the_wire(&d, "SABnzbd_nzo_nzbfast1", 3_000_000_000, 4_000_000_000);
        assert!(!d.pause_cost_under(budget()).is_empty());
        // The runner hands the wire to the next job. The owner record is
        // deliberately left behind.
        *d.active_dl.lock_ok() = Some("SABnzbd_nzo_nzbfast2".to_string());
        assert!(
            d.pause_cost_under(budget()).is_empty(),
            "the previous job is no longer losing anything by being paused"
        );
        // And with no owner at all - a daemon that has never run a job.
        let fresh = crate::serve::testutil::test_daemon(&scratch("stale2"));
        assert!(fresh.pause_cost_under(budget()).is_empty());
    }

    /// The case this whole two-slot record exists for, and the sibling
    /// of the stale-owner test above: a real hand-over, with the
    /// predecessor DRAINING rather than gone.
    ///
    /// The two differ by one field and the difference is the defect.
    /// That test leaves `drain_dl` empty, so it models the instant
    /// AFTER the predecessor left the wire, where reporting nothing is
    /// correct. This one populates it, which is what the runner
    /// actually does at the claim (`tasks/worker.rs` installs the drain
    /// slot in the same lock section as the `active_dl` publish and the
    /// owner note): the predecessor is still `Downloading` and still
    /// moving bytes it would lose. Under the single-slot owner it lost
    /// its answer the moment the successor claimed the wire, and BOTH
    /// dashboard pause doors then went quiet - the whole-queue one
    /// because only the successor could carry a cost and it is under the
    /// screen's floor for the whole early overlap, the per-row one
    /// because the predecessor's own row read null.
    #[test]
    fn a_draining_predecessor_keeps_its_cost_while_the_successor_holds_the_wire() {
        let dir = scratch("drain");
        let next_dir = scratch("drain-next");
        let d = crate::serve::testutil::test_daemon(&dir);
        // The compressed set again: it shields nothing, so every byte
        // the wire moved for it is a byte the pause throws away.
        let (j, _) = nzbkit::journal::Journal::open(&dir, b"<nzb/>").unwrap();
        j.flush();
        d.note_wire_owner("SABnzbd_nzo_nzbfast1", &dir);
        on_the_wire(&d, "SABnzbd_nzo_nzbfast1", 3_000_000_000, 4_000_000_000);
        assert!(!d.pause_cost_under(budget()).is_empty());

        hand_over(
            &d,
            "SABnzbd_nzo_nzbfast1",
            3_000_000_000,
            4_000_000_000,
            "SABnzbd_nzo_nzbfast2",
            &next_dir,
        );
        // The successor holds the hub and has fetched nothing, so it is
        // under the screen and carries no cost of its own. The one
        // answer is the predecessor's, and it is its whole spend.
        let (id, cost) = only(
            d.pause_cost_under(budget()),
            "the draining job is still losing what it fetched",
        );
        assert_eq!(id, "SABnzbd_nzo_nzbfast1");
        let RequeueCost::Refetch { refetch } = cost else {
            panic!("a journal shielding no placed payload is the Refetch arm");
        };
        assert_eq!(refetch, 3_000_000_000);

        // ...and once the drain finishes there is nothing left to lose,
        // which is the invariant that lets both slots go untorn-down.
        *d.drain_dl.lock_ok() = None;
        assert!(
            d.pause_cost_under(budget()).is_empty(),
            "off the wire, a stale owner reports no cost"
        );
    }

    /// Both jobs on the wire past the floor: the payload must carry BOTH
    /// answers, because a whole-queue pause stops both and the page can
    /// only take the worst of what it is given.
    #[test]
    fn a_hand_over_with_both_jobs_over_the_floor_prices_both_rows() {
        let dir = scratch("both");
        let next_dir = scratch("both-next");
        let d = crate::serve::testutil::test_daemon(&dir);
        for p in [&dir, &next_dir] {
            let (j, _) = nzbkit::journal::Journal::open(p, b"<nzb/>").unwrap();
            j.flush();
        }
        d.note_wire_owner("SABnzbd_nzo_nzbfast1", &dir);
        hand_over(
            &d,
            "SABnzbd_nzo_nzbfast1",
            3_000_000_000,
            4_000_000_000,
            "SABnzbd_nzo_nzbfast2",
            &next_dir,
        );
        // The successor has now run long enough to be over the floor too.
        d.progress.reset().store(2_000_000_000, Ordering::Relaxed);
        d.active_total.store(9_000_000_000, Ordering::Relaxed);

        let answers = d.pause_cost_under(budget());
        assert_eq!(answers.len(), 2, "both jobs are losing something");
        let by_id = |want: &str| {
            answers
                .iter()
                .find(|(id, _)| id == want)
                .map(|(_, c)| match *c {
                    RequeueCost::Refetch { refetch } => refetch,
                    RequeueCost::Disk { .. } => panic!("both journals shield nothing"),
                })
                .unwrap_or_else(|| panic!("no answer for {want}"))
        };
        assert_eq!(by_id("SABnzbd_nzo_nzbfast1"), 3_000_000_000);
        assert_eq!(by_id("SABnzbd_nzo_nzbfast2"), 2_000_000_000);
    }

    /// The cache, pinned the only way a TTL can be pinned without a
    /// clock: change the journal under a fresh answer and show the
    /// answer does NOT move. A cache that quietly stopped caching would
    /// pass every other test in this module and put a full journal parse
    /// on the queue poll for the whole of every large download.
    #[test]
    fn a_second_ask_inside_the_window_reuses_the_answer() {
        let dir = scratch("cache");
        let d = crate::serve::testutil::test_daemon(&dir);
        let (j, _) = nzbkit::journal::Journal::open(&dir, b"<nzb/>").unwrap();
        j.flush();
        d.note_wire_owner("SABnzbd_nzo_nzbfast1", &dir);
        on_the_wire(&d, "SABnzbd_nzo_nzbfast1", 3_000_000_000, 4_000_000_000);
        assert!(matches!(
            only(d.pause_cost_under(budget()), "one job on the wire").1,
            RequeueCost::Refetch { .. }
        ));
        // Now make the journal shield 2 GB in one wide volume, which the
        // uncached answer would price as `Disk`.
        journal_of(&dir, 2000, 1_000_000);
        assert!(
            matches!(
                only(d.pause_cost_under(budget()), "one job on the wire").1,
                RequeueCost::Refetch { .. }
            ),
            "inside the TTL the previous answer stands"
        );
    }

    /// The cache is TWO slots, one per owner, and a single slot would be
    /// worse than none here.
    ///
    /// The poll path asks about both owners in ONE pass, so with one
    /// entry the second ask evicts the first's every time and every poll
    /// re-parses both journals - the exact cost [`PAUSE_COST_TTL`]
    /// exists to prevent, on the largest downloads, for the whole of the
    /// hand-over. Pinned the same way its sibling above is, and it can
    /// only be pinned that way: move BOTH journals under fresh answers
    /// and show that NEITHER answer moves. Under one slot both would.
    #[test]
    fn two_owners_alternating_reuse_their_own_answers() {
        let dir = scratch("twocache");
        let next_dir = scratch("twocache-next");
        let d = crate::serve::testutil::test_daemon(&dir);
        for p in [&dir, &next_dir] {
            let (j, _) = nzbkit::journal::Journal::open(p, b"<nzb/>").unwrap();
            j.flush();
        }
        d.note_wire_owner("SABnzbd_nzo_nzbfast1", &dir);
        hand_over(
            &d,
            "SABnzbd_nzo_nzbfast1",
            3_000_000_000,
            4_000_000_000,
            "SABnzbd_nzo_nzbfast2",
            &next_dir,
        );
        d.progress.reset().store(2_000_000_000, Ordering::Relaxed);
        d.active_total.store(9_000_000_000, Ordering::Relaxed);
        assert_eq!(d.pause_cost_under(budget()).len(), 2);

        // Both journals now shield 2 GB in one wide volume, which an
        // uncached answer prices as `Disk`.
        journal_of(&dir, 2000, 1_000_000);
        journal_of(&next_dir, 2000, 1_000_000);
        for (id, cost) in d.pause_cost_under(budget()) {
            assert!(
                matches!(cost, RequeueCost::Refetch { .. }),
                "inside the TTL {id} keeps its own answer"
            );
        }
    }
}
