//! The `queue_json` walk over the queue (TODO 106; split out by B5).
//!
//! A child module of `sabcompat` rather than a sibling under `serve`,
//! for the same reason `prelock` is one: `slot_json` and `SlotCtx` are
//! private to sabcompat.rs and `use super::*` is what keeps them
//! reachable from here.

use super::*;

/// What the caller asked to SEE, in one argument: the two SAB filters
/// and the window, which travel together and only ever read together.
pub(super) struct QueueView<'a> {
    /// SAB's `category=`, absent for "*" or empty (the *arrs send one
    /// when they have a category configured).
    pub(super) cat_filter: Option<&'a String>,
    /// SAB's `nzo_ids=` selection. Present means "exactly these rows,
    /// with no window at all" - see `nzo_ids_param`.
    pub(super) ids: Option<&'a std::collections::HashSet<String>>,
    /// SAB's `(start, limit)`; see `window_of`. Ignored when `ids` is
    /// set.
    pub(super) window: (usize, usize),
    /// Ours: keep live rows in the page whatever their rank.
    pub(super) pin_live: bool,
}

/// The page of rows, and the whole-queue totals the header states
/// beside them. One walk produces both, which is the §91 property -
/// a total can never describe a different instant from its own parts.
pub(super) struct QueueWalk {
    pub(super) slots: Vec<Value>,
    /// Rows matching the caller's filter, BEFORE the window: SAB's
    /// `noofslots`, which is exactly what it was back when pagination
    /// happened after every row had been built.
    pub(super) matched: usize,
    pub(super) remaining_bytes: u64,
    pub(super) total_bytes_all: u64,
    pub(super) runnable_bytes: u64,
    pub(super) need_bytes: u64,
}

/// The queue walk. Split out of `queue_json` for the size gate (TODO
/// 106) with the reads it owns, `active_left` among them: `q` is the
/// contents of the caller's queue guard, so everything in here still
/// happens under that one lock, which is the whole point of several of
/// the comments inside it.
pub(super) fn queue_walk(
    d: &Daemon,
    q: &std::collections::VecDeque<Arc<Mutex<Job>>>,
    ctx: &SlotCtx,
    view: &QueueView<'_>,
) -> QueueWalk {
    let (_, limit) = view.window;
    let windowed = view.ids.is_none();
    // §91: the active job's progress is read fresh at every pairing with
    // a slot's state (see `active_left` below), never snapshotted up
    // here. A snapshot taken before the queue walk could pair the
    // PREVIOUS job's near-100% progress with a slot that flipped to
    // Downloading mid-walk - a state the queue was never in.
    // ...and only for the slot that OWNS them. Two jobs are `Downloading`
    // whenever one is finishing (job N stays in that state through its
    // whole disk tail while job N+1 is already on the wire), and this
    // used to answer for both - so the finishing row, the hero card and
    // the drawer all drew the NEW download's bar: ~98%, then 0%, then
    // climbing again. `None` means "not yours": the caller falls through
    // to the tail arm, which has fixed numbers and needs no counters.
    //
    // The owner is re-read here with the counters, under the one lock
    // the writer sets both in, so no reader can pair a stale owner with
    // the next job's zeroes.
    let active_left = |nzo_id: &str| {
        let owner = d.active_dl.lock_ok();
        if owner.as_deref() != Some(nzo_id) {
            return None;
        }
        // UX §15, preferred whenever the pipeline has published one: both
        // halves are declared NZB bytes of this run's article set, so the
        // fraction reaches exactly 100% at net-drain and cannot pass it,
        // and the seed already includes everything a resume had in hand.
        //
        // The arithmetic below is the fallback, and it is why the plan
        // exists: decoded payload (every slot, PAR2 included) over the
        // NZB's encoded bytes minus recovery volumes stalls near 97% on a
        // clean set - the "1.5 GB left" that is not really left - and
        // tops out early on a damaged one, where the extra recovery bytes
        // land on its numerator alone.
        if let Some(honest) = d.hub.fetch_left() {
            return Some(honest);
        }
        let done = d
            .progress
            .load(Ordering::Relaxed)
            // Bytes a resume never had to fetch. Counted here rather
            // than in the shared counter so that everything measuring
            // the WIRE (quota, average speed, best_rate_bps, the CLI
            // ticker, the rolling speed window) goes on seeing only what
            // this run actually moved. See StreamHub::resume_seeded.
            .saturating_add(d.hub.resume_seeded.load(Ordering::Relaxed));
        let total = d.active_total.load(Ordering::Relaxed).max(1);
        Some((done.min(total), total, total.saturating_sub(done)))
    };
    // Whole-queue bytes still to fetch, for the top-level sizeleft /
    // timeleft SAB carries - accumulated from the very number each row
    // reports, so the header and its rows are the same arithmetic on
    // the same instant by construction. See queue_json for why it is
    // not its own walk.
    let mut remaining_bytes: u64 = 0;
    // ...and the whole queue's declared bytes, on the same walk and for
    // the same reason - SAB's `mb` / `size` header pair is this total
    // against the `mbleft` / `sizeleft` beside it, and two walks could
    // report a total that its own remainder exceeds.
    let mut total_bytes_all: u64 = 0;
    let mut slots: Vec<Value> = Vec::with_capacity(if windowed && limit > 0 {
        limit.min(q.len())
    } else {
        q.len()
    });
    // Rows matching the caller's category / id filter, counted BEFORE
    // the window - SAB's `noofslots`, which is what it always was when
    // pagination happened afterwards.
    let mut n = 0usize;
    // B5: two more whole-queue totals, summed on the walk that
    // already visits every job. The dashboard used to reduce both out
    // of the slot array it was sent, which is exactly the thing a page
    // cannot answer - so paging the rows would have turned two headline
    // numbers into numbers about the page. Pre-filter and pre-window,
    // like `mbleft` beside them.
    let mut runnable_bytes: u64 = 0;
    let mut need_bytes: u64 = 0;
    for (i, j) in q.iter().enumerate() {
        let j = j.lock_ok();
        // §91: both sampled under this slot's lock, after its state
        // was read, so (status, percentage) is one instant.
        //
        // The pipeline's own phase word once past the network; a
        // suspended job answers "Paused" in `slot_json` and its phase
        // would only contradict that.
        //
        // `Downloading` is in the match for the whole post-network
        // stretch, hand-off included: the engine writes `finalizing`
        // while the record still says Downloading and the lane marks it
        // `Finishing` only once it has taken custody. A poll landing in
        // that window with no phase falls through to
        // `j.downloaded_bytes` below - 0, the counters having gone at
        // net-drain - and draws a finished download at 0%.
        let phase = (matches!(j.state, JobState::Downloading | JobState::Finishing)
            && !j.suspended)
            .then(|| d.tail_phase(&j.nzo_id))
            .flatten();
        let live = (j.state == JobState::Downloading)
            .then(|| active_left(&j.nzo_id))
            .flatten();
        let (pct, left) = slot_progress(
            j.state,
            live.map(|(done, total, _)| (done, total)),
            phase.is_some(),
            j.total_bytes,
            j.downloaded_bytes,
        );
        // The queue's own sizeleft, summed here from the row's own
        // remainder - see `remaining_bytes` above. Counted for EVERY
        // job, before the caller's view filter AND before its window:
        // the header describes the whole queue, the rows describe the
        // slice asked for.
        remaining_bytes = remaining_bytes.saturating_add(left);
        total_bytes_all = total_bytes_all.saturating_add(j.total_bytes);
        // What the line can actually work through, for the header ETA:
        // the same two rows the dashboard's own filter meant, spelled
        // the way `slot_json`'s `status` arm renders them. A paused job - and a
        // duplicate held at Duplicate priority is paused - contributes
        // size but never time, and counting it put an ETA on the header
        // that every row underneath contradicted.
        //
        // A row anywhere in the tail is excluded by `phase.is_none()`,
        // the finalize window included: its `left` is 0 by the arm
        // above, so this is the same number either way - but the ETA
        // must not be built out of rows with no bytes left to fetch.
        if (j.state == JobState::Downloading && !j.suspended && phase.is_none())
            || (j.state == JobState::Queued && !j.paused)
        {
            runnable_bytes = runnable_bytes.saturating_add(left);
        }
        // ...and the queue-wide disk forecast behind the "this queue
        // needs about N GB" banner. Per row this is exactly the
        // arithmetic its own amber `space_short` chip uses - so the
        // banner and the chips can no longer disagree about the disk
        // they both describe - and it is the reason this is summed here
        // rather than on the client: a shape that unpacks on disk needs
        // room for the parts AND the payload, which is a fact about the
        // row, not about the page.
        //
        // The move tail is excluded exactly where the chip excludes it.
        // The client's own loop meant to (`status === 'Completed'`) but
        // that row renders as "Moving", so the test never fired.
        if j.state != JobState::Completed {
            let shape = ctx
                .live_shape
                .as_ref()
                .filter(|(owner, _)| *owner == j.nzo_id)
                .map_or(j.archive_shape.as_str(), |(_, tag)| tag.as_str());
            need_bytes = need_bytes.saturating_add(if shape_unpacks_on_disk(shape) {
                unpack_space_needed(left, j.total_bytes, shape)
            } else {
                left
            });
        }
        if !view.cat_filter.is_none_or(|c| j.category == *c)
            || !view.ids.is_none_or(|s| s.contains(j.nzo_id.as_str()))
        {
            continue;
        }
        let rank = n;
        n += 1;
        if windowed
            && !in_window(rank, view.window)
            && !(view.pin_live
                && matches!(
                    j.state,
                    JobState::Downloading | JobState::Finishing | JobState::Completed
                ))
        {
            continue;
        }
        slots.push(slot_json(ctx, i, &j, phase, live.is_some(), pct, left));
    }
    QueueWalk {
        slots,
        matched: n,
        remaining_bytes,
        total_bytes_all,
        runnable_bytes,
        need_bytes,
    }
}
