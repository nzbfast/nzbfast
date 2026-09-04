//! How fast the line is running, what it costs, and what ceiling is
//! imposed on it (TODO 106 code motion out of daemon.rs).
//!
//! Four facts about ONE rate, and every consumer that reads any of them
//! reads at least two. MEASURED: `current_speed_bps`, the live rate off
//! a ~5 s rolling window of decoded bytes, and `cpu_pct`, what the box
//! is spending to achieve it. IMPOSED: `set_speed_ceiling` /
//! `set_speed_ceiling_from`, the one door every manual, API and
//! scheduled cap change goes through, and `auto_speed_step` with its
//! four constants - the 1 Hz LEDBAT-flavoured AIMD governor that picks
//! its own ceiling from the queueing delay our traffic is inflicting on
//! the household.
//!
//! The two halves are not merely adjacent, they are wired to each
//! other, and the wiring is the reason this is one module. The governor
//! DELIBERATELY BYPASSES `set_speed_ceiling_from`: its per-second steps
//! would otherwise flood the event ring with "speed limit set to ..."
//! markers nobody chose and bump `queue_rev` on a hot path. That is
//! stated twice inside `set_speed_ceiling_from` and is only checkable
//! against `auto_speed_step`, which is now on the same screen.
//!
//! `cpu_pct` belongs with them for the same why-is-it-slow question:
//! whyslow, the download report and the SAB facade read the rate and
//! the CPU figure together, and both go through here so the two
//! consumers cannot disagree - the 500 ms re-poll window exists exactly
//! so a second open dashboard reads the same number rather than
//! amplifying the noise.
//!
//! A second `impl Daemon` in a child module of `daemon`, so `Daemon`'s
//! private fields (`speed_ceiling`, `limit_source`, `speed_win`,
//! `cpu_sample`, `progress`, `drain_dl`, `started_at`, `queue_rev`,
//! `hub`) stay in scope exactly as they were inline. `pub(super)`
//! becomes `pub(crate)` here, because `super` is `daemon`
//! from inside a child. The governor is a free function rather than a
//! `Daemon` method, so it and its four constants are re-exported from
//! daemon.rs: tasks.rs drives the AIMD loop and tests_index.rs pins its
//! arithmetic, and both name them unqualified.

use super::*;

pub const AUTO_SPEED_TARGET_MS: u64 = 60;
pub const AUTO_SPEED_FLOOR: u64 = 512_000;
pub const AUTO_SPEED_START: u64 = 8_000_000;
pub const AUTO_SPEED_MAX: u64 = 10_000_000_000;

/// M14g3: one 1 Hz auto-speed control step (LEDBAT-flavoured AIMD).
/// `delay_ms` is smoothed RTT minus the base (uncongested) RTT - the
/// queueing delay OUR traffic is inflicting on the household. Above
/// target: multiplicative backoff (yield fast when someone starts a call
/// or a game). Well below target: additive-ish climb to soak spare
/// capacity. Never below the floor (downloads always trickle), never
/// above the user/schedule ceiling.
pub fn auto_speed_step(delay_ms: u64, target_ms: u64, cap: u64, ceiling: u64) -> u64 {
    let max = if ceiling == 0 {
        AUTO_SPEED_MAX
    } else {
        ceiling
    };
    let cap = if cap == 0 {
        AUTO_SPEED_START.min(max)
    } else {
        cap
    };
    let new = if delay_ms > target_ms {
        (cap as f64 * 0.8) as u64
    } else if delay_ms < target_ms / 2 {
        (cap as f64 * 1.10) as u64 + 250_000
    } else {
        cap
    };
    new.clamp(AUTO_SPEED_FLOOR.min(max), max)
}

impl Daemon {
    /// Route every manual/scheduled cap change through here so the
    /// governor's ceiling stays in sync.
    pub fn set_speed_ceiling(&self, bps: u64) {
        self.set_speed_ceiling_from(bps, "user");
    }

    /// As [`Self::set_speed_ceiling`], recording WHO chose the number.
    /// A cap a schedule entry applied was presented as the operator's
    /// own setting, so an unexpected 4 MB/s at 08:00 looked like a bug
    /// in the limiter rather than the schedule doing its job.
    pub fn set_speed_ceiling_from(&self, bps: u64, src: &'static str) {
        // Marker on change only: startup re-applies the persisted cap
        // through here, and re-applying the number already in force is
        // not a change anyone made. The auto-speed governor's AIMD
        // steps deliberately bypass this method, so they cannot flood
        // the ring either.
        let old = self.speed_ceiling.swap(bps, Ordering::Relaxed);
        if old != bps {
            let who = match src {
                "schedule" => " by the schedule",
                "api" => " by an API client",
                _ => "",
            };
            let detail = if bps == 0 {
                format!("speed limit removed{who}")
            } else {
                format!("speed limit set to {:.1} MB/s{who}", bps as f64 / 1e6)
            };
            self.note_event("limit", detail);
        }
        *self.limit_source.lock_ok() = src;
        // The cap and its source ride the revisioned queue payload, and
        // the two paths that reach here without going through
        // `apply_and_save` - a schedule entry firing, and the SAB
        // facade's speedlimit - would otherwise leave every open
        // dashboard showing the old number until something else moved
        // the revision. Safe to bump on every call: the auto-speed
        // governor's per-second AIMD steps bypass this method (see
        // above), so there is no hot path behind it.
        self.queue_rev.fetch_add(1, Ordering::Relaxed);
        self.hub.rate.set(bps);
    }

    /// All-core CPU% (0-100) from the process cpu-time delta since the
    /// previous call. One getrusage/task_info per call, no sampling
    /// thread; sub-500 ms re-polls (a second open dashboard, or the
    /// stats poll landing beside the whyslow ticker) reuse the last
    /// reading instead of amplifying noise. Shared sample state - both
    /// consumers reading through here is what keeps them agreeing.
    pub fn cpu_pct(&self) -> f64 {
        let now = Instant::now();
        let cpu = nzbkit::mem::cpu_time_secs().unwrap_or(0.0);
        // cpu-workers-gate: the divisor that turns CPU seconds into a
        // percentage of this machine. A cap would make a loaded box read
        // as busier than it is.
        let ncpu = std::thread::available_parallelism().map_or(1, |n| n.get()) as f64;
        let mut prev = self.cpu_sample.lock_ok();
        match *prev {
            Some((t0, _, last)) if now.duration_since(t0).as_secs_f64() < 0.5 => last,
            Some((t0, c0, _)) => {
                let wall = now.duration_since(t0).as_secs_f64();
                let pct = ((cpu - c0) / wall / ncpu * 100.0).clamp(0.0, 100.0);
                *prev = Some((now, cpu, pct));
                pct
            }
            None => {
                *prev = Some((now, cpu, 0.0));
                0.0
            }
        }
    }

    /// Live download speed (bytes/sec) over a ~5 s rolling window of
    /// decoded-byte samples (also feeds queue_json's kbpersec).
    pub fn current_speed_bps(&self) -> f64 {
        // The whole line: the active job's bytes plus whatever the
        // previous job is still draining behind it (the cross-job
        // hand-over), otherwise the figure dips at every queue boundary
        // while the line is in fact full.
        let active = self.started_at.lock_ok().is_some();
        if !active {
            self.speed_win.lock_ok().clear();
            return 0.0;
        }
        // BOTH counters inside the closure, so both are read under the
        // window's lock - see `window_rate`. The drain slot is the other
        // half of this figure, so a stale reading of it inverts exactly
        // as a stale reading of `progress` would. Lock order is
        // speed_win -> drain_dl and there is no other: `speed_win` is
        // touched here and nowhere else in the tree.
        window_rate(&self.speed_win, || {
            let drain = self
                .drain_dl
                .lock_ok()
                .as_ref()
                .map_or(0, |s| s.progress.load(Ordering::Relaxed));
            self.progress.load(Ordering::Relaxed).saturating_add(drain)
        })
    }
}

/// Bytes/sec over a ~5 s rolling window of monotonic byte samples.
///
/// `read_done` is called INSIDE the window's own lock, and that is the
/// point of taking a closure rather than a number. Every poll of the
/// queue payload samples these windows, several can be in flight at
/// once (a dashboard, a phone remote, a *arr), and a counter read
/// BEFORE the lock lets two readers arrive out of order - the later
/// reading pushed first, the earlier one then looking like a counter
/// that went backwards, which drops the window.
///
/// Closed on inspection rather than after an incident, and said plainly
/// because the two are easy to confuse: this is NOT what caused the
/// 29 Aug 2026 sawtooth on the early start's trace - the eviction rule
/// below was, and closing this one did not move it. What makes the hole
/// worth closing anyway is that the early start reads at ~780 MB/s,
/// where the counter moves ~780 bytes per microsecond, so any
/// reordering at all inverts. Under the lock it cannot happen rather
/// than being unlikely, and the closure is what makes that structural
/// instead of a rule the next caller has to remember.
///
/// Shared rather than copied, because there is a SECOND live rate now:
/// the idle-server early start runs its own pipeline on its own counter
/// (`Sidecar::rate_bps`), and the dashboard draws the two as two series
/// on one chart. Two hand-copied windows would be two rates computed
/// slightly differently and drawn against each other as if they were
/// comparable - which is the one thing a second series on the same axis
/// promises. Every rule below is therefore in one place:
///
/// * a counter that went BACKWARDS is a new download on a reused window,
///   so the window is dropped rather than reporting a negative rate as a
///   huge positive one;
/// * samples older than 5 s leave, BUT never the last two. A window fed
///   by its own readers must not be able to evict itself empty: a client
///   polling more slowly than the window is long would then find one
///   sample every time and read 0 forever. Measured on a live early
///   start at ~777 MB/s on 29 Aug 2026 - a background dashboard tab
///   backs its poll off past five seconds, and the second trace
///   alternated its true rate with zero, once per poll. Held to two, a
///   sparse poller gets an honest average over its own gap instead;
/// * the leading no-progress samples are dropped, because at download
///   start the window otherwise spans the TLS/connect handshakes and the
///   first figures are bytes divided by dead time - a rate that climbs
///   to the truth over five seconds and reads as a slow ramp-up the line
///   never had. Measured from the first byte that moved, the first
///   figure is the real one. Steady state is untouched: consecutive
///   one-second samples always differ while bytes flow;
/// * under a quarter second of span is not a measurement.
pub(crate) fn window_rate(
    win: &Mutex<VecDeque<(Instant, u64)>>,
    read_done: impl FnOnce() -> u64,
) -> f64 {
    let win = &mut *win.lock_ok();
    let done = read_done();
    let now = Instant::now();
    if win.back().is_some_and(|&(_, b)| done < b) {
        win.clear();
    }
    win.push_back((now, done));
    while win.len() > 2
        && win
            .front()
            .is_some_and(|&(t, _)| now.duration_since(t).as_secs_f64() > 5.0)
    {
        win.pop_front();
    }
    while win.len() >= 2 && win[0].1 == win[1].1 {
        win.pop_front();
    }
    match (win.front(), win.back()) {
        (Some(&(t0, b0)), Some(&(t1, b1))) if t1.duration_since(t0).as_secs_f64() > 0.25 => {
            (b1 - b0) as f64 / t1.duration_since(t0).as_secs_f64()
        }
        _ => 0.0,
    }
}

#[cfg(test)]
mod window_rate_tests {
    use super::*;

    /// The counter must be read INSIDE the window's lock, or two
    /// concurrent pollers can invert and the earlier reading clears the
    /// window - which is what put a 765 / 0 / 765 / 0 sawtooth on the
    /// early start's chart trace before this was a closure.
    ///
    /// Ordering is proved rather than raced: the test holds the lock,
    /// and while it does, the reader parked behind it must not have
    /// sampled anything. A machine slow enough that the thread has not
    /// reached the lock yet fails this test in the SAFE direction (it
    /// passes), so there is no flaky red in it.
    #[test]
    fn the_counter_is_never_read_before_the_window_lock() {
        let win: Arc<Mutex<VecDeque<(Instant, u64)>>> = Arc::new(Mutex::new(VecDeque::new()));
        let sampled = Arc::new(AtomicU64::new(0));
        let guard = win.lock_ok();
        let t = {
            let win = win.clone();
            let sampled = sampled.clone();
            std::thread::spawn(move || {
                window_rate(&win, || {
                    sampled.fetch_add(1, Ordering::SeqCst);
                    7
                })
            })
        };
        std::thread::sleep(std::time::Duration::from_millis(60));
        assert_eq!(
            sampled.load(Ordering::SeqCst),
            0,
            "the counter was sampled while the window was locked by someone else"
        );
        drop(guard);
        t.join().expect("reader");
        assert_eq!(
            sampled.load(Ordering::SeqCst),
            1,
            "and it is sampled exactly once, once the lock is free"
        );
        assert_eq!(win.lock_ok().len(), 1, "the reading reached the window");
    }

    /// A reader slower than the window is long still gets a rate. The
    /// window is fed BY its readers, so evicting on age alone let it
    /// empty itself: one sample in, everything else aged out, 0 back,
    /// every time. That is what put a 777 / 0 / 777 / 0 sawtooth on the
    /// early start's trace when the dashboard tab went to the
    /// background and backed its poll off past five seconds.
    #[test]
    fn a_poller_slower_than_the_window_still_reads_a_rate() {
        let win = Mutex::new(VecDeque::new());
        assert_eq!(window_rate(&win, || 0), 0.0, "one sample is no rate");
        // Six seconds is past the window's own length, so age alone
        // would have taken the first sample with it.
        let old = Instant::now() - std::time::Duration::from_secs(6);
        win.lock_ok().front_mut().expect("the first sample").0 = old;
        let r = window_rate(&win, || 600_000_000);
        assert!(
            (r - 100_000_000.0).abs() < 1_000_000.0,
            "600 MB over ~6 s is ~100 MB/s, not zero: {r}"
        );
        assert_eq!(
            win.lock_ok().len(),
            2,
            "the older sample was kept, not aged out"
        );
    }

    /// ...and a busy poller still gets a ~5 s window rather than the
    /// whole run, which is what makes the figure follow a stall.
    #[test]
    fn a_busy_poller_still_gets_a_rolling_window() {
        let win = Mutex::new(VecDeque::new());
        for i in 0..8 {
            window_rate(&win, || i * 1_000);
        }
        let n = win.lock_ok().len();
        assert_eq!(n, 8, "nothing is old enough to leave yet");
        // Age everything but the last two past the window.
        let old = Instant::now() - std::time::Duration::from_secs(9);
        for e in win.lock_ok().iter_mut().take(6) {
            e.0 = old;
        }
        window_rate(&win, || 9_000);
        assert_eq!(
            win.lock_ok().len(),
            3,
            "the six stale samples left; the two fresh ones and the new one stay"
        );
    }

    /// A counter that really did go backwards - a new download on a
    /// reused window - drops the history rather than reporting the
    /// difference as an enormous positive rate.
    #[test]
    fn a_counter_that_went_backwards_drops_the_window() {
        let win = Mutex::new(VecDeque::new());
        assert_eq!(window_rate(&win, || 1_000), 0.0, "one sample is no rate");
        assert_eq!(win.lock_ok().len(), 1);
        assert_eq!(window_rate(&win, || 10), 0.0);
        assert_eq!(
            win.lock_ok().len(),
            1,
            "the older history went with the counter that no longer explains it"
        );
    }
}
