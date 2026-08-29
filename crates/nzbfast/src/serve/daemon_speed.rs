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
//! becomes `pub(in crate::serve)` here, because `super` is `daemon`
//! from inside a child. The governor is a free function rather than a
//! `Daemon` method, so it and its four constants are re-exported from
//! daemon.rs: tasks.rs drives the AIMD loop and tests_index.rs pins its
//! arithmetic, and both name them unqualified.

use super::*;

pub(in crate::serve) const AUTO_SPEED_TARGET_MS: u64 = 60;
pub(in crate::serve) const AUTO_SPEED_FLOOR: u64 = 512_000;
pub(in crate::serve) const AUTO_SPEED_START: u64 = 8_000_000;
pub(in crate::serve) const AUTO_SPEED_MAX: u64 = 10_000_000_000;

/// M14g3: one 1 Hz auto-speed control step (LEDBAT-flavoured AIMD).
/// `delay_ms` is smoothed RTT minus the base (uncongested) RTT - the
/// queueing delay OUR traffic is inflicting on the household. Above
/// target: multiplicative backoff (yield fast when someone starts a call
/// or a game). Well below target: additive-ish climb to soak spare
/// capacity. Never below the floor (downloads always trickle), never
/// above the user/schedule ceiling.
pub(in crate::serve) fn auto_speed_step(
    delay_ms: u64,
    target_ms: u64,
    cap: u64,
    ceiling: u64,
) -> u64 {
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
    pub(in crate::serve) fn set_speed_ceiling(&self, bps: u64) {
        self.set_speed_ceiling_from(bps, "user");
    }

    /// As [`Self::set_speed_ceiling`], recording WHO chose the number.
    /// A cap a schedule entry applied was presented as the operator's
    /// own setting, so an unexpected 4 MB/s at 08:00 looked like a bug
    /// in the limiter rather than the schedule doing its job.
    pub(in crate::serve) fn set_speed_ceiling_from(&self, bps: u64, src: &'static str) {
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
    pub(in crate::serve) fn cpu_pct(&self) -> f64 {
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
    pub(in crate::serve) fn current_speed_bps(&self) -> f64 {
        // The whole line: the active job's bytes plus whatever the
        // previous job is still draining behind it (the cross-job
        // hand-over), otherwise the figure dips at every queue boundary
        // while the line is in fact full.
        let drain = self
            .drain_dl
            .lock_ok()
            .as_ref()
            .map_or(0, |s| s.progress.load(Ordering::Relaxed));
        let done = self.progress.load(Ordering::Relaxed).saturating_add(drain);
        let active = self.started_at.lock_ok().is_some();
        let mut win = self.speed_win.lock_ok();
        if !active {
            win.clear();
            return 0.0;
        }
        let now = Instant::now();
        if win.back().is_some_and(|&(_, b)| done < b) {
            win.clear();
        }
        win.push_back((now, done));
        while win
            .front()
            .is_some_and(|&(t, _)| now.duration_since(t).as_secs_f64() > 5.0)
        {
            win.pop_front();
        }
        // Drop the leading no-progress samples: at download start the
        // window otherwise spans the TLS/connect handshakes, and the
        // first shown figures are bytes divided by dead time - a rate
        // that climbs to the truth over five seconds and reads as a slow
        // ramp-up the line never had. Measured from the first byte that
        // moved, the first figure is the real one. Steady state is
        // untouched: consecutive one-second samples always differ while
        // bytes flow.
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
}
