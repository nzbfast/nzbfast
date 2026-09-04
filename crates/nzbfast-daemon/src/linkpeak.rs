//! §125: the throughput graph's 100% line - learn the link's real peak.
//!
//! The graph used to scale to whatever the visible window happened to
//! contain, so "how are we doing" had no fixed answer: a line hugging
//! the top might be a saturated 10 Gbit link or a bad hour on a 1 Gbit
//! one. The anchor this module learns gives the chart a stable
//! definition of 100%: the best rate this link has actually sustained.
//! Working well then LOOKS like working well - a band riding the top -
//! and a shortfall is legible as the gap it is.
//!
//! Three sources, in order of authority:
//!
//! 1. MEASURED: the best 30 s sustained rate ever observed, persisted
//!    to .spool/linkpeak.json (the same measure-then-remember shape as
//!    the connection knee in conntune.json). Observation is the truth.
//! 2. LINE: the Settings line speed. It seeds the anchor so the graph
//!    is honest from the first download - but it is a PRIOR, and it
//!    only rules while no measurement has either beaten it or gathered
//!    enough evidence against it (see `invalidated_line_bps`).
//! 3. Nothing: anchor unknown, the dashboard keeps its old
//!    scale-to-window behaviour.
//!
//! Learning is deliberately asymmetric. Raising is instant: a sustained
//! window above the anchor is proof the link can do it (a VU meter
//! never clips the incoming spike). Lowering needs real evidence:
//! being below peak while downloading is normal - small-job tails,
//! provider ceilings, a slow remote - so only a long stretch of
//! full-effort, unthrottled downloading that never comes near the
//! anchor is allowed to pull it down. How long depends on what is
//! being disowned: demonstrated fact (a measured anchor, or a typed
//! line the link once confirmed) takes the full three hours, while a
//! never-confirmed typed line falls on a clock that shrinks with the
//! size of the shortfall (see `downlearn_secs`). The clock itself is
//! persisted, so a desktop install that quits between sessions still
//! accumulates its verdict. Semi-permanent, in other words: the anchor
//! moves only when future measurements invalidate it.
//!
//! What never counts as evidence: seconds with a user speed limit in
//! force below the anchor (a throttled line cannot demonstrate
//! anything), and seconds with no bytes moving (a stalled provider is
//! a provider problem, not a link measurement).

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Instant;

use crate::tools::MutexExt;

/// A "sustained" rate is the average over this many consecutive
/// countable seconds. Long enough to flatten the write-side sawtooth
/// and per-article jitter, short enough that a real peak inside an
/// ordinary download registers.
const SUSTAIN_SECS: usize = 30;

/// A sustained window at or above this fraction of the anchor counts as
/// the link confirming it, and resets the down-learn clock. 90%, not
/// 100%: riding within a TLS-overhead of the peak is the peak.
const CONFIRM_BAR: f64 = 0.9;

/// Full-effort active seconds below the confirm bar before the anchor
/// lowers to the best rate that stretch actually reached. Three hours
/// of unthrottled downloading that never came within 10% of the anchor
/// is evidence about the LINK, not about one job. This is the FULL
/// clock, for near misses; the further below the anchor the evidence
/// sits, the less of it is needed - see [`Core::downlearn_secs`].
const DOWNLEARN_SECS: u64 = 3 * 3600;

/// The down-learn clock never shrinks below this, however large the
/// gap: twenty minutes of full-effort seconds is one substantial
/// download, and nothing shorter should disown a typed line speed.
const DOWNLEARN_FLOOR_SECS: u64 = 20 * 60;

/// Countable seconds of backing before the best-sustained-so-far is
/// solid enough to drive the units hint (see [`Core::line_hint`]).
/// Ten full-effort minutes is one substantial job, not a blip.
const HINT_SECS: u64 = 10 * 60;

/// Raise only past this margin, so jitter exactly at the peak does not
/// churn the stored value (and its persist) every window.
const RAISE_MARGIN: f64 = 1.01;

/// Persist a raise at most this often; the final value always lands on
/// the next quiet tick. Lowerings persist immediately - they carry three
/// hours of evidence and happen once.
const SAVE_MIN_SECS: u64 = 30;

/// What linkpeak.json holds.
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct Stored {
    /// Best sustained rate measured on this link, bytes/sec. 0 = no
    /// measurement yet.
    #[serde(default)]
    pub measured_bps: u64,
    /// Unix time of the last change, for the curious reading the file.
    #[serde(default)]
    pub checked: u64,
    /// The Settings line speed this learner gathered DOWNLEARN_SECS of
    /// evidence against. While the setting still holds this exact
    /// value, the (lower) measurement rules the anchor; the moment the
    /// user types a DIFFERENT line speed, that new declaration becomes
    /// a live prior again and gets its own chance. Retyping after an
    /// ISP upgrade therefore reseeds the graph instantly instead of
    /// arguing with stale evidence about the old plan.
    #[serde(default)]
    pub invalidated_line_bps: u64,
    /// The typed line speed a sustained window once proved real (a
    /// window at or above CONFIRM_BAR of it). A confirmed line that
    /// now underperforms is provider information the chart should keep
    /// exposing, so disowning it always takes the full DOWNLEARN_SECS;
    /// only a never-confirmed prior gets the gap-scaled fast path.
    #[serde(default)]
    pub confirmed_line_bps: u64,
    /// The down-learn evidence clock, persisted so a desktop install
    /// that quits between sessions can still accumulate a verdict: the
    /// anchor the evidence argues against, the countable full-window
    /// seconds gathered, and the best sustained rate they reached.
    /// Zeroed whenever the anchor is confirmed or changes.
    #[serde(default)]
    pub clock_anchor_bps: u64,
    #[serde(default)]
    pub clock_secs: u64,
    #[serde(default)]
    pub clock_best_bps: u64,
}

/// The learner, pure of IO so tests can drive it a simulated second at
/// a time.
#[derive(Default)]
pub struct Core {
    pub(super) stored: Stored,
    /// The last up-to-SUSTAIN_SECS countable samples, bytes/sec.
    /// Cleared by any non-countable second, so a full window really is
    /// consecutive. Deliberately NOT persisted (unlike the clock in
    /// `stored`): thirty seconds refills it, and a stale window from a
    /// previous session would be exactly the non-consecutive evidence
    /// this exists to exclude.
    win: VecDeque<f64>,
}

impl Core {
    /// The anchor the dashboard should treat as 100%, and where it came
    /// from: ("measured" | "line"), or (0, "") when nothing is known.
    pub(super) fn effective(&self, line_bps: u64) -> (u64, &'static str) {
        let m = self.stored.measured_bps;
        if m > 0 && (line_bps == 0 || m >= line_bps || self.stored.invalidated_line_bps == line_bps)
        {
            (m, "measured")
        } else if line_bps > 0 {
            (line_bps, "line")
        } else {
            (0, "")
        }
    }

    /// Feed one second of observation. Returns true when `stored`
    /// changed and should (eventually) be persisted.
    pub(super) fn step(&mut self, bps: f64, throttle_bps: u64, line_bps: u64) -> bool {
        let (anchor, _) = self.effective(line_bps);
        // A user speed limit below (or near) the anchor makes every
        // sample a measurement of the limiter. Near, not just below:
        // a cap AT the anchor still clips the peaks that would confirm
        // it, so give it 5% of air before trusting the samples again.
        // No anchor yet = ANY active cap rules the samples out: with
        // anchor 0 the comparison below is vacuously false, and the
        // first 30 s window would store the limiter's rate as the
        // link's first "measured" peak.
        if throttle_bps > 0 && (anchor == 0 || (throttle_bps as f64) < anchor as f64 * 1.05) {
            self.win.clear();
            return false;
        }
        if bps <= 0.0 {
            self.win.clear();
            return false;
        }
        self.win.push_back(bps);
        if self.win.len() > SUSTAIN_SECS {
            self.win.pop_front();
        }
        if self.win.len() < SUSTAIN_SECS {
            return false;
        }
        let sustained = self.win.iter().sum::<f64>() / self.win.len() as f64;
        let mut changed = false;
        // A window at or above the confirm bar of the TYPED line proves
        // that declaration real, whatever currently rules the anchor.
        // Once proven, only the full three-hour clock may disown it.
        if line_bps > 0
            && sustained >= line_bps as f64 * CONFIRM_BAR
            && self.stored.confirmed_line_bps != line_bps
        {
            self.stored.confirmed_line_bps = line_bps;
            changed = true;
        }
        // The clock is evidence against ONE anchor. If the anchor moved
        // since it started counting (a retyped line speed, a raise, or
        // a restart into different settings), what it gathered argues
        // about something that no longer rules - start over.
        if self.stored.clock_anchor_bps != anchor {
            self.stored.clock_anchor_bps = anchor;
            self.stored.clock_secs = 0;
            self.stored.clock_best_bps = 0;
        }
        self.stored.clock_secs += 1;
        self.stored.clock_best_bps = self.stored.clock_best_bps.max(sustained as u64);
        if anchor == 0 || sustained > anchor as f64 * RAISE_MARGIN {
            // Demonstrated. Raise instantly (or record the very first
            // measurement); the graph rescales and stays there.
            self.stored.measured_bps = sustained as u64;
            self.reset_clock();
            true
        } else if sustained >= anchor as f64 * CONFIRM_BAR {
            // The link just showed it can still do (about) the anchor.
            self.reset_clock();
            changed
        } else if self.stored.clock_best_bps > 0
            && self.stored.clock_secs >= self.downlearn_secs(line_bps)
        {
            // Enough full-effort downloading never came near the
            // anchor: the real peak is what that stretch actually
            // reached. If a typed line speed was ruling, it is the
            // thing being disowned - remember which value, so only THAT
            // declaration stays overridden.
            if line_bps > 0 && self.stored.clock_best_bps < line_bps {
                self.stored.invalidated_line_bps = line_bps;
            }
            self.stored.measured_bps = self.stored.clock_best_bps;
            self.reset_clock();
            true
        } else {
            changed
        }
    }

    /// How much full-effort evidence a down-learn needs. Two tiers:
    ///
    /// A MEASURED anchor, or a typed line the link once confirmed, is
    /// demonstrated fact - a proven line that now underperforms is
    /// provider information the chart should keep exposing, so
    /// disowning fact always takes the full three hours, however large
    /// the gap.
    ///
    /// A NEVER-confirmed typed line is only a claim, and the required
    /// evidence scales with how far below it the best sustained rate
    /// sits. A miss just under the confirm bar still keeps (about) the
    /// full clock - that could be one bad evening. An 8x shortfall is
    /// a different animal: it is the signature of a line speed typed
    /// in the wrong units (a 1 Gbps plan entered as "1G" parses as
    /// 1 GB/s), and a graph anchored to it renders a saturated link as
    /// ~12%. Evidence that far out earns its verdict within one big
    /// download, floored so a short burst never decides.
    fn downlearn_secs(&self, line_bps: u64) -> u64 {
        let (anchor, src) = self.effective(line_bps);
        if anchor == 0
            || src != "line"
            || self.stored.confirmed_line_bps == line_bps
            || self.stored.clock_best_bps == 0
        {
            return DOWNLEARN_SECS;
        }
        // Normalised to the confirm bar, so the clock reaches the full
        // three hours as the evidence approaches the bar that would
        // have confirmed the anchor instead.
        let ratio = (self.stored.clock_best_bps as f64 / anchor as f64 / CONFIRM_BAR).min(1.0);
        ((DOWNLEARN_SECS as f64 * ratio) as u64).max(DOWNLEARN_FLOOR_SECS)
    }

    /// The bits-typed-as-bytes tell: a typed line speed whose best
    /// sustained evidence sits near one EIGHTH of it. Providers sell
    /// megabits and this box reads a bare magnitude as bytes, so "1G"
    /// on a 1 Gbps plan anchors the graph 8x high. True while the
    /// evidence (the live best-sustained once a substantial stretch
    /// backs it, or the stored measurement after the down-learn has
    /// disowned THIS typed value) lands in the 0.10-0.16 band of the
    /// setting. Bool only - the wording lives in the page, where it
    /// can be translated.
    pub(super) fn line_hint(&self, line_bps: u64) -> bool {
        if line_bps == 0 {
            return false;
        }
        let live = if self.stored.clock_secs >= HINT_SECS {
            self.stored.clock_best_bps
        } else {
            0
        };
        let disowned = if self.stored.invalidated_line_bps == line_bps {
            self.stored.measured_bps
        } else {
            0
        };
        let best = live.max(disowned);
        best > 0 && (0.10..=0.16).contains(&(best as f64 / line_bps as f64))
    }

    fn reset_clock(&mut self) {
        self.stored.clock_secs = 0;
        self.stored.clock_best_bps = 0;
    }
}

/// The daemon-facing wrapper: Core behind a lock, plus load/persist.
pub struct LinkPeak {
    core: Mutex<Core>,
    path: PathBuf,
    /// (last persist instant, dirty) - raises are throttled to
    /// SAVE_MIN_SECS, and `dirty` makes sure the settled value lands on
    /// a later tick instead of staying memory-only.
    save: Mutex<(Option<Instant>, bool)>,
}

impl LinkPeak {
    pub fn load(path: PathBuf) -> Self {
        let stored = crate::persist::load_json_with_backup(&path)
            .and_then(|v| serde_json::from_value::<Stored>(v).ok())
            .unwrap_or_default();
        LinkPeak {
            core: Mutex::new(Core {
                stored,
                ..Core::default()
            }),
            path,
            save: Mutex::new((None, false)),
        }
    }

    /// The dashboard's 100% anchor - see [`Core::effective`].
    pub fn effective(&self, line_bps: u64) -> (u64, &'static str) {
        self.core.lock_ok().effective(line_bps)
    }

    /// Everything the queue poll's chart block needs, in one lock:
    /// the anchor, its source, and the units hint ([`Core::line_hint`]).
    pub fn chart(&self, line_bps: u64) -> (u64, &'static str, bool) {
        let c = self.core.lock_ok();
        let (bps, src) = c.effective(line_bps);
        (bps, src, c.line_hint(line_bps))
    }

    /// One second of observation from the ticker.
    pub fn tick(&self, bps: f64, throttle_bps: u64, line_bps: u64) {
        let (changed, lowered, clock_moved, snapshot) = {
            let mut c = self.core.lock_ok();
            let before = c.stored.measured_bps;
            let secs_before = c.stored.clock_secs;
            let changed = c.step(bps, throttle_bps, line_bps);
            if changed {
                c.stored.checked = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
            }
            (
                changed,
                changed && c.stored.measured_bps < before,
                c.stored.clock_secs != secs_before,
                c.stored.clone(),
            )
        };
        let mut save = self.save.lock_ok();
        let due = changed
            && (lowered
                || save
                    .0
                    .is_none_or(|t| t.elapsed().as_secs() >= SAVE_MIN_SECS));
        // A raise inside the throttle window only marks dirty; the next
        // tick past the window writes the settled value. The evidence
        // clock rides the same dirty path: it advances every countable
        // second, so during a download the file settles into one write
        // per SAVE_MIN_SECS, and a restart resumes the clock instead of
        // handing the wrong prior a fresh three hours.
        if (changed && !due) || clock_moved {
            save.1 = true;
        }
        let flush_dirty = save.1
            && save
                .0
                .is_none_or(|t| t.elapsed().as_secs() >= SAVE_MIN_SECS);
        if due || flush_dirty {
            *save = (Some(Instant::now()), false);
            drop(save);
            let wrote = serde_json::to_vec_pretty(&snapshot)
                .map_err(|_| ())
                .and_then(|b| crate::persist::write_atomic(&self.path, &b).map_err(|_| ()));
            // A failed write (transient ENOSPC, read-only mount) must
            // stay DIRTY: with a stable peak no later tick changes
            // state, so clearing the bit here meant the anchor was
            // never persisted and a restart forgot it. The ticker is
            // the only caller, so re-arming after the drop is safe.
            if wrote.is_err() {
                self.save.lock_ok().1 = true;
            }
        }
    }

    /// The Settings line speed changed: clear the sample window. The
    /// down-learn clock needs nothing here - it is keyed to the anchor
    /// it gathered evidence against (`clock_anchor_bps`) and resets
    /// itself on the first step under a different one, so a retyped
    /// declaration can never be disowned by the old value's evidence.
    /// The window's 30 s of samples were taken under the old regime,
    /// though, and a sustained window straddling the change would blend
    /// the two - drop them and start clean.
    pub fn line_changed(&self) {
        self.core.lock_ok().win.clear();
    }
}

/// The 1 s ticker. Reads the same rolling speed window the queue API
/// serves, so the learner and the readout can never disagree about what
/// the link was doing.
pub fn spawn(daemon: &std::sync::Arc<super::daemon::Daemon>) {
    use std::sync::atomic::Ordering;
    let d = daemon.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            let bps = d.current_speed_bps();
            let throttle = d.hub.rate.get();
            let line = d.line_speed.load(Ordering::Relaxed);
            d.link_peak.tick(bps, throttle, line);
            // §129 4b rides the same readings: the learner and the
            // attribution can never disagree about what the link did.
            super::whyslow::feed(&d, bps, throttle, line);
            // TODO 275 item 1 part 2 rides this loop too, for the same
            // reason and one level down: what a SOCKET carried, banked
            // for the next job's fleet seed. It reads the pool's own
            // published maximum rather than these bytes - the divisor
            // is `workers_dialling`, which only the pool knows.
            super::linecarry::feed(&d);
            // TODO 313 rides it too, and one level up: whether the job
            // on the wire is USING the sockets it holds, and if not,
            // lending them to the queue. Reads the carry banked a line
            // above as its denominator, so the two can never disagree
            // about what a socket on this link carries. Returns at once
            // with the switch off, which is every install today.
            super::spill::feed(&d);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(c: &mut Core, secs: usize, bps: f64, throttle: u64, line: u64) {
        for _ in 0..secs {
            c.step(bps, throttle, line);
        }
    }

    #[test]
    fn first_sustained_window_becomes_the_measurement() {
        let mut c = Core::default();
        run(&mut c, SUSTAIN_SECS - 1, 100e6, 0, 0);
        assert_eq!(c.effective(0), (0, ""), "no anchor before a full window");
        c.step(100e6, 0, 0);
        assert_eq!(c.effective(0), (100_000_000, "measured"));
    }

    /// Bug sweep 2026-08-07: with NO anchor yet, an active speed limit
    /// meant the anchor==0 comparison was vacuously false, so a fresh
    /// install with a cap (or auto_speed ramping) stored the LIMITER's
    /// rate as the link's first "measured" peak. Throttled seconds are
    /// evidence of nothing, anchored or not.
    #[test]
    fn a_throttled_fresh_install_learns_nothing() {
        let mut c = Core::default();
        run(&mut c, SUSTAIN_SECS + 10, 5e6, 5_000_000, 0);
        assert_eq!(c.effective(0), (0, ""), "the cap is not the link");
        // The cap lifts: the real link measures normally.
        run(&mut c, SUSTAIN_SECS, 100e6, 0, 0);
        assert_eq!(c.effective(0), (100_000_000, "measured"));
    }

    #[test]
    fn line_speed_seeds_until_measurement_beats_it() {
        let mut c = Core::default();
        let line = 1_000_000_000;
        run(&mut c, SUSTAIN_SECS + 10, 500e6, 0, line);
        // Below the seed: the typed number still rules the anchor, and
        // nothing is stored yet - a rate under the prior is not a
        // measurement of the link until the down-learn evidence says so.
        assert_eq!(c.effective(line), (line, "line"));
        assert_eq!(c.stored.measured_bps, 0);
        // Above the seed: observation takes over instantly.
        run(&mut c, SUSTAIN_SECS, 1.2e9, 0, line);
        assert_eq!(c.effective(line), (1_200_000_000, "measured"));
    }

    #[test]
    fn hours_below_the_seed_disown_it() {
        let mut c = Core::default();
        let line = 1_000_000_000;
        run(
            &mut c,
            SUSTAIN_SECS + DOWNLEARN_SECS as usize,
            500e6,
            0,
            line,
        );
        assert_eq!(
            c.effective(line),
            (500_000_000, "measured"),
            "three active hours of evidence lower the anchor"
        );
        assert_eq!(c.stored.invalidated_line_bps, line);
        // A DIFFERENT typed value is a fresh declaration and seeds again.
        assert_eq!(c.effective(2_000_000_000), (2_000_000_000, "line"));
    }

    #[test]
    fn confirming_windows_reset_the_downlearn_clock() {
        let mut c = Core::default();
        run(&mut c, SUSTAIN_SECS, 1e9, 0, 0);
        assert_eq!(c.stored.measured_bps, 1_000_000_000);
        // Alternate long slow stretches with an occasional confirming
        // window; the clock never accumulates DOWNLEARN_SECS.
        for _ in 0..5 {
            run(&mut c, (DOWNLEARN_SECS / 2) as usize, 500e6, 0, 0);
            run(&mut c, SUSTAIN_SECS, 950e6, 0, 0);
        }
        assert_eq!(
            c.effective(0),
            (1_000_000_000, "measured"),
            "an anchor the link keeps confirming does not decay"
        );
    }

    #[test]
    fn throttled_and_idle_seconds_are_not_evidence() {
        let mut c = Core::default();
        run(&mut c, SUSTAIN_SECS, 1e9, 0, 0);
        // A 100 MB/s user cap: three "hours" at the cap teach nothing.
        run(&mut c, DOWNLEARN_SECS as usize + 100, 100e6, 100_000_000, 0);
        assert_eq!(c.effective(0), (1_000_000_000, "measured"));
        // Idle seconds break the window: 29 fast samples, a stall, 29
        // more - never a sustained window, never a raise.
        let mut c2 = Core::default();
        run(&mut c2, SUSTAIN_SECS - 1, 2e9, 0, 0);
        c2.step(0.0, 0, 0);
        run(&mut c2, SUSTAIN_SECS - 1, 2e9, 0, 0);
        assert_eq!(c2.effective(0), (0, ""));
    }

    #[test]
    fn eightfold_shortfall_corrects_within_one_download() {
        // A 1 Gbps plan typed as "1G": the setting parses as 1e9
        // BYTES/s, the real link tops out near 118 MB/s. The gap-scaled
        // clock (ratio 0.118/0.9 of three hours, ~24 min) must disown
        // the seed inside one big download, not after three hours.
        let mut c = Core::default();
        let line = 1_000_000_000;
        run(&mut c, SUSTAIN_SECS + 1200, 118e6, 0, line);
        assert_eq!(
            c.effective(line),
            (line, "line"),
            "twenty minutes is not yet a verdict at this ratio"
        );
        run(&mut c, 1200, 118e6, 0, line);
        assert_eq!(
            c.effective(line),
            (118_000_000, "measured"),
            "within one big download the graph rescales to the real link"
        );
        assert_eq!(c.stored.invalidated_line_bps, line);
    }

    #[test]
    fn near_miss_still_takes_the_full_clock() {
        // 85% of the anchor is a shortfall a bad evening can produce,
        // nowhere near the wrong-units signature: most of the original
        // three hours (0.85/0.9 of it, ~2.8 h) must still be required.
        let mut c = Core::default();
        let line = 1_000_000_000;
        run(
            &mut c,
            SUSTAIN_SECS + DOWNLEARN_SECS as usize * 8 / 10,
            850e6,
            0,
            line,
        );
        assert_eq!(
            c.effective(line),
            (line, "line"),
            "2.4 h of a 90%-ish miss is not enough evidence"
        );
        run(&mut c, DOWNLEARN_SECS as usize / 2, 850e6, 0, line);
        assert_eq!(c.effective(line), (850_000_000, "measured"));
    }

    #[test]
    fn downlearn_never_faster_than_the_floor() {
        // However huge the gap (here 3% of the anchor, nominal clock
        // ~6 min), nothing shorter than the 20 min floor may decide.
        let mut c = Core::default();
        let line = 1_000_000_000;
        run(&mut c, SUSTAIN_SECS + 600, 30e6, 0, line);
        assert_eq!(
            c.effective(line),
            (line, "line"),
            "ten minutes never disowns a typed line speed"
        );
        run(&mut c, 700, 30e6, 0, line);
        assert_eq!(c.effective(line), (30_000_000, "measured"));
    }

    #[test]
    fn confirmed_line_keeps_the_full_clock() {
        // The link once proved the typed 1 GB/s line real (a sustained
        // window at 95% of it). When it later sits at an eighth, that
        // is provider information, not a wrong setting: the fast
        // gap-scaled path must NOT apply, and the full three hours of
        // evidence are still required - exactly today's behavior.
        let mut c = Core::default();
        let line = 1_000_000_000;
        run(&mut c, SUSTAIN_SECS, 950e6, 0, line);
        assert_eq!(c.stored.confirmed_line_bps, line);
        assert_eq!(c.effective(line), (line, "line"));
        // An idle second between the fast and slow eras, so the slow
        // era's windows are purely slow samples rather than a decaying
        // blend of both (the blend is what a real taper looks like and
        // it counts, but this test wants clean figures).
        c.step(0.0, 0, line);
        run(
            &mut c,
            SUSTAIN_SECS + DOWNLEARN_SECS as usize - 130,
            125e6,
            0,
            line,
        );
        assert_eq!(
            c.effective(line),
            (line, "line"),
            "an 8x gap alone must not fast-track a once-proven line"
        );
        run(&mut c, 200, 125e6, 0, line);
        assert_eq!(c.effective(line), (125_000_000, "measured"));
        assert_eq!(c.stored.invalidated_line_bps, line);
    }

    #[test]
    fn evidence_clock_survives_a_reload() {
        // 1000 countable seconds against the wrong prior, then the
        // daemon restarts (only `stored` survives; the window does
        // not). The clock resumes where it left off: the verdict lands
        // ~500 countable seconds into the second session, far sooner
        // than the ~1500 a fresh clock would need.
        let mut c = Core::default();
        let line = 1_000_000_000;
        run(&mut c, SUSTAIN_SECS + 999, 118e6, 0, line);
        assert_eq!(c.effective(line), (line, "line"));
        assert!(c.stored.clock_secs >= 1000, "clock persisted in stored");
        let mut c2 = Core {
            stored: c.stored.clone(),
            ..Core::default()
        };
        run(&mut c2, SUSTAIN_SECS + 500, 118e6, 0, line);
        assert_eq!(
            c2.effective(line),
            (118_000_000, "measured"),
            "the two sessions' evidence adds up to the verdict"
        );
    }

    #[test]
    fn carried_clock_is_dropped_when_the_anchor_changed() {
        // Evidence gathered against one typed value must not disown a
        // DIFFERENT one typed while the daemon was down: the clock is
        // tied to the anchor it argued against.
        let mut c = Core::default();
        let line = 1_000_000_000;
        run(&mut c, SUSTAIN_SECS + 1400, 118e6, 0, line);
        let mut c2 = Core {
            stored: c.stored.clone(),
            ..Core::default()
        };
        let retyped = 2_000_000_000;
        run(&mut c2, SUSTAIN_SECS + 300, 118e6, 0, retyped);
        assert_eq!(
            c2.effective(retyped),
            (retyped, "line"),
            "a fresh declaration starts a fresh clock"
        );
        assert!(c2.stored.clock_secs <= 301, "old evidence discarded");
    }

    #[test]
    fn units_hint_needs_an_eighth_peak_with_substance_behind_it() {
        let mut c = Core::default();
        let line = 1_000_000_000;
        assert!(!c.line_hint(line), "no evidence, no hint");
        // Five full-window minutes at an eighth: band matched, but not
        // yet a substantial job.
        run(&mut c, SUSTAIN_SECS - 1 + 300, 125e6, 0, line);
        assert!(!c.line_hint(line));
        run(&mut c, 300, 125e6, 0, line);
        assert!(c.line_hint(line));
        assert!(!c.line_hint(0), "no line speed set, nothing to hint about");
        // Half the line is an ordinary shortfall, not the signature.
        let mut c2 = Core::default();
        run(&mut c2, SUSTAIN_SECS + HINT_SECS as usize, 500e6, 0, line);
        assert!(!c2.line_hint(line));
    }

    #[test]
    fn units_hint_survives_the_downlearn_correction() {
        let mut c = Core::default();
        let line = 1_000_000_000;
        // Long enough that the gap-scaled down-learn fires and the
        // anchor drops to the measurement; the setting is still wrong.
        run(&mut c, SUSTAIN_SECS + 3600, 125e6, 0, line);
        assert_eq!(c.effective(line), (125_000_000, "measured"));
        assert!(
            c.line_hint(line),
            "the disowned value still reads as bits typed as bytes"
        );
        // A different typed value is a fresh declaration: clean slate.
        assert!(!c.line_hint(2_000_000_000));
    }

    #[test]
    fn jitter_at_the_peak_does_not_churn_the_store() {
        let mut c = Core::default();
        run(&mut c, SUSTAIN_SECS, 1e9, 0, 0);
        let anchored = c.stored.measured_bps;
        // Riding within the raise margin: confirmed, not rewritten.
        let mut changes = 0;
        for _ in 0..100 {
            if c.step(1.005e9, 0, 0) {
                changes += 1;
            }
        }
        assert_eq!(changes, 0);
        assert_eq!(c.stored.measured_bps, anchored);
    }
}
