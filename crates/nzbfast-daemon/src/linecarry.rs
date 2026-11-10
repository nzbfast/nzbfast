//! TODO 275 item 1 part 2: remember what one socket actually carried,
//! so the next job's fleet seed starts where the last one ended.
//!
//! `pool::linecap::fleet_for_line` sizes a fleet by PLANNING
//! `LINE_CAP_SOCKET_BPS` (150 Mbit) per socket. Where a provider cannot
//! hold that - a long-haul route, a cold spool, a small account - the
//! plan is optimistic by exactly the ratio it is wrong by and the fleet
//! comes out that many times too small. `fleet_for_supply` (27 Aug
//! 2026) fixes that DURING a run by sizing off the carry it measures
//! instead of the one it assumes, and GH #62's reporter goes 25 -> 50
//! sockets on the strength of it.
//!
//! What it does not do is remember. The governor's verdict dies with
//! the pool, so job two starts at the curve's floor and walks the same
//! climb again, over `LINE_CAP_RAISE_TICKS` ticks plus the dial, for
//! ever - and the climb is paid at the FRONT of a job, which is where
//! the backlog is. This module is the memory: the same measure-then-
//! remember shape as `linkpeak.json` and the connection knee in
//! `conntune.json`, one number, persisted to `.spool/linecarry.json`.
//!
//! **Last job's best, not a lifetime maximum**, and both halves of that
//! are deliberate:
//!
//! * WITHIN a job the best reading is what is kept, because a carry is
//!   an achieved rate and so a LOWER bound on what a socket can hold -
//!   the same asymmetry `linkpeak` applies to a link. `LiveStats::
//!   line_carry_bps` is already that maximum; this module only reads
//!   it.
//! * ACROSS jobs the newest job overwrites, so the number decays with
//!   the provider instead of latching. A lifetime max would need
//!   `linkpeak`'s three-hour down-learn clock to be honest, and it is
//!   not worth one here: both error directions are bounded, because the
//!   seed clamps into the SAME window as the in-run arm. A carry
//!   remembered too HIGH asks for fewer sockets and simply loses the
//!   benefit; one remembered too LOW asks for more and can reach no
//!   further than `LINE_CAP_MAX_FLEET`, which is where the in-run arm
//!   would have walked anyway.
//!
//! **And since 9 Nov 2026 the same file remembers the FLEET** - the
//! count the last job's line cap settled at, and the step-back point if
//! it had to back off - so the next job on the same line starts there
//! rather than climbing again, and does not climb into a step-back it
//! already measured. That half is filtered harder than the carry,
//! because a fleet that is wrong in the UP direction is the one §208
//! measured costing a slow line: it is recalled only on a MEASURED
//! anchor within a quarter of the one it was learned on, for a week,
//! and the hold for a day ([`Stored::recall`]); and the run checks the
//! line itself once the fleet is up (`linecap::recall_check`). A CLI
//! run has none of it, as it has no carry.
//!
//! It is read at job build (`get::fleet`, through the hub) and written
//! by the 1 s ticker that already drives `linkpeak` - so a job that
//! runs for a minute has banked its carry long before it ends, and a
//! daemon killed mid-job still teaches the next one.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Instant;

use crate::tools::MutexExt;

/// Persist at most this often. The value moves at most once a second
/// and settles within a job, so this is one write per job in practice;
/// the same figure `linkpeak` uses, for the same reason.
const SAVE_MIN_SECS: u64 = 30;

/// A carry under this is not evidence about a socket, it is evidence
/// about a job that was barely moving - a settle pass, a repair fetch,
/// a queue with two articles left in it. 32 KB/s is a quarter of a
/// megabit and below anything TODO 208 ever measured a healthy socket
/// at (its trickle regime was 35 KB/s and it called that pathological).
///
/// Without a floor, the last flicker of any run would be banked as the
/// link's carry and the next job would seed at the ceiling on the
/// strength of it. The tail guard in `line_cap_tick` covers the
/// queue-dry case upstream; this covers everything else that is not a
/// download.
const MIN_CARRY_BPS: u64 = 32_768;

/// What linecarry.json holds.
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct Stored {
    /// The best per-socket carry the last job measured, bytes/s.
    /// 0 = nothing measured yet, which is what a fresh install has and
    /// is exactly the behaviour that shipped.
    #[serde(default)]
    pub carry_bps: u64,
    /// Unix time of the last change, for the curious reading the file.
    #[serde(default)]
    pub checked: u64,
    /// 9 Nov 2026: the fleet the last job with a line-cap verdict
    /// SETTLED at (`LiveStats::line_cap_settled`), 0 = none. Newest
    /// overwrites, for the carry's reason above.
    #[serde(default)]
    pub fleet: usize,
    /// The link anchor that job sized from, bytes/s: the line the fleet
    /// was learned on. See [`Stored::recall`].
    #[serde(default)]
    pub fleet_anchor_bps: u64,
    /// Unix time `fleet` was last banked.
    #[serde(default)]
    pub fleet_checked: u64,
    /// The step-back ceiling a job left (`LiveStats::line_cap_hold`),
    /// 0 = none.
    #[serde(default)]
    pub hold: usize,
    /// Unix time the hold was FIRST seen at its value. Not refreshed by a
    /// job that merely carried it forward, so it expires on its own clock
    /// and the line gets re-tested.
    #[serde(default)]
    pub hold_checked: u64,
}

/// How long a banked fleet may be recalled for: the connection knee's
/// own re-probe appointment (`conntune::STALE_SECS`), which is the
/// repo's figure for how long a per-line connection count stays true.
pub const RECALL_MAX_AGE_SECS: u64 = crate::conntune::STALE_SECS;

/// How long a step-back is held across jobs. A day, so a line that
/// stopped punishing a bigger fleet is re-tested by the next day's first
/// job; what the re-test costs is the one step-back it measured before
/// (a few seconds), against holding a fleet too small for ever.
pub const HOLD_MAX_AGE_SECS: u64 = 86_400;

/// How far today's anchor may sit from the one a fleet was learned on
/// before the memory is not about this line, percent either way.
pub const RECALL_ANCHOR_PCT: u64 = 25;

impl Stored {
    /// What the next job may start from: `(fleet, hold)`, 0 = none.
    ///
    /// Only on a MEASURED anchor within [`RECALL_ANCHOR_PCT`] of the one
    /// the fleet was learned on, because a fleet is a fact about a LINE
    /// and the anchor is the only evidence the daemon has of which line
    /// it is on - a typed line speed says nothing about where the last
    /// fleet came from. A fleet older than [`RECALL_MAX_AGE_SECS`] and a
    /// hold older than [`HOLD_MAX_AGE_SECS`] are dropped. The fleet never
    /// comes back above the hold: the hold is the fleet that hurt less.
    /// The run checks the line for itself once it is up
    /// (`nzbkit::pool::linecap::recall_check`), so this filter is the
    /// first of two.
    pub fn recall(&self, anchor_bps: u64, measured: bool, now: u64) -> (usize, usize) {
        let near = |a: u64| {
            let lo = a as u128 * (100 - RECALL_ANCHOR_PCT) as u128;
            let hi = a as u128 * (100 + RECALL_ANCHOR_PCT) as u128;
            let x = anchor_bps as u128 * 100;
            a > 0 && x >= lo && x <= hi
        };
        if !measured || !near(self.fleet_anchor_bps) {
            return (0, 0);
        }
        let hold = match now.saturating_sub(self.hold_checked) <= HOLD_MAX_AGE_SECS {
            true => self.hold,
            false => 0,
        };
        let fleet = match now.saturating_sub(self.fleet_checked) <= RECALL_MAX_AGE_SECS {
            true => self.fleet,
            false => 0,
        };
        let fleet = match hold {
            0 => fleet,
            h => fleet.min(h),
        };
        (fleet, hold)
    }
}

/// The daemon-facing store: one number behind a lock, plus load and a
/// throttled persist.
pub struct LineCarry {
    stored: Mutex<Stored>,
    path: PathBuf,
    /// (last persist instant, dirty) - the same shape `linkpeak` uses,
    /// and for the same reason: a write that failed must stay dirty, or
    /// a value that never changes again is never persisted at all.
    save: Mutex<(Option<Instant>, bool)>,
    /// The pool whose fleet verdict was last banked. In memory only, and
    /// a `Weak` so it can never keep a finished job's pool alive - and so
    /// its allocation cannot be reused by the next job's pool while this
    /// is held, which is what makes `ptr_eq` an honest "same job" test.
    fleet_pool: Mutex<std::sync::Weak<nzbkit::pool::LiveStats>>,
}

impl LineCarry {
    pub fn load(path: PathBuf) -> Self {
        let stored = crate::persist::load_json_with_backup(&path)
            .and_then(|v| serde_json::from_value::<Stored>(v).ok())
            .unwrap_or_default();
        LineCarry {
            stored: Mutex::new(stored),
            path,
            save: Mutex::new((None, false)),
            fleet_pool: Mutex::new(std::sync::Weak::new()),
        }
    }

    /// The carry the next job's seed should size from, bytes/s;
    /// 0 = none, which is `fleet_for_carry`'s own "no opinion".
    pub fn carry_bps(&self) -> u64 {
        self.stored.lock_ok().carry_bps
    }

    /// What the next job may start from; see [`Stored::recall`].
    pub fn recall(&self, anchor_bps: u64, measured: bool) -> (usize, usize) {
        self.stored
            .lock_ok()
            .recall(anchor_bps, measured, unix_now())
    }

    /// One second of the line cap's verdicts (9 Nov 2026): the fleet this
    /// job's pool settled at, the step-back hold it is under, and the
    /// anchor the job sized from. `settled == 0` is no verdict and changes
    /// nothing, so a job that never reached one keeps the last job's
    /// memory. Returns true when the stored values moved.
    ///
    /// `fresh` says this verdict is a new MEASUREMENT - the first one a
    /// job's pool delivered - rather than the same pool's verdict read
    /// again. Only a fresh verdict or a changed value moves the fleet's
    /// clock: the ticker keeps reading the last job's `LiveStats` for as
    /// long as the daemon sits idle (`hub.pool_live` is only replaced at
    /// the next job), and until 9 Nov 2026 every one of those re-reads
    /// re-stamped the clock, so [`RECALL_MAX_AGE_SECS`] never bit while
    /// the daemon stayed up and a month-idle daemon recalled a month-old
    /// fleet.
    pub fn observe_fleet(&self, settled: usize, hold: usize, anchor_bps: u64, fresh: bool) -> bool {
        if settled == 0 || anchor_bps == 0 {
            return false;
        }
        let now = unix_now();
        let changed = {
            let mut st = self.stored.lock_ok();
            let before = (st.fleet, st.fleet_anchor_bps, st.hold);
            st.fleet = settled;
            st.fleet_anchor_bps = anchor_bps;
            if hold != st.hold {
                st.hold = hold;
                st.hold_checked = now;
            }
            // The fleet's own clock moves on a fresh verdict (a job's
            // pool measuring it) or a changed one; the hold's moves only
            // when the hold does, so a job carrying it forward cannot keep
            // it alive. Neither moves for a finished job's verdict read
            // again by the idle ticker.
            let moved = before != (st.fleet, st.fleet_anchor_bps, st.hold);
            if fresh || moved {
                st.fleet_checked = now;
            }
            moved
        };
        if changed {
            self.save.lock_ok().1 = true;
        }
        self.flush_if_due();
        changed
    }

    /// One observation from the ticker: the running best this job's
    /// pool has published. `0` - no pool, no reading yet, or a run with
    /// the rule off - changes nothing at all, which is what makes an
    /// idle daemon unable to forget what the last job taught it.
    ///
    /// Returns true when the stored value moved, for the tests.
    pub fn observe(&self, carry_bps: u64) -> bool {
        if carry_bps < MIN_CARRY_BPS {
            return false;
        }
        let changed = {
            let mut st = self.stored.lock_ok();
            if st.carry_bps == carry_bps {
                false
            } else {
                st.carry_bps = carry_bps;
                st.checked = unix_now();
                true
            }
        };
        if changed {
            self.save.lock_ok().1 = true;
        }
        self.flush_if_due();
        changed
    }

    /// Persist when dirty and [`SAVE_MIN_SECS`] has passed since the last
    /// write.
    fn flush_if_due(&self) {
        let due = {
            let save = self.save.lock_ok();
            save.1
                && save
                    .0
                    .is_none_or(|t| t.elapsed().as_secs() >= SAVE_MIN_SECS)
        };
        if due {
            self.flush();
        }
    }

    /// Write the current value out, clearing the dirty bit only on a
    /// successful write. A failed write (transient ENOSPC, a read-only
    /// mount) must stay dirty: the value may never change again, so
    /// clearing here is how a restart forgets it.
    fn flush(&self) {
        let snapshot = self.stored.lock_ok().clone();
        *self.save.lock_ok() = (Some(Instant::now()), false);
        let wrote = serde_json::to_vec_pretty(&snapshot)
            .map_err(|_| ())
            .and_then(|b| crate::persist::write_atomic(&self.path, &b).map_err(|_| ()));
        if wrote.is_err() {
            self.save.lock_ok().1 = true;
        }
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One second of observation, from the ticker `linkpeak::spawn` already
/// runs. Rides that loop rather than opening a second one: the two read
/// the same job's state a second apart and nothing here is worth a task
/// of its own.
pub fn feed(d: &super::daemon::Daemon) {
    use std::sync::atomic::Ordering::Relaxed;
    // The anchor the runner stamped for THIS job, which is the line its
    // fleet was learned on. A typed anchor banks nothing: `recall` would
    // never hand it back.
    //
    // Read BEFORE the pool, and that order is the whole of a rule. At a
    // job start the runner clears `pool_live` and only then restamps the
    // anchor (`reset_hub_for_job`), so a pool read here that is still the
    // last job's was read before that clear, and an anchor read before
    // the pool cannot be the next job's. Read the other way round, a
    // tick landing between the two halves banked the last job's fleet
    // against the next job's line (9 Nov 2026 sweep).
    let anchor = d.hub.line_anchor_bps.load(Relaxed);
    let measured = d.hub.line_anchor_measured.load(Relaxed);
    let live = d.hub.pool_live.lock_ok().clone();
    let (carry, settled, hold) = live
        .as_ref()
        .map(|l| {
            (
                l.line_carry_bps.load(Relaxed),
                l.line_cap_settled.load(Relaxed),
                l.line_cap_hold.load(Relaxed),
            )
        })
        .unwrap_or((0, 0, 0));
    d.line_carry.observe(carry);
    if let Some(l) = live.as_ref()
        && measured
        && settled != 0
        && anchor != 0
    {
        // Fresh only the first time THIS pool's verdict is banked: every
        // later tick over the same pool - including the whole idle spell
        // after its job ended - is the same measurement read again.
        let fresh = {
            let mut seen = d.line_carry.fleet_pool.lock_ok();
            let first = !std::sync::Weak::ptr_eq(&seen, &std::sync::Arc::downgrade(l));
            if first {
                *seen = std::sync::Arc::downgrade(l);
            }
            first
        };
        d.line_carry.observe_fleet(settled, hold, anchor, fresh);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch directory of this test's own. The house idiom in
    /// `serve` (logscrub_tests) rather than a tempfile crate: these
    /// tests share a process with ~1750 others and a name keyed on the
    /// pid plus the case is what keeps them out of each other's files.
    fn scratch(tag: &str) -> crate::testscratch::ScratchDir {
        let d =
            std::env::temp_dir().join(format!("nzbfast-linecarry-{tag}-{}", std::process::id()));
        crate::testscratch::ScratchDir::attach(&d)
    }

    fn store(tag: &str) -> (crate::testscratch::ScratchDir, LineCarry) {
        let dir = scratch(tag);
        let path = dir.join("linecarry.json");
        (dir, LineCarry::load(path))
    }

    #[test]
    fn a_fresh_install_has_no_opinion() {
        let (_d, lc) = store("fresh");
        assert_eq!(lc.carry_bps(), 0, "nothing measured is nothing claimed");
    }

    #[test]
    fn a_measured_carry_survives_a_restart() {
        let (dir, lc) = store("restart");
        assert!(lc.observe(1_250_000), "10 Mbit a socket is a reading");
        lc.flush();
        let again = LineCarry::load(dir.join("linecarry.json"));
        assert_eq!(
            again.carry_bps(),
            1_250_000,
            "the next job must start where the last one ended"
        );
    }

    #[test]
    fn the_newest_job_overwrites_rather_than_maxing() {
        // Across jobs the number decays with the provider: a lifetime
        // maximum would need linkpeak's down-learn clock to be honest,
        // and the module doc says why it is not worth one here.
        let (_d, lc) = store("overwrite");
        lc.observe(4_000_000);
        lc.observe(1_250_000);
        assert_eq!(lc.carry_bps(), 1_250_000);
    }

    /// The whole point of the module, end to end across a job
    /// boundary: what job one's POOL measured is what job two's SEED
    /// sizes from.
    ///
    /// The link here is GH #62's - a 1 Gbit anchor, sockets carrying
    /// ~13 Mbit against the curve's planned 150 - so job one is the
    /// curve's floor and its five servers get 5 connections each, which
    /// is what the reporter saw. The assertions walk the whole path:
    /// the pool publishes onto `LiveStats`, the ticker banks it, the
    /// runner would hand it to the hub, and the seed asks the in-run
    /// arm's own question of it and gets the in-run arm's own answer -
    /// at job build, instead of three ticks and a dial into the job.
    ///
    /// It also pins the ceiling, which is the one thing that would make
    /// this unsafe. The seed clamps into exactly the window the in-run
    /// arm does, so no banked carry can put a job past
    /// `LINE_CAP_MAX_FLEET` - the rung TODO 208 Round A cleared at
    /// 99 Mbit. The second ceiling (item 7, 2 Sep 2026) did not change
    /// that: it is the in-run governor's to walk to and the seed's
    /// clamp is still the first ceiling, so this test asserts the same
    /// window it always did.
    #[test]
    fn job_two_seeds_from_what_job_one_measured() {
        let dir = scratch("jobtwo");
        let d = crate::testutil::test_daemon(&dir);
        let anchor = 125_000_000; // 1 Gbit
        let floor = nzbkit::pool::linecap::LINE_CAP_DEFAULT_FLEET;
        let ceiling = nzbkit::pool::linecap::LINE_CAP_MAX_FLEET;
        // TODO 312 item 1: the seed reads its own override out of
        // settings.json beside this config, and this fixture writes
        // neither - which is the AUTOMATIC case every assertion below
        // is about.
        let cfg = d.cfg_path.clone();

        // JOB ONE. Nothing banked, so the curve's floor and the
        // reporter's own five-connections-a-server.
        assert_eq!(crate::conntune::line_cap_fleet(&cfg, anchor, 0), floor);
        assert_eq!(
            crate::conntune::line_cap_share(&cfg, vec![0; 5], anchor, 0).map(|s| s.share(0)),
            Some(5),
            "which is what GH #62 reported seeing"
        );
        // Its pool measures ~13 Mbit a socket and publishes it.
        let live = nzbkit::pool::LiveStats::for_servers(&[]);
        live.line_carry_bps
            .store(1_625_000, std::sync::atomic::Ordering::Relaxed);
        *d.hub.pool_live.lock_ok() = Some(live);
        feed(&d);
        assert_eq!(d.line_carry.carry_bps(), 1_625_000, "the ticker banks it");

        // JOB TWO. The runner stamps it on the hub beside the anchor;
        // the fleet build reads it there.
        d.hub.line_carry_bps.store(
            d.line_carry.carry_bps(),
            std::sync::atomic::Ordering::Relaxed,
        );
        let carry = d
            .hub
            .line_carry_bps
            .load(std::sync::atomic::Ordering::Relaxed);
        let seeded = crate::conntune::line_cap_fleet(&cfg, anchor, carry);
        assert!(
            seeded > floor,
            "job two must not re-walk job one's climb: {seeded}"
        );
        assert_eq!(
            crate::conntune::line_cap_share(&cfg, vec![0; 5], anchor, carry).map(|s| s.share(0)),
            Some(10),
            "10 connections a server at job build, not 5 walked to 10"
        );
        // And it stops exactly where the in-run arm already stopped.
        assert_eq!(seeded, ceiling, "at today's ceiling and no further");
        for c in [1u64, 1_024, 1_625_000, 18_750_000, u64::MAX] {
            assert!(
                crate::conntune::line_cap_fleet(&cfg, anchor, c) <= ceiling,
                "carry {c} seeded past the ceiling"
            );
        }
    }

    const TEN_GIG: u64 = 1_250_000_000;

    fn banked(fleet: usize, hold: usize, at: u64) -> Stored {
        Stored {
            fleet,
            fleet_anchor_bps: TEN_GIG,
            fleet_checked: at,
            hold,
            hold_checked: at,
            ..Stored::default()
        }
    }

    /// 9 Nov 2026: a banked fleet comes back only for the line it was
    /// learned on, as the daemon can tell lines apart: a MEASURED anchor
    /// within a quarter of the banked one.
    #[test]
    fn a_fleet_is_recalled_only_on_the_line_it_was_learned_on() {
        let st = banked(100, 0, 1_000);
        assert_eq!(st.recall(TEN_GIG, true, 1_000), (100, 0));
        assert_eq!(st.recall(TEN_GIG * 4 / 5, true, 1_000), (100, 0));
        assert_eq!(st.recall(TEN_GIG, false, 1_000), (0, 0), "a typed line");
        assert_eq!(st.recall(TEN_GIG / 2, true, 1_000), (0, 0), "another line");
        assert_eq!(st.recall(TEN_GIG * 2, true, 1_000), (0, 0), "another line");
        assert_eq!(Stored::default().recall(TEN_GIG, true, 1_000), (0, 0));
    }

    /// The fleet keeps for the knee's week and the hold for a day, so a
    /// line that stopped punishing a bigger fleet is re-tested; and the
    /// fleet never comes back above the hold.
    #[test]
    fn a_hold_expires_before_the_fleet_and_bounds_it() {
        let st = banked(100, 50, 0);
        assert_eq!(st.recall(TEN_GIG, true, 10), (50, 50));
        assert_eq!(st.recall(TEN_GIG, true, HOLD_MAX_AGE_SECS + 1), (100, 0));
        assert_eq!(st.recall(TEN_GIG, true, RECALL_MAX_AGE_SECS + 1), (0, 0));
    }

    /// A job carrying the hold forward does not keep it alive: only a NEW
    /// hold value restarts its clock. And it all survives a restart.
    #[test]
    fn a_carried_hold_keeps_its_first_seen_clock() {
        let (dir, lc) = store("hold");
        assert!(
            !lc.observe_fleet(0, 0, TEN_GIG, true),
            "no verdict is no change"
        );
        assert!(lc.observe_fleet(50, 50, TEN_GIG, true));
        let first = lc.stored.lock_ok().hold_checked;
        lc.stored.lock_ok().hold_checked = first - 1_000;
        lc.observe_fleet(50, 50, TEN_GIG, true);
        assert_eq!(lc.stored.lock_ok().hold_checked, first - 1_000);
        lc.flush();
        let again = LineCarry::load(dir.join("linecarry.json"));
        assert_eq!(again.recall(TEN_GIG, true), (50, 50));
        // A job with no hold clears it.
        assert!(again.observe_fleet(100, 0, TEN_GIG, true));
        assert_eq!(again.recall(TEN_GIG, true), (100, 0));
    }

    /// End to end across a job boundary: the pool's verdict, banked by
    /// the ticker against the anchor the runner stamped for the job.
    #[test]
    fn job_two_starts_where_job_one_settled() {
        let dir = scratch("settled");
        let d = crate::testutil::test_daemon(&dir);
        let live = nzbkit::pool::LiveStats::for_servers(&[]);
        live.line_cap_settled
            .store(100, std::sync::atomic::Ordering::Relaxed);
        *d.hub.pool_live.lock_ok() = Some(live);
        d.hub
            .line_anchor_bps
            .store(TEN_GIG, std::sync::atomic::Ordering::Relaxed);
        feed(&d);
        assert_eq!(
            d.line_carry.recall(TEN_GIG, true),
            (0, 0),
            "a typed anchor banks nothing"
        );
        d.hub
            .line_anchor_measured
            .store(true, std::sync::atomic::Ordering::Relaxed);
        feed(&d);
        assert_eq!(d.line_carry.recall(TEN_GIG, true), (100, 0));
    }

    /// 9 Nov 2026 sweep: the ticker goes on reading the LAST job's pool
    /// for as long as the daemon sits idle, and that is the same verdict
    /// read again, not a fresh measurement - so it must not keep the
    /// fleet young. Simulated by backdating the bank past the recall age
    /// and feeding again over the same pool: the fleet must expire. A
    /// NEW job's pool settling at the same count is a fresh measurement
    /// and does renew it.
    #[test]
    fn an_idle_reread_of_the_last_jobs_verdict_does_not_keep_it_fresh() {
        use std::sync::atomic::Ordering::Relaxed;
        let dir = scratch("idlefresh");
        let d = crate::testutil::test_daemon(&dir);
        let job = |settled: usize| {
            let live = nzbkit::pool::LiveStats::for_servers(&[]);
            live.line_cap_settled.store(settled, Relaxed);
            live
        };
        d.hub.line_anchor_bps.store(TEN_GIG, Relaxed);
        d.hub.line_anchor_measured.store(true, Relaxed);
        *d.hub.pool_live.lock_ok() = Some(job(100));
        feed(&d);
        assert_eq!(d.line_carry.recall(TEN_GIG, true), (100, 0));
        // A week and a bit of idle ticks later.
        let aged = unix_now() - RECALL_MAX_AGE_SECS - 60;
        d.line_carry.stored.lock_ok().fleet_checked = aged;
        feed(&d);
        assert_eq!(
            d.line_carry.stored.lock_ok().fleet_checked,
            aged,
            "an idle re-read of a finished job's verdict re-stamped its clock"
        );
        assert_eq!(
            d.line_carry.recall(TEN_GIG, true),
            (0, 0),
            "a fleet older than the recall age must not come back"
        );
        // The next job measures the same fleet: that IS fresh evidence.
        *d.hub.pool_live.lock_ok() = Some(job(100));
        feed(&d);
        assert_eq!(d.line_carry.recall(TEN_GIG, true), (100, 0));
    }

    #[test]
    fn a_dribble_is_not_a_measurement_of_a_socket() {
        let (_d, lc) = store("dribble");
        lc.observe(1_250_000);
        // A settle pass, a repair fetch, the last flicker of a run:
        // without the floor this is what the next job would seed from.
        assert!(!lc.observe(MIN_CARRY_BPS - 1));
        assert!(!lc.observe(0), "no pool at all changes nothing");
        assert_eq!(lc.carry_bps(), 1_250_000, "the last real reading stands");
    }
}
