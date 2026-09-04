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
        }
    }

    /// The carry the next job's seed should size from, bytes/s;
    /// 0 = none, which is `fleet_for_carry`'s own "no opinion".
    pub fn carry_bps(&self) -> u64 {
        self.stored.lock_ok().carry_bps
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
                st.checked = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                true
            }
        };
        if changed {
            self.save.lock_ok().1 = true;
        }
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
        changed
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

/// One second of observation, from the ticker `linkpeak::spawn` already
/// runs. Rides that loop rather than opening a second one: the two read
/// the same job's state a second apart and nothing here is worth a task
/// of its own.
pub fn feed(d: &super::daemon::Daemon) {
    let carry = d
        .hub
        .pool_live
        .lock_ok()
        .as_ref()
        .map(|l| l.line_carry_bps.load(std::sync::atomic::Ordering::Relaxed))
        .unwrap_or(0);
    d.line_carry.observe(carry);
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
            crate::conntune::line_cap_share(&cfg, 5, anchor, 0),
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
            crate::conntune::line_cap_share(&cfg, 5, anchor, carry),
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
