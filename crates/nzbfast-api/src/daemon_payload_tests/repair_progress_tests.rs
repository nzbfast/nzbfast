//! The queue row's REPAIR numbers, from the handle the job registers to
//! the JSON the dashboard reads.
//!
//! The sibling of `unpack_progress_tests` one stage earlier in the tail,
//! and the failure it pins is the same shape one stage earlier too:
//! `serve/mod.rs`'s own comment named it - "the queue row has read
//! `Repairing, 100%, timeleft 0:00:00` through exactly that kind of
//! stall before" - and that comment was the argument for capping what a
//! daemon would even start.
//!
//! The engine-side half is proved in
//! `nzbkit_base::par2repair::unit_tests::control_tests` and the
//! daemon-side half on a real damaged set in
//! `nzbfast_core::repairprog::tests`. This is the PAYLOAD half: that the
//! phase and the fraction reach the row, on the right row, and that
//! every other row and every stage that is not an engine repair still
//! says nothing - which is what keeps the page's bare "repairing" phrase
//! correct for the recovery-volume side-fetches, which run under the
//! same activity word and are not a phase of the repair.
//!
//! A child of the payload tests, out here for the size gate; the module
//! is named for its file so size-gate.py's CFG_TEST_MOD resolver still
//! reads it as test code, and the imports mirror its sibling's.

use nzbfast_daemon::MutexExt;
use nzbfast_daemon::daemon::Daemon;
use nzbfast_daemon::testutil::{jv, with_daemon};
use nzbkit::par2repair::{ProgressSink, RepairPhase};
use serde_json::Value;
use std::sync::Arc;

/// The row the queue payload builds for `id`.
fn row(d: &Arc<Daemon>, id: &str) -> Value {
    let v = crate::sabcompat::queue_json(d, &std::collections::HashMap::new());
    v["queue"]["slots"]
        .as_array()
        .expect("slots array")
        .iter()
        .find(|s| s["nzo_id"] == id)
        .cloned()
        .unwrap_or(Value::Null)
}

/// Register a job's recovery handle the way `get::install_tail_cancel`
/// does, and hand it back.
fn arm(d: &Arc<Daemon>, id: &str) -> Arc<crate::streamhub::SideCancel> {
    let c = Arc::new(crate::streamhub::SideCancel::new());
    d.hub
        .tail_cancel
        .lock_ok()
        .insert(id.to_string(), c.clone());
    c
}

#[test]
fn only_the_repairing_row_carries_its_phase_and_fraction() {
    with_daemon("repairprog", |d| {
        {
            let mut q = d.queue.lock_ok();
            q.push_back(jv("nzo-a", "Set.A-GRP", serde_json::json!({})));
            q.push_back(jv("nzo-b", "Set.B-GRP", serde_json::json!({})));
        }
        // No handle registered at all - a queued job that never ran.
        assert_eq!(row(d, "nzo-a")["repair"], Value::Null);

        // A handle registered and NO repair inside the engine. This is
        // most of a repair section's wall - the recovery-volume
        // side-fetches - and it must say nothing, or the row shows a
        // percentage for work that is not running.
        let a = arm(d, "nzo-a");
        let b = arm(d, "nzo-b");
        assert_eq!(
            row(d, "nzo-a")["repair"],
            Value::Null,
            "a registered handle is not a running repair"
        );

        // Job A's repair enters the engine and reports.
        let run = a.repair_progress().enter();
        a.repair_progress().progress(RepairPhase::Fold, 1, 4);
        let ra = row(d, "nzo-a");
        assert_eq!(ra["repair"]["phase"], "fold");
        assert_eq!(ra["repair"]["done"], 1);
        assert_eq!(ra["repair"]["total"], 4);
        // 45% of the bar for the verify band, plus a quarter of the
        // fold's 40 - the band `nzbfast_core::repairprog` takes, and the
        // one `parfast` takes, so the two products agree.
        assert_eq!(ra["repair"]["pct"], 55.0);

        // ...and job B, behind it, is untouched: the whole reason the
        // handle is keyed by owning nzo_id is that job N's tail overlaps
        // job N+1's work.
        assert_eq!(row(d, "nzo-b")["repair"], Value::Null);
        let _ = &b;

        // The phase advances and the fraction rises with it.
        a.repair_progress().progress(RepairPhase::Write, 1, 2);
        let ra = row(d, "nzo-a");
        assert_eq!(ra["repair"]["phase"], "write");
        assert_eq!(ra["repair"]["pct"], 97.5);

        // The engine leaves, and the row goes quiet again rather than
        // freezing at the last phase it saw.
        drop(run);
        assert_eq!(row(d, "nzo-a")["repair"], Value::Null);
    });
}

/// The row's `pct` is MONOTONE for one engine call, because a slabbed
/// solve re-enters its phase from zero and a bar that fell from 95% to
/// 85% reads as a restart. The phase's own `done`/`total` go back with
/// it, because they are about the phase.
#[test]
fn a_re_entered_phase_does_not_take_the_rows_percentage_backwards() {
    with_daemon("repairprog-monotone", |d| {
        d.queue
            .lock_ok()
            .push_back(jv("nzo-m", "Set.M-GRP", serde_json::json!({})));
        let c = arm(d, "nzo-m");
        let _run = c.repair_progress().enter();
        c.repair_progress().progress(RepairPhase::Solve, 10, 10);
        assert_eq!(row(d, "nzo-m")["repair"]["pct"], 95.0);
        c.repair_progress().progress(RepairPhase::Solve, 0, 10);
        let r = row(d, "nzo-m")["repair"].clone();
        assert_eq!(r["done"], 0, "the phase pair is about the phase");
        assert_eq!(r["pct"], 95.0, "the bar is not");
    });
}
