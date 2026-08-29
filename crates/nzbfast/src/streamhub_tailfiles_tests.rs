//! TODO 274 (e): the run table a job keeps through its TAIL.
//!
//! A sibling file rather than an inline `mod` (TODO 106): streamhub.rs
//! is production code and its subject here is two free functions that
//! exist precisely so this can be driven without an `Extractor` and the
//! pool's queue handle.
//!
//! What is being pinned is a property nothing else in the tree checks:
//! the frozen copy must read the SAME counters the live table would
//! have reported at that instant, because both sides go through one row
//! builder in `api/queue/files.rs` and a drift here would be a drift in
//! the words the tail drawer prints - "damaged" against a file that
//! arrived whole, or "waiting" against one already on the disk.

use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize};

fn slot(
    remaining: usize,
    missing: usize,
    deferred: usize,
    par2: bool,
) -> Arc<crate::unpack::FileSlot> {
    Arc::new(crate::unpack::FileSlot {
        hint: "f".into(),
        hint_is_posted_name: nzbkit::release::stem_is_a_name("f"),
        name_choice: std::sync::atomic::AtomicU8::new(crate::unpack::NAME_UNDECIDED),
        is_par2_main: par2,
        sample_skipped: false,
        par2_sniffed: AtomicBool::new(false),
        total_segments: 10,
        remaining: AtomicUsize::new(remaining),
        missing: AtomicUsize::new(missing),
        errors: AtomicUsize::new(2),
        deferred: AtomicUsize::new(deferred),
        abandoned: AtomicUsize::new(0),
        capture: std::sync::Mutex::new(None),
    })
}

fn row(id: &str, slot: Option<usize>) -> JobFileRow {
    JobFileRow {
        id: id.into(),
        name: format!("{id}.rar"),
        bytes: 1_000,
        segments: 10,
        slot,
    }
}

/// A settled entry - nothing left draining - under one row named `id`.
fn frozen(id: &str) -> TailTable {
    TailTable {
        frozen: Arc::new(freeze_rows(&[row(id, None)], &[])),
        draining: None,
    }
}

/// The freeze is the live reading, not a re-derivation of it.
///
/// Both halves matter. The counters must come out as they stood - a
/// slot that lost articles stays lost, one that deferred them stays a
/// choice - and the NZB half of the row must survive with them, since
/// the handle is what a client acts on and the name is what the drawer
/// prints. `is_par2` is read rather than taken from the row because the
/// in-stream magic sniff can set it long after the slot was built.
#[test]
fn a_frozen_table_carries_the_counters_the_live_one_would_have_reported() {
    let rows = vec![row("aa", Some(0)), row("bb", Some(1)), row("vol", None)];
    let slots = vec![slot(0, 3, 0, false), slot(0, 0, 10, true)];
    let f = freeze_rows(&rows, &slots);

    assert_eq!(f.rows.len(), 3, "every row survives, volumes included");
    assert_eq!(
        f.counts.len(),
        f.rows.len(),
        "counts stay aligned with rows"
    );
    assert_eq!(f.rows[0].id, "aa");
    assert_eq!(f.rows[0].name, "aa.rar");
    assert_eq!(f.rows[0].bytes, 1_000);

    let a = f.counts[0].as_ref().expect("the payload slot's counters");
    assert_eq!((a.total_segments, a.remaining, a.missing), (10, 0, 3));
    assert_eq!(a.errors, 2, "per-slot decode errors travel too");
    assert!(!a.is_par2);

    let b = f.counts[1].as_ref().expect("the recovery slot's counters");
    assert_eq!(b.deferred, 10, "a deferral is a choice and stays one");
    assert!(b.is_par2, "recovery by ANY route, read at freeze time");

    // The volume the plan never gave a slot: a row with no counters,
    // which is what makes it report as "recovery" rather than as a
    // payload file that arrived with nothing in it.
    assert!(f.counts[2].is_none(), "a row with no slot freezes to none");
}

/// A slot index the table does not have must freeze to "no counters"
/// rather than to a neighbour's. Nothing builds a table that way today;
/// the arm exists so that a future one cannot report file A's damage
/// under file B's name.
#[test]
fn a_row_pointing_past_the_slots_freezes_to_nothing() {
    let f = freeze_rows(&[row("aa", Some(9))], &[slot(0, 0, 0, false)]);
    assert!(f.counts[0].is_none());
}

/// The cap evicts the OLDEST, and a repeat replaces rather than doubles.
///
/// Both are about the reader, which takes the first entry matching an
/// id: two entries under one id make the answer depend on insertion
/// order, and evicting the newest would drop the tail that is running
/// now in favour of one that has already parked.
#[test]
fn the_kept_tables_are_capped_oldest_first_and_never_doubled() {
    let mut g: Vec<(String, TailTable)> = Vec::new();
    for i in 0..TAIL_FILES_KEPT + 2 {
        let id = format!("nzo{i}");
        keep_tail_table(&mut g, id.clone(), frozen(&id));
    }
    assert_eq!(g.len(), TAIL_FILES_KEPT, "the cap holds");
    assert_eq!(g[0].0, "nzo2", "the two oldest went, not the two newest");
    assert_eq!(
        g[TAIL_FILES_KEPT - 1].0,
        format!("nzo{}", TAIL_FILES_KEPT + 1)
    );

    keep_tail_table(&mut g, "nzo3".into(), frozen("again"));
    assert_eq!(
        g.iter().filter(|(t, _)| t == "nzo3").count(),
        1,
        "a job retired twice holds exactly one entry: {:?}",
        g.iter().map(|(t, _)| t).collect::<Vec<_>>()
    );
    assert_eq!(
        g.iter()
            .find(|(t, _)| t == "nzo3")
            .expect("nzo3")
            .1
            .frozen
            .rows[0]
            .id,
        "again",
        "and it is the LATER of the two"
    );
}

/// Retiring hands the active cell to the tail side, and the ownership
/// tag travels with it: the table is answerable under the job that
/// owned it and under nothing else.
#[test]
fn the_tail_side_answers_only_its_own_owner() {
    let hub = StreamHub::default();
    keep_tail_table(&mut hub.tail_files.lock_ok(), "nzo_a".into(), frozen("aa"));

    assert!(hub.tail_files_for("nzo_a").is_some());
    assert!(
        hub.tail_files_for("nzo_b").is_none(),
        "one job's rows must never be reported under another job's id"
    );
    assert!(
        hub.job_files_for("nzo_a").is_none(),
        "and not as the ACTIVE table"
    );
}

/// Retiring an empty cell is a no-op, not an entry under the empty id.
///
/// The runner calls this at every job start, including the first of a
/// daemon's life and every start that follows a job which failed before
/// it published a plan.
#[test]
fn retiring_nothing_keeps_nothing() {
    let hub = StreamHub::default();
    hub.retire_job_files();
    assert!(hub.tail_files.lock_ok().is_empty());
    assert!(hub.tail_files_for("").is_none());
}

/// The reading is taken AGAIN when the run's network phase ends.
///
/// A run is retired when its successor claims the hub, and on the
/// hand-over path that happens mid-drain: rows still in flight at that
/// instant read "active", and a tail drawer showing them says a job is
/// downloading directly under a sentence saying it is not (measured on
/// the live daemon 24 Aug 2026: 7 of 88 rows). The settle is what turns
/// those into whatever they actually became.
#[test]
fn a_settle_rereads_the_counters_the_drain_was_still_moving() {
    let mid = slot(4, 0, 0, false);
    let mut e = TailTable {
        frozen: Arc::new(freeze_rows(
            &[row("aa", Some(0))],
            std::slice::from_ref(&mid),
        )),
        draining: Some(vec![mid.clone()]),
    };
    assert_eq!(
        e.frozen.counts[0].as_ref().expect("counters").remaining,
        4,
        "the retire caught this file mid-flight"
    );

    // The drain lands the last four, two of them missing.
    mid.remaining.store(0, std::sync::atomic::Ordering::Relaxed);
    mid.missing.store(2, std::sync::atomic::Ordering::Relaxed);
    e.settle();

    let c = e.frozen.counts[0].as_ref().expect("counters");
    assert_eq!((c.remaining, c.missing), (0, 2), "read again at the drain");
    assert_eq!(e.frozen.rows[0].id, "aa", "and the NZB half is untouched");

    // Idempotent, and the slots are gone: a second settle must not
    // resurrect a reading from counters this entry no longer holds.
    mid.missing.store(9, std::sync::atomic::Ordering::Relaxed);
    e.settle();
    assert_eq!(
        e.frozen.counts[0].as_ref().expect("counters").missing,
        2,
        "settling twice keeps the reading taken at the drain"
    );
}

/// Retiring settles whatever was still draining from the run before.
///
/// The runner settles at its own `finish`, which is the exact moment;
/// this is the belt for a run torn down before its drain ever resolved,
/// so no entry can carry a slot vector to the cap's eviction.
#[test]
fn retiring_settles_the_entries_already_kept() {
    let mut g: Vec<(String, TailTable)> = Vec::new();
    let s0 = slot(4, 0, 0, false);
    keep_tail_table(
        &mut g,
        "nzo_old".into(),
        TailTable {
            frozen: Arc::new(freeze_rows(
                &[row("aa", Some(0))],
                std::slice::from_ref(&s0),
            )),
            draining: Some(vec![s0.clone()]),
        },
    );
    s0.remaining.store(0, std::sync::atomic::Ordering::Relaxed);
    for (_, e) in g.iter_mut() {
        e.settle();
    }
    assert_eq!(
        g[0].1.frozen.counts[0]
            .as_ref()
            .expect("counters")
            .remaining,
        0
    );
    assert!(
        g[0].1.draining.is_none(),
        "the slots are let go, not held to the cap"
    );
}
