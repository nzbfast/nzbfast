//! The ONE door to `parfast::run_with` in this target, and the lock that
//! comes with it.
//!
//! # Why a lock (27 Oct 2026)
//!
//! `run_with` publishes process-global engine knobs on EVERY call - the
//! verify tier (`par2::set_fast_check`, both directions), the digest
//! cache, the thread widths - because a parfast switch that parses onto
//! `Options` and reaches nobody is that crate's own repeated defect. In
//! the binary that is right: one process, one run. In THIS target it is
//! not, because `cargo test` runs every test here as a thread of ONE
//! process, so a neighbour's default run could reset the tier between
//! `fast_check`'s `--slow` run and its assertion that `--slow` reached the
//! engine. It did, in a one-process run, while passing alone and under
//! nextest (whose per-test process hides the class entirely).
//!
//! Guarding the one test that failed would not have fixed it: the writer
//! that raced it was an UNGUARDED neighbour. So the lock is held by every
//! in-process caller, for the whole test - post-call assertions on a
//! global included - and the only way to reach `run_with` here is through
//! [`InProcess::run`], which needs the guard to exist. The test at the
//! bottom holds every other module to that.
//!
//! Tests that drive the BUILT binary (`Command::new(env!(
//! "CARGO_BIN_EXE_parfast"))`) need none of this: a child process has
//! globals of its own.

use std::sync::{Mutex, MutexGuard};

static RUN_WITH: Mutex<()> = Mutex::new(());

/// Exclusive use of `parfast::run_with`, and of every global it sets,
/// for as long as this lives. Take it at the top of the test and keep it
/// to the end.
pub struct InProcess(#[allow(dead_code)] MutexGuard<'static, ()>);

/// Wait for, and take, the in-process lock. A test that panicked while
/// holding it poisons nothing that matters - every run sets the globals
/// it reads afresh - so a poisoned lock is taken as it stands rather
/// than failing every later test for the first one's sake.
pub fn in_process() -> InProcess {
    InProcess(RUN_WITH.lock().unwrap_or_else(|e| e.into_inner()))
}

impl InProcess {
    /// One parfast command line, run in this process, as
    /// `(exit code, stdout, stderr)`.
    pub fn run(&self, args: &[String]) -> (u8, String, String) {
        let mut sink = parfast::out::Sink::buffered();
        let code = parfast::run_with("parfast", args, &mut sink);
        let (out, err) = sink.take();
        (code, out, err)
    }
}

/// No module in this target reaches `run_with` except through the door
/// above, so no in-process run can happen without the lock held. A new
/// module that calls it directly would race every test here again, and
/// only in a one-process run, which is the one nothing on CI's nextest
/// legs would show.
#[test]
fn every_in_process_run_goes_through_the_one_lock() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/integration");
    let call = concat!("run_", "with(");
    let mut seen = 0;
    let mut offenders = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("the integration directory") {
        let path = entry.expect("entry").path();
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        seen += 1;
        if path.file_name().is_some_and(|n| n == "inproc.rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("module source");
        if text.contains(call) {
            offenders.push(path.display().to_string());
        }
    }
    assert!(
        seen > 5,
        "found only {seen} modules under {}",
        dir.display()
    );
    assert!(
        offenders.is_empty(),
        "call `crate::inproc::in_process().run(..)` instead of `parfast::run_with` in: \
         {offenders:?}"
    );
}
