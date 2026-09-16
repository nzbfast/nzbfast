//! One create-arm at a time, for every module in this binary that runs a
//! create whose ARM is the subject.
//!
//! A create's arm is chosen from process-global state and reported through
//! process-global counters: `ntt_range`'s three pins (transform off, map
//! off, band corpus) and `par2gen::pin_accum_budget_for_tests` decide which
//! arm runs, and `cold_builds_for_tests` / `band_sweeps_for_tests` are
//! monotone counters a caller reads as a DIFFERENCE across its own create.
//! Both halves are shared by the whole process, so two such creates running
//! at once pool into each other: one test's pin sends the other's create
//! down an arm it was not written for, and one test's plan lands inside the
//! other test's counter window. `ntt_range`'s own header says as much and
//! names "the caller's serializer" - this is it.
//!
//! WHY IT LIVES HERE rather than beside the tests that first needed it.
//! It was a module-private `Arms` in `par2gen_create_ntt`, which serialised
//! that module against itself and nothing else, while `par2gen_cancel`'s two
//! transform tests ran creates of exactly this kind under no lock at all.
//! Measured 15 Sep 2026 on `cargo test -p nzbkit --test integration` (the
//! whole binary in ONE process, 188 tests): `a_pause_parks_the_stripe_
//! first_arm_and_a_resume_finishes_it` read `cold == 2` where its own create
//! built one plan and a cancel-module create built the other inside its
//! window, and `a_pause_raised_inside_the_transform_parks_the_create` found
//! volumes on disk because a neighbour's `pin_transform_off_for_tests(true)`
//! had taken its create off the transform, which is the only arm that test
//! has a park site in. Both pass alone, both pass under `--test-threads=1`,
//! and both pass under nextest, which gives every test its own process - so
//! nothing in CI except `unit-one-process` could see it. A module-private
//! lock over process-global state is a lock over half the process; the
//! serializer has to be as wide as the state is.
//!
//! Same shape and same reason as [`crate::tls_env`], which made the process's
//! one trust anchor one-at-a-time for the two TLS modules.
//!
//! WHAT DOES NOT NEED IT: a create whose shape the transform's admission
//! refuses cannot build a plan or move a counter, so `par2gen_interop`'s
//! creates (tens of slices at 4-8 KiB blocks, far under
//! `ntt_range::floor_shape_for_tests`) stay unserialised and stay parallel.
//! A test that SIZES itself from those gates is the one that needs the
//! guard - which is the rule to apply to the next one.

use std::sync::{Mutex, MutexGuard};

use nzbkit::par2gen::{ntt_range, pin_accum_budget_for_tests};

static ARMS: Mutex<()> = Mutex::new(());

/// Held for as long as the caller's pins are the process's pins, with
/// every one of them LIFTED on the way out however the test leaves - a
/// pin left standing by a panicking test is the same defect one class
/// removed.
pub struct Arms(Option<MutexGuard<'static, ()>>);

impl Arms {
    /// Take the serializer. Through `into_inner` so one failing test does
    /// not turn its neighbours into poisoned-lock failures that hide it.
    pub fn take() -> Arms {
        Arms(Some(ARMS.lock().unwrap_or_else(|e| e.into_inner())))
    }
}

impl Drop for Arms {
    fn drop(&mut self) {
        ntt_range::pin_transform_off_for_tests(false);
        ntt_range::pin_map_off_for_tests(false);
        ntt_range::pin_band_corpus_for_tests(0);
        pin_accum_budget_for_tests(0);
        drop(self.0.take());
    }
}
