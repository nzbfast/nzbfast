//! The race harness the occupancy claims are pinned with.
//!
//! Nine doors in this crate and two in `nzbkit` rename a file onto a
//! name they first establish is free. Until 31 Aug 2026 they
//! established it by LOOKING - `exists()`, then `symlink_metadata`
//! (855f7fd91) - and a look is a check before a use: MEASURED on the
//! sibling guard in `unpack::published_names::publish`, one `lstat` is
//! 968 ns against ~112 us of rename behind it, so the guard covered
//! about 1% of its own interval and 96.8% of concurrent arrivals that
//! got the name landed inside the gap. Each door now CLAIMS the name
//! with `create_new` and renames over the placeholder it owns.
//!
//! WHY THE PINS HAVE TO RACE, and it is the whole reason this file
//! exists rather than a deterministic assertion at each door: the claim
//! and the look agree on every question that can be asked without a
//! second thread. Both answer `AlreadyExists`/occupied over a regular
//! file, a dangling link, a link out of the directory and a directory;
//! both decline; both leave the payload under its posted name. The ONE
//! observable difference is an entry that arrives after the answer and
//! before the rename, so a pin that does not race is a pin that cannot
//! tell the fixed door from the broken one - and every one of these was
//! VERIFIED red against its own door reverted to the `lstat`.
//!
//! THE ARRIVAL SEEKS THE RENAME, and it is not a fixed sweep, which is
//! the one thing about this harness that had to be measured rather
//! than copied. The sibling's pin sweeps a fixed count of `spin_loop`s
//! and that covers `publish_weak_name`, whose guard is a few
//! instructions from its entry. Most doors here spend nearly all of
//! their time BEFORE the guard - `rename_nameless_video` reads the
//! directory, gathers sidecars and budgets the stem first - so a fixed
//! sweep put every arrival in front of the guard, where a door
//! declines correctly whether it looks or claims. Three of these pins
//! were GREEN against their own door reverted to the `lstat` until
//! this was fixed: a pin that races the wrong microsecond races
//! nothing.
//!
//! A CALIBRATED SPAN WAS TRIED FIRST AND IS NOT ENOUGH either, for a
//! reason that only shows on a loaded box: one timing run is cold, the
//! trials that follow are warm, so the span systematically OVERSHOOTS
//! and every arrival lands after the rename with the name already
//! taken - which is not a wrong verdict, it is the floor tripping and
//! the pin reporting that it raced nothing. Seen once during
//! authoring, under a concurrent build. What runs instead is a
//! hill-climb: the arrival moves one step LATER whenever it got the
//! name and one step EARLIER whenever it did not, so it settles either
//! side of the rename - which is exactly where the window is - and it
//! re-settles by itself when the box's speed changes under it. There
//! is nothing to calibrate and nothing to keep in step with the doors.
//!
//! AND THE CLIMB NEEDS SOMEWHERE TO CLIMB TO, which is the half that
//! only shows on a four-vCPU CI runner. Both threads used to be released
//! by one flag, so the earliest an arrival could land was the door's own
//! START - and when the box is oversubscribed the adversary is off-core
//! at that moment, needs to arrive EARLIER than a time it cannot reach,
//! and the offset saturates at zero with nothing left to steer. It fails
//! on the floor rather than on the assertion, which is exactly what
//! `unit-one-process` reported on 31 Aug 2026: 8 of 300. The arrival now
//! times itself from its OWN clock and hands the door a `lead` before it
//! starts, so the door's start sits in the middle of the reachable range
//! instead of at its edge; the lead doubles while the climb is pinned at
//! zero, so a box whose jitter exceeds one door duration re-centres
//! itself. See `never_renames_over_a_neighbour` for the measurement.
//! COPIED, not shared, in `nzbkit/src/renameclaim.rs`. A crate cannot
//! see another crate's `#[cfg(test)]` items and making this `pub` in a
//! release build would be a test harness on a shipped surface;
//! the two are BYTE-IDENTICAL below this module
//! doc, so `diff <(tail -n +N a) <(tail -n +M b)` settles whether they
//! still are. `testscratch.rs` beside this one is duplicated per crate for the
//! same reason and says so.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

/// Drive `door` `trials` times against a thread that claims `target`
/// with `create_new` at a swept offset across the door's own duration,
/// and assert that a door which LOST that race never renamed over the
/// entry it lost to.
///
/// `before` runs at the top of every trial with `target` already
/// removed: put the door's source back there.
///
/// PRECONDITION, and it is what makes the assertion exact: every source
/// the door might rename onto `target` must be NON-EMPTY. The adversary
/// holds the name with a zero-byte file, so "still zero bytes" is
/// "still the adversary's", and an empty source would let a real
/// overwrite read as a survival.
///
/// The classification needs no timing and no guess. `create_new` can
/// only succeed while nothing is at the name, so the adversary's own
/// return value says exactly whether it held the name at any point in
/// this trial; a door that renamed over it is then a door whose claim
/// could not have been the thing that answered. There are three
/// buckets and no fourth: it lost the answer (correct decline), it
/// landed in the window (what this asserts against), or it arrived
/// after the rename and got EEXIST.
///
/// The exercised population is FLOORED. An adversary that never got the
/// name would make every trial vacuous and the run green having raced
/// nothing, which is the shape this repository keeps writing gates
/// about. The floor is set low because these run on loaded CI boxes
/// where the scheduler, not the sweep, decides where an arrival lands.
pub(crate) fn never_renames_over_a_neighbour(
    target: &Path,
    trials: usize,
    mut before: impl FnMut(),
    mut door: impl FnMut(),
) {
    // One untimed run to warm anything the door caches. It is UNTIMED on
    // purpose, and it used to be the thing that sized everything below.
    // A cold run overshoots badly - 0.5 ms to 6 ms against a warm door of
    // ~0.6 ms on the dev box - which the offset paragraph in this module's
    // header already records, and a lead or a step seeded from it spends
    // milliseconds a trial on every box to buy a range only a struggling
    // one needs. Nothing here is calibrated from a measurement any more;
    // the climb and the doubling below find the box on their own.
    before();
    door();

    // THE DOOR STARTS LATE, BY `lead`, and that is what gives the climb
    // authority on a BUSY box rather than only on an idle one. Until
    // 31 Aug 2026 both threads were released by the same flag and the
    // arrival's only control was a wait measured from it, so the earliest
    // an arrival could ever land was the door's own start. That is fine
    // while the adversary wakes in a microsecond and the door's guard is
    // fifty microseconds in. It is not fine when the box is oversubscribed
    // and the adversary - a pure spin loop with no syscall in it, which is
    // the first thing a scheduler takes a core back from - is off-core at
    // the moment the flag flips: it then needs to arrive EARLIER than the
    // door's start, the offset saturates at zero, and the climb has
    // nothing left to steer with. It fails LOUDLY and correctly, on the
    // floor below rather than on the assertion, which is how it was found:
    // `unit-one-process` on run 33420059671, 8 of 300, where the whole
    // nzbkit binary runs in one process on a four-vCPU runner and that
    // target took 387 s. Reproduced by reading the climb, not by luck -
    // this dev box settles at 125-162 of 300 with 64 concurrent copies of
    // the rig, so no amount of local load shows it.
    //
    // So the arrival is measured from ITS OWN clock and the door waits
    // `lead` before starting, which puts the door's start in the MIDDLE of
    // the arrival's reachable range instead of at its edge. `lead` doubles
    // whenever the climb is pinned at zero and still losing, so a box
    // whose residual jitter is larger than one door duration re-centres
    // itself instead of reporting that it raced nothing.
    // 20 us, small on purpose - see the warm-up above for why nothing
    // here is seeded from a timing run. The doubling below is what finds
    // a box that needs more, which is the same argument the hill-climb
    // itself rests on.
    let mut lead = 20_000u64;
    // 32 steps across the lead, so the whole reachable range is crossed
    // well inside `trials`. The floor matters more than the figure: a door
    // that measured near zero would otherwise give a step of zero and
    // never climb at all.
    let mut step = (lead / 32).max(1_000);

    let go = Arc::new(AtomicBool::new(false));
    let armed = Arc::new(AtomicBool::new(false));
    let claimed = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let offset = Arc::new(AtomicU64::new(0));

    // A plain copy of the PATH: the caller's scratch guard removes the
    // tree on drop and stays on this thread.
    let (t, g, a, c, st, off) = (
        target.to_path_buf(),
        go.clone(),
        armed.clone(),
        claimed.clone(),
        stop.clone(),
        offset.clone(),
    );
    let adversary = std::thread::spawn(move || {
        loop {
            while !g.load(Ordering::Acquire) {
                if st.load(Ordering::Relaxed) {
                    return;
                }
                std::hint::spin_loop();
            }
            // The clock starts HERE, on this thread, and `armed` then
            // tells the door it may start. Everything between the flag
            // flipping and this line - which is the part a descheduled
            // spinner pays and which is what pinned the old climb at zero
            // - is absorbed rather than counted against the offset.
            let at = Instant::now();
            let wait = off.load(Ordering::Relaxed);
            a.store(true, Ordering::Release);
            while (at.elapsed().as_nanos() as u64) < wait {
                std::hint::spin_loop();
            }
            let ok = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&t)
                .is_ok();
            c.store(ok, Ordering::Release);
            g.store(false, Ordering::Release);
        }
    });

    // The offset the climb steers is the arrival's own wait, so the
    // arrival lands `at_ns - lead` from the door's start and starting at
    // `lead` puts the first trial on the door's start exactly.
    let mut at_ns = lead;
    let mut raced = 0usize;
    let mut pinned_at_zero = 0usize;
    let floor = trials / 20;
    // A SLOW BOX IS GIVEN MORE TRIALS, not a lower bar. Reaching the
    // window takes as long as it takes; what must not happen is judging a
    // run that never got there. The cap is what keeps a door that truly
    // cannot be raced from spinning forever - it still fails, just after
    // having genuinely tried.
    let cap = trials.saturating_mul(4);
    let mut ran = 0usize;
    while ran < trials || (raced < floor && ran < cap) {
        let _ = std::fs::remove_file(target);
        before();
        claimed.store(false, Ordering::Relaxed);
        armed.store(false, Ordering::Relaxed);
        offset.store(at_ns, Ordering::Relaxed);
        go.store(true, Ordering::Release);
        while !armed.load(Ordering::Acquire) {
            std::hint::spin_loop();
        }
        let from = Instant::now();
        while (from.elapsed().as_nanos() as u64) < lead {
            std::hint::spin_loop();
        }
        door();
        while go.load(Ordering::Acquire) {
            std::hint::spin_loop();
        }
        if claimed.load(Ordering::Acquire) {
            // It got the name, so it arrived no later than the rename:
            // step LATER, towards the window.
            at_ns += step;
            pinned_at_zero = 0;
            raced += 1;
            let len = std::fs::symlink_metadata(target).map(|m| m.len());
            assert_eq!(
                len.ok(),
                Some(0),
                "trial {ran}: the door renamed over an entry that was created \
                 beside it - the occupancy window at {}",
                target.display()
            );
        } else {
            // Either the door had already renamed, or the name was
            // unusable: step EARLIER. This is the half that keeps the
            // climb from running away on a box that slowed down - and if
            // it is already as early as this `lead` allows, the range
            // itself is what is too small, so widen that instead.
            if at_ns == 0 {
                pinned_at_zero += 1;
                if pinned_at_zero >= 4 && lead < 8_000_000 {
                    lead = lead.saturating_mul(2);
                    step = (lead / 32).max(1_000);
                    pinned_at_zero = 0;
                }
            }
            at_ns = at_ns.saturating_sub(step);
        }
        ran += 1;
    }
    stop.store(true, Ordering::Release);
    go.store(true, Ordering::Release);
    let _ = adversary.join();

    assert!(
        raced >= floor,
        "the adversary claimed the name only {raced} times in {ran}, so this \
         run raced nothing and its green means nothing"
    );
}
