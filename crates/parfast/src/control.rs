//! The command line's half of the engine's controls: Ctrl-C as the
//! engine's own cancel, and the engine's progress as a meter on stdout.
//!
//! All three commands take the gate as of 12 Sep 2026, and all three
//! take the meter as of 17 Sep 2026 (GH #88). Create was the gate
//! alone until then - interruptible, and silent from the first
//! `Opening:` to `Wrote ... bytes to disk` - because the label its
//! meter would have to print was an open question; [`CreateMeter`]
//! settles it and says how.
//!
//! Until 12 Sep 2026 the CLI handed the engine no control at all - its
//! watch was `()` - so Ctrl-C on a long repair was a plain kill: the
//! fold's temp-staged members stayed on disk, nothing said what state the
//! set was in, and a two-hour solve printed nothing from start to end.
//! The engine grew a [`PauseGate`] its loops poll and a [`ProgressSink`]
//! its phases report to (`par2repair::control`) for the GUI and the
//! daemon; this module is the same two things for a terminal.
//!
//! What a cancel leaves on disk is the engine's promise, stated on
//! `RepairError::Cancelled`: nothing written before the patch, every
//! temp-staged member removed during it, an in-place member no worse
//! than it was. `lib.rs` says so on stderr and exits 130, the shell's
//! own code for an interrupted process, so a script that tests `== 1`
//! for "damage found" does not read a cancelled verify as a verdict.
//!
//! The meter prints par2cmdline's `Repairing: 12.3%\r` shape - a
//! carriage-return redraw per tenth of a percent, under the verbosity
//! rule the reference applies (`-q` silences it) - because SABnzbd
//! reads exactly those fragments off par2's pipe for its queue
//! percentage, and a drop-in that stayed silent would show a job stuck
//! at 0%.
//!
//! MEASURED 17 Sep 2026 against a real SABnzbd 5.1.2 with its bundled
//! par2 tapped (`research/SAB-PARFAST-METER-DROPIN-2026-09-17.md`, off
//! claim `sab-parfast-meter-dropin-17sep`): SAB drives that percentage
//! from `Repairing:` ALONE - `Solving:`, `Scanning:`, `Loading:` and
//! `Constructing:` reach no branch of its parser and are discarded
//! unread. So until 18 Sep 2026 the per-phase labels bought SAB
//! nothing, and the tail this module exists to avoid happened anyway
//! and worse than on the reference: our `Repairing:` counted the fold
//! alone and left SAB's bar pegged at 100% for 7.3 s of an 8.0 s
//! repair, against the reference's 2%, because the reference's own
//! `Repairing:` spans the reconstruction AND the write.
//!
//! So [`Meter`] now spans the same thing the reference's does, and
//! more: `Repairing:` carries the fold, the solve and the patch on one
//! weighted bar, and `Scanning:` keeps the verify. The `Solving:` label
//! the merge costs was only ever read by the terminal, the GUI and the
//! daemon - and all three take their progress from the engine's own
//! [`ProgressSink`] phases, which are untouched. See [`Meter`] for the
//! span, the weights and what they were measured on.

use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use nzbkit::par2gen::control::CreateControl;
use nzbkit::par2repair::{PauseGate, ProgressSink, RepairControl, RepairPhase};

use crate::create::CreateWatch;
use crate::out::{Level, Sink};
use crate::repair::RepairWatch;
use crate::verify::SurveyWatch;

/// Exit code for a run the user interrupted: 128 + SIGINT, the shell's
/// own convention, on every platform so a script sees one number.
pub const EXIT_INTERRUPTED: u8 = 130;

/// How many interrupts the process has taken. The signal handler is the
/// only writer; the watcher thread and the second-interrupt exit read it.
static INTERRUPTS: AtomicU32 = AtomicU32::new(0);

/// Hook Ctrl-C (SIGINT and SIGTERM on unix; Ctrl-C, Ctrl-Break and the
/// console closing on Windows) to a fresh gate and hand the gate back.
///
/// The FIRST interrupt cancels cleanly: a watcher thread sees the count
/// move and calls [`PauseGate::cancel`], which a signal handler itself
/// cannot (it takes a mutex). The SECOND exits the process at once, the
/// way a user who pressed twice meant - `_exit`, which is signal-safe,
/// so a fold that was mid-write leaves whatever it leaves. Both are said
/// on stderr by `lib.rs` when the first one lands.
///
/// Once per process, and only the binary calls it: an in-process test
/// must not re-point the test runner's signals. If the hook cannot be
/// installed the gate is returned anyway and simply never trips, which
/// is the pre-12-Sep behaviour and not an error worth a line.
pub fn install_interrupt() -> Arc<PauseGate> {
    let gate = PauseGate::new();
    if !hook() {
        return gate;
    }
    let watched = gate.clone();
    // Detached on purpose: it lives as long as the process and exits
    // with it. 20 ms is the cancel's latency ceiling, under the engine's
    // own per-block poll on any set worth cancelling.
    let _ = std::thread::Builder::new()
        .name("parfast-interrupt".into())
        .spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_millis(20));
                if INTERRUPTS.load(Ordering::SeqCst) > 0 {
                    watched.cancel();
                    return;
                }
            }
        });
    gate
}

#[cfg(unix)]
extern "C" fn on_signal(_sig: libc::c_int) {
    // Async-signal-safe throughout: one atomic and, on the second press,
    // `_exit`. No allocation, no lock, no stdio.
    let n = INTERRUPTS.fetch_add(1, Ordering::SeqCst) + 1;
    if n >= 2 {
        // SAFETY: `_exit` is async-signal-safe and takes no pointer.
        unsafe { libc::_exit(i32::from(EXIT_INTERRUPTED)) };
    }
}

#[cfg(unix)]
fn hook() -> bool {
    let handler = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
    // SAFETY: `signal` with a plain function pointer of the documented
    // shape; both signals are ones this process may take.
    unsafe {
        libc::signal(libc::SIGINT, handler) != libc::SIG_ERR
            && libc::signal(libc::SIGTERM, handler) != libc::SIG_ERR
    }
}

#[cfg(windows)]
unsafe extern "system" fn on_ctrl(_kind: u32) -> windows_sys::core::BOOL {
    // Runs on a thread of the console's own, not a signal context, so a
    // plain `exit` is fine here. `1` tells the console it was handled.
    let n = INTERRUPTS.fetch_add(1, Ordering::SeqCst) + 1;
    if n >= 2 {
        std::process::exit(i32::from(EXIT_INTERRUPTED));
    }
    1
}

#[cfg(windows)]
fn hook() -> bool {
    // SAFETY: registering a handler of the documented signature.
    unsafe { windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(on_ctrl), 1) != 0 }
}

#[cfg(not(any(unix, windows)))]
fn hook() -> bool {
    false
}

/// The `Repairing: 12.3%\r` meter: one redraw per tenth of a percent
/// per phase, on the writer it was given, silent when told to be.
///
/// # The sweep frame, and why this bar does NOT start over per sweep
///
/// A solve whose working window does not fit the memory budget is cut
/// along the block's byte axis, and the payload is then swept once per
/// slab (`reconstruct::plan_slabs`), so [`RepairPhase::Fold`] and
/// [`RepairPhase::Solve`] are each ENTERED once per sweep with their
/// counters reset. Until 17 Sep 2026 this meter implemented `progress`
/// and not [`ProgressSink::slab`], so a four-sweep repair drew eight
/// 0-to-100 bars alternating between `Repairing:` and `Solving:` on one
/// terminal line - the engine's own recorded per-sweep order is in
/// `research/REPAIR-SLABBED-BAR-2026-09-16.md` section 2.
///
/// The trait's own doc exempted this type BY NAME: a sink that "draws
/// one bar per phase" was said to be correct ignoring the frame. That
/// exemption is now gone, and what removed it is the REFERENCE rather
/// than taste. par2cmdline spans its memory passes with ONE bar.
///
/// MEASURED 17 Sep 2026, aarch64 macOS, against the `par2` on that box
/// (par2cmdline v1.2.0 - near but not the v1.3.0 [`CreateMeter`] pinned
/// its own measurement to, and the claim here is about a structure both
/// carry). 64 MiB payload, 1 MiB blocks, 30 damaged blocks, so `-m1`
/// cuts the reference's output buffer to a thirtieth of a block:
///
/// * `par2 r -m1` prints `Repairing:` ONCE, 0.1% to 100.0%, strictly
///   monotone over 1,008 fragments with ZERO backward steps.
/// * `par2 r -m512` on the same set prints one run of the same bar.
/// * The passes are real and not optimised away: the two runs do the
///   same arithmetic (user 1.48 s against 1.38 s) and differ 8x in
///   SYSTEM time (0.73 s against 0.09 s), which is the payload being
///   re-read once per pass.
///
/// So a drop-in that starts over per sweep does not merely look worse
/// than the tool it replaces - it reports a thing that tool never
/// reports, on the fragments a queue scraper reads off the pipe.
///
/// AND THE SCRAPER IS NOT HYPOTHETICAL, measured the same day by claim
/// `sab-parfast-meter-dropin-17sep` against a real SABnzbd 5.1.2 with
/// its bundled par2 tapped - landing as
/// `research/SAB-PARFAST-METER-DROPIN-2026-09-17.md`, and the CLAIM ID
/// is the handle to search if that file arrived under another name,
/// because no gate in this repo checks a research path in a comment:
/// SAB reads the pipe in TEXT mode, so every `\r` fragment is one
/// `readline()` and this module's shape is right; it dispatches on
/// `line.startswith(("Repairing:", "Processing:"))` and on nothing
/// else; and its own percentage NEVER falls (`if new_perc - perc > 1`,
/// against a figure monotone for the run). Put together, those say
/// exactly what a per-sweep reset cost: SAB would take sweep 1 of 8,
/// reach 100%, and be unable to see sweeps 2 to 8 AT ALL. Banded, the
/// one label it reads climbs once across every sweep.
///
/// That measurement is also why the WORD is left alone here. `perc`
/// moving at all depends on `startswith("Repairing:")` with the colon
/// where it is - `Repairing (sweep 2/4): ` matches nothing, and blanks
/// the bar in silence. The SPAN that label covers was the same lane's
/// larger finding and is settled below.
///
/// # THE SPAN: one weighted `Repairing:` over the fold, the solve and
/// the patch
///
/// Settled 17 Sep 2026 on claim `sab-meter-label-covers-whole-repair`
/// and implemented 18 Sep. Three things argued for it:
///
/// * **The reference does this.** par2cmdline's `Repairing:` spans the
///   reconstruction and the write, which is why the tapped control arm
///   spent 2% of its wall after its bar maxed and ours spent 99%. A
///   drop-in whose bar covers the fold alone is not matching the tool
///   it replaces.
/// * **The precedent is in this file.** [`CreateMeter`] already folds
///   two engine phases onto one `Processing:` bar. This is that move.
/// * **It is the only candidate that SPENDS the bar.** The alternative
///   - keep four labels, let the LAST be `Repairing:` - leaves SAB at
///   its `Repair is possible` floor of 0% through the fold and the
///   solve, then climbs 0 to 100 across the write alone. That trades a
///   bar stuck at 100% for one stuck at 0%.
///
/// The objection this type's own doc used to make - that merging costs
/// the `Solving:` label, "the thing this module exists for" - inverts
/// once the merged bar is WEIGHTED. The fear is a bar pegged at 100%
/// while a long solve runs; a weighted bar is precisely the shape in
/// which the solve still has bar left to spend, so the peg cannot
/// happen. A separate label only ever helped a reader that renders all
/// four, and those three readers (terminal, GUI, daemon) read the
/// engine's own [`ProgressSink`] phases, which this change does not
/// touch. SABnzbd, the reader the paragraph was about, discards
/// `Solving:` unread.
///
/// # Sweep FIRST, phase inside - and why not the other way round
///
/// `nzbfast-core`'s `repairprog` and `parfast-session`'s
/// `RepairProgress` cut `[0.45, 0.95)` by SWEEP and put the fold/solve
/// weighting INSIDE each segment. Until the merge, this meter could do
/// the opposite - a counter per phase, nothing monotone, two bars
/// crossing one frame in step - because no two of its bars shared a
/// number. A merged bar is in those two types' position for the first
/// time, so it inherits their shape and their reason: `Fold` and
/// `Solve` are entered ONCE PER SWEEP, so a phase-first cut puts sweep
/// 1's solve above sweep 2's fold and the bar walks backwards at every
/// boundary.
///
/// ```text
/// Repairing: [0 .. HEAD)     the sweep-carrying head, cut into N
///                            equal segments, one per slab;
///                            within segment i, Fold owns the
///                            first FOLD_SHARE and Solve the rest
/// Repairing: [HEAD .. 1000]  the Write tail, which takes NO
///                            sweep frame
/// ```
///
/// Equal sweep segments are MEASURED and not assumed:
/// `research/SLABBED-REPAIR-METER-2026-09-17.md` Q3 put every arm of a
/// 512 MiB set inside 1.35x of an even split (2 sweeps 44.5-55.5%, 8
/// sweeps 10.5-16.0%, 29 sweeps 3.1-4.2%), loosening only at 64 MiB and
/// 31 sweeps where a sweep is ~30 ms and scheduling noise dominates.
///
/// The bar is also MONOTONE, which a per-phase bar never had to be: the
/// merge gives it three hand-overs that can each present a smaller
/// fraction than the frame already on screen - fold to solve, sweep to
/// sweep, and head to tail. `max` of what was asked for before, exactly
/// as [`CreateMeter`] does it. `Scanning:` keeps its own counter and is
/// not in that maximum; it is a different bar with a different label.
///
/// # The weights, and what they were measured on
///
/// `Meter::HEAD` and `Meter::FOLD_SHARE` are FIXED SHARES chosen off
/// a measured round, not derived from the set. Measured 18 Sep 2026,
/// dev Mac (M3 Ultra), RELEASE build, over SEVEN arms: five offline
/// taps of `parfast r` with every `\r` fragment wall-stamped, plus two
/// real SABnzbd 5.1.2 jobs. The offline sets are both 512 MiB - a LIGHT
/// one (4 MiB blocks, 60 of 128 damaged) and a HEAVY one (1 MiB blocks,
/// 250 of 512), each at the default memory budget and forced to eight
/// sweeps with `-m64` / `-m16` - and were taken at `uptime` 7.51 7.08
/// 7.92, load1 under load15, the drained window `CLAUDE.md` says to
/// measure in.
///
/// TWO THINGS MOVE THE PHASE SPLIT, and between them no fixed share can
/// be right everywhere. GEOMETRY: on a large-block set the fold and the
/// solve are the repair and the patch is a seventh of it; on a real
/// SABnzbd job - a usenet post, so thousands of small blocks - the
/// patch can be nearly all of it. And BOX STATE: the same SAB corpus,
/// twice, split 1.9% fold / 95.7% write on a loaded box and 40.9% /
/// 9.5% on a quiet one, because the patch is I/O and the fold is CPU.
/// That second one is the larger effect and it is not a property of the
/// set at all.
///
/// So the choice is which error to take. Scored as the worst gap
/// between the bar's fraction and the repair's own elapsed fraction,
/// every arm re-simulated under each candidate:
///
/// | `HEAD` | heavy/1 | heavy/8 | light/1 | light/8 | SAB loaded | SAB quiet | worst | mean |
/// |---|---|---|---|---|---|---|---|---|
/// | 400 | 36.9 | 29.8 | 18.5 | 24.3 | 36.0 | 44.2 | 44.2 | 32.0 |
/// | **450** | 31.9 | 24.8 | 18.5 | 24.3 | 41.0 | 39.2 | **41.0** | 29.8 |
/// | 500 | 26.9 | 22.0 | 18.5 | 24.3 | 46.0 | 34.2 | 46.0 | **28.0** |
/// | 600 | 17.1 | 27.9 | 18.5 | 29.4 | 56.0 | 24.2 | 56.0 | 28.7 |
/// | 850 | 10.3 | 43.0 | 28.4 | 44.6 | 81.0 | 17.8 | 81.0 | 38.3 |
///
/// **450 is the MINIMAX**, and minimax is the right criterion for a
/// bar: what a reader notices is the worst divergence in the run in
/// front of them, not the average over a fleet of geometries. 500 is
/// mean-optimal and is 1.8 points off the minimax, so anything in
/// 425-500 is defensible. 850 - the head's share on the large-block
/// sets, and what this constant was on the first build of this change -
/// is the WORST of the candidates on five of the seven arms, because it
/// generalised from the offline sets before either SAB arm existed.
///
/// NO CANDIDATE EVER FREEZES OR REVERSES THE BAR. The stall figure is
/// identical across all of them - it is the post-write self-proof - so
/// this choice is about PACING alone, and the acceptance numbers below
/// are the same whichever row is taken.
///
/// `FOLD_SHARE` is 550. Fold against solve within one sweep, same
/// round: 51:49 heavy/1, 56:44 heavy/8, 58:42 heavy(`-m16`)/8, 55:45
/// light/1. `research/SAB-PARFAST-METER-DROPIN-2026-09-17.md` derives
/// 50:50-and-slightly-fold-heavy independently, off the slab round's Q2
/// table, on a different box and a DEBUG build.
///
/// THE GEOMETRY HOOK WAS MEASURED AND REFUSED, 18 Sep 2026, and this
/// paragraph used to say it was the real answer. It is not, and the
/// round that settled it is
/// `research/REPAIR-METER-GEOMETRY-HOOK-2026-09-18.md`.
///
/// The half of the idea that is TRUE: fold work scales with
/// `present_bytes x missing_blocks` and solve with `missing_blocks`
/// squared, both on the same cores, so their ratio cancels the hardware
/// and obeys one law - `solve/fold ~ 1.2 x missing/present` - measured
/// over a 60x range of that ratio on eleven purpose-built geometries and
/// confirmed on the banked arms above. So `Meter::FOLD_SHARE` IS
/// derivable.
///
/// The half that kills it: deriving it moves the score by ZERO on all
/// seven arms, because what the score measures is where the bar sits in
/// the WHOLE repair, which `Meter::HEAD` fixes and `FOLD_SHARE` does
/// not touch. And `HEAD` is the head/WRITE split, where the write is the
/// one phase that is I/O - measured at 15 MB/s on the loaded SAB arm
/// against 10.1 GiB/s here, a factor of 1,400 on one binary. Write the
/// cost model out and every symbol is geometry except `R_cpu / R_io`,
/// which is all of `HEAD` and none of it knowable from the set. Swept
/// over five decades, the best geometry-derived `HEAD` scores 65.4
/// worst-case against 41.0 for the constant, and inverts the arms'
/// ORDER while doing it. A second free parameter (a per-block write
/// cost, the one signal that could separate a 3,465-tiny-block SAB job
/// from a 250-big-block set) reaches 44.2, and only by driving the
/// per-byte cost to zero and handing all three geometries nearly the
/// same `HEAD` - a constant with extra steps.
///
/// AND THE CEILING SETTLES IT WITHOUT REFERENCE TO ANY MODEL. `SAB
/// loaded` and `SAB quiet` in the table above are the SAME corpus
/// through the SAME binary, split 1.9%/95.7% and 42.1%/7.7%, so EVERY
/// geometry model hands them one `HEAD` by construction and their two
/// scores move oppositely in it. The best any model can do on that pair
/// is 40.6, against these constants' 41.0. That 0.4 points is the whole
/// prize for a new method on `nzbkit-base`'s engine surface, three sink
/// implementations and a calibration constant that would need
/// re-measuring whenever the fold's SIMD moved.
///
/// So the constants stay, and what the box-state half costs is stated
/// above rather than engineered around.
///
/// THE ACCEPTANCE NUMBER is the drop-in report's own: the fraction of
/// the repair's wall (`Repair is possible.` to `Repair complete.`) left
/// AFTER the bar reaches its maximum, against the reference's 2% and
/// the 91% SABnzbd measured on the fold-only bar. Offline, the
/// fold-only bar against the merged one: heavy/1 59.2% -> 7.8%,
/// heavy/8 33.7% -> 16.5%, `-m16` 29.6% -> 13.3%, light/1 65.7% ->
/// 18.5%, light/8 44.2% -> 24.3%. Re-tapped against the BUILT change
/// rather than predicted: 7.9% at one sweep and 9.9% at eight, 636 and
/// 998 fragments, ZERO reversals, both ending at exactly 100.0%, and
/// exactly two labels on the pipe.
///
/// AND THROUGH A REAL SABnzbd 5.1.2, which is the reader this whole
/// module doc is about - a controlled pair on ONE corpus, one binary
/// swapped, SAB's own bundled par2 tapped so the bytes scored are the
/// ones it read:
///
/// | arm | repair wall | SAB's bar | frozen tail |
/// |---|---|---|---|
/// | parfast, merged | 11.30 s | 39 steps, 3% -> 99% | **0.4%** |
/// | par2cmdline-turbo 1.4.0 | 34.97 s | 90 steps, 1% -> 99% | 14.8% |
///
/// So the merged bar is now BETTER than the tool it replaces on the
/// metric that tool was the benchmark for, on the same job. (SAB stops
/// at 99% in BOTH arms and that is SAB, not a shortfall of the merge:
/// `if new_perc - perc > 1` cannot fire on the last step from 99.x.)
///
/// What is LEFT in the acceptance column is the self-proof - `Verifying
/// repaired files:` and its re-hash - which no METER covers in either
/// tool: the reference announces it as a LINE, and this CLI's `Write`
/// phase ends at the patch. It is NOT a gap for a SABnzbd user, checked
/// against the banked polls: SAB counts that phase itself off the
/// `Verifying repaired files:` and `Target:` lines `verify.rs` emits,
/// and showed a live `Verifying repair: 02/02` there where the
/// REFERENCE left the queue blank for 5.2 s. So giving our self-proof
/// the `Scanning:` bar would buy SAB nothing - `Scanning:` is in its
/// skip tuple - and would be a terminal-and-GUI change only.
///
/// # The shape at the terminal
///
/// REPRODUCED END TO END, and it needs no test seam. On the heavy set
/// above, `NZBFAST_REPAIR_SOLVE_BUDGET` (the figure
/// `reconstruct::solve_window_budget` reads, and the one `-m` lowers)
/// cut into eight sweeps: before 17 Sep the single terminal line
/// carried SIXTEEN 0-to-100 bars, `Repairing:` and `Solving:`
/// alternating; `f3f512012` made that one climb per label; and this
/// change makes it ONE climb, 0.0 to 100.0, under one word.
///
/// The sweep number does NOT go in the label, though the 16 Sep report
/// suggested `Repairing (sweep 2/4)`: `Repairing: ` is the reference's
/// word to the byte, and a scraper keying on it is exactly the reader
/// the paragraphs above are about. The frame is said in the number.
///
/// A side effect worth naming because it is a fix and not a loss: the
/// repair no longer prints `Writing:` at all, and `Writing:` is the one
/// label of ours that is NOT in SABnzbd's skip tuple - so 257 frames
/// per repair used to land verbatim in every SAB user's `sabnzbd.log`
/// under "par2cmdline output was:", where the reference emits no such
/// label. [`CreateMeter`] keeps its own `Writing:`; SAB never runs a
/// create.
///
/// LIMIT, stated because it is one call site away: `Verify` and `Write`
/// take no sweep frame, which is right for the two engine entries this
/// CLI calls. `repair_dir_set_surveyed_as` and
/// `repair_dir_set_with_donors_as` hash once before the first sweep and
/// patch once after the last. The MAPPED driver writes INSIDE the sweep
/// loop and self-proves after it, so a caller that grows that route
/// owes `Write` a frame of its own - and [`ProgressSink::route`], which
/// this type still ignores, is how it would tell the two apart. Under
/// the merge that mistake is bounded rather than silent: the tail is
/// monotone, so a per-sweep `Write` would step to 100% during sweep 1
/// and hold, which is the pre-merge failure in the last 15% of the bar
/// instead of the last 60%.
pub struct Meter {
    quiet: bool,
    /// The last tenth-percent drawn per phase, `RepairPhase` order;
    /// `u32::MAX` is "nothing yet". A swap, not a compare: the engine
    /// says `done` may step back across calls, and a redraw on any
    /// change is what the reference does too.
    last: [AtomicU32; 4],
    /// Whether the last thing written was a `\r` fragment that nothing
    /// has terminated, so [`Meter::end_line`] knows whether a `\n` is
    /// owed before something else is printed on the same terminal.
    dirty: AtomicBool,
    /// The sweep frame the fold and the solve are drawn inside: which
    /// sweep, and how many. `(0, 1)` - one sweep of one - until the
    /// engine says otherwise, which is the right reading both of a
    /// repair that does not slab and of one that announces nothing
    /// because it has no block to rebuild.
    sweep: AtomicU32,
    sweeps: AtomicU32,
    /// The thousandth the merged `Repairing:` bar last ASKED for, held
    /// so it cannot fall back across the three hand-overs the merge
    /// gives it - fold to solve, sweep to sweep, head to tail. Not the
    /// same thing as `last[1]`, which is what was DRAWN and exists to
    /// drop a redraw of an unchanged figure.
    drawn: AtomicU32,
    out: Mutex<Box<dyn Write + Send>>,
}

impl Meter {
    /// A meter that draws on `out`. `quiet` is the reference's rule -
    /// progress is a `-q` casualty - decided once by the caller from the
    /// sink's level, because this is called from the engine's workers
    /// and the sink is not.
    pub fn new(quiet: bool, out: Box<dyn Write + Send>) -> Arc<Meter> {
        Arc::new(Meter {
            quiet,
            last: std::array::from_fn(|_| AtomicU32::new(u32::MAX)),
            dirty: AtomicBool::new(false),
            sweep: AtomicU32::new(0),
            sweeps: AtomicU32::new(1),
            drawn: AtomicU32::new(0),
            out: Mutex::new(out),
        })
    }

    /// The meter for the program's own stdout, or a silent one when the
    /// sink is a buffer or a host's tap - those readers get their
    /// progress from the engine directly, or want none.
    ///
    /// `forced` is `--progress` (GH #88): the bar stays on under `-q`,
    /// and under `-q -q` it is the only thing on stdout. It lifts the
    /// LEVEL gate only - a buffered or tapped sink still gets no meter,
    /// because that reader has its own.
    pub fn for_sink(sink: &Sink, forced: bool) -> Arc<Meter> {
        let quiet = !(sink.is_stdio() && (forced || sink.shows(Level::Normal)));
        Meter::new(quiet, Box::new(std::io::stdout()))
    }

    /// The share of the merged bar the sweep-carrying head owns, in
    /// tenths of a percent; `[HEAD, 1000]` is the `Write` tail. See the
    /// weights section on [`Meter`] for the round this came off.
    const HEAD: u32 = 450;

    /// The share of ONE sweep segment the fold owns; the solve owns the
    /// rest. Same round, same section.
    const FOLD_SHARE: u32 = 550;

    fn slot(phase: RepairPhase) -> usize {
        match phase {
            RepairPhase::Verify => 0,
            RepairPhase::Fold => 1,
            RepairPhase::Solve => 2,
            RepairPhase::Write => 3,
        }
    }

    /// `done` out of `total` as TENTHS OF A PERCENT, clamped to 1000.
    /// The redraw grain, and the reference's.
    fn tenth(done: u64, total: u64) -> u32 {
        u32::try_from((done.min(total) * 1000) / total.max(1)).unwrap_or(1000)
    }

    /// Where one repair phase's own fraction `within` lands on the
    /// merged bar: the patch in the tail `[HEAD, 1000]`, and the fold
    /// and the solve inside sweep `i` of `N`'s equal segment of
    /// `[0, HEAD)`, the fold taking that segment's first `FOLD_SHARE`.
    ///
    /// `Verify` never reaches here - it is the other bar.
    fn placed(&self, phase: RepairPhase, within: u32) -> u32 {
        if matches!(phase, RepairPhase::Write) {
            let tail = u64::from(1000 - Meter::HEAD);
            return Meter::HEAD
                + u32::try_from(u64::from(within) * tail / 1000).unwrap_or(tail as u32);
        }
        // Inside one segment, in MILLIONTHS of that segment, so the
        // whole placement is one division and not three: at a tenth of
        // a percent of a phase of a sweep of the head, a truncation per
        // step is visible in the figure drawn.
        let share = u64::from(Meter::FOLD_SHARE);
        let inside = if matches!(phase, RepairPhase::Fold) {
            u64::from(within) * share
        } else {
            (share + u64::from(within) * (1000 - share) / 1000) * 1000
        };
        let of = u64::from(self.sweeps.load(Ordering::Relaxed).max(1));
        let i = u64::from(self.sweep.load(Ordering::Relaxed)).min(of - 1);
        u32::try_from((i * 1_000_000 + inside) * u64::from(Meter::HEAD) / (of * 1_000_000))
            .unwrap_or(Meter::HEAD)
    }

    /// Draw `tenth` under `label`, unless this slot already shows it.
    ///
    /// `slot` is the per-bar counter, not the phase: the create folds
    /// two phases onto one bar (see [`CreateMeter`]) and they must
    /// share a counter or each would redraw over the other's frame.
    fn draw(&self, slot: usize, label: &str, tenth: u32) {
        if self.quiet {
            return;
        }
        if self.last[slot].swap(tenth, Ordering::Relaxed) == tenth {
            return;
        }
        let mut out = self.out.lock().unwrap_or_else(|p| p.into_inner());
        let _ = write!(out, "{label}{}.{}%\r", tenth / 10, tenth % 10);
        let _ = out.flush();
        self.dirty.store(true, Ordering::SeqCst);
    }

    /// The `--progress` frame: one label, the percentage, and a drawn
    /// bar of [`Meter::BAR_CELLS`] cells, which is the shape the GH #88
    /// reporter asked for by example. Same slot, grain and redraw rule
    /// as [`Meter::draw`]; only the text differs, and it is not the
    /// reference's shape on purpose - this frame exists only behind a
    /// switch the reference does not have.
    fn draw_bar(&self, slot: usize, tenth: u32) {
        if self.quiet {
            return;
        }
        if self.last[slot].swap(tenth, Ordering::Relaxed) == tenth {
            return;
        }
        let filled = (tenth * Meter::BAR_CELLS / 1000) as usize;
        let empty = Meter::BAR_CELLS as usize - filled;
        let mut out = self.out.lock().unwrap_or_else(|p| p.into_inner());
        let _ = write!(
            out,
            "Progress: {:>3}.{}% [{}{}]\r",
            tenth / 10,
            tenth % 10,
            "=".repeat(filled),
            " ".repeat(empty)
        );
        let _ = out.flush();
        self.dirty.store(true, Ordering::SeqCst);
    }

    /// Cells in the `--progress` bar. Forty keeps the whole frame under
    /// sixty columns, so it fits an eighty-column terminal with room.
    const BAR_CELLS: u32 = 40;

    /// Terminate a pending `\r` fragment with a newline, so the next
    /// line on the terminal does not overprint it. Owed before the
    /// "Cancelled" line; a completed run needs none, because every
    /// phase is followed by a full line that overwrites the fragment,
    /// which is the reference's behaviour to the byte.
    pub fn end_line(&self) {
        if self.dirty.swap(false, Ordering::SeqCst) {
            let mut out = self.out.lock().unwrap_or_else(|p| p.into_inner());
            let _ = out.write_all(b"\n");
            let _ = out.flush();
        }
    }
}

impl ProgressSink for Meter {
    /// WHICH SWEEP IS STARTING. Announced from the driver thread before
    /// that sweep's first `progress` and never beside one, so a plain
    /// store is enough: see [`Meter`] for why this type takes it at all,
    /// having been exempted by name until 17 Sep 2026.
    fn slab(&self, index: usize, of: usize) {
        self.sweeps
            .store(u32::try_from(of.max(1)).unwrap_or(1), Ordering::Relaxed);
        self.sweep
            .store(u32::try_from(index).unwrap_or(0), Ordering::Relaxed);
    }

    fn progress(&self, phase: RepairPhase, done: u64, total: u64) {
        if total == 0 {
            return;
        }
        let within = Meter::tenth(done, total);
        // The scan is its own bar under its own word, unbanded and
        // outside the merged bar's monotone floor: it runs once, before
        // the first sweep, on both engine entries this CLI calls.
        if matches!(phase, RepairPhase::Verify) {
            self.draw(Meter::slot(phase), "Scanning: ", within);
            return;
        }
        let tenth = self.placed(phase, within);
        // Monotone - see [`Meter`]. `max` of what was asked for before,
        // so no hand-over can take the bar backwards.
        let tenth = tenth.max(self.drawn.fetch_max(tenth, Ordering::Relaxed));
        self.draw(Meter::slot(RepairPhase::Fold), "Repairing: ", tenth);
    }
}

/// The CREATE's meter: par2cmdline's `Processing:` over the fold, then
/// a `Writing:` bar the reference does not have.
///
/// # Why `Processing:`, which is the question that kept this off
///
/// par2cmdline prints `Processing: 12.3%\r` while it creates, and until
/// 17 Sep 2026 `parfast c` printed nothing at all rather than print a
/// label that looked like the reference's and might not mean the same
/// thing. That was a deliberate omission and not an oversight (GH #88),
/// and what it was waiting for was evidence rather than a guess. So the
/// reference was measured, at the PINNED version `tools/conformance`
/// compares to (par2cmdline v1.3.0), on an aarch64 macOS box,
/// 17 Sep 2026:
///
/// * The reference's `Processing:` is linear in wall - 10/25/50/75/90%
///   of the bar at 0.101/0.250/0.495/0.753/0.903 of the phase's own
///   elapsed time - which is what a fraction of the SOURCE PAYLOAD read
///   and folded looks like, and is what `par2creator.cpp` counts
///   (`progress` per input block against `totaldata`).
/// * It spans every pass. Forced multi-pass with `-m1` it still runs 0
///   to 100 ONCE, not once per pass.
/// * It ends before the volumes are written: the reference's own next
///   frame on that line is the literal `Writing recovery packets`.
///
/// All three are true of the bar below, so the label is the reference's
/// AND it means the reference's thing. What differs between the two
/// tools is not what the percentage counts but how long it takes to
/// cross: par2cmdline's create slows down sharply with the recovery
/// block count and this engine's barely does, so the recovery work here
/// tracks the payload size far more closely than it tracks the block
/// count. That is a statement about the clock, not about the
/// denominator - so it argues for counting bytes, which is what the
/// engine's phases already count, and not against the word.
///
/// The conformance tables cannot hold this claim and it is worth
/// knowing why rather than looking for the row: `run.py`'s `normalise`
/// keeps only the LAST `\r` fragment of a physical line, so every
/// meter frame either tool draws is gone before a table sees it. The
/// shape is pinned by this module's own tests instead, exactly as the
/// repair's is.
///
/// # The two phases behind the one bar
///
/// `Verify` (hashing the members) and `Fold` (the recovery arithmetic)
/// run AT THE SAME TIME on a create - the engine hashes on one thread
/// while the fold reads the same payload on another, and on the fused
/// arm the fold's own reader does the hashing and `Verify` never
/// reports at all. Two labels redrawing over each other on one terminal
/// line is not a bar, so they share one, which is also how the GUI's
/// bar reads them (`parfast-session`'s `CreateProgress`).
///
/// They are merged by taking the LESSER fraction, once both have
/// spoken. Until 20 Sep 2026 it was the LARGER, as the GUI's bar still
/// takes it, and that was measured wrong on the create this CLI most
/// often runs: with the payload in page cache the hash's block lanes
/// finish in a fraction of the fold's wall and the larger of the two
/// pinned the bar at 100 for 70-80% of the run on three legs of four
/// (1 GiB and 4 GiB, `-r5` and `-r10`) - GH #88's "gets to 100 and
/// then waits". A create is over when BOTH spans are, so the slower
/// one is where it stands. Two things make the lesser safe to take:
/// the engine now steps the fold per stripe on the stripe-first arm
/// (it stepped per chunk, which on a one-chunk create was 0 and then
/// 100), and it reports `Verify` as the slower of ITS two lanes, the
/// block digests and the whole-file MD5 chain, so the hash's fraction
/// is honest about the chain that used to run on behind it.
///
/// The batches take care of themselves under this rule. `Verify` is
/// sized once for the whole create and `Fold` re-sized per batch, so
/// `Fold` is banded across the batch frame the engine announces
/// (`ProgressSink::slab`); a hash that finishes during batch 1 then
/// reads 100 and the lesser is the fold for the rest of the create,
/// which is right, and a hash still running in batch 3 holds the bar
/// to where it really is. No cap on the hash is needed any more - the
/// cap existed to stop the LARGER rule pinning the bar, and the lesser
/// cannot pin. A create whose hash never reports (the fused arm, where
/// the fold's reader does the hashing) is the fold alone.
///
/// # And why the volume writes wait for their turn on the line
///
/// `Write` overlaps the fold on the stripe-first arm (volumes are laid
/// out up front and filled by chunk) and sits between batches on the
/// batched one, so two labels drawn as they arrive alternate on one
/// terminal line - measured on the first build of this: `Processing:
/// 0.0%`, `Writing: 0.0%`, `Processing: 100.0%`, `Writing: 1.2%`. That
/// is not a bar. The write bar therefore holds its frames until the
/// fold's is full, which is also the reference's order: `Processing:`
/// runs to 100 and only then does `Writing recovery packets` take the
/// line.
pub struct CreateMeter {
    inner: Arc<Meter>,
    /// `--progress`: the two labels become ONE bar, the fold's `[0,
    /// PROC_SHARE)` and the writes' `[PROC_SHARE, 1000]`, drawn as
    /// [`Meter::draw_bar`]. See [`CreateMeter::PROC_SHARE`] for where
    /// the split comes from.
    unified: bool,
    /// The fold batch frame: index, and how many. `(0, 1)` until the
    /// engine says otherwise, which is the right reading of a create
    /// that folds in one pass or announces nothing.
    batch: AtomicU32,
    batches: AtomicU32,
    /// The thousandth the `Processing:` bar last showed, held so it
    /// cannot go backwards across a batch boundary or when the hash and
    /// the fold trade places as the slower of the two. Also the gate on
    /// the write bar: full means the fold is done with the line.
    drawn: AtomicU32,
    /// The fold's own banded thousandth and the hash's raw one, each the
    /// latest the engine said; `u32::MAX` on the hash is "never spoke",
    /// which is the fused arm and means the fold answers alone.
    fold_at: AtomicU32,
    hash_at: AtomicU32,
    /// The last write fraction the engine reported while the fold still
    /// held the line, in tenths; `u32::MAX` is none. On the stripe-first
    /// arm the volumes are filled UNDER the fold and can finish before
    /// its last frame, so a write bar that only listened after the fold
    /// let go could end the run never having drawn - held here, and
    /// released the moment the fold reaches 100.
    held_write: AtomicU32,
}

impl CreateMeter {
    /// A create meter drawing on `inner`. It SHARES that meter rather
    /// than opening a second one: one lock on the output, one pending-
    /// fragment flag, so [`Meter::end_line`] still owes exactly one
    /// newline whichever command was running.
    pub fn new(inner: Arc<Meter>) -> Arc<CreateMeter> {
        CreateMeter::with_shape(inner, false)
    }

    /// [`CreateMeter::new`], with `--progress`'s one-bar shape when
    /// `unified` is set.
    pub fn with_shape(inner: Arc<Meter>, unified: bool) -> Arc<CreateMeter> {
        Arc::new(CreateMeter {
            inner,
            unified,
            batch: AtomicU32::new(0),
            batches: AtomicU32::new(1),
            drawn: AtomicU32::new(0),
            fold_at: AtomicU32::new(0),
            hash_at: AtomicU32::new(u32::MAX),
            held_write: AtomicU32::new(u32::MAX),
        })
    }

    /// The share of the one `--progress` bar the fold owns, in tenths;
    /// the volume writes own the rest.
    ///
    /// Measured 20 Sep 2026 on the dev Mac (load1 12-16, payload in
    /// page cache), `parfast c` over 1 GiB and 4 GiB at `-r5` and
    /// `-r10`: the `Writing:` frames spanned 0.00-0.05 s of runs of
    /// 1.5-6.3 s, under 1% of the wall on every leg. On the
    /// stripe-first arm the volumes are flushed UNDER the fold, chunk
    /// by chunk, so most of the write's wall is already inside the
    /// fold's; what is left for the tail is the last chunk's flush and
    /// the seals. 950 leaves the tail 5%, room for a disk slower than
    /// the page cache without a bar that sits at 95 for a visible
    /// while on the common one.
    const PROC_SHARE: u32 = 950;

    /// Where a write fraction `within` lands, and under which shape:
    /// the `Writing:` bar's own scale, or the tail of the one bar.
    fn draw_write(&self, within: u32) {
        if self.unified {
            let tail = u64::from(1000 - CreateMeter::PROC_SHARE);
            let placed = CreateMeter::PROC_SHARE
                + u32::try_from(u64::from(within) * tail / 1000).unwrap_or(tail as u32);
            self.inner.draw_bar(Meter::slot(RepairPhase::Fold), placed);
        } else {
            self.inner
                .draw(Meter::slot(RepairPhase::Write), "Writing: ", within);
        }
    }

    /// Where the create stands: the fold's banded fraction, held back by
    /// the hash's when the hash has spoken. See the type doc.
    fn lesser(&self) -> u32 {
        let fold = self.fold_at.load(Ordering::Relaxed);
        match self.hash_at.load(Ordering::Relaxed) {
            u32::MAX => fold,
            hash => fold.min(hash),
        }
    }

    /// The fold's frame `tenth`, under whichever shape.
    fn draw_fold(&self, tenth: u32) {
        if self.unified {
            let placed =
                u32::try_from(u64::from(tenth) * u64::from(CreateMeter::PROC_SHARE) / 1000)
                    .unwrap_or(CreateMeter::PROC_SHARE);
            self.inner.draw_bar(Meter::slot(RepairPhase::Fold), placed);
        } else {
            self.inner
                .draw(Meter::slot(RepairPhase::Fold), "Processing: ", tenth);
        }
    }
}

impl ProgressSink for CreateMeter {
    fn slab(&self, index: usize, of: usize) {
        self.batches
            .store(u32::try_from(of.max(1)).unwrap_or(1), Ordering::Relaxed);
        self.batch
            .store(u32::try_from(index).unwrap_or(0), Ordering::Relaxed);
    }

    fn progress(&self, phase: RepairPhase, done: u64, total: u64) {
        if total == 0 {
            return;
        }
        let within = Meter::tenth(done, total);
        let of = self.batches.load(Ordering::Relaxed).max(1);
        let i = self.batch.load(Ordering::Relaxed).min(of - 1);
        let tenth = match phase {
            // A create has nothing to solve and the engine never sends
            // this; drawing it would be drawing a phase that does not
            // exist.
            RepairPhase::Solve => return,
            // The volume writes, sized once for the whole create, so
            // this one bar walks up across every batch - once the fold
            // has let go of the line.
            RepairPhase::Write => {
                if self.drawn.load(Ordering::Relaxed) < 1000 {
                    self.held_write.store(within, Ordering::Relaxed);
                    return;
                }
                self.draw_write(within);
                return;
            }
            // This batch's own fraction, placed inside the batch frame.
            RepairPhase::Fold => {
                let banded = (u64::from(i) * 1000 + u64::from(within)) as u32 / of;
                self.fold_at.fetch_max(banded, Ordering::Relaxed);
                self.lesser()
            }
            // The hash's whole-create fraction, honest about its chain
            // since the engine's 20 Sep change; the lesser of it and the
            // fold is where the create stands - see the type doc.
            RepairPhase::Verify => {
                let seen = self.hash_at.load(Ordering::Relaxed);
                let now = if seen == u32::MAX {
                    within
                } else {
                    seen.max(within)
                };
                self.hash_at.store(now, Ordering::Relaxed);
                self.lesser()
            }
        };
        // Monotone: `max` of what was asked for before. Every hand-over
        // this bar has - hashing to folding and back, one batch to the
        // next - can present a smaller fraction than the frame already
        // on screen, and a bar that falls back is worse than one that
        // pauses.
        let tenth = tenth.max(self.drawn.fetch_max(tenth, Ordering::Relaxed));
        self.draw_fold(tenth);
        // The fold has let go of the line: a write that finished (or
        // got somewhere) underneath it is drawn now rather than never.
        if tenth >= 1000 {
            let held = self.held_write.swap(u32::MAX, Ordering::Relaxed);
            if held != u32::MAX {
                self.draw_write(held);
            }
        }
    }
}

/// The watch the binary passes to `verify` and `repair`: the interrupt
/// gate in, the meter out. In-process callers (`run_with`, the tests)
/// get one with no gate and a silent meter, which is the `()` watch
/// they had.
pub struct CliWatch {
    gate: Option<Arc<PauseGate>>,
    meter: Arc<Meter>,
    create: Arc<CreateMeter>,
}

impl CliWatch {
    /// Read the sink's loudness NOW - `set_level` must already have
    /// run, which `lib.rs` does before building this.
    ///
    /// `progress` is `--progress` (GH #88): the meters stay on under
    /// `-q`, and the create's two labels become one bar.
    pub fn new(gate: Option<Arc<PauseGate>>, sink: &Sink, progress: bool) -> CliWatch {
        let meter = Meter::for_sink(sink, progress);
        CliWatch {
            gate,
            create: CreateMeter::with_shape(meter.clone(), progress),
            meter,
        }
    }

    pub fn cancelled(&self) -> bool {
        self.gate.as_ref().is_some_and(|g| g.is_cancelled())
    }

    /// See [`Meter::end_line`].
    pub fn end_line(&self) {
        self.meter.end_line();
    }
}

impl RepairWatch for CliWatch {
    /// The meter is ALWAYS supplied, quiet or not, so that what the
    /// engine is willing to attempt does not change with `-q`: its
    /// unattended-unstructured ceiling asks whether somebody can see
    /// and stop the repair, and with Ctrl-C wired a terminal run is
    /// stoppable whatever the user chose to print.
    fn control(&self) -> RepairControl {
        let sink: Arc<dyn ProgressSink> = self.meter.clone();
        RepairControl::new(Some(sink), self.gate.clone())
    }
}

impl CreateWatch for CliWatch {
    /// The gate AND the meter, as of 17 Sep 2026 (GH #88) - the same
    /// shape as the repair's above, and for the same reason: the meter
    /// goes in quiet or not, so what the engine is willing to attempt
    /// does not change with `-q`.
    ///
    /// It was the gate alone from 12 Sep, when the create control
    /// landed with no caller for its sink on this side. What it cost to
    /// start reading the phases is the `PROCESSING-METER` half of
    /// `research/PAR2GEN-CREATE-CONTROL-AB-2026-09-17.md`; what the
    /// label means is [`CreateMeter`].
    fn control(&self) -> CreateControl {
        let sink: Arc<dyn ProgressSink> = self.create.clone();
        CreateControl::new(Some(sink), self.gate.clone())
    }
}

impl SurveyWatch for CliWatch {
    fn should_continue(&self) -> bool {
        !self.cancelled()
    }
    /// The standalone verify counts MEMBERS, not bytes - that is what
    /// the pass reports - so a one-member set goes 0 to 100 in one step.
    /// The repair's own verify pass is the engine's and counts bytes.
    fn member_done(&self, done: usize, total: usize) {
        self.meter
            .progress(RepairPhase::Verify, done as u64, total as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A writer the test can read back after the meter has taken it.
    struct Tap(Arc<Mutex<Vec<u8>>>);
    impl Write for Tap {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn meter(quiet: bool) -> (Arc<Meter>, Arc<Mutex<Vec<u8>>>) {
        let buf = Arc::new(Mutex::new(Vec::new()));
        (Meter::new(quiet, Box::new(Tap(buf.clone()))), buf)
    }

    fn text(buf: &Arc<Mutex<Vec<u8>>>) -> String {
        String::from_utf8(buf.lock().unwrap().clone()).unwrap()
    }

    /// The redraw grain and the word, which are the reference's and are
    /// what SAB keys on. The FIGURES are the merge's: a fold that
    /// finishes owns `FOLD_SHARE` of one sweep segment of `HEAD`, which
    /// on a one-sweep repair is 24.7%, not 100%.
    #[test]
    fn a_redraw_per_tenth_of_a_percent_in_the_reference_shape() {
        let (m, buf) = meter(false);
        m.progress(RepairPhase::Fold, 0, 1000);
        m.progress(RepairPhase::Fold, 123, 1000);
        // Same tenth again: no redraw.
        m.progress(RepairPhase::Fold, 123, 1000);
        m.progress(RepairPhase::Fold, 1000, 1000);
        assert_eq!(
            text(&buf),
            "Repairing: 0.0%\rRepairing: 3.0%\rRepairing: 24.7%\r"
        );
    }

    /// THE SPAN, pinned to the byte: three engine phases under ONE word,
    /// each on its own stretch of one bar, and the scan on the other.
    /// `Solving:` and `Writing:` are gone from the repair path - SAB
    /// discarded the first unread and logged 257 frames of the second
    /// per repair.
    ///
    /// The discriminating assertion is the ORDER of the figures: one
    /// climb, never a second 0-to-100 under a second word.
    #[test]
    fn the_fold_the_solve_and_the_patch_share_one_repairing_bar() {
        let (m, buf) = meter(false);
        m.progress(RepairPhase::Verify, 1, 2);
        m.progress(RepairPhase::Fold, 1, 2);
        m.progress(RepairPhase::Fold, 2, 2);
        m.progress(RepairPhase::Solve, 1, 2);
        m.progress(RepairPhase::Solve, 2, 2);
        m.progress(RepairPhase::Write, 1, 2);
        m.progress(RepairPhase::Write, 2, 2);
        assert_eq!(
            text(&buf),
            // Scan on its own bar; then fold to 55% of 45%, solve to
            // 45%, patch across the remaining 55%.
            "Scanning: 50.0%\r\
             Repairing: 12.3%\rRepairing: 24.7%\r\
             Repairing: 34.8%\rRepairing: 45.0%\r\
             Repairing: 72.5%\rRepairing: 100.0%\r"
        );
    }

    /// The bar may not fall back, which a per-phase bar never had to
    /// promise. All three of the merge's hand-overs present a fraction
    /// smaller than the frame already on screen, and none may be drawn:
    /// `Solve` opens at 0% of a segment the fold has already spent,
    /// sweep 2 opens both counters at zero, and `Write` opens at 0% of
    /// the tail.
    #[test]
    fn no_hand_over_takes_the_merged_bar_backwards() {
        let (m, buf) = meter(false);
        m.slab(0, 2);
        m.progress(RepairPhase::Fold, 1000, 1000);
        // Fold to solve.
        m.progress(RepairPhase::Solve, 0, 1000);
        m.progress(RepairPhase::Solve, 1000, 1000);
        // Sweep to sweep.
        m.slab(1, 2);
        m.progress(RepairPhase::Fold, 0, 1000);
        m.progress(RepairPhase::Fold, 1000, 1000);
        m.progress(RepairPhase::Solve, 1000, 1000);
        // Head to tail.
        m.progress(RepairPhase::Write, 0, 1000);
        m.progress(RepairPhase::Write, 1000, 1000);
        let out = text(&buf);
        let seen: Vec<f64> = out
            .split('\r')
            .filter(|f| !f.is_empty())
            .map(|f| {
                f.trim_start_matches("Repairing: ")
                    .trim_end_matches('%')
                    .parse()
                    .unwrap()
            })
            .collect();
        assert!(
            seen.windows(2).all(|w| w[1] > w[0]),
            "the merged bar stepped backwards or repeated: {seen:?}"
        );
        assert_eq!(
            seen.first(),
            Some(&12.3),
            "sweep 1's fold owns 55% of half the head"
        );
        assert_eq!(seen.last(), Some(&100.0));
    }

    /// A memory-capped repair sweeps the payload once per slab and the
    /// engine re-sizes `Fold` and `Solve` at each, so both bars are
    /// drawn inside the frame `slab` announced and neither starts over.
    /// Without the frame this is 0 to 100 EIGHT times on one line,
    /// alternating between two labels - the shape the reference does
    /// not have (see [`Meter`]).
    ///
    /// The discriminating assertion is what is ABSENT: sweep 2's fold
    /// opens on the figure sweep 1's solve closed on, so the boundary
    /// draws no frame at all - and the whole head stops at `HEAD`,
    /// leaving the patch its tail.
    #[test]
    fn the_fold_and_the_solve_share_one_segment_of_the_sweep_frame() {
        let (m, buf) = meter(false);
        m.slab(0, 4);
        m.progress(RepairPhase::Fold, 0, 1000);
        m.progress(RepairPhase::Fold, 1000, 1000);
        m.progress(RepairPhase::Solve, 0, 4);
        m.progress(RepairPhase::Solve, 4, 4);
        m.slab(1, 4);
        // Both counters start over at zero and the bar does not.
        m.progress(RepairPhase::Fold, 0, 1000);
        m.progress(RepairPhase::Fold, 1000, 1000);
        m.progress(RepairPhase::Solve, 0, 4);
        m.progress(RepairPhase::Solve, 4, 4);
        m.slab(3, 4);
        m.progress(RepairPhase::Fold, 1000, 1000);
        m.progress(RepairPhase::Solve, 4, 4);
        assert_eq!(
            text(&buf),
            // A quarter of 45% is 11.25%; the fold owns 55% of each.
            "Repairing: 0.0%\rRepairing: 6.1%\rRepairing: 11.2%\r\
             Repairing: 17.4%\rRepairing: 22.5%\r\
             Repairing: 39.9%\rRepairing: 45.0%\r"
        );
    }

    /// The common case, pinned to the byte both ways it arrives: the
    /// engine announcing one sweep of one, and the engine announcing
    /// nothing at all (a repair with no block to rebuild, and every
    /// caller of this meter that is not a repair - the standalone
    /// verify's `member_done`). Neither may move a figure.
    #[test]
    fn a_repair_that_does_not_slab_draws_what_it_always_drew() {
        let (m, buf) = meter(false);
        m.slab(0, 1);
        m.progress(RepairPhase::Fold, 0, 1000);
        m.progress(RepairPhase::Fold, 123, 1000);
        m.progress(RepairPhase::Fold, 1000, 1000);
        m.progress(RepairPhase::Solve, 1, 2);
        assert_eq!(
            text(&buf),
            "Repairing: 0.0%\rRepairing: 3.0%\rRepairing: 24.7%\rRepairing: 34.8%\r"
        );
        let (m, buf) = meter(false);
        m.progress(RepairPhase::Fold, 123, 1000);
        m.progress(RepairPhase::Solve, 1, 2);
        assert_eq!(text(&buf), "Repairing: 3.0%\rRepairing: 34.8%\r");
    }

    /// The hash runs once before the first sweep and the patch once
    /// after the last, on both engine entries this CLI calls, so the
    /// SWEEP frame is not theirs - a `Write` placed inside it would end
    /// a four-sweep repair's patch partway up its own tail. The scan
    /// keeps its own word and its own counter; the patch is the merged
    /// bar's last 15% and is unaffected by which sweep last spoke. See
    /// the LIMIT on [`Meter`] for the driver where that is not true.
    #[test]
    fn the_scan_keeps_its_word_and_the_patch_takes_the_tail_not_a_frame() {
        let (m, buf) = meter(false);
        m.progress(RepairPhase::Verify, 500, 1000);
        m.slab(3, 4);
        m.progress(RepairPhase::Write, 1, 4);
        m.progress(RepairPhase::Write, 4, 4);
        assert_eq!(
            text(&buf),
            "Scanning: 50.0%\rRepairing: 58.7%\rRepairing: 100.0%\r"
        );
    }

    #[test]
    fn quiet_draws_nothing_and_an_empty_total_draws_nothing() {
        let (m, buf) = meter(true);
        m.progress(RepairPhase::Fold, 5, 10);
        assert_eq!(text(&buf), "");
        let (m, buf) = meter(false);
        m.progress(RepairPhase::Fold, 0, 0);
        assert_eq!(text(&buf), "");
    }

    #[test]
    fn a_pending_fragment_is_terminated_once_and_a_clean_meter_owes_nothing() {
        let (m, buf) = meter(false);
        m.end_line();
        assert_eq!(text(&buf), "");
        m.progress(RepairPhase::Fold, 1, 4);
        m.end_line();
        m.end_line();
        assert_eq!(text(&buf), "Repairing: 6.1%\r\n");
    }

    #[test]
    fn done_past_total_is_clamped_to_one_hundred() {
        let (m, buf) = meter(false);
        m.progress(RepairPhase::Write, 12, 10);
        assert_eq!(text(&buf), "Repairing: 100.0%\r");
    }

    #[test]
    fn the_in_process_watch_is_the_empty_watch() {
        // No gate: never cancelled, and the control it hands the engine
        // is not "attended" - the pre-12-Sep ceiling still applies to a
        // test that builds no gate.
        let sink = Sink::buffered();
        let w = CliWatch::new(None, &sink, false);
        assert!(!w.cancelled());
        assert!(w.should_continue());
        // QUALIFIED, because this watch implements three traits and two
        // of them declare `control`.
        assert!(!RepairWatch::control(&w).is_attended());
        let gate = PauseGate::new();
        let w = CliWatch::new(Some(gate.clone()), &sink, false);
        assert!(RepairWatch::control(&w).is_attended());
        gate.cancel();
        assert!(w.cancelled());
        assert!(!w.should_continue());
    }

    /// The CREATE control carries the SAME gate as the other two, so
    /// one Ctrl-C means one thing whichever command is running - and
    /// since 17 Sep 2026 it carries a meter beside it.
    #[test]
    fn the_create_watch_carries_the_gate_and_the_meter() {
        let sink = Sink::buffered();
        let gate = PauseGate::new();
        let w = CliWatch::new(Some(gate.clone()), &sink, false);
        let c = CreateWatch::control(&w);
        assert!(c.is_active(), "a create with no control cannot be stopped");
        assert!(!c.cancelled());
        gate.cancel();
        assert!(c.cancelled(), "the create's gate is the interrupt's gate");
        // With no interrupt installed (the in-process caller) the sink
        // is still supplied, exactly as `RepairWatch` supplies it: the
        // create's `is_active` gates nothing in the engine - it only
        // selects the `NZBFAST_CREATE_CONTROL` A/B arm - so there is
        // nothing here to keep inert, and a caller that reads the CLI's
        // stdout gets its meter whether or not signals could be hooked.
        let w = CliWatch::new(None, &sink, false);
        assert!(CreateWatch::control(&w).is_active());
        assert!(!CreateWatch::control(&w).cancelled());
    }

    fn create_meter(quiet: bool) -> (Arc<CreateMeter>, Arc<Mutex<Vec<u8>>>) {
        let (m, buf) = meter(quiet);
        (CreateMeter::new(m), buf)
    }

    /// The label decision, pinned to the byte: the reference's word,
    /// the reference's grain, over the fold. See [`CreateMeter`] for
    /// the measurement that says the word means the same thing here.
    #[test]
    fn the_create_bar_is_the_references_processing_shape() {
        let (m, buf) = create_meter(false);
        m.progress(RepairPhase::Fold, 0, 1000);
        m.progress(RepairPhase::Fold, 123, 1000);
        // Same tenth again: no redraw.
        m.progress(RepairPhase::Fold, 123, 1000);
        m.progress(RepairPhase::Fold, 1000, 1000);
        assert_eq!(
            text(&buf),
            "Processing: 0.0%\rProcessing: 12.3%\rProcessing: 100.0%\r"
        );
    }

    /// The hash and the fold are one span over one payload and the bar
    /// stands where the SLOWER of them does: a create is over when both
    /// are. The larger was the rule until 20 Sep 2026, and from page
    /// cache it pinned the bar at 100 for most of the run - the
    /// measurement is on [`CreateMeter`]. A hash that never speaks (the
    /// fused arm) leaves the fold answering alone.
    #[test]
    fn the_bar_follows_the_slower_of_the_hash_and_the_fold() {
        let (m, buf) = create_meter(false);
        m.progress(RepairPhase::Fold, 0, 1000);
        // The block lanes finish the member at once; the bar does not
        // follow them past the fold.
        m.progress(RepairPhase::Verify, 1000, 1000);
        m.progress(RepairPhase::Fold, 400, 1000);
        // The fold done, a hash still hashing holds the bar.
        let (h, hb) = create_meter(false);
        h.progress(RepairPhase::Verify, 300, 1000);
        h.progress(RepairPhase::Fold, 1000, 1000);
        h.progress(RepairPhase::Verify, 650, 1000);
        h.progress(RepairPhase::Verify, 1000, 1000);
        // And no hash at all: the fold is the bar.
        let (f, fb) = create_meter(false);
        f.progress(RepairPhase::Fold, 250, 1000);
        assert_eq!(text(&buf), "Processing: 0.0%\rProcessing: 40.0%\r");
        // The hash spoke first, with the fold at nothing: the bar is at
        // nothing too, and says so.
        assert_eq!(
            text(&hb),
            "Processing: 0.0%\rProcessing: 30.0%\rProcessing: 65.0%\rProcessing: 100.0%\r"
        );
        assert_eq!(text(&fb), "Processing: 25.0%\r");
    }

    /// The hash reads the payload ONCE, beside the first batch. Under
    /// the lesser rule a hash that finishes there reads 100 and hands
    /// the bar to the banded fold for the rest of the create - no cap
    /// needed, where the larger rule needed one to stop the pin.
    #[test]
    fn a_hash_finished_in_the_first_batch_hands_the_bar_to_the_fold() {
        let (m, buf) = create_meter(false);
        m.slab(0, 4);
        m.progress(RepairPhase::Fold, 100, 1000);
        // The whole payload hashed, while three of four batches remain.
        m.progress(RepairPhase::Verify, 1000, 1000);
        m.slab(1, 4);
        m.progress(RepairPhase::Fold, 0, 1000);
        m.progress(RepairPhase::Fold, 1000, 1000);
        // Batch two opening is a frame of its own: one of four done.
        assert_eq!(
            text(&buf),
            "Processing: 2.5%\rProcessing: 25.0%\rProcessing: 50.0%\r"
        );
    }

    /// A memory-capped create folds the set in batches and the engine
    /// re-sizes `Fold` at each, so the bar bands them against the frame
    /// `slab` announced and stays monotone across the boundary. Without
    /// the frame this is 0 to 100 once per batch.
    #[test]
    fn the_fold_is_banded_across_the_batch_frame() {
        let (m, buf) = create_meter(false);
        m.slab(0, 4);
        m.progress(RepairPhase::Fold, 500, 1000);
        m.slab(1, 4);
        // Batch two starts over at zero and the bar does not: it reads
        // as one of four batches finished.
        m.progress(RepairPhase::Fold, 0, 1000);
        m.progress(RepairPhase::Fold, 1000, 1000);
        m.slab(3, 4);
        m.progress(RepairPhase::Fold, 1000, 1000);
        assert_eq!(
            text(&buf),
            "Processing: 12.5%\rProcessing: 25.0%\rProcessing: 50.0%\rProcessing: 100.0%\r"
        );
    }

    /// The write bar waits for the fold to finish with the line and is
    /// then its own counter - sized once for the whole create, so it
    /// picks up at the fraction it has really reached rather than at
    /// zero: the last write frame that arrived under the fold is drawn
    /// the moment the fold lets go, which is also what stops a write
    /// that FINISHED under the fold from never drawing at all. A create
    /// never solves, and a `Solve` that somehow arrived must draw
    /// nothing.
    #[test]
    fn the_write_bar_waits_for_the_line_and_a_create_never_solves() {
        let (m, buf) = create_meter(false);
        m.progress(RepairPhase::Fold, 1, 2);
        // The stripe-first arm fills volumes while it still folds.
        // Drawn now, these alternate with the bar above and neither
        // reads as a bar.
        m.progress(RepairPhase::Write, 1, 4);
        m.progress(RepairPhase::Write, 2, 4);
        m.progress(RepairPhase::Solve, 1, 2);
        m.progress(RepairPhase::Fold, 2, 2);
        m.progress(RepairPhase::Write, 3, 4);
        m.progress(RepairPhase::Write, 4, 4);
        assert_eq!(
            text(&buf),
            "Processing: 50.0%\rProcessing: 100.0%\rWriting: 50.0%\rWriting: 75.0%\rWriting: 100.0%\r"
        );
    }

    fn unified_meter() -> (Arc<CreateMeter>, Arc<Mutex<Vec<u8>>>) {
        let (m, buf) = meter(false);
        (CreateMeter::with_shape(m, true), buf)
    }

    /// `--progress` (GH #88): ONE climb from 0 to 100 under one label,
    /// the fold's `[0, PROC_SHARE)` and then the writes' tail, with the
    /// drawn bar the reporter asked for by example. The hash-and-fold
    /// rule is the default bar's (the slower of the two), and a write
    /// that lands under the fold is held, then drawn when the fold lets
    /// go, so the bar ends on 100 whichever arm ran.
    #[test]
    fn the_progress_bar_is_one_climb_over_the_fold_and_then_the_writes() {
        let (m, buf) = unified_meter();
        m.progress(RepairPhase::Fold, 0, 1000);
        // The whole payload hashed at once: the bar stays with the fold.
        m.progress(RepairPhase::Verify, 1000, 1000);
        m.progress(RepairPhase::Fold, 500, 1000);
        // Volumes flushed under the fold: held.
        m.progress(RepairPhase::Write, 500, 1000);
        m.progress(RepairPhase::Fold, 1000, 1000);
        m.progress(RepairPhase::Write, 1000, 1000);
        assert_eq!(
            text(&buf),
            concat!(
                "Progress:   0.0% [                                        ]\r",
                "Progress:  47.5% [===================                     ]\r",
                "Progress:  95.0% [======================================  ]\r",
                "Progress:  97.5% [======================================= ]\r",
                "Progress: 100.0% [========================================]\r",
            )
        );
        // And the write held under the fold is the one released - a
        // write that FINISHED there draws full the moment the fold does.
        let (m, buf) = unified_meter();
        m.progress(RepairPhase::Write, 1000, 1000);
        m.progress(RepairPhase::Fold, 1000, 1000);
        assert_eq!(
            text(&buf),
            concat!(
                "Progress:  95.0% [======================================  ]\r",
                "Progress: 100.0% [========================================]\r",
            )
        );
    }

    /// `--progress` lifts the `-q` gate off the meter, and only that
    /// gate: a `-q -q` terminal run draws the bar and nothing else, and
    /// a buffered sink (the GUI, the in-process callers) still gets no
    /// meter, because it has its own reader for the same events.
    #[test]
    fn progress_keeps_the_meter_on_under_quiet_but_not_off_a_buffer() {
        let mut silent = Sink::stdio();
        silent.set_level(-2);
        assert!(!silent.shows(Level::Terse), "-q -q is silence");
        assert!(
            Meter::for_sink(&silent, false).quiet,
            "the reference's rule"
        );
        assert!(
            !Meter::for_sink(&silent, true).quiet,
            "--progress keeps the bar"
        );
        let mut loud = Sink::stdio();
        loud.set_level(0);
        assert!(!Meter::for_sink(&loud, false).quiet);
        assert!(
            Meter::for_sink(&Sink::buffered(), true).quiet,
            "a buffer has its own reader"
        );
    }

    /// `-q` is the reference's own rule for progress, and the create
    /// bar inherits it from the meter it shares - which is also what
    /// makes the pending-fragment bookkeeping single.
    #[test]
    fn the_create_bar_is_quiet_when_the_meter_is_and_shares_its_line() {
        let (m, buf) = create_meter(true);
        m.progress(RepairPhase::Fold, 1, 2);
        assert_eq!(text(&buf), "");
        let (m, buf) = create_meter(false);
        m.progress(RepairPhase::Fold, 1, 2);
        m.inner.end_line();
        m.inner.end_line();
        assert_eq!(text(&buf), "Processing: 50.0%\r\n");
    }
}
