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
//! at 0%. The phases the engine distinguishes keep their own labels:
//! the reference's `Repairing:` counts the fold, and a solve that runs
//! for ten minutes after the fold hit 100% is the bar this exists to
//! avoid.

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
/// That measurement is also why the label is left alone here. `perc`
/// moving at all depends on `startswith("Repairing:")` with the colon
/// where it is - `Repairing (sweep 2/4): ` matches nothing. What that
/// lane found about the SPAN of the label (SAB sees the fold and never
/// the solve or the patch, so `Repairing: 100%` is not the end of our
/// job) is a real and larger item, and it is theirs: it asks which
/// phases one label should cover, which is a different question from
/// which sweep the answer is in.
///
/// # Banded per phase, and NOT merged into one sweep-cut bar
///
/// Each phase's own bar is placed inside the frame instead: sweep `i`
/// of `N` covers `[i/N, (i+1)/N)` of that bar. `Repairing:` and
/// `Solving:` then each cross the frame once, in step, and a sweep
/// boundary redraws nothing at all - the first frame of sweep `i+1` is
/// the last frame of sweep `i`, which `Meter::draw`'s per-slot dedupe
/// drops.
///
/// `nzbfast-core`'s `repairprog` and `parfast-session`'s
/// `RepairProgress` had to do the opposite - cut `[0.45, 0.95)` by
/// SWEEP and put the fold/solve weighting inside each segment - because
/// they weigh all four phases into ONE monotone value, where splitting
/// by phase puts sweep 1's solve above sweep 2's fold and the monotone
/// bar swallows every later fold. That argument does not reach here.
/// This meter holds a counter PER PHASE (`last`, deduped by slot),
/// nothing compares one against another and nothing is monotone, so
/// the two bars span the frame without either standing in the other's
/// way. Merging them would cost the `Solving:` label, which is the
/// thing this module exists for - a solve that runs for ten minutes
/// after the fold reached 100% is the bar it was built to avoid - and
/// the reference draws its own `Solving:` separately too.
///
/// REPRODUCED END TO END, and it needs no test seam. 17 Sep 2026, same
/// box, on par2cmdline's own 64 MiB set at a 1 MiB block size with 30
/// blocks damaged: `NZBFAST_REPAIR_SOLVE_BUDGET=8388608 parfast r
/// set.par2` (the figure `reconstruct::solve_window_budget` reads, and
/// the one `-m` lowers) cuts that solve into EIGHT sweeps. Before this
/// change the single terminal line carried SIXTEEN 0-to-100 bars,
/// `Repairing:` and `Solving:` alternating; after it, one climb -
/// `Repairing: 0.0 -> 12.5`, `Solving: 0.0 -> 12.5`, `Repairing: 12.8
/// -> 25.0`, and so on to 100.
///
/// The sweep number does NOT go in the label, though the 16 Sep report
/// suggested `Repairing (sweep 2/4)`: `Repairing: ` is the reference's
/// word to the byte, and a scraper keying on it is exactly the reader
/// the paragraph above is about. The frame is said in the number.
///
/// LIMIT, stated because it is one call site away: `Verify` and `Write`
/// are NOT banded, which is right for the two engine entries this CLI
/// calls. `repair_dir_set_surveyed_as` and `repair_dir_set_with_donors_as`
/// hash once before the first sweep and patch once after the last. The
/// MAPPED driver writes INSIDE the sweep loop and self-proves after it,
/// so a caller that grows that route owes `Write` this same frame -
/// and [`ProgressSink::route`], which this type still ignores, is how
/// it would tell the two apart.
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
            out: Mutex::new(out),
        })
    }

    /// The meter for the program's own stdout, or a silent one when the
    /// sink is a buffer or a host's tap - those readers get their
    /// progress from the engine directly, or want none.
    pub fn for_sink(sink: &Sink) -> Arc<Meter> {
        let quiet = !(sink.is_stdio() && sink.shows(Level::Normal));
        Meter::new(quiet, Box::new(std::io::stdout()))
    }

    fn label(phase: RepairPhase) -> &'static str {
        match phase {
            RepairPhase::Verify => "Scanning: ",
            RepairPhase::Fold => "Repairing: ",
            RepairPhase::Solve => "Solving: ",
            RepairPhase::Write => "Writing: ",
        }
    }

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

    /// Place a phase's own fraction inside the sweep frame: sweep `i`
    /// of `N` owns `[i/N, (i+1)/N)` of that phase's bar. At `(0, 1)` -
    /// a repair that does not slab, and a meter nothing has announced
    /// to - this is the identity to the tenth, which is what
    /// `a_repair_that_does_not_slab_draws_what_it_always_drew` pins.
    fn banded(&self, within: u32) -> u32 {
        let of = u64::from(self.sweeps.load(Ordering::Relaxed).max(1));
        let i = u64::from(self.sweep.load(Ordering::Relaxed)).min(of - 1);
        u32::try_from((i * 1000 + u64::from(within)) / of).unwrap_or(1000)
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
        let tenth = match phase {
            // Entered once per sweep, counter reset at each: drawn
            // inside the frame so the bar crosses it once.
            RepairPhase::Fold | RepairPhase::Solve => self.banded(within),
            // Entered once for the whole repair on this CLI's two engine
            // entries - the hash before the first sweep, the patch after
            // the last - so the frame is not theirs to be placed in.
            // The LIMIT paragraph on [`Meter`] says what would change
            // that.
            RepairPhase::Verify | RepairPhase::Write => within,
        };
        self.draw(Meter::slot(phase), Meter::label(phase), tenth);
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
/// They are merged by taking the LARGER fraction, as that GUI does, with
/// one correction it does not make. `Verify` is sized once for the
/// whole create and `Fold` is re-sized per batch, so on a memory-capped
/// create the hash finishes during batch 1 and the larger of the two is
/// then pinned at 100% for every remaining batch - the daemon's slabbed
/// repair bar froze the same way until 16 Sep 2026. So `Fold` is banded
/// across the batch frame the engine announces
/// (`ProgressSink::slab`), and `Verify` may not push the bar past the
/// end of the batch it is running beside: the scan reads the payload
/// ONCE, beside the first batch, so that is the only stretch its
/// fraction is evidence about. On a one-batch create - which is every
/// create that fits the accumulator budget, and so nearly every CLI
/// create - the cap is 100% and the rule is exactly the GUI's.
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
    /// The fold batch frame: index, and how many. `(0, 1)` until the
    /// engine says otherwise, which is the right reading of a create
    /// that folds in one pass or announces nothing.
    batch: AtomicU32,
    batches: AtomicU32,
    /// The thousandth the `Processing:` bar last showed, held so it
    /// cannot go backwards across a batch boundary or when the hash and
    /// the fold trade places as the further-on of the two. Also the
    /// gate on the write bar: full means the fold is done with the
    /// line.
    drawn: AtomicU32,
}

impl CreateMeter {
    /// A create meter drawing on `inner`. It SHARES that meter rather
    /// than opening a second one: one lock on the output, one pending-
    /// fragment flag, so [`Meter::end_line`] still owes exactly one
    /// newline whichever command was running.
    pub fn new(inner: Arc<Meter>) -> Arc<CreateMeter> {
        Arc::new(CreateMeter {
            inner,
            batch: AtomicU32::new(0),
            batches: AtomicU32::new(1),
            drawn: AtomicU32::new(0),
        })
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
                    return;
                }
                self.inner.draw(Meter::slot(phase), "Writing: ", within);
                return;
            }
            // This batch's own fraction, placed inside the batch frame.
            RepairPhase::Fold => (u64::from(i) * 1000 + u64::from(within)) as u32 / of,
            // The hash, which cannot speak for a batch it does not run
            // beside - see the type doc.
            RepairPhase::Verify => within.min((i + 1) * 1000 / of),
        };
        // Monotone: `max` of what was asked for before. Every hand-over
        // this bar has - hashing to folding and back, one batch to the
        // next - can present a smaller fraction than the frame already
        // on screen, and a bar that falls back is worse than one that
        // pauses.
        let tenth = tenth.max(self.drawn.fetch_max(tenth, Ordering::Relaxed));
        self.inner
            .draw(Meter::slot(RepairPhase::Fold), "Processing: ", tenth);
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
    pub fn new(gate: Option<Arc<PauseGate>>, sink: &Sink) -> CliWatch {
        let meter = Meter::for_sink(sink);
        CliWatch {
            gate,
            create: CreateMeter::new(meter.clone()),
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
            "Repairing: 0.0%\rRepairing: 12.3%\rRepairing: 100.0%\r"
        );
    }

    #[test]
    fn each_phase_keeps_its_own_label_and_its_own_counter() {
        let (m, buf) = meter(false);
        m.progress(RepairPhase::Verify, 1, 2);
        m.progress(RepairPhase::Solve, 1, 2);
        m.progress(RepairPhase::Write, 1, 2);
        // The fold at the same fraction still draws: its counter is its own.
        m.progress(RepairPhase::Fold, 1, 2);
        assert_eq!(
            text(&buf),
            "Scanning: 50.0%\rSolving: 50.0%\rWriting: 50.0%\rRepairing: 50.0%\r"
        );
    }

    /// A memory-capped repair sweeps the payload once per slab and the
    /// engine re-sizes `Fold` and `Solve` at each, so both bars are
    /// drawn inside the frame `slab` announced and neither starts over.
    /// Without the frame this is 0 to 100 EIGHT times on one line,
    /// alternating between two labels - the shape the reference does
    /// not have (see [`Meter`]).
    ///
    /// The discriminating assertion is what is ABSENT: sweep 2's fold
    /// opens on the figure sweep 1's fold closed on, so the boundary
    /// draws no frame at all.
    #[test]
    fn the_fold_and_the_solve_are_each_banded_across_the_sweep_frame() {
        let (m, buf) = meter(false);
        m.slab(0, 4);
        m.progress(RepairPhase::Fold, 0, 1000);
        m.progress(RepairPhase::Fold, 1000, 1000);
        m.progress(RepairPhase::Solve, 0, 4);
        m.progress(RepairPhase::Solve, 4, 4);
        m.slab(1, 4);
        // Both counters start over at zero and neither bar does.
        m.progress(RepairPhase::Fold, 0, 1000);
        m.progress(RepairPhase::Fold, 1000, 1000);
        m.progress(RepairPhase::Solve, 0, 4);
        m.progress(RepairPhase::Solve, 4, 4);
        m.slab(3, 4);
        m.progress(RepairPhase::Fold, 1000, 1000);
        m.progress(RepairPhase::Solve, 4, 4);
        assert_eq!(
            text(&buf),
            "Repairing: 0.0%\rRepairing: 25.0%\rSolving: 0.0%\rSolving: 25.0%\r\
             Repairing: 50.0%\rSolving: 50.0%\r\
             Repairing: 100.0%\rSolving: 100.0%\r"
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
            "Repairing: 0.0%\rRepairing: 12.3%\rRepairing: 100.0%\rSolving: 50.0%\r"
        );
        let (m, buf) = meter(false);
        m.progress(RepairPhase::Fold, 123, 1000);
        m.progress(RepairPhase::Solve, 1, 2);
        assert_eq!(text(&buf), "Repairing: 12.3%\rSolving: 50.0%\r");
    }

    /// The hash runs once before the first sweep and the patch once
    /// after the last, on both engine entries this CLI calls, so the
    /// frame is not theirs - a `Write` placed inside it would end a
    /// four-sweep repair's patch at 100% of the last quarter and read
    /// as a bar that had already finished. See the LIMIT on [`Meter`]
    /// for the driver where that is not true.
    #[test]
    fn the_scan_and_the_patch_span_the_repair_and_take_no_frame() {
        let (m, buf) = meter(false);
        m.progress(RepairPhase::Verify, 500, 1000);
        m.slab(3, 4);
        m.progress(RepairPhase::Write, 1, 4);
        m.progress(RepairPhase::Write, 4, 4);
        assert_eq!(
            text(&buf),
            "Scanning: 50.0%\rWriting: 25.0%\rWriting: 100.0%\r"
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
        assert_eq!(text(&buf), "Repairing: 25.0%\r\n");
    }

    #[test]
    fn done_past_total_is_clamped_to_one_hundred() {
        let (m, buf) = meter(false);
        m.progress(RepairPhase::Write, 12, 10);
        assert_eq!(text(&buf), "Writing: 100.0%\r");
    }

    #[test]
    fn the_in_process_watch_is_the_empty_watch() {
        // No gate: never cancelled, and the control it hands the engine
        // is not "attended" - the pre-12-Sep ceiling still applies to a
        // test that builds no gate.
        let sink = Sink::buffered();
        let w = CliWatch::new(None, &sink);
        assert!(!w.cancelled());
        assert!(w.should_continue());
        // QUALIFIED, because this watch implements three traits and two
        // of them declare `control`.
        assert!(!RepairWatch::control(&w).is_attended());
        let gate = PauseGate::new();
        let w = CliWatch::new(Some(gate.clone()), &sink);
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
        let w = CliWatch::new(Some(gate.clone()), &sink);
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
        let w = CliWatch::new(None, &sink);
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

    /// The hash and the fold are one span over one payload and both
    /// draw the same bar, whichever is further on - the rule the GUI's
    /// bar uses. The fold's grain is coarse on the stripe-first arm
    /// (one chunk of stripes), so without the hash beside it a real
    /// create draws 0.0% and then 100.0% and nothing between; that is
    /// measured, not hypothetical.
    #[test]
    fn the_bar_takes_whichever_of_the_hash_and_the_fold_is_further_on() {
        let (m, buf) = create_meter(false);
        m.progress(RepairPhase::Fold, 0, 1000);
        m.progress(RepairPhase::Verify, 50, 1000);
        m.progress(RepairPhase::Verify, 400, 1000);
        // The fold catches up and passes it.
        m.progress(RepairPhase::Fold, 600, 1000);
        // ...and the hash, still running behind it, does not pull back.
        m.progress(RepairPhase::Verify, 500, 1000);
        assert_eq!(
            text(&buf),
            "Processing: 0.0%\rProcessing: 5.0%\rProcessing: 40.0%\rProcessing: 60.0%\r"
        );
    }

    /// The hash reads the payload ONCE, beside the first batch, so on a
    /// multi-batch create its fraction is evidence about that batch and
    /// no further. Uncapped it reaches 100% during batch 1 and pins the
    /// bar there for the rest of the create - the defect the daemon's
    /// slabbed repair bar had until 16 Sep 2026.
    #[test]
    fn the_hash_cannot_push_the_bar_past_the_batch_it_runs_beside() {
        let (m, buf) = create_meter(false);
        m.slab(0, 4);
        m.progress(RepairPhase::Fold, 100, 1000);
        // The whole payload hashed, while three of four batches remain.
        m.progress(RepairPhase::Verify, 1000, 1000);
        m.slab(1, 4);
        m.progress(RepairPhase::Fold, 0, 1000);
        m.progress(RepairPhase::Fold, 1000, 1000);
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
    /// zero. A create never solves, and a `Solve` that somehow arrived
    /// must draw nothing.
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
            "Processing: 50.0%\rProcessing: 100.0%\rWriting: 75.0%\rWriting: 100.0%\r"
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
