//! The command line's half of the engine's controls: Ctrl-C as the
//! engine's own cancel, and the engine's progress as a meter on stdout.
//!
//! All three commands take the gate as of 12 Sep 2026. CREATE takes the
//! gate and NOT the meter - see [`CliWatch`]'s `CreateWatch` impl for
//! why - so a `parfast c` is interruptible and prints exactly what it
//! printed before.
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
    fn progress(&self, phase: RepairPhase, done: u64, total: u64) {
        if self.quiet || total == 0 {
            return;
        }
        let tenth = u32::try_from((done.min(total) * 1000) / total).unwrap_or(1000);
        if self.last[Meter::slot(phase)].swap(tenth, Ordering::Relaxed) == tenth {
            return;
        }
        let mut out = self.out.lock().unwrap_or_else(|p| p.into_inner());
        let _ = write!(
            out,
            "{}{}.{}%\r",
            Meter::label(phase),
            tenth / 10,
            tenth % 10
        );
        let _ = out.flush();
        self.dirty.store(true, Ordering::SeqCst);
    }
}

/// The watch the binary passes to `verify` and `repair`: the interrupt
/// gate in, the meter out. In-process callers (`run_with`, the tests)
/// get one with no gate and a silent meter, which is the `()` watch
/// they had.
pub struct CliWatch {
    gate: Option<Arc<PauseGate>>,
    meter: Arc<Meter>,
}

impl CliWatch {
    /// Read the sink's loudness NOW - `set_level` must already have
    /// run, which `lib.rs` does before building this.
    pub fn new(gate: Option<Arc<PauseGate>>, sink: &Sink) -> CliWatch {
        CliWatch {
            gate,
            meter: Meter::for_sink(sink),
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
    /// The gate ALONE, and no sink - which is the one place this watch
    /// is deliberately asymmetric with the repair's.
    ///
    /// par2cmdline's create draws `Processing: 12.3%`, and a create
    /// meter here would have to be conformance-checked against that
    /// byte for byte; nothing asked for one (12 Sep 2026: the GUI is
    /// the surface that wants a create bar, and it draws its own from
    /// the engine). So the CLI takes the half it needs - Ctrl-C
    /// reaching the engine's loops - and leaves the phases unread,
    /// which also means a `parfast c` pays not one sink call.
    fn control(&self) -> CreateControl {
        CreateControl::new(None, self.gate.clone())
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

    /// The CREATE control is the gate alone - the asymmetry the impl
    /// argues for - and it is the SAME gate, so one Ctrl-C means one
    /// thing whichever command is running.
    #[test]
    fn the_create_watch_carries_the_gate_and_no_meter() {
        let sink = Sink::buffered();
        let gate = PauseGate::new();
        let w = CliWatch::new(Some(gate.clone()), &sink);
        let c = CreateWatch::control(&w);
        assert!(c.is_active(), "a create with no control cannot be stopped");
        assert!(!c.cancelled());
        gate.cancel();
        assert!(c.cancelled(), "the create's gate is the interrupt's gate");
        // And with no interrupt installed (the in-process caller), the
        // create gets nothing at all rather than a control it would pay
        // for and nobody could trip.
        let w = CliWatch::new(None, &sink);
        assert!(!CreateWatch::control(&w).is_active());
    }
}
