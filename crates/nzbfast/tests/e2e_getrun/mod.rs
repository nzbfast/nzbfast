//! The one `nzbfast get` command spelling this binary dials, and the
//! KILLABLE child that lets a crash row stop a run mid-flight.
//!
//! `run_get` and its `_args`/`_win` wrappers (in `e2e.rs`) run the job to
//! completion and hand back what it printed - the right shape for the ~95
//! legs that grade a FINISHED job, and no shape at all for the class that
//! asks what survives an unclean death. Three rows of the 31 Aug 2026
//! capability round (X5-03, X5-12, X5-13) were dispositioned "harness"
//! for exactly that, and that round's own write-up names a spawn variant
//! returning the `Child` as the single highest-value piece of test
//! infrastructure it did not build. What it bought, and what is still
//! owed: `research/X5-03-CRASH-TRANSACTION-2026-08-31.md`.
//!
//! WHY THIS IS A SIBLING DIRECTORY AND NOT LINES IN `e2e.rs`. That file
//! carries a size-gate baseline entry and the note on it is explicit that
//! a lane wanting a new top-level module should take a subject OUT
//! first. This does: the `Command` builder and the two dial constants
//! moved here, so `e2e.rs` is SHORTER with this module than without it.
//!
//! WHY THE SPAWN FORM CAPTURES TO A FILE while `run_get_win` keeps
//! `output_under_test`'s pipes. A pipe cannot be read while the child is
//! still running without a reader thread, and the whole point here is to
//! wait for a LINE and then act; a file is what `harness::spawn_one` uses
//! for the daemon, for the same reason. It is NOT a second command
//! spelling - both take `get_cmd` below, which is the only place the
//! dial is written - and the two capture shapes are deliberately not
//! merged, because `output_under_test` keeps stdout and stderr in two
//! streams concatenated in that order and 95 legs already assert against
//! that text.
//!
//! `run_get_spawn` and `run_get_spawn_sub` split the same way `run_get_args`
//! and `e2e_sample::get_with` do: `extra_args`/`sub_args` land ahead of or
//! behind the `get` subcommand word, and only a subcommand-only flag like
//! `--password` needs the `_sub` form (31 Aug 2026, converting every
//! `kill9_*` test's hand-rolled `Command` onto this door -
//! `research/X5-03-CRASH-TRANSACTION-2026-08-31.md` section 9f).

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::harness::{KillOnDrop, spawn_under_test};

/// The fetch pipeline every `run_get` leg dials: `GET_CONNS` sockets per
/// SERVER (`--connections` is a per-server ceiling - `get/fleet.rs`) each
/// holding `GET_WINDOW` pipelined requests. Named rather than typed twice
/// because `rotated_ladder_does_not_fetch_every_article_twice` derives
/// its BODY bounds from exactly these numbers (TODO 286), and a dial
/// moved here with a bound left behind would silently widen it.
pub const GET_CONNS: u32 = 4;
pub const GET_WINDOW: u32 = 3;

/// The `nzbfast get` invocation, built once for both capture shapes.
///
/// Stdout and stderr are NOT set here - each caller owns that, and
/// `spawn_get` overwrites them.
///
/// `connections` and `window` are both explicit rather than the second
/// defaulting to `GET_CONNS`: the kill9 resume legs in `e2e.rs` and
/// `e2e_resume` dial `--connections 2 --window 2` on purpose (an unpaced
/// higher fleet can finish a fixture before the poll loop ever sees the
/// kill threshold, per those legs' own comments), and every other
/// caller keeps passing `GET_CONNS` unchanged.
pub fn get_cmd(
    config: &Path,
    nzb: &Path,
    out: &Path,
    extra_env: &[(&str, &str)],
    extra_args: &[&str],
    connections: u32,
    window: u32,
) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
    // The daemon mints an API key on a genuinely first run (see
    // serve::first_run_apikey). These suites drive it keyless on purpose,
    // so they take the same deliberate opt-out an operator would.
    cmd.env("NZBFAST_OPEN", "1");
    for a in extra_args {
        cmd.arg(a);
    }
    cmd.arg("--config")
        .arg(config)
        .arg("get")
        .arg(nzb)
        .arg("--out")
        .arg(out)
        .arg("--connections")
        .arg(connections.to_string())
        .arg("--window")
        .arg(window.to_string())
        .arg("--decoders")
        .arg("4");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd
}

/// Distinguishes one spawn's log from the next in the same fixture
/// directory. A crash row runs the SAME `out` twice, so a fixed name
/// would let run 2 read run 1's marker and call the barrier reached
/// before the child had started - `harness::spawn_one` keeps its log
/// per-port for exactly that reason.
///
/// Nothing reads the value back, so this is the benign counter shape:
/// no test's outcome depends on which number it drew.
static SPAWN_SEQ: AtomicU64 = AtomicU64::new(0);

/// A `nzbfast get` child under test: still running, signallable, with
/// everything it has printed so far readable from disk.
///
/// Killed and reaped on drop, so a test that panics between
/// `run_get_spawn` and its kill cannot leave an orphan holding provider
/// sockets and the
/// output directory - `ScratchDir` keeps the tree of a failing test, and
/// a live writer in it would keep changing what the next reader grades.
pub struct GetRun {
    child: KillOnDrop,
    log: PathBuf,
}

impl GetRun {
    /// Everything the run has written to stdout and stderr so far.
    ///
    /// One file, so the two streams interleave - which is why
    /// `run_get_win` stayed on the piped form: `contains` is the same
    /// answer either way, and the ORDER of two lines from different
    /// streams is not.
    pub fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Block until `needle` appears in what the run has printed, and
    /// return the log at that point. Panics with the whole log if it
    /// never arrives.
    ///
    /// An ORDERING wait, in `harness::wait_until`'s sense: the deadline
    /// only has to beat scheduler starvation, never the thing being
    /// waited for, so it can be generous without making any test slow.
    /// It is also the ONLY sound way to reach a crash window - see
    /// `get::tail`'s `test_park_after_journal_retire` for the product
    /// half and why a sleep into the window is a guess.
    pub fn wait_for(&self, needle: &str) -> String {
        let deadline = std::time::Instant::now() + WAIT_FOR_LIMIT;
        loop {
            let l = self.log();
            if l.contains(needle) {
                return l;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "never saw {needle:?} in {WAIT_FOR_LIMIT:?}\n--- {} ---\n{l}",
                self.log.display()
            );
            std::thread::sleep(WAIT_FOR_GAP);
        }
    }

    /// SIGKILL the run and reap it, returning everything it printed.
    ///
    /// `Child::kill` IS SIGKILL on unix, which is what the crash rows
    /// want: no unwinding, no destructor, no flush - the process simply
    /// stops between two instructions, exactly as a power cut does.
    pub fn kill9(mut self) -> String {
        self.child.0.kill().expect("SIGKILL the run");
        // Reap before reading: the log is a file the child may still be
        // appending to, and a tail read out from under a live writer is
        // the flake `harness::Daemon`'s field order was written to stop.
        let _ = self.child.0.wait();
        self.log()
    }

    /// Let the run finish, and answer with what it printed and whether
    /// it exited 0.
    ///
    /// The pair `run_get` hands back, MINUS the adopt guard: that is
    /// `adoptguard::refuse_a_solve_that_solved_nothing`, which
    /// `run_get_win` applies and which only has an answer for a run that
    /// reached a repair verdict. A leg that both spawns and grades a
    /// repair should call it itself.
    pub fn finish(mut self) -> (String, bool) {
        let status = self.child.0.wait().expect("waiting on nzbfast get");
        (self.log(), status.success())
    }
}

/// How long [`GetRun::wait_for`] waits for a line before calling it
/// absent - `harness::Daemon::wait_for`'s own budget, and for its
/// reason: this box routinely runs nine lanes' cargo builds at once, so
/// the number has to beat scheduler starvation and nothing else. It is
/// paid ONLY by a test that is already failing, and measured 31 Aug 2026
/// with the barrier removed from the product: the whole cost of a
/// regression here is this number twice, once per nextest retry.
const WAIT_FOR_LIMIT: std::time::Duration = std::time::Duration::from_secs(30);
const WAIT_FOR_GAP: std::time::Duration = std::time::Duration::from_millis(25);

/// The shared second half of both spawn constructors below: open the log
/// beside `config`, wire it as both stdout and stderr, and spawn.
///
/// The log lands beside `config` - the fixture directory, which always
/// exists because the config was just written into it - and never under
/// `out`, which the rows grade file by file.
fn spawn_get(config: &Path, mut cmd: Command) -> GetRun {
    let dir = config
        .parent()
        .expect("the config path names a file in a fixture directory");
    let log = dir.join(format!(
        "get-{}-{}.log",
        std::process::id(),
        SPAWN_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let f = std::fs::File::create(&log).expect("open the run log");
    let err = f.try_clone().expect("clone the run log handle");
    cmd.stdin(Stdio::null())
        .stdout(Stdio::from(f))
        .stderr(Stdio::from(err));
    let child: Child = spawn_under_test(&mut cmd);
    GetRun {
        child: KillOnDrop(child),
        log,
    }
}

/// Start `nzbfast get` and hand back the running child.
///
/// `extra_args` are GLOBAL flags, landing ahead of `--config` - right for
/// everything that has needed one so far (`--mem-limit` is `global =
/// true` on the `Cli` struct, so it parses in either position). A `get`
/// SUBCOMMAND-only flag (`--password`, `--skip-samples`, ...) needs
/// [`run_get_spawn_sub`] instead - the same split `e2e_sample::get_with`
/// already draws for the non-killable form, extended to this one.
pub fn run_get_spawn(
    config: &Path,
    nzb: &Path,
    out: &Path,
    extra_env: &[(&str, &str)],
    extra_args: &[&str],
    connections: u32,
    window: u32,
) -> GetRun {
    spawn_get(
        config,
        get_cmd(config, nzb, out, extra_env, extra_args, connections, window),
    )
}

/// [`run_get_spawn`], but `sub_args` land after the `get` subcommand's own
/// flags instead of ahead of `--config` - for a flag like `--password`
/// that clap does not mark `global`.
pub fn run_get_spawn_sub(
    config: &Path,
    nzb: &Path,
    out: &Path,
    extra_env: &[(&str, &str)],
    sub_args: &[&str],
    connections: u32,
    window: u32,
) -> GetRun {
    let mut cmd = get_cmd(config, nzb, out, extra_env, &[], connections, window);
    cmd.args(sub_args);
    spawn_get(config, cmd)
}
