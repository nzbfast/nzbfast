//! `parfast`: PAR2 create, verify and repair wearing par2cmdline's
//! command shape, over the ONE PAR2 engine in this workspace.
//!
//! # Why this crate is a front and not an engine
//!
//! Chip 13 of `research/SPEC-POSTING-LAYOUT-TOOLKIT-2026-09-03.md`,
//! decision D1: there is exactly one copy of the PAR2 engine anywhere,
//! and it is `nzbkit`'s (`par2`, `par2gen`, `par2repair`, `gf16`,
//! `par2ntt`). This crate adds no arithmetic of its own - it parses
//! par2cmdline's argument dialect, calls that engine, and prints
//! par2cmdline's lines with par2cmdline's exit codes. Every later PAR2
//! commit therefore reaches this binary on its next build with no sync
//! step, which is the whole reason the standalone tree at
//! `~/Claude/parfast` is superseded: a diff-synced copy reaches nothing
//! until somebody re-copies it.
//!
//! The engine files were NOT relocated into this crate, and the reason
//! is a dependency cycle rather than a preference. The engine reaches
//! `disk` (14 symbols over 91 sites), `mem`, `memgauge`, `sync` and the
//! rapidyenc `crc32_zeros` in `nzbkit-base`, while `nzbkit-base`'s
//! `live`, `dupedonor`, `pesto` and `mem` reach `par2` back. Cargo can
//! express neither direction without either dragging `live` (10.6k
//! lines of the download-side verifier, which is not part of a
//! par2cmdline drop-in) up here, or cutting `disk` and the rapidyenc
//! build down into a fourth crate. The reading taken on 3 Sep 2026 was
//! the third one: the front moves, the engine stays, and the end state
//! the chip asked for - one engine, no copy, no sync step - is reached
//! either way.
//!
//! # Exit codes are the interface
//!
//! Scripts branch on these, so they are the part of the drop-in claim
//! that must not drift. They are par2cmdline's, captured per input
//! shape into `tools/conformance/expected/par2-*.json` rather than read
//! off the manual, and asserted by `tools/conformance/run.py`.

/// Every file correct, or a repair completed and re-verified.
pub const EXIT_SUCCESS: u8 = 0;
/// Damage found, repair is possible, and none was attempted.
pub const EXIT_REPAIR_POSSIBLE: u8 = 1;
/// Damage found and there is not enough recovery data to fix it.
pub const EXIT_REPAIR_NOT_POSSIBLE: u8 = 2;
/// The command line did not parse, or asked for something incoherent.
pub const EXIT_INVALID_ARGS: u8 = 3;
/// No usable Main/FileDesc set could be assembled from the input.
pub const EXIT_INSUFFICIENT_DATA: u8 = 4;
/// A repair ran and the result failed its own verification.
pub const EXIT_REPAIR_FAILED: u8 = 5;
/// A read or write failed.
pub const EXIT_FILE_IO_ERROR: u8 = 6;
/// An invariant this program holds about itself did not hold.
pub const EXIT_LOGIC_ERROR: u8 = 7;
/// An allocation this program needs was refused.
pub const EXIT_OUT_OF_MEMORY: u8 = 8;

pub mod cli;
pub mod create;
pub mod help;
pub mod out;
pub mod repair;
pub mod verify;

pub use cli::{Command, Options};

/// One run, argv already split. `argv0` is the invoked name with any
/// executable suffix removed, because `par2create` / `par2verify` /
/// `par2repair` select the command by NAME - scripts invoke them that
/// way and the drop-in claim covers it.
pub fn run(argv0: &str, args: &[String]) -> u8 {
    let mut sink = out::Sink::stdio();
    run_with(argv0, args, &mut sink)
}

/// [`run`] against a caller-supplied sink, which is what the unit tests
/// assert on: a test that shells out to the built binary cannot run
/// until the binary is built, and this crate's whole job is the exact
/// text of these lines.
pub fn run_with(argv0: &str, args: &[String], sink: &mut out::Sink) -> u8 {
    let parsed = match cli::parse(argv0, args) {
        Ok(p) => p,
        Err(e) => {
            // par2cmdline puts the diagnosis on stderr and nothing on
            // stdout, and the captured table pins that split per shape.
            //
            // An EMPTY message is the `-h`-as-an-option shape, whose
            // whole point is that stderr stays empty while stdout gets
            // the screen - so it must not reach `err()`, which would
            // terminate the line it was not given and leave a stray
            // newline behind. Measured 3 Sep 2026: the reference's
            // stderr for `par2 c -h ...` is 0 bytes and ours was 1
            // (research/CLI-SUBSTITUTION-2026-09-03.md).
            if !e.message.is_empty() {
                sink.err(&e.message);
            }
            if e.show_usage {
                sink.out(&help::help());
            }
            return EXIT_INVALID_ARGS;
        }
    };
    // `-m`, the memory limit in MB. It was parsed onto `Options.mem_mb`
    // and read by nothing, so a create still sized its accumulators from
    // the process budget: `parfast c -m256 out.par2 8g.bin` on a large
    // host took up to the 8 GiB accumulator ceiling where par2cmdline
    // capped near 256 MiB. Published here, before any command runs, so
    // create and verify both see it.
    //
    // Honest limit: the accumulator formula has a 256 MiB floor, so a
    // `-m` below that is a ceiling the create still overshoots. It binds
    // everything above, which is the range that matters, and it is no
    // longer ignored outright.
    if let Some(mb) = parsed.opts.mem_mb {
        nzbkit::mem::set_process_budget(nzbkit::mem::MemBudget::with_total(
            mb.saturating_mul(1 << 20),
        ));
    }
    match parsed.command {
        Command::Help => {
            sink.out(&help::help());
            EXIT_SUCCESS
        }
        Command::Version => {
            sink.out(&help::version_line());
            EXIT_SUCCESS
        }
        Command::VersionCopyright => {
            sink.out(&help::version_line());
            sink.out(help::COPYRIGHT);
            EXIT_SUCCESS
        }
        Command::Create => create::run(&parsed.opts, sink),
        Command::Verify => verify::run(&parsed.opts, sink, false),
        Command::Repair => repair::run(&parsed.opts, sink),
    }
}
