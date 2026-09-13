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
//! `the parfast reference tree` is superseded: a diff-synced copy reaches nothing
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
pub mod control;
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
    // Windows demotes sustained "background" work onto E-cores a few
    // seconds in, which is exactly the shape of a repair fold: measured
    // on an i7-1280P the GF(2^16) fold ran 111 GB/s for ~3 s and then
    // 13 GB/s with the machine 66% idle, and a heavy leg went 16.6 s to
    // 58 s. The daemon and its bench drivers have opted out since; this
    // CLI had not, so a Windows user's long repair was being throttled
    // where the same engine in the daemon was not. A no-op off Windows
    // and on Windows builds without the API, and it touches execution
    // speed only - priority CLASS is left alone, so nothing else on the
    // box is starved. Found 9 Sep 2026 while auditing why the CLI timed
    // slower than the bench driver.
    nzbkit::mem::opt_out_of_power_throttling();
    install_timing_sink();
    let mut sink = out::Sink::stdio();
    // Ctrl-C is the engine's clean cancel from here on, and the engine's
    // progress is a meter on stdout - `control.rs`. The binary only:
    // an in-process caller keeps the signals it had.
    let gate = control::install_interrupt();
    run_controlled(argv0, args, &mut sink, Some(gate))
}

/// Give `NZBFAST_REPAIR_TIMING` somewhere to land, and only then.
///
/// The engine reports its phases (`plan prep`, `forney solve`, `create
/// seals`, the fold traces) as tracing EVENTS. A binary that installs no
/// subscriber drops them on the floor, so the variable appeared to do
/// nothing under this CLI while the bench driver beside it printed a full
/// breakdown - and every phase share measured in the September 2026 PAR2
/// campaign is therefore the DRIVER's run, not this one.
///
/// Three properties this must keep, all of them load-bearing:
///
/// * **stderr, never stdout.** This CLI's stdout is par2cmdline-compatible
///   and pinned line for line by a captured conformance table. A timing
///   line on stdout would break every row of it.
/// * **Nothing installed unless the variable is set.** Off, this function
///   is one `var_os` and returns; there is no subscriber, so no other
///   crate's events can reach a user's terminal either.
/// * **The driver's exact format** - no ANSI, no timestamp, target kept.
///   The target is the `repair-timing` key these lines have always been
///   grepped by, and matching the driver is what lets the two be diffed
///   phase against phase, which is the whole reason this exists.
///
/// `try_init` rather than `init`: a second call must not panic a repair.
fn install_timing_sink() {
    if std::env::var_os("NZBFAST_REPAIR_TIMING").is_none() {
        return;
    }
    let _ = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_target(true)
        .with_writer(std::io::stderr)
        .try_init();
}

/// [`run`] against a caller-supplied sink, which is what the unit tests
/// assert on: a test that shells out to the built binary cannot run
/// until the binary is built, and this crate's whole job is the exact
/// text of these lines.
pub fn run_with(argv0: &str, args: &[String], sink: &mut out::Sink) -> u8 {
    run_controlled(argv0, args, sink, None)
}

/// [`run_with`] with the interrupt gate the binary installs. `None` is
/// the in-process shape: nothing can cancel it and the meter is silent.
pub fn run_controlled(
    argv0: &str,
    args: &[String],
    sink: &mut out::Sink,
    gate: Option<std::sync::Arc<nzbkit::par2repair::PauseGate>>,
) -> u8 {
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
    // `-t`, the pool width, and the same defect one switch over: it was
    // parsed onto `Options.threads` and read only by the verify pass's
    // own hashing width, so everything the engine sizes from
    // `mem::cpu_workers` - the fold, the solve, the packet scan, the
    // catalog build - went on taking the whole machine, so the switch
    // the help text calls "threads used for main processing" reached
    // everything except the main processing. A separate diagnostic build
    // counted the fold's spawn loop directly and saw 32 workers at `-t1`
    // and at `-t2` alike, on create and on repair, where
    // `NZBFAST_CPU_WORKERS=1` saw 1
    // (research/PARFAST-CODEX-AUDIT-VALIDATION-2026-09-09.md).
    //
    // Confirmed here without instrumenting anything, on the wall clock
    // of a fold-heavy create (256 MiB, `-s262144 -c256`, 32-core M3
    // Ultra). Before: 0.36 s at the default and 0.37 s at both `-t1` and
    // `-t4` - the switch doing nothing. After: 0.35 s / 0.62 s / 2.42 s,
    // landing on the 0.63 s and 2.41 s that `NZBFAST_CPU_WORKERS=4` and
    // `=1` already produced. Byte output is identical at all three
    // widths and par2cmdline 1.2.0 accepts it.
    //
    // Published here for the same reason `-m` is, and before any
    // command runs so create and repair both see it.
    if let Some(t) = parsed.opts.threads.filter(|&n| n > 0) {
        nzbkit::mem::set_cpu_workers(t);
    }
    // `-T`, the file-hash width, and the same defect one switch further
    // on: it was parsed onto `Options.file_threads` and read at exactly
    // one site, `verify::survey`, which a REPAIR reaches only through
    // `run_resurveying` - the fallback for a set whose engine report
    // cannot be matched member for member. The main repair route calls
    // `verify::survey_from_engine`, which reads surveys the engine has
    // already finished and hashes nothing, so `parfast r -T1` - what a
    // script passes to be gentle on a spinning disk or a network volume
    // - ran at full width with no diagnostic.
    //
    // Not a cosmetic gap. Measured 10 Sep 2026 on a 1.5 GiB set of 24
    // members with one damaged 1 MiB block, both binaries on the same
    // box and the same fixture: par2cmdline-turbo 1.5.0 repairs in
    // 2.73 s at `-T1`, 1.65 s at its default and 0.61 s at `-T24`, a
    // 4.5x span across the switch. parfast before this line read 1.77 s
    // at `-T1`, 1.60 s at the default and 1.78 s at `-T24` (medians of
    // three) - one overlapping band, so the switch was doing nothing -
    // while `NZBFAST_CPU_WORKERS=1` took the same repair to 25.9 s,
    // which is how we know the pool it should have been narrowing was
    // there to narrow. After: 22.5 s / 1.79 s / 1.62 s over the same
    // three arms, and `-T2` lands between at 12.1 s. The fixture and the
    // full ladder are in TODO 339.
    //
    // REFUSING it was considered and rejected: `-B` is refused on repair
    // because honouring it would write the wrong bytes, but the
    // reference accepts `-T` on repair and acts on it, so refusing would
    // be a drop-in break for a script that passes it.
    //
    // It does NOT re-scale `-t`. `mem::file_workers` pins the file axis
    // only; the engine's verify pass still spends the `-t` budget across
    // the two axes, and they multiply - the same rule `verify::survey`
    // applies to the same pair. Byte output is identical at every width:
    // this changes how many files are hashed at once, not what the
    // hashes are.
    if let Some(t) = parsed.opts.file_threads.filter(|&n| n > 0) {
        nzbkit::mem::set_file_workers(t);
    }
    // The verify tier, published HERE for the reason the three switches
    // above carry between them: a parfast switch that parses onto
    // `Options` and is read by nobody is this file's own repeated
    // defect - `-m`, `-t` and `-T` each shipped that way - and `run()`
    // before the command dispatch is where all three were fixed.
    //
    // Always set, both directions: parfast's default is the per-block
    // tier (13 Sep 2026, the product decision after the crafted shape was put in
    // front of turbo - research/PARFAST-SINGLE-FILE-MD5-HEADROOM-
    // 2026-09-13.md), and `--slow` is the whole-file verdict. An explicit
    // CLI choice wins over the environment in the engine's precedence,
    // which is what makes `--slow` an answer and not a suggestion. There
    // is no `--fast` any more: it armed the joint solve, which is the
    // default on every class that can run it, and the engine's
    // `NZBFAST_FORNEY_JOINT` is the measurement rounds' control.
    nzbkit::par2::set_fast_check(!parsed.opts.slow);
    let command = parsed.command;
    // The watch reads the sink's loudness when it is built, so the level
    // goes on first; the commands set it again, to the same value.
    sink.set_level(parsed.opts.level);
    let watch = control::CliWatch::new(gate, sink);
    let mut code = match parsed.command {
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
            sink.out(&help::build_line());
            sink.out(help::COPYRIGHT);
            EXIT_SUCCESS
        }
        Command::Create => create::run_watched(&parsed.opts, sink, &watch),
        Command::Verify => verify::run_watched(&parsed.opts, sink, false, &watch),
        Command::Repair => repair::run_watched(&parsed.opts, sink, &watch),
    };
    if watch.cancelled() {
        // Said once, on stderr, unfiltered by `-q` like every diagnosis;
        // and the pending `\r` fragment is ended first or this line
        // overprints it. The exit code is the shell's own for an
        // interrupted process, NOT the dialect's 1: a script that reads
        // 1 as "damage found" must not read a cancelled verify that way.
        watch.end_line();
        sink.err(match command {
            Command::Repair => {
                "Cancelled. No file is worse than it was; run the repair again to finish."
            }
            _ => "Cancelled.",
        });
        code = control::EXIT_INTERRUPTED;
    }
    code
}

#[cfg(test)]
mod switch_tests {
    /// `-B <dir>` as TWO arguments, which is what SABnzbd emits.
    ///
    /// SAB probes `par2 -h`, sees "Set the basepath" on our help screen,
    /// and then does `insert(2, "-B"); insert(3, parfolder)` for every
    /// repair (sabnzbd/newsunpack.py, par2cmdline_verify). Until this
    /// was accepted, parfast took the empty attached value, consumed the
    /// FOLDER as the par2 file and answered "failed to set the main par
    /// file" - exit 3 on every SABnzbd job, which made the drop-in claim
    /// untrue for the largest caller of par2 there is.
    ///
    /// PINNED AGAINST THE REFERENCE rather than invented, and the second
    /// half is why this is one special case and not a general rule:
    /// par2cmdline 1.2.0 accepts `-B <dir>` (exit 0) and REFUSES
    /// `-m 512` and `-t 2` (exit 3), which parfast also refuses.
    /// Widening separated values to the other switches would be a
    /// divergence in the opposite direction.
    #[test]
    fn basepath_takes_a_separated_path_the_way_the_reference_does() {
        let args: Vec<String> = ["r", "-B", "/tmp/set", "/tmp/set/x.par2"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let p = super::cli::parse("parfast", &args).expect("-B <dir> must parse");
        assert_eq!(
            p.opts.basepath.as_deref(),
            Some(std::path::Path::new("/tmp/set")),
            "the next argument is the basepath"
        );
        assert_eq!(
            p.opts.par2.as_deref(),
            Some(std::path::Path::new("/tmp/set/x.par2")),
            "and it must NOT have been eaten as the par2 file"
        );

        // The attached spelling the help screen documents still works.
        let args: Vec<String> = ["r", "-B/tmp/set", "/tmp/set/x.par2"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let p = super::cli::parse("parfast", &args).expect("-B<dir> must parse");
        assert_eq!(
            p.opts.basepath.as_deref(),
            Some(std::path::Path::new("/tmp/set"))
        );

        // A bare -B at the end of the line says so rather than silently
        // taking an empty path.
        let args: Vec<String> = ["r", "-B"].iter().map(|s| (*s).to_string()).collect();
        assert!(
            super::cli::parse("parfast", &args).is_err(),
            "-B with nothing after it must refuse"
        );
    }

    /// A long option that is NOT ours still gets the reference's own
    /// refusal, in the reference's own words. Adding `--fast` must not
    /// have turned the long-option arm into a catch-all.
    #[test]
    fn other_long_options_are_still_refused_the_reference_way() {
        let args: Vec<String> = ["r", "--zzz", "set.par2"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let e = super::cli::parse("parfast", &args).expect_err("--zzz is unknown");
        assert_eq!(e.message, "Unknown option: --zzz");
        // And the near-miss spellings, which must not be taken as `--fast`.
        for spell in ["--fas", "--fastt", "--FAST"] {
            let args: Vec<String> = ["r", spell, "set.par2"]
                .iter()
                .map(|s| (*s).to_string())
                .collect();
            assert!(
                super::cli::parse("parfast", &args).is_err(),
                "{spell} must not be taken for --fast"
            );
        }
    }

    /// `--comment` parses in BOTH GNU spellings, on every command, and
    /// the text survives the split the parser does on `-<letter><rest>`
    /// - which means an `=` inside the comment itself must reach the
    /// engine rather than ending it.
    #[test]
    fn comment_parses_in_both_spellings_on_every_command() {
        let parse = |args: &[&str]| {
            let v: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
            super::cli::parse("parfast", &v)
        };
        for cmd in ["c", "v", "r"] {
            for args in [
                vec![cmd, "--comment=hello world", "set.par2"],
                vec![cmd, "--comment", "hello world", "set.par2"],
            ] {
                let p = parse(&args).expect("--comment is accepted");
                assert_eq!(p.opts.comment.as_deref(), Some("hello world"), "cmd={cmd}");
                // The bare argument after it is still the set, not the
                // comment's second word.
                assert_eq!(
                    p.opts.par2.as_deref(),
                    Some(std::path::Path::new("set.par2"))
                );
            }
        }
        assert_eq!(
            parse(&["c", "--comment=a=b=c", "set.par2"])
                .expect("parses")
                .opts
                .comment
                .as_deref(),
            Some("a=b=c"),
            "only the FIRST = separates the option from its value"
        );
        // An empty value is legal at the command line and is the absence
        // of a comment to the engine, which writes no packet for one.
        assert_eq!(
            parse(&["c", "--comment=", "set.par2"])
                .expect("parses")
                .opts
                .comment
                .as_deref(),
            Some("")
        );
        assert!(
            parse(&["c", "set.par2"])
                .expect("parses")
                .opts
                .comment
                .is_none(),
            "absent unless asked for"
        );
        // The separated form with nothing after it is a refusal and not
        // a silent empty comment.
        let e = parse(&["c", "--comment"]).expect_err("no value");
        assert_eq!(e.message, "Option --comment requires a value.");
        // Near-miss spellings are still unknown long options.
        for spell in ["--comment=x", "--commen=x", "--COMMENT=x"] {
            let r = parse(&["c", spell, "set.par2"]);
            assert_eq!(
                r.is_ok(),
                spell == "--comment=x",
                "{spell} must not be taken for --comment"
            );
        }
    }

    /// `--volume-blocks` reaches the SAME two spellings, because the
    /// value-taking list is one rule and not one rule per option. It
    /// landed attached-only hours before `--comment` did, and joining
    /// it is strictly additive: the attached form it shipped with is
    /// unchanged, including its refusal.
    #[test]
    fn volume_blocks_takes_both_spellings_too() {
        let parse = |args: &[&str]| {
            let v: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
            super::cli::parse("parfast", &v)
        };
        for args in [
            vec!["c", "--volume-blocks=512", "set.par2"],
            vec!["c", "--volume-blocks", "512", "set.par2"],
        ] {
            let p = parse(&args).expect("--volume-blocks is accepted");
            assert_eq!(p.opts.volume_blocks, Some(512), "{args:?}");
            assert_eq!(
                p.opts.par2.as_deref(),
                Some(std::path::Path::new("set.par2")),
                "{args:?}"
            );
        }
        // The attached form's own refusal, in its own words, unchanged.
        assert_eq!(
            parse(&["c", "--volume-blocks=0", "set.par2"])
                .expect_err("zero is refused")
                .message,
            "Invalid option specified: --volume-blocks=0"
        );
        // And the separated form reaches that same refusal rather than
        // a different one, because it is joined into the same shape.
        assert_eq!(
            parse(&["c", "--volume-blocks", "nope", "set.par2"])
                .expect_err("not a number")
                .message,
            "Invalid option specified: --volume-blocks=nope"
        );
        assert_eq!(
            parse(&["c", "--volume-blocks"])
                .expect_err("no value")
                .message,
            "Option --volume-blocks requires a value."
        );
    }
}
