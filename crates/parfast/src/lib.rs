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
    // `--fast`, and published HERE for the reason the three switches
    // above carry between them: a parfast switch that parses onto
    // `Options` and is read by nobody is this file's own repeated
    // defect - `-m`, `-t` and `-T` each shipped that way - and `run()`
    // before the command dispatch is where all three were fixed.
    // `switch_reaches_the_engine` below asserts the reach rather than
    // the parse, which is the half a parse-only test misses.
    //
    // Set only when asked, never cleared: an unset switch must leave
    // `NZBFAST_FORNEY_JOINT` to decide, or `--fast`'s absence would
    // silently override an environment that armed it deliberately.
    if parsed.opts.fast {
        nzbkit::par2repair::set_joint_arm(true);
        // A process that repairs once does not need this; the daemon
        // repairs many times and would otherwise report the previous
        // job's decline against this one. Cleared BEFORE, so the record
        // read below can only be this run's.
        nzbkit::par2repair::reset_joint_reach();
    }
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
    if parsed.opts.fast {
        report_fast(command, sink);
    }
    code
}

/// Say, on stderr, what `--fast` actually did - TODO 340 item 1.
///
/// The defect this closes: `--fast` was accepted on every command,
/// built the joint plan and paid for it, and then ran the SHIPPED
/// arithmetic on any host or any set the joint kernel declines - saying
/// so only inside a `repair-timing` trace line behind
/// `NZBFAST_REPAIR_TIMING`, which nobody sets. On a GFNI x86 part that
/// is EVERY repair; on sets parfast writes itself it is about seven in
/// eight on every platform. A switch whose effect is conditional on the
/// host has to be able to report that it declined; silence is the
/// defect, not the decline.
///
/// **A decline is not the switch doing nothing**, and this line must
/// not be read as saying so. The joint CONSTRUCTOR runs whatever
/// arithmetic the solve then uses, so `--fast` is a win on a GFNI part
/// even while falling back - measured 12 of 12 paired legs,
/// `research/FAST-MODE-X86-GFNI-2026-09-11.md`. What a decline costs is
/// the DIFFERENCE between falling back and not. The "7% slower at
/// m = 8,192" this file was written against is withdrawn: one leg, on
/// the box later found to be giving fifteen of sixteen cores to a
/// screensaver.
///
/// stderr rather than stdout for the reason `install_timing_sink`
/// gives: this CLI's stdout is pinned line for line against
/// par2cmdline's, and `Sink::err` is the channel the verbosity ladder
/// never filters - `-q -q` is silence about progress, not about a
/// switch that did nothing.
///
/// One line, and only when there is something to say: a run that TOOK
/// the joint path prints nothing, because a switch that worked is not
/// news.
fn report_fast(command: Command, sink: &mut out::Sink) {
    if let Some(line) = fast_note(command, nzbkit::par2repair::joint_reach()) {
        sink.err(&line);
    }
}

/// [`report_fast`]'s line, as a pure function of the two things that
/// decide it - so every branch is pinned by a test rather than by a
/// repair that has to be built to reach it. The host's kernel name is
/// the one thing it still reads from the machine, because that IS the
/// answer on the arm that needs it.
fn fast_note(command: Command, reach: nzbkit::par2repair::JointReach) -> Option<String> {
    use nzbkit::par2repair::{JointDecline, JointReach};
    // `--fast` parses on every command so that a wrapper passing it to
    // all three does not fail (see `cli::parse`), but only `repair`
    // has a solve to arm. `-h` and the version lines are not commands a
    // wrapper passes work to, and their whole contract is that stdout
    // gets the screen while stderr stays EMPTY - so they are silent
    // here rather than told about a switch they were never going to
    // use.
    match command {
        Command::Repair => {}
        Command::Create | Command::Verify => {
            return Some(
                "parfast: --fast affects repair only; this command ignored it.".to_string(),
            );
        }
        Command::Help | Command::Version | Command::VersionCopyright => return None,
    }
    let why = match reach {
        // Nothing was repaired, so no solve was asked for one. Not a
        // decline and not worth a line.
        JointReach::Untouched | JointReach::Taken => return None,
        JointReach::Declined(d) => d,
    };
    let (reason, remedy) = match why {
        // THREE causes, and the third is the BUILD: `forney::backsub_gate`
        // never selects the Forney solver on a part with no fused fold
        // kernel (`gf16::multi_fold_width() == 0` - the armv7 tarball,
        // or `NZBFAST_GF16_MULTI=0`), whatever the damage. Telling a
        // Raspberry Pi 2/3 owner "too few blocks were missing" after a
        // 1,500-block repair would be false, and it is the shipped case
        // (claim `fast-mode-arch-breadth-11sep`, measured under qemu-arm:
        // m=1,500 on a 1,280 gate took the dense product with no joint
        // line at all). The 64-bit build on the same board reaches it.
        JointDecline::NotForney if nzbkit::gf16::multi_fold_width() == 0 => {
            // The knob and the build say the same thing to the solver and
            // need opposite remedies: one is unset, the other is a
            // different download.
            if std::env::var_os("NZBFAST_GF16_MULTI").is_some_and(|v| v == "0") {
                (
                    "NZBFAST_GF16_MULTI=0 refuses this CPU's fused fold kernel, so the \
                     solver --fast arms is never selected"
                        .to_string(),
                    "unset it".to_string(),
                )
            } else {
                (
                    "this build has no fused fold kernel, so the solver --fast arms is \
                     never selected"
                        .to_string(),
                    "--fast needs an x86-64 or 64-bit ARM build".to_string(),
                )
            }
        }
        JointDecline::NotForney => (
            "this repair does not use the solver it arms".to_string(),
            "too few blocks were missing, or recovery packets were lost too".to_string(),
        ),
        JointDecline::BlockAlignment => (
            "this set's block size is not a multiple of 32 bytes".to_string(),
            "create the set with a 32-byte-aligned block size (-s)".to_string(),
        ),
        JointDecline::NoScaleKernel => {
            let k = nzbkit::gf16::scale_kernel();
            (
                format!(
                    "this CPU has no vector row-scale kernel (GF16 arm: {})",
                    k.name()
                ),
                k.remedy()
                    .unwrap_or("no setting on this CPU changes it")
                    .to_string(),
            )
        }
        JointDecline::KernelArena => (
            "the fast solve's tables do not fit the memory budget".to_string(),
            "raise it with -m".to_string(),
        ),
        JointDecline::NotMixed => (
            "this set's recovery exponents are not the shape the fast solve needs".to_string(),
            "nothing on the command line changes it".to_string(),
        ),
        JointDecline::Held => (
            "NZBFAST_FORNEY_STAGE1 held the fast solve's first stage on the shipped arithmetic"
                .to_string(),
            "unset it; it is a measurement knob".to_string(),
        ),
    };
    Some(format!("parfast: --fast did not run: {reason}; {remedy}."))
}

#[cfg(test)]
mod switch_tests {
    /// `--fast` must PARSE, on every command, and must not be confused
    /// with a reference switch or with an unknown long option.
    #[test]
    fn fast_parses_on_every_command() {
        for cmd in ["c", "v", "r"] {
            let args: Vec<String> = [cmd, "--fast", "set.par2"]
                .iter()
                .map(|s| (*s).to_string())
                .collect();
            let p = super::cli::parse("parfast", &args).expect("--fast is accepted");
            assert!(p.opts.fast, "cmd={cmd}");
        }
        let args: Vec<String> = ["r", "set.par2"].iter().map(|s| (*s).to_string()).collect();
        assert!(
            !super::cli::parse("parfast", &args)
                .expect("plain repair parses")
                .opts
                .fast,
            "the flag must be OFF unless asked for"
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

    /// THE PLUMB, which is the half this repo has shipped broken twice
    /// (`-m` and `-t` both parsed onto `Options` and were read by
    /// nobody). Asserting the parse alone would have passed on both of
    /// those days, so assert that the ENGINE's own answer changes.
    ///
    /// Process-global, so this test sets the arm and leaves it set; it
    /// is the only test in this binary that touches it.
    ///
    /// It starts from an EXPLICIT disarm rather than from the default.
    /// Until 11 Sep 2026 the first line here read the default and
    /// asserted it was off - which proved the reach only for as long as
    /// that happened to be true, and the default moved. What this test
    /// is FOR is that `set_joint_arm` reaches the engine in both
    /// directions, and that is provable without knowing what an
    /// untouched process would have answered. The rewrite is strictly
    /// stronger: the old first line took the disarm's reach on faith
    /// from the default, and this one measures it.
    #[test]
    fn switch_reaches_the_engine() {
        nzbkit::par2repair::set_joint_arm(false);
        assert!(
            !nzbkit::par2repair::joint_armed(),
            "an explicit disarm must reach the engine"
        );
        nzbkit::par2repair::set_joint_arm(true);
        assert!(nzbkit::par2repair::joint_armed());
        nzbkit::par2repair::set_joint_arm(false);
        assert!(
            !nzbkit::par2repair::joint_armed(),
            "the override must work in BOTH directions, so a CLI can \
             disarm a box whose environment armed it"
        );
    }
    /// THE OTHER HALF OF THE SAME DEFECT (TODO 340): the switch reaches
    /// the engine, the engine DECLINES, and until 11 Sep 2026 nothing
    /// said so. Every decline must produce a line, and a run that took
    /// the path must produce none - a switch that worked is not news,
    /// and a line on every successful repair would be noise a script
    /// learns to ignore, which is how the next silent decline hides.
    #[test]
    fn every_decline_is_reported_and_a_success_is_not() {
        use super::cli::Command;
        use nzbkit::par2repair::{JointDecline, JointReach};
        for reach in [JointReach::Untouched, JointReach::Taken] {
            assert_eq!(
                super::fast_note(Command::Repair, reach),
                None,
                "{reach:?} is not a decline and must print nothing"
            );
        }
        for d in [
            JointDecline::NotForney,
            JointDecline::BlockAlignment,
            JointDecline::NoScaleKernel,
            JointDecline::KernelArena,
            JointDecline::NotMixed,
            JointDecline::Held,
        ] {
            let line = super::fast_note(Command::Repair, JointReach::Declined(d))
                .unwrap_or_else(|| panic!("{d:?} must be reported"));
            assert!(line.starts_with("parfast: --fast did not run: "), "{line}");
            assert!(line.ends_with('.'), "{line}");
            // One LINE, not a paragraph: this goes to stderr beside a
            // repair's own output.
            assert!(!line.contains('\n'), "{line}");
            // The reason and the remedy are both there - naming the
            // decline without saying what would change it is the trace
            // line this replaces.
            assert!(line.contains("; "), "no remedy clause: {line}");
            // House copy rule: no em-dashes or en-dashes in UI copy.
            assert!(
                !line.contains('\u{2014}') && !line.contains('\u{2013}'),
                "{line}"
            );
        }
        // The NotForney arm has a BUILD cause on a part with no fused
        // fold kernel (armv7), and on such a build the line must say so
        // rather than blame the damage; on every other build it must NOT
        // mention the build. Host-dependent by construction: on this
        // fleet's Macs and x86 the second branch is what runs, and the
        // first is proved by running THIS test under qemu-arm on the
        // armv7 lib test binary (research/FAST-MODE-ARCH-BREADTH-2026-09-11.md).
        let nf = super::fast_note(
            Command::Repair,
            JointReach::Declined(JointDecline::NotForney),
        )
        .expect("reported");
        if nzbkit::gf16::multi_fold_width() == 0 {
            // The build, or `NZBFAST_GF16_MULTI=0` on a host: either way
            // the sentence names the fused fold kernel, not the damage.
            assert!(nf.contains("fused fold kernel"), "{nf}");
            assert!(!nf.contains("too few blocks"), "{nf}");
        } else {
            assert!(nf.contains("too few blocks"), "{nf}");
            assert!(!nf.contains("fused fold kernel"), "{nf}");
        }
        // The kernel arm names the kernel this CPU actually selected, so
        // a user on a GFNI part is not told "unsupported CPU".
        let k = nzbkit::gf16::scale_kernel();
        let line = super::fast_note(
            Command::Repair,
            JointReach::Declined(JointDecline::NoScaleKernel),
        )
        .expect("reported");
        assert!(line.contains(k.name()), "{line} must name {}", k.name());
    }

    /// `--fast` parses on create and verify so a wrapper can pass it to
    /// all three, and reaches nothing there - which is the same defect
    /// one command over, so it says so too.
    ///
    /// `-h` and the version lines are the exception, and not a
    /// cosmetic one: their contract is stdout gets the screen and
    /// stderr stays EMPTY, which the captured conformance table pins.
    #[test]
    fn fast_on_a_command_with_no_solve_says_so() {
        use super::cli::Command;
        use nzbkit::par2repair::JointReach;
        for cmd in [Command::Create, Command::Verify] {
            let line = super::fast_note(cmd, JointReach::Taken).expect("reported");
            assert!(line.contains("repair only"), "{cmd:?}: {line}");
        }
        for cmd in [Command::Help, Command::Version, Command::VersionCopyright] {
            assert_eq!(
                super::fast_note(cmd, JointReach::Untouched),
                None,
                "{cmd:?} must leave stderr empty"
            );
        }
    }
}
