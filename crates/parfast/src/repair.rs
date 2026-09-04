//! `r` / `repair`: verify, then hand the damage to the engine.
//!
//! Everything up to "Repair is possible." is [`crate::verify`]'s, line
//! for line, because par2cmdline prints the identical block on the way
//! in and a second copy of it here would be a second answer to the same
//! question. What is left is the repair itself, the re-verify, and the
//! `-p` purge.

use nzbkit::par2repair::{self, AfterSurvey, MemberSurvey, RepairStatus};

use crate::cli::Options;
use crate::out::{Level, Sink};
use crate::verify::{self, Loaded, Survey, Target, extra_candidates};

/// Why the run stopped before the engine folded anything.
///
/// Each is a verdict par2cmdline reaches WITHOUT repairing, so each is
/// an [`AfterSurvey::Stop`]. The lines are already printed by the time
/// one of these comes back; what is left is the exit code and, for a
/// clean set, the `-p` purge - a filesystem write, deliberately not
/// done from inside the observer while the engine still holds the
/// directory's packet catalog open.
enum Stopped {
    /// Nothing was wrong. `-p` still applies.
    Clean,
    /// Not enough recovery data and nothing for the adoption scan.
    NotPossible,
    /// `-O`: the verify verdict, and no reconstruction.
    RenameOnly,
    /// The engine's report could not be matched to the set one-for-one
    /// (see [`verify::survey_from_engine`]), so the caller re-surveys
    /// for itself. Correct, and the cost of the pass this exists to
    /// remove.
    Unmatched,
}

/// `r` / `repair`.
pub fn run(opts: &Options, sink: &mut Sink) -> u8 {
    sink.set_level(opts.level);
    // WHICH set and WHERE, before anything expensive. The engine's own
    // pass needs nothing from us but these two, so it can run BESIDE
    // the load instead of after it - see the scope below.
    let (_named, dir, want) = match verify::locate(opts, sink) {
        Ok(v) => v,
        Err(code) => return code,
    };

    let mut stopped: Option<Stopped> = None;
    let mut surveyed: Option<Survey> = None;
    let mut loaded_slot: Option<Loaded> = None;
    let mut early: Option<u8> = None;

    // TWO PASSES THAT NEEDED EACH OTHER ONLY FOR THEIR ORDER.
    //
    // `verify::load` reads and MD5-scans every packet in the set - 108 MB
    // of recovery volumes on the published corpus, ~26 ms - to print the
    // reference's `Loading` / `Loaded N new packets` lines and to count
    // the recovery blocks. The engine's survey re-derives all of that
    // for itself from the same directory. Neither needs the other's
    // output, so the only thing that made this a 26 ms prologue was the
    // PRINTED ORDER: every `Loading` line precedes every `Opening:` line
    // and the conformance table pins that.
    //
    // So they run together and the order is held by the channel instead.
    // The engine builds its catalog and verifies the payload on the
    // worker; the main thread loads and prints; the observer hands its
    // survey over and BLOCKS until the main thread has finished printing
    // and decided. The engine's verify is ~106 ms against the load's
    // ~26 ms, so in practice the main thread is always waiting on the
    // worker and never the other way round.
    //
    // Nothing races on the filesystem: until the observer answers
    // `Repair` the engine only READS, and the fold - the only writer -
    // starts after the main thread has finished with the directory.
    let engine = std::thread::scope(|scope| {
        let (tx_members, rx_members) = std::sync::mpsc::channel::<Vec<MemberSurvey>>();
        let (tx_action, rx_action) = std::sync::mpsc::channel::<AfterSurvey>();
        let edir = dir.clone();
        let worker = scope.spawn(move || {
            let mut observe = |members: &[MemberSurvey]| {
                // A dead receiver means the main thread gave up before
                // it could decide; stopping is the safe answer, and it
                // leaves the directory untouched.
                if tx_members.send(members.to_vec()).is_err() {
                    return AfterSurvey::Stop;
                }
                rx_action.recv().unwrap_or(AfterSurvey::Stop)
            };
            par2repair::repair_dir_set_surveyed(&edir, &want, &[], &mut observe)
        });

        let mut action = AfterSurvey::Stop;
        match verify::load(opts, sink) {
            Err(code) => early = Some(code),
            Ok(loaded) => {
                verify::print_set_summary(&loaded, sink);
                // `-B` names where the DATA is; the engine resolves a
                // FileDesc name against the directory it is handed, and
                // that is the directory the `.par2` files live in.
                // Repairing anyway wrote reconstructed files beside the
                // recovery set while the damaged originals under `-B`
                // sat untouched, then re-verified `-B` (still damaged),
                // still printed "Repair complete.", still exited 0, and
                // with `-p` deleted the only recovery data left.
                // Refusing is the honest answer until the engine takes a
                // data path separately from its packet path - a change
                // to `par2repair`'s target walk, not to this caller.
                //
                // VERIFY still honours `-B` in full: it only reads.
                if loaded.data_dir != loaded.dir {
                    sink.err(
                        "-B is not supported on repair: the recovery set and the data \
                         files must be in the same directory.",
                    );
                    early = Some(crate::EXIT_INVALID_ARGS);
                } else if loaded.set.recovery_set_id != want {
                    // The engine was started on the set the NAMED file
                    // declares and the load settled on a different one,
                    // which only a directory holding several can do. Its
                    // pass is about somebody else's files, so drop it.
                    stopped = Some(Stopped::Unmatched);
                } else {
                    // A `recv` error is the engine having failed
                    // before it surveyed anything. Nothing to say here:
                    // its own error is the one worth reporting and the
                    // join below carries it out of the scope.
                    if let Ok(members) = rx_members.recv() {
                        match verify::survey_from_engine(&loaded, &members, sink) {
                            Some(survey) => {
                                action = announce(&loaded, opts, &survey, sink, &mut stopped);
                                surveyed = Some(survey);
                            }
                            None => stopped = Some(Stopped::Unmatched),
                        }
                    }
                }
                loaded_slot = Some(loaded);
            }
        }
        let _ = tx_action.send(action);
        worker.join().expect("engine survey thread panicked")
    });

    if let Some(code) = early {
        return code;
    }
    let loaded = loaded_slot.expect("load either failed into `early` or filled this");
    if let Some(Stopped::Unmatched) = stopped {
        return run_resurveying(&loaded, opts, sink);
    }
    let status = match engine {
        // `Ok(None)` is our own `Stop` coming back: `announce` printed
        // the block already, so only the exit code is left. Anything
        // else and the engine folded.
        Ok(None) => return stop_code(&loaded, opts, stopped, sink),
        Ok(Some(st)) => Ok(st),
        Err(e) => Err(e),
    };
    let survey = surveyed.expect("the engine folded, so the observer ran and kept its survey");
    finish(&loaded, opts, &survey, status, sink)
}

/// Everything par2cmdline prints between the `Target:` table and the
/// fold, and the decision at the end of it: repair, or one of the three
/// verdicts it reaches without repairing.
///
/// Shared by both entries into the engine (the surveyed one and the
/// fallback), so the printed block cannot drift between them.
fn announce(
    loaded: &Loaded,
    opts: &Options,
    survey: &Survey,
    sink: &mut Sink,
    stopped: &mut Option<Stopped>,
) -> AfterSurvey {
    verify::print_targets(survey, sink);
    if !survey.damaged() {
        sink.line(Level::Terse, "");
        sink.line(
            Level::Terse,
            "All files are correct, repair is not required.",
        );
        *stopped = Some(Stopped::Clean);
        return AfterSurvey::Stop;
    }
    sink.line(Level::Terse, "");
    verify::print_extra_scan(loaded, survey, sink);
    sink.line(Level::Terse, "Repair is required.");
    verify::print_damage_detail(survey, sink);
    // The block-count gate may only refuse when there is NOTHING for the
    // engine's adoption pass to find.
    //
    // `Survey::repairable` is `recovery_blocks >= owed()`, and `owed()`
    // counts a member as wholly missing unless it sits at its FileDesc
    // name. That is strictly less than the engine knows: it adopts an
    // unnamed file by checksum (`par2repair::adopt`), so a complete
    // payload beside the set under a hash name repairs with ZERO
    // recovery blocks. Refusing on the count alone turned that - the
    // ordinary shape of an obfuscated Usenet post - into "Repair is not
    // possible.", and the reference, which really does scan extra files
    // here, repairs it.
    //
    // Deciding on "is there a candidate at all" rather than dropping the
    // gate keeps the refusal in its printed position for the sets that
    // genuinely are hopeless, which is what the captured conformance
    // rows pin. When a candidate exists we say nothing and let the
    // engine answer; its own `Unrepairable` arm below prints the same
    // block.
    if !survey.repairable() && extra_candidates(loaded, survey).is_empty() {
        sink.line(Level::Terse, "Repair is not possible.");
        sink.line(
            Level::Terse,
            &format!(
                "You need {} more recovery blocks to be able to repair.",
                survey.owed() - survey.recovery_blocks
            ),
        );
        *stopped = Some(Stopped::NotPossible);
        return AfterSurvey::Stop;
    }
    sink.line(Level::Terse, "Repair is possible.");
    print_plan(survey, sink);

    // `-O` is rename-only: par2cmdline fixes files that are perfect
    // matches under another name and does NOT reconstruct anything, so
    // it stops here with the verify verdict rather than solving.
    if opts.rename_only {
        *stopped = Some(Stopped::RenameOnly);
        return AfterSurvey::Stop;
    }

    sink.line(Level::Terse, "");
    print_solve_detail(sink);
    back_up_damaged(loaded, survey);
    AfterSurvey::Repair
}

/// The exit code for a run that stopped before the fold, plus the one
/// filesystem action left over: `-p` on a clean set. Held back until
/// here rather than done inside the observer, which runs while the
/// engine still holds the directory's packet catalog.
fn stop_code(loaded: &Loaded, opts: &Options, stopped: Option<Stopped>, sink: &mut Sink) -> u8 {
    match stopped {
        Some(Stopped::Clean) => {
            if opts.purge {
                verify::purge(loaded, sink);
            }
            crate::EXIT_SUCCESS
        }
        Some(Stopped::NotPossible) => crate::EXIT_REPAIR_NOT_POSSIBLE,
        Some(Stopped::RenameOnly) => crate::EXIT_REPAIR_POSSIBLE,
        // Unreachable: the engine stops only when the observer says so,
        // and every `Stop` above records why first.
        Some(Stopped::Unmatched) | None => crate::EXIT_REPAIR_FAILED,
    }
}

/// The old two-pass route, kept for the set whose engine report cannot
/// be matched member for member (see [`Stopped::Unmatched`]): survey
/// here, then hand the directory to the engine, which surveys it again.
/// Correct, and slower by exactly the pass this module exists to stop
/// paying.
fn run_resurveying(loaded: &Loaded, opts: &Options, sink: &mut Sink) -> u8 {
    let survey = verify::survey(loaded, opts, sink);
    let mut stopped: Option<Stopped> = None;
    if announce(loaded, opts, &survey, sink, &mut stopped) == AfterSurvey::Stop {
        return stop_code(loaded, opts, stopped, sink);
    }
    let set_id = loaded.set.recovery_set_id;
    let status = par2repair::repair_dir_set_with_donors(&loaded.dir, &set_id, &[]);
    finish(loaded, opts, &survey, status, sink)
}

/// The block after the fold: the byte count, the re-verify of what was
/// touched, and the verdict.
fn finish(
    loaded: &Loaded,
    opts: &Options,
    survey: &Survey,
    status: Result<RepairStatus, par2repair::RepairError>,
    sink: &mut Sink,
) -> u8 {
    // The reference's own reading of this line is the OUTPUT it
    // produced, not the syscalls it made: it reconstructs each damaged
    // member whole, so its figure is the member's length. Our engine
    // patches in place and physically writes only the blocks it
    // rebuilt, but the output produced is the same file, so the same
    // figure is the honest one to report here - a caller reads it as
    // "how much repaired data now exists", and reporting 1,368 where
    // the reference reports 24,576 would answer a question nobody asked.
    if status.is_ok() {
        let bytes: u64 = survey
            .targets
            .iter()
            .filter(|(_, t)| !matches!(t, Target::Found))
            .filter_map(|(n, _)| loaded.set.files.iter().find(|f| &f.name == n))
            .map(|f| f.length)
            .sum();
        sink.line(Level::Normal, &format!("Wrote {bytes} bytes to disk"));
    }
    sink.line(Level::Terse, "");
    sink.line(Level::Terse, "");
    sink.line(Level::Terse, "Verifying repaired files:");
    sink.line(Level::Terse, "");
    match status {
        Ok(RepairStatus::NoDamage) | Ok(RepairStatus::Repaired(_)) => {
            // What the ENGINE already proved, so the re-verify below can
            // stop re-deriving it. See [`engine_proved`].
            let proved = match &status {
                Ok(RepairStatus::Repaired(report)) => engine_proved(survey, report),
                _ => std::collections::HashSet::new(),
            };
            // The reference re-verifies and prints a Target line per
            // member a second time. The harness gathers the whole
            // `Target:` family at its first position, so these join the
            // ones printed above rather than appearing here - which is
            // exactly what the captured tables show.
            // Only the targets this repair TOUCHED are re-verified and
            // re-announced. Announcing every member would put a second
            // `Target:` line under a file that was never damaged, and the
            // captured `repair-damaged` row carries exactly three: the
            // damaged member before and after, and the clean one once.
            let repaired: Vec<String> = survey
                .targets
                .iter()
                .filter(|(_, t)| !matches!(t, Target::Found))
                .map(|(n, _)| n.clone())
                .collect();
            let mut all_found = true;
            for name in &repaired {
                if proved.contains(name) {
                    // The engine wrote this member and proved it by its
                    // whole-file FileDesc MD5 before reporting it. Reading
                    // it back to compute the same digest a second time is
                    // the THIRD whole-set pass over the payload, and it was
                    // 1.510 s of the 1,500-block leg's 2.810 s. The lines
                    // are the ones `verify_one` would have printed.
                    sink.line(Level::Normal, &format!("Opening: \"{name}\""));
                    sink.line(Level::Terse, &format!("Target: \"{name}\" - found."));
                } else if let Target::Found = verify::verify_one(loaded, opts, name, sink) {
                    sink.line(Level::Terse, &format!("Target: \"{name}\" - found."));
                } else {
                    all_found = false;
                }
            }
            sink.line(Level::Terse, "");
            // The re-verify is the POINT of this block, so it has to be
            // able to fail. It used to be consumed only to decide
            // whether to print a `Target: ... - found.` line: a member
            // that came back damaged or missing printed nothing, and
            // "Repair complete." plus exit 0 followed anyway - then `-p`
            // deleted the recovery volumes AND the `.1` backup of the
            // damaged original, which is every copy of the data.
            //
            // A script branching on the exit code is the caller that
            // gets hurt, and `EXIT_REPAIR_FAILED` is documented for
            // exactly this ("a repair ran and the result failed its own
            // verification") while never being returned for it.
            if !all_found {
                sink.err("Repair Failed.");
                return crate::EXIT_REPAIR_FAILED;
            }
            sink.line(Level::Terse, "Repair complete.");
            if opts.purge {
                verify::purge(loaded, sink);
            }
            crate::EXIT_SUCCESS
        }
        Ok(RepairStatus::Unrepairable { needed, have, .. }) => {
            sink.line(Level::Terse, "Repair is not possible.");
            sink.line(
                Level::Terse,
                &format!(
                    "You need {} more recovery blocks to be able to repair.",
                    needed.saturating_sub(have)
                ),
            );
            crate::EXIT_REPAIR_NOT_POSSIBLE
        }
        Err(e) => {
            sink.err(&format!("Repair failed: {e}"));
            crate::EXIT_REPAIR_FAILED
        }
    }
}

/// Members the engine has ALREADY proved, by the same whole-file
/// FileDesc MD5 the re-verify would compute.
///
/// `RepairStatus::Repaired`'s contract is "every patched file
/// re-verified by MD5", and it is the write path that enforces it: a
/// rebuild is hashed after it lands and only reaches
/// `RepairReport::files_patched` if it matched (`par2repair.rs`, the
/// self-prove, then `status::drop_unpublished`). A member in that list
/// has been proved; re-reading it here proves nothing new.
///
/// THIS MAY ONLY EVER SHRINK THE RE-VERIFY, NEVER WEAKEN IT. Anything
/// not named here still goes through [`verify::verify_one`], so the
/// guard `3496f44ab` added stands: a member that comes back damaged or
/// missing still fails the run rather than riding "Repair complete."
/// and exit 0 into a `-p` that deletes the recovery volumes AND the
/// `.1` backup of the damaged original. Two shapes rely on that
/// fallback rather than being special-cased:
///
/// * `RepairStatus::NoDamage`, which carries no report at all - reached
///   when the engine's shortfall arbitration finishes a digest the
///   verify pass cut short and a member the IFSC called damaged turns
///   out byte-exact.
/// * a member the engine did not touch, whatever the reason.
///
/// Names are matched only where the SET declares them once. A FileDesc
/// name is not unique - `FileRepair::name`'s own doc says so, two
/// descriptors may declare one name and are given distinct paths - and
/// `files_patched` is a list of names, so on a duplicate "some file
/// called this was proved" is not "this one was". Those fall back too.
fn engine_proved(
    survey: &Survey,
    report: &par2repair::RepairReport,
) -> std::collections::HashSet<String> {
    let mut seen: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for (name, _) in &survey.targets {
        *seen.entry(name.as_str()).or_default() += 1;
    }
    let mut patched: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for name in &report.files_patched {
        *patched.entry(name.as_str()).or_default() += 1;
    }
    report
        .files_patched
        .iter()
        .filter(|n| seen.get(n.as_str()) == Some(&1) && patched.get(n.as_str()) == Some(&1))
        .cloned()
        .collect()
}

/// par2cmdline keeps the damaged original beside the repaired file, as
/// `<name>.1` (then `.2`, and so on), and `-p` is what removes it again.
/// The captured `repair-damaged` row lists `rand.bin.1` in the working
/// directory afterwards, so a drop-in that quietly discarded the
/// original would be throwing away a file the user still has on the
/// reference.
///
/// COPY, not the reference's rename. The engine patches a damaged file
/// in place from the blocks that are still good, so renaming the
/// original aside would make every one of those blocks missing and turn
/// a two-block repair into a whole-file reconstruction. Peak disk is the
/// same either way - the reference also ends up holding both copies.
fn back_up_damaged(loaded: &verify::Loaded, survey: &verify::Survey) {
    for (name, t) in &survey.targets {
        if matches!(t, Target::Found | Target::Missing) {
            continue;
        }
        let src = loaded.data_path(name);
        for n in 1..=9u32 {
            let dst = loaded.data_path(&format!("{name}.{n}"));
            if !dst.exists() {
                let _ = std::fs::copy(&src, &dst);
                break;
            }
        }
    }
}

/// The `-v` lines between "Repair is required." and "Repair is
/// possible.".
fn print_plan(survey: &verify::Survey, sink: &mut Sink) {
    if !sink.shows(Level::Normal) {
        return;
    }
    let owed = survey.owed();
    sink.line(
        Level::Normal,
        &format!(
            "You have an excess of {} recovery blocks.",
            survey.recovery_blocks.saturating_sub(owed)
        ),
    );
    sink.line(
        Level::Normal,
        &format!("{owed} recovery blocks will be used to repair."),
    );
}

/// The `-v` solve trace.
///
/// The reference names its own kernels here (`Construction accel: NEON`,
/// `Inversion method: CLMul (SHA3)`), and parfast's engine selects
/// different ones - the AVX-512 GFNI fold, the NTT, the NEON blake2sp -
/// chosen at run time by a different rule. Printing the reference's
/// strings would be a false statement about which code ran, so these
/// lines carry the structure and not the reference's kernel names, and
/// the three `-v` rows are waived in
/// `tools/conformance/allow/par2.txt` with that reason.
fn print_solve_detail(sink: &mut Sink) {
    if !sink.shows(Level::Verbose) {
        return;
    }
    sink.line(Level::Verbose, "Computing Reed Solomon matrix.");
    sink.line(Level::Verbose, "Constructing: done.");
    sink.line(Level::Verbose, "Solving: done.");
    sink.line(Level::Verbose, "");
}
