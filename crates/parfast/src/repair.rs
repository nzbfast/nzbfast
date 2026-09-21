//! `r` / `repair`: verify, then hand the damage to the engine.
//!
//! Everything up to "Repair is possible." is [`crate::verify`]'s, line
//! for line, because par2cmdline prints the identical block on the way
//! in and a second copy of it here would be a second answer to the same
//! question. What is left is the repair itself, the re-verify, and the
//! `-p` purge.

use nzbkit::par2repair::{
    self, AfterSurvey, MemberSurvey, RepairStatus, ScanReport, SurveyObserver,
};

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
    /// A [`RepairWatch`] called the repair off: at the handshake, or
    /// through its control from inside the engine. Nothing is printed
    /// for it HERE: a host that refused already knows why, and the
    /// binary's Ctrl-C (`control.rs`, 12 Sep 2026) says "Cancelled" in
    /// `lib.rs`, after the meter's pending line is ended. No captured
    /// conformance row covers it - the reference has no cancel.
    Cancelled,
}

/// What a LONG-LIVED caller is shown before the fold, the one point at
/// which it may call the repair off cleanly, and what it hears from
/// inside the fold.
///
/// [`before_fold`](Self::before_fold) is the engine's own
/// [`AfterSurvey`] handshake: the verify pass is done, the packet walk
/// is done, and NOTHING has been written, so a refusal there leaves the
/// directory exactly as it was, and this crate spells it
/// `Stopped::Cancelled` and exits "repair possible".
///
/// [`control`](Self::control) is the SECOND door, since 12 Sep 2026
/// (plan 4.2 item 1): progress out of the hashing, fold, solve and
/// write loops, a cancel those loops poll, and a pause they park on.
/// A cancel raised through it does NOT come back as `Ok(None)` - the
/// engine unwinds with `RepairError::Cancelled` and this crate turns
/// that into the same "repair possible" code, because nothing about the
/// set is wrong. What a cancelled repair leaves on disk is stated on
/// that variant.
///
/// Both are defaulted, so the in-process watch - which watches nothing
/// and refuses nothing - is still `impl RepairWatch for ()`. The binary
/// passes `control::CliWatch`: Ctrl-C through the gate, progress to the
/// terminal (12 Sep 2026).
pub trait RepairWatch {
    /// The survey the repair is about to act on. `false` calls it off.
    fn before_fold(&self, _survey: &Survey) -> bool {
        true
    }
    /// Progress out, cancel in, pause parked. Asked ONCE, before the
    /// verify pass. See `nzbkit::par2repair::control`.
    fn control(&self) -> par2repair::RepairControl {
        par2repair::RepairControl::default()
    }
}

/// The watch the CLI passes: it watches nothing and refuses nothing.
impl RepairWatch for () {}

/// `r` / `repair`.
pub fn run(opts: &Options, sink: &mut Sink) -> u8 {
    run_watched(opts, sink, &())
}

/// [`run`] that shows a caller the survey before the fold and lets it
/// call the repair off. See [`RepairWatch`].
pub fn run_watched(opts: &Options, sink: &mut Sink, watch: &dyn RepairWatch) -> u8 {
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
    // What `back_up_damaged` made, kept outside the scope because the
    // batch itself is handed to the engine thread and joined there,
    // while `-p` needs the list after the fold. Provenance is the ONLY
    // thing that makes a numbered file safe to delete - see
    // `verify::purge`.
    let mut created: Vec<std::path::PathBuf> = Vec::new();

    // ONE PASS OVER THE PACKETS, AND THE ORDER IS HELD BY THE CHANNELS.
    //
    // The reference prints a `Loading` / `Loaded N new packets` pair per
    // file, every one of them BEFORE the first `Opening:` line, and the
    // conformance table pins that order. Until 10 Sep 2026 `verify::load`
    // earned those lines by reading and MD5-scanning every packet in the
    // set on this thread while the engine's catalog hashed the very same
    // bytes on the worker: 26 ms twice on the published corpus's 108 MB,
    // but 2 GiB twice on a 2 GiB set with 100% parity - and once the
    // engine's scan overlapped its verify pass, that duplicate was the
    // whole critical path of the CLI-versus-driver gap (TODO 334).
    //
    // Now the engine does the one pass and REPORTS it: the observer's
    // `packets_scanned` hands over every validated packet identity as
    // soon as the scan completes, the main thread prints the `Loading`
    // lines from that (`verify::load_scanned`, which reads only the
    // critical packets for itself), then takes the survey and prints the
    // rest. `NZBFAST_PARFAST_LOAD=whole` keeps the old load reachable as
    // the A/B arm, and an engine that fails before its scan completes
    // drops the report channel, which sends the load down that same old
    // path so a failing run prints exactly what it always printed.
    //
    // Nothing races on the filesystem: until the observer answers
    // `Repair` the engine only READS, and the fold - the only writer -
    // starts after the main thread has finished with the directory.
    // The engine's observer. `after_survey` is the channel handshake
    // described above; `before_write` is where the backup copies
    // (`back_up_damaged`, started by `announce` on the main thread and
    // handed over with the action) are waited for - they read the
    // damaged originals, the fold reads them too, and the first write to
    // any of them is what must not overtake the copy. Whatever the
    // engine never reached (a failure before the patch) is joined by the
    // main thread after the scope, so a backup is always whole or absent
    // by the time this command exits.
    struct Observer {
        tx_report: std::sync::mpsc::Sender<ScanReport>,
        tx_members: std::sync::mpsc::Sender<Vec<MemberSurvey>>,
        rx_action: std::sync::mpsc::Receiver<(AfterSurvey, BackupBatch)>,
        /// The extra-file scan's result, and the main thread's
        /// acknowledgement that it has PRINTED it. Both halves are
        /// needed: the printing thread must get the lines out before
        /// the fold's meter starts writing to the same terminal, and
        /// only a blocking handshake can promise that.
        tx_extra: std::sync::mpsc::Sender<Vec<par2repair::ExtraFileMatch>>,
        rx_extra_ack: std::sync::mpsc::Receiver<()>,
        /// THE THIRD HANDSHAKE, and it exists for the same reason the
        /// extra-file one does: a damaged original this run could not
        /// back up has to be SAID before the fold's meter starts
        /// writing to the same terminal, and only a blocking
        /// acknowledgement can promise that. It carries the failures
        /// out of `before_write` to the main thread, which owns the
        /// sink. An empty vector is still sent, so the main thread's
        /// `recv` has exactly two outcomes: the engine reached its
        /// first write, or it never did and the sender dropped.
        tx_backup_failed: std::sync::mpsc::Sender<Vec<BackupFailure>>,
        rx_backup_ack: std::sync::mpsc::Receiver<()>,
        pending: BackupBatch,
        /// The watch's, taken once on the main thread before the engine
        /// thread is spawned - the trait's contract is that it is the
        /// same value every time, and this observer crosses a thread.
        control: par2repair::RepairControl,
    }
    impl SurveyObserver for Observer {
        fn packets_scanned(&mut self, report: &ScanReport) {
            // Unbounded channel: this never blocks the repair thread,
            // and a main thread that is not listening (the A/B arm, or
            // one that already failed) simply never reads it.
            let _ = self.tx_report.send(report.clone());
        }
        fn after_survey(&mut self, members: &[MemberSurvey]) -> AfterSurvey {
            // A dead receiver means the main thread gave up before it
            // could decide; stopping is the safe answer, and it leaves
            // the directory untouched.
            if self.tx_members.send(members.to_vec()).is_err() {
                return AfterSurvey::Stop;
            }
            match self.rx_action.recv() {
                Ok((action, backups)) => {
                    self.pending = backups;
                    action
                }
                Err(_) => AfterSurvey::Stop,
            }
        }
        fn extra_files_scanned(&mut self, matches: &[par2repair::ExtraFileMatch]) {
            // A dead receiver is a main thread that is no longer
            // printing - it refused, or it failed. Nothing to wait for.
            if self.tx_extra.send(matches.to_vec()).is_err() {
                return;
            }
            let _ = self.rx_extra_ack.recv();
        }
        fn before_write(&mut self) {
            let failed = join_backups(std::mem::take(&mut self.pending));
            // Hand them over and WAIT. Not a fire-and-forget: the value
            // of the line is that it lands while the damaged original
            // is still whole, and the first write follows this call.
            // A dead receiver is a main thread that is no longer
            // printing, and then there is nobody to wait for.
            if self.tx_backup_failed.send(failed).is_ok() {
                let _ = self.rx_backup_ack.recv();
            }
        }
        fn control(&self) -> par2repair::RepairControl {
            self.control.clone()
        }
        fn adoption_exclusions(&self) -> &[std::path::PathBuf] {
            // ON by default since 5 Sep 2026 (the review's lead): a backup this
            // repair just made is a copy of a damaged file and can carry no
            // block the original lacks, so scanning it as a donor is pure
            // cost (0.846 -> 0.680 s on the review's 50 MiB-backup fixture; flat
            // on rigs whose backups are not candidates). Older numbered
            // backups stay donors. `NZBFAST_SKIP_NEW_BACKUP_SCAN=0` scans
            // them again, the A/B arm.
            if std::env::var_os("NZBFAST_SKIP_NEW_BACKUP_SCAN").as_deref()
                != Some(std::ffi::OsStr::new("0"))
            {
                &self.pending.created
            } else {
                &[]
            }
        }
    }
    let (engine, leftover) = std::thread::scope(|scope| {
        let (tx_report, rx_report) = std::sync::mpsc::channel::<ScanReport>();
        let (tx_members, rx_members) = std::sync::mpsc::channel::<Vec<MemberSurvey>>();
        let (tx_action, rx_action) = std::sync::mpsc::channel::<(AfterSurvey, BackupBatch)>();
        let (tx_extra, rx_extra) = std::sync::mpsc::channel::<Vec<par2repair::ExtraFileMatch>>();
        let (tx_extra_ack, rx_extra_ack) = std::sync::mpsc::channel::<()>();
        let (tx_backup_failed, rx_backup_failed) = std::sync::mpsc::channel::<Vec<BackupFailure>>();
        let (tx_backup_ack, rx_backup_ack) = std::sync::mpsc::channel::<()>();
        let edir = dir.clone();
        // The bare arguments AFTER the recovery-set name. par2cmdline
        // takes them as extra data files / donor directories to scan,
        // and the engine's adoption pass has taken a donor list since
        // X6-02 - but both entries here passed `&[]`, so
        // `parfast r set.par2 /backup` walked the set's own directory
        // and nothing else while the reference adopted from `/backup`
        // and repaired. The engine screens every candidate by checksum,
        // so handing it a path that holds nothing useful costs a walk
        // and changes no outcome.
        let donors: Vec<std::path::PathBuf> = opts.files.clone();
        let control = watch.control();
        // For the load fallback below: a cancel during the engine's scan
        // must not be answered with a whole-read load of the set.
        let cancelled_early = control.clone();
        let worker = scope.spawn(move || {
            let mut observe = Observer {
                tx_report,
                tx_members,
                rx_action,
                tx_extra,
                rx_extra_ack,
                tx_backup_failed,
                rx_backup_ack,
                pending: BackupBatch::default(),
                control,
            };
            let status = par2repair::repair_dir_set_surveyed_as(
                &edir,
                &want,
                &donors,
                &mut observe,
                par2repair::RetentionCaller::new(par2repair::CallerSite::ParfastRepair),
            );
            (status, observe.pending)
        });

        let mut action = AfterSurvey::Stop;
        let mut backups = BackupBatch::default();
        // Is the announcement's tail waiting on the engine's extra-file
        // answer? See the deferral comment in `announce`.
        let mut deferred_tail = false;
        // The engine's scan report, or the old whole-read load when there
        // is none coming: the A/B arm, or an engine that failed before its
        // scan completed (the sender dropped with the worker's observer).
        let loaded_res = if load_from_scan() {
            match rx_report.recv() {
                Ok(report) => verify::load_scanned(opts, sink, &report),
                // The engine unwound before its scan reported, and if
                // that was a cancel there is nothing to load for: the
                // exit code is the handshake refusal's, and the fold
                // never started.
                Err(_) if cancelled_early.cancelled() => Err(crate::EXIT_REPAIR_POSSIBLE),
                Err(_) => verify::load(opts, sink),
            }
        } else {
            verify::load(opts, sink)
        };
        match loaded_res {
            Err(code) => early = Some(code),
            Ok(mut loaded) => {
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
                            Some(mut survey) => {
                                // A quiet load deferred the recovery
                                // packets; the damaged verdicts below read
                                // the count (see `verify::load`).
                                if survey.damaged() {
                                    survey.recovery_blocks = verify::ensure_recovery(&mut loaded);
                                }
                                (action, backups, deferred_tail) =
                                    announce(&loaded, opts, &survey, sink, &mut stopped, true);
                                // The caller's refusal, after `announce`
                                // so the survey it sees is the one the
                                // reference would have printed, and
                                // before the action is sent so the
                                // engine never starts the fold.
                                if !watch.before_fold(&survey) {
                                    action = AfterSurvey::Stop;
                                    backups = BackupBatch::default();
                                    stopped = Some(Stopped::Cancelled);
                                }
                                created = backups.created.clone();
                                surveyed = Some(survey);
                            }
                            None => stopped = Some(Stopped::Unmatched),
                        }
                    }
                }
                loaded_slot = Some(loaded);
            }
        }
        let _ = tx_action.send((action, backups));
        // THE SECOND HANDSHAKE, and it is answered on every run rather
        // than only on a deferred one: the engine BLOCKS on the
        // acknowledgement, so a main thread that took the answer and
        // said nothing would park the repair. A `recv` error is the
        // engine having finished or failed before the adoption pass -
        // our own `Stop`, a clean set, a cancel - and then there is
        // nobody to acknowledge and nothing to print but the tail we
        // were holding.
        let scanned = rx_extra.recv();
        if deferred_tail {
            let matches: &[par2repair::ExtraFileMatch] = scanned.as_deref().unwrap_or(&[]);
            let (Some(loaded), Some(survey)) = (loaded_slot.as_ref(), surveyed.as_ref()) else {
                // Unreachable: `deferred_tail` is only ever set by the
                // `announce` call above, which runs with both in hand
                // and fills both slots in the same arm.
                unreachable!("a deferred tail always has the load and the survey behind it")
            };
            let mut ignored = None;
            let verdict = announce_tail(loaded, opts, survey, matches, sink, &mut ignored);
            debug_assert!(
                matches!(verdict, AfterSurvey::Repair) && ignored.is_none(),
                "the tail is only deferred where its verdict cannot be a stop"
            );
        }
        if scanned.is_ok() {
            let _ = tx_extra_ack.send(());
        }
        // THE THIRD HANDSHAKE, answered here because this thread owns
        // the sink. A `recv` error is the engine having stopped, failed
        // or found nothing to repair before it reached its first write,
        // and then there is no backup verdict to print and nobody
        // waiting on one. Whatever comes back is printed BEFORE the ack,
        // so the engine is still parked and the fold's meter has not
        // started.
        if let Ok(failed) = rx_backup_failed.recv() {
            report_backup_failures(&failed, sink);
            let _ = tx_backup_ack.send(());
        }
        worker.join().expect("engine survey thread panicked")
    });
    // Non-empty only where `before_write` never ran, so the fold wrote
    // nothing and the damaged original is still whole. Reported anyway:
    // the copy failing says the directory is not writable, which is
    // worth knowing whichever way the run then went.
    report_backup_failures(&join_backups(leftover), sink);

    if let Some(code) = early {
        return code;
    }
    let loaded = loaded_slot.expect("load either failed into `early` or filled this");
    // A CANCEL RAISED THROUGH THE CONTROL comes back as an ERROR and not
    // as `Ok(None)`, because the engine unwinds from wherever it was -
    // the hashing loop, the fold, the solve, the patch - rather than
    // answering the survey handshake. It is not a failed repair and must
    // not print like one: nothing is wrong with the set, and "repair
    // possible" is what `Stopped::Cancelled` already says for the
    // refusal at the handshake. BEFORE the re-survey: a cancel that
    // landed in the engine's verify pass left the handshake unanswered,
    // which reads as `Unmatched` below, and answering a Ctrl-C with a
    // second full verify on this thread is the opposite of a cancel.
    if matches!(engine, Err(par2repair::RepairError::Cancelled)) {
        return stop_code(
            &loaded,
            opts,
            Some(Stopped::Cancelled),
            surveyed.as_ref(),
            sink,
        );
    }
    if let Some(Stopped::Unmatched) = stopped {
        return run_resurveying(&loaded, opts, sink);
    }
    let status = match engine {
        // `Ok(None)` is our own `Stop` coming back: `announce` printed
        // the block already, so only the exit code is left. Anything
        // else and the engine folded.
        Ok(None) => return stop_code(&loaded, opts, stopped, surveyed.as_ref(), sink),
        Ok(Some(st)) => Ok(st),
        Err(e) => Err(e),
    };
    let Some(survey) = surveyed else {
        // The engine folded BEFORE it reached the survey observer, so
        // there is no survey for `finish` to report against and its
        // error is the whole verdict. Reachable, not defensive: the
        // engine refuses a set whose Main packet names a file id with
        // no FileDesc packet (`par2repair`'s pre-verify walk), while
        // `verify::load` DROPS that id and hands back an Ok set - so
        // ordinary index damage lands here. `stop_code` degrades the
        // same way one arm above rather than panicking; this used to
        // `expect`, which aborted the process with an exit code
        // outside the dialect this crate's whole interface is.
        // The SAME line as `finish`'s `Err` arm, through the same
        // helper, on purpose: this is a failed repair too, it returns
        // the same exit code, and SAB reads the stream and not the code.
        // Leaving one of the two arms unmapped would give a caller a
        // reason for some repair failures and silence for others, which
        // is the half-mapped dialect `repair_failed_line` exists to
        // close.
        if let Err(e) = &status {
            sink.err(&repair_failed_line(e));
        }
        return crate::EXIT_REPAIR_FAILED;
    };
    finish(&loaded, opts, &survey, status, &created, sink)
}

/// Does the repair's load print from the engine's scan report
/// (`verify::load_scanned`) rather than reading and hashing the set for
/// itself? ON unless the whole-read arm is forced - the two loads print
/// the same bytes, and that is the property the arm exists to keep
/// checkable. Verify's own seeking load answers the same switch, from
/// the same predicate ([`verify::whole_load_forced`]).
fn load_from_scan() -> bool {
    !verify::whole_load_forced()
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
    defer: bool,
) -> (AfterSurvey, BackupBatch, bool) {
    verify::print_targets(survey, sink);
    if !survey.damaged() {
        sink.line(Level::Terse, "");
        sink.line(
            Level::Terse,
            "All files are correct, repair is not required.",
        );
        *stopped = Some(Stopped::Clean);
        return (AfterSurvey::Stop, BackupBatch::default(), false);
    }
    sink.line(Level::Terse, "");
    // HOLD THE REST BACK WHEN THE ENGINE IS ABOUT TO SAY WHICH EXTRA
    // FILES FED WHICH MEMBER. The reference scans the extra files HERE,
    // between the `Target:` table and "Repair is required.", and prints
    // a result line per donor under the section header; our adoption
    // pass runs inside the engine, after this observer has answered. So
    // the section and everything after it waits for
    // `SurveyObserver::extra_files_scanned`, and the caller prints it
    // from there - which is also the reference's own TIMELINE, the scan
    // being what the pause between the table and the verdict is.
    //
    // It matters because SABnzbd stops reading rename announcements at
    // "Repair is required." (`newsunpack.py`'s `verified` flag): a
    // donor named after that line is a donor it never hears about, and
    // then it keeps the obfuscated names, ships the consumed originals
    // to the completed folder as junk, and reads a joined rar as a
    // phantom set. See `research/SAB-PARFAST-METER-DROPIN-2026-09-17.md`
    // addendum A.
    //
    // Only where a deferred verdict is certain to be `Repair`: `-O`
    // stops here with its own block, and the "Repair is not possible."
    // arm below needs the candidate list to be EMPTY, which is the one
    // case with nothing to wait for anyway.
    if defer && !opts.rename_only && !extra_candidates(loaded, survey).is_empty() {
        return (AfterSurvey::Repair, back_up_damaged(loaded, survey), true);
    }
    let action = announce_tail(loaded, opts, survey, &[], sink, stopped);
    let backups = match action {
        AfterSurvey::Repair => back_up_damaged(loaded, survey),
        AfterSurvey::Stop => BackupBatch::default(),
    };
    (action, backups, false)
}

/// Everything `announce` prints from the extra-file scan onwards, and
/// the verdict it reaches - split out because on the surveying route it
/// is printed LATER, once the engine has said which extra files it
/// adopted from. See the deferral comment in [`announce`].
///
/// `matches` is empty on every route that has no engine answer, and an
/// empty list prints what this printed before the deferral existed.
fn announce_tail(
    loaded: &Loaded,
    opts: &Options,
    survey: &Survey,
    matches: &[par2repair::ExtraFileMatch],
    sink: &mut Sink,
    stopped: &mut Option<Stopped>,
) -> AfterSurvey {
    verify::print_extra_scan(loaded, survey, matches, sink);
    sink.line(Level::Terse, "Repair is required.");
    verify::print_damage_detail(survey, matches, sink);
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
    // it stops here rather than solving. The renames themselves are
    // done by `stop_code`, after the engine has let go of the
    // directory - the same reason `-p` is deferred to there.
    if opts.rename_only {
        *stopped = Some(Stopped::RenameOnly);
        return AfterSurvey::Stop;
    }

    sink.line(Level::Terse, "");
    print_solve_detail(sink);
    AfterSurvey::Repair
}

/// The exit code for a run that stopped before the fold, plus the one
/// filesystem action left over: `-p` on a clean set. Held back until
/// here rather than done inside the observer, which runs while the
/// engine still holds the directory's packet catalog.
fn stop_code(
    loaded: &Loaded,
    opts: &Options,
    stopped: Option<Stopped>,
    survey: Option<&Survey>,
    sink: &mut Sink,
) -> u8 {
    match stopped {
        Some(Stopped::Clean) => {
            // Clean: nothing was damaged, so `back_up_damaged` never
            // ran and this run created no backup to remove.
            if opts.purge {
                verify::purge(loaded, &[], sink);
            }
            crate::EXIT_SUCCESS
        }
        Some(Stopped::NotPossible) => crate::EXIT_REPAIR_NOT_POSSIBLE,
        Some(Stopped::RenameOnly) => match survey {
            Some(s) => rename_only(loaded, s, sink),
            // Unreachable: `announce` sets `RenameOnly` from a survey it
            // is holding, and both call sites pass that survey on.
            None => crate::EXIT_REPAIR_POSSIBLE,
        },
        // A caller's own refusal. Nothing was written, so the set is
        // exactly as repairable as it was; "repair possible" is the
        // honest code, and the caller that refused knows why it did.
        Some(Stopped::Cancelled) => crate::EXIT_REPAIR_POSSIBLE,
        // Unreachable: the engine stops only when the observer says so,
        // and every `Stop` above records why first.
        Some(Stopped::Unmatched) | None => crate::EXIT_REPAIR_FAILED,
    }
}

/// `-O`: rename every perfectly-matching file that is sitting under the
/// wrong name, and reconstruct nothing.
///
/// This used to be a printed verdict and no filesystem action at all:
/// `announce` reached "Repair is possible." (the extra-file arm keeps
/// that gate open), then stopped and exited 1 with every file exactly
/// where it was. The help calls `-O` "useful for quickly fixing renamed
/// files", so advertising it while renaming nothing was the whole
/// defect - a complete payload at `a1b2c3d4` beside a set whose
/// FileDesc says `movie.mkv` is the ordinary obfuscated-post shape, and
/// the reference renames it and exits 0.
///
/// Matching is by the FileDesc's own whole-file MD5, which is what
/// "perfect match" means here: `verify_file_md5_path` returns false on a
/// length mismatch before it reads a byte, so the walk costs one hash
/// over the candidates that are the right size and nothing over the
/// rest. A candidate is consumed by the first target it matches, and a
/// target whose name is already occupied on disk is left alone - this
/// command may not overwrite.
///
/// Run AFTER the engine has stopped, never from inside the observer:
/// the engine still holds the directory's packet catalog open there,
/// which is the same reason the `-p` purge waits until here.
fn rename_only(loaded: &Loaded, survey: &Survey, sink: &mut Sink) -> u8 {
    let mut candidates = extra_candidates(loaded, survey);
    let mut renamed = 0usize;
    for (name, target) in &survey.targets {
        if !matches!(target, Target::Missing) {
            continue;
        }
        let Some(file) = loaded.set.files.iter().find(|f| &f.name == name) else {
            continue;
        };
        let dest = loaded.data_path(name);
        if dest.exists() {
            continue;
        }
        let Some(pos) = candidates
            .iter()
            .position(|c| nzbkit::par2::verify_file_md5_path(c, file).unwrap_or(false))
        else {
            continue;
        };
        let src = candidates.remove(pos);
        let from_name = src
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        match std::fs::rename(&src, &dest) {
            Ok(()) => {
                renamed += 1;
                sink.line(
                    Level::Terse,
                    &format!("Renamed \"{from_name}\" to \"{name}\"."),
                );
            }
            // THE REFERENCE'S OWN SENTENCE, unquoted and without the
            // errno, because a caller MATCHES it: SABnzbd fails the job
            // with any line containing " cannot be renamed to " as the
            // reason it shows (`newsunpack.py`), and par2cmdline's
            // `DiskFile::Rename` prints exactly
            // `<from> cannot be renamed to <to>` (diskfile.cpp, v1.3.0).
            // "Could not rename to ..." reached no branch of it and was
            // a second spelling of a line the dialect already has. The
            // errno goes with it, which is the price of the dialect -
            // the reference does not print one either.
            Err(_) => sink.err(&format!("{from_name} cannot be renamed to {name}")),
        }
    }
    // Everything the set was missing is now at its own name and nothing
    // was damaged, so the set is whole without a single recovery block -
    // which is the outcome `-O` exists to reach.
    let outstanding = survey
        .targets
        .iter()
        .filter(|(_, t)| !matches!(t, Target::Found))
        .count();
    if renamed > 0 && renamed == outstanding {
        sink.line(Level::Terse, "");
        sink.line(Level::Terse, "Repair complete.");
        crate::EXIT_SUCCESS
    } else {
        crate::EXIT_REPAIR_POSSIBLE
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
    // No observer on this entry point, so nothing can deliver an
    // extra-file answer and the tail prints in place.
    let (action, backups, _) = announce(loaded, opts, &survey, sink, &mut stopped, false);
    if action == AfterSurvey::Stop {
        return stop_code(loaded, opts, stopped, Some(&survey), sink);
    }
    // The batch is consumed by the join; `-p` still needs to know what
    // it made, so the destinations are taken off it first.
    let created = backups.created.clone();
    // No `before_write` on this entry point, so the copies finish here,
    // in front of the fold, as they always did on this path - which
    // makes this the one site where the warning is naturally in front
    // of the first write with no handshake to arrange.
    report_backup_failures(&join_backups(backups), sink);
    let set_id = loaded.set.recovery_set_id;
    let status = par2repair::repair_dir_set_with_donors_as(
        &loaded.dir,
        &set_id,
        &opts.files,
        par2repair::RetentionCaller::new(par2repair::CallerSite::ParfastResurvey),
    );
    finish(loaded, opts, &survey, status, &created, sink)
}

/// How many bytes the run may say it wrote, and whether to say anything
/// at all - the arithmetic behind [`finish`]'s "Wrote N bytes to disk",
/// split out because the shortfall arm is the half worth a test and the
/// rest of `finish` needs a directory and an engine run to reach.
///
/// `damaged` is every target the survey did not find, with the length
/// its FileDesc declares. `published` is `None` on a verdict that
/// rebuilt the whole set (every damaged target is now on disk), and on a
/// shortfall it is the names the engine actually published - so a
/// shortfall that published nothing returns `None` and prints no line,
/// rather than claiming the payload.
///
/// `renamed` is `RepairReport::files_renamed`: a member whose complete
/// bytes were already on disk under a hash name is landed by a
/// directory operation, so none of its length was written. Counting it
/// is what made the ordinary obfuscated post read "Wrote 600000 bytes
/// to disk" where the reference says 300000, and it is subtracted here
/// rather than at the call site because this is the function the test
/// can reach.
fn wrote_bytes(
    damaged: &[(String, u64)],
    published: Option<&[String]>,
    renamed: &[String],
) -> Option<u64> {
    let bytes: u64 = damaged
        .iter()
        .filter(|(n, _)| published.is_none_or(|p| p.contains(n)))
        .filter(|(n, _)| !renamed.contains(n))
        .map(|(_, len)| len)
        .sum();
    if published.is_some() && bytes == 0 {
        return None;
    }
    // The reference prints this line from INSIDE its write, so a repair
    // that entered no write at all prints nothing. Measured 17 Sep 2026
    // on a two-member set with both members whole-matched under hash
    // names: par2cmdline goes straight from "Repair is possible." to
    // "Repair complete.". The degenerate `damaged.is_empty()` zero below
    // is a different case and is unchanged - nothing was renamed there
    // either.
    if bytes == 0 && !renamed.is_empty() {
        return None;
    }
    Some(bytes)
}

/// The lines that say how much of a repair was COPIED rather than
/// computed, or nothing when none of it was.
///
/// The plan line above ("N recovery blocks will be used to repair") is
/// printed from the survey BEFORE the engine runs, so it counts every
/// missing block as a block to reconstruct. The engine then finds any
/// missing block whose bytes already sit intact somewhere on disk - in a
/// donor, an extra file, or another member of the set itself
/// (`par2repair::adopt::harvest_in_set`) - and copies those instead of
/// solving for them. Until 10 Sep 2026 nothing told the user. A field
/// fixture whose ten members were near-copies of one another produced
/// "350 recovery blocks will be used" and then adopted 349 of them, and
/// the resulting 8 s "repair" was benchmarked as a 1,399-block decode for
/// a whole round; par2j prints `Duplicate slice count` / `Input File
/// Slice lost` in the same position and was readable at a glance. This
/// is that line. Normal level, like the plan line it corrects, so `-q`
/// silences both together.
fn adoption_lines(adopted: usize, rebuilt: usize, adopted_from: &[String]) -> Vec<String> {
    if adopted == 0 {
        return Vec::new();
    }
    let mut lines = vec![format!(
        "{adopted} block(s) recovered from duplicate slices already on disk; {rebuilt} rebuilt from recovery data."
    )];
    if !adopted_from.is_empty() {
        const SHOWN: usize = 5;
        let mut from = adopted_from[..adopted_from.len().min(SHOWN)].join(", ");
        if adopted_from.len() > SHOWN {
            from.push_str(&format!(" and {} more", adopted_from.len() - SHOWN));
        }
        lines.push(format!("Duplicate slices found in: {from}"));
    }
    lines
}

/// The block after the fold: the byte count, the re-verify of what was
/// touched, and the verdict.
fn finish(
    loaded: &Loaded,
    opts: &Options,
    survey: &Survey,
    status: Result<RepairStatus, par2repair::RepairError>,
    // The backup copies this run made, for `-p`. Provenance, not a name
    // shape - see `verify::purge`.
    created: &[std::path::PathBuf],
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
    //
    // A SHORTFALL is the case that rule must NOT be applied to, and was
    // until 7 Sep 2026. `RepairStatus::Unrepairable` is an `Ok`, and it
    // publishes only the members whose own blocks were all accounted
    // for without a Reed-Solomon pass (`partial`) - on the everyday
    // shortfall, none at all. Summing every non-`Found` target there
    // announced a whole-payload write that never happened: a 2 GiB
    // single-member set whose recovery data came up short printed
    // "Wrote 2147483648 bytes to disk" into a directory that still held
    // no data file at all, and a 10 GiB one claimed 10 GB. That reads as
    // a repair which wrote the WRONG bytes rather than one which wrote
    // none, and a full day was spent looking for the former.
    let published: Option<&[String]> = match &status {
        Ok(RepairStatus::Unrepairable { partial, .. }) => Some(&partial.files_patched),
        _ => None,
    };
    if status.is_ok() {
        let damaged: Vec<(String, u64)> = survey
            .targets
            .iter()
            .filter(|(_, t)| !matches!(t, Target::Found))
            .filter_map(|(n, _)| {
                loaded
                    .set
                    .files
                    .iter()
                    .find(|f| &f.name == n)
                    .map(|f| (n.clone(), f.length))
            })
            .collect();
        // A renamed member wrote nothing; `RepairReport::files_renamed`
        // is the only surface that says so, and it exists only on the
        // `Repaired` verdict (a shortfall never renames).
        let renamed: &[String] = match &status {
            Ok(RepairStatus::Repaired(r)) => &r.files_renamed,
            _ => &[],
        };
        if let Some(bytes) = wrote_bytes(&damaged, published, renamed) {
            sink.line(Level::Normal, &format!("Wrote {bytes} bytes to disk"));
        }
        if let Ok(RepairStatus::Repaired(report)) = &status {
            for l in adoption_lines(
                report.blocks_adopted,
                report.blocks_rebuilt,
                &report.adopted_from,
            ) {
                sink.line(Level::Normal, &l);
            }
        }
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
                verify::purge(loaded, created, sink);
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
            sink.err(&repair_failed_line(&e));
            crate::EXIT_REPAIR_FAILED
        }
    }
}

/// The line a failed repair prints, and A DELIBERATE DIVERGENCE FROM
/// par2cmdline 1.2.0, taken 20 Sep 2026 as a contract decision rather
/// than by accident.
///
/// The reference prints no `Repair Failed.` sentence at 1.2.0 at all: on
/// an I/O failure mid-repair it prints its own `<x> cannot be renamed to
/// <y>` or `Could not write ...` line and exits 6 (measured 18 Sep 2026,
/// three ways, in the READ-ONLY OUTPUT DIRECTORY block of
/// `tools/sab-parser-gate.py`'s header). `Repair Failed.` is the
/// 0.8.1-era sentence SABnzbd's branch was written for, and SAB is the
/// caller that reads this stream.
///
/// WHAT IT BUYS. SAB does not look at the exit code. Every verdict it
/// reaches comes out of a chain of `startswith` tests in
/// `newsunpack.py::par2cmdline_verify`, and the arm for an otherwise
/// unclassified failure is `line.startswith("Repair Failed.")`, whose
/// body is `msg = T("Repairing failed, %s") % line`. So SAB shows THE
/// LINE THAT TOOK THE BRANCH, which is why the reason is on this line
/// and not on a second one: `Repair failed: Permission denied (os error
/// 13)` - lower-case `f`, a colon - matched that branch, and every other
/// branch of that chain, NOT AT ALL, so a permission failure, a
/// read-only volume and every other `io::Error` failed the job with no
/// reason for SAB to show the user. A second line carrying the reason
/// would not help: the branch fires on the FIRST line and SAB
/// interpolates that one.
///
/// WHY THIS IS NOT A NEW KIND OF EDIT. [`failure_reason`] already takes
/// exactly this trade for one error kind - it rewrites `StorageFull`
/// into the reference's WINDOWS sentence so the line reaches SAB's
/// `disk-full` branch on a Mac, where the reference itself cannot reach
/// it. This widens that accepted shape from one `io::ErrorKind` to the
/// whole arm. The two compose in the right order and that is checked,
/// not assumed: SAB tests `"There is not enough space on the disk" in
/// line` EARLIER in the chain than `startswith("Repair Failed.")`, so a
/// full disk still reaches `disk-full` and still reads "Repairing
/// failed, Disk full" rather than the generic verdict.
///
/// WHAT IT COSTS. A script that greps par2cmdline's exact bytes for a
/// failed repair sees a sentence the reference does not print. Nothing
/// in `tools/conformance/`'s matrix reaches this arm - no row induces an
/// I/O failure mid-repair, so no expected table moves - and the
/// divergence is recorded in `tools/conformance/README.md` beside the
/// Creator packet's so the oracle records it rather than a later lane
/// reading it as a defect.
fn repair_failed_line(e: &par2repair::RepairError) -> String {
    format!("Repair Failed. {}", failure_reason(e))
}

/// What a failed repair says went wrong, with ONE substitution: a full
/// disk says so in the reference's words.
///
/// SABnzbd has a "Repairing failed, Disk full" verdict and reaches it on
/// any line containing "There is not enough space on the disk"
/// (`newsunpack.py`). That string is par2cmdline's WINDOWS spelling -
/// `DiskFile::ErrorMessage` is `FormatMessage`, while the POSIX arm of
/// the same `Could not write ...` line prints `strerror`, which is "No
/// space left on device" and matches nothing. So the branch is one the
/// reference itself cannot reach on a Mac or a Linux box, and a full
/// disk reads there as an unexplained repair failure.
///
/// We print the Windows spelling on every platform, deliberately: the
/// message is TRUE wherever the error kind is `StorageFull`, it is the
/// dialect a par2 caller parses, and "the disk is full" is the one
/// repair failure a user can actually do something about. It is NOT
/// dressed up as the reference's whole `Could not write N bytes to X at
/// offset Y:` line - the byte count, the name and the offset are the
/// engine's and do not reach here, and inventing them would be three
/// false facts bought for no branch. It also keeps the line clear of
/// `Could not write ... at offset 0:`, which is an EARLIER arm of SAB's
/// chain (the joinables special case) and would swallow it.
fn failure_reason(e: &par2repair::RepairError) -> String {
    match e {
        par2repair::RepairError::Io(io) if io.kind() == std::io::ErrorKind::StorageFull => {
            "There is not enough space on the disk.".to_string()
        }
        other => other.to_string(),
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
///
/// BESIDE the fold, not in front of it. The copies only read the
/// damaged originals, which is all the fold does with them too, so they
/// run on their own threads and the engine waits for them in
/// [`SurveyObserver::before_write`], immediately before the first byte
/// is written to any target. Measured on the 1 GiB / 21-member corpus
/// on an i5-10600KF desktop (Windows 11, where `std::fs::copy` really
/// moves the bytes - macOS clones and pays nothing): the serial copy was
/// 0.06 s of the 3-block leg, 0.19 s of the 101-block leg and 0.45 s of
/// the 1,500-block leg, all of it in front of a fold that takes 0.25 to
/// 6 s.
///
/// **"BESIDE" IS A PROPERTY OF THAT CORPUS AND NOT OF THE DESIGN, and on
/// ONE LARGE MEMBER it is the largest single term in the repair.** Twenty-one
/// members mean twenty-one small copies against a fold over all of them;
/// one 8.86 GB member means ONE copy of 8.86 GB against a fold that a
/// one-block repair finishes in 0.9 s, so the wait is what is left of the
/// copy. Measured 16 Sep 2026 on a Core Ultra 9 386H (Windows 11, NTFS),
/// the 8.86 GB single-member set of the 13 Sep tier rounds: `backup join`
/// 4.09 s of a 6.88 s one-block repair, and 6.15 s of a 13.63 s one on an
/// EPYC 9354P (Linux, ext4), against 0.000 s on an M5 Max, where APFS
/// clones. It is FIXED - 0.66 s and 0.24 s at m=100 only because the
/// longer fold covers more of the same copy, which is also why 99 further
/// lost blocks cost the EPYC nothing net - and it is inherent: the
/// join may not move below the patch, which overwrites in place the very
/// bytes the copy still has to read, and a range-split copy of one
/// member is 3x SLOWER than the serial one on that box's NVMe (1.07
/// GB/s serial against 0.33 at four lanes). Do not chase it; the write-up
/// and the three-box table are
/// `research/PARFAST-SINGLE-MEMBER-REPAIR-FIXED-COST-2026-09-16.md`.
/// The
/// `.n` names are still chosen here, serially, so numbering does not
/// depend on which copy starts first; at most four copies run at once,
/// so a set of many damaged members does not fan a thread per file out
/// against the fold's own workers.
fn back_up_damaged(loaded: &verify::Loaded, survey: &verify::Survey) -> BackupBatch {
    // A `.n` that the SET declares is not a free slot, even when
    // nothing is at it yet. `exists()` alone says a missing member's
    // path is free, so a set protecting both `payload.bin` and
    // `payload.bin.1` - with `.1` the member that is missing and about
    // to be reconstructed - would have the backup written AT the repair
    // target, and `-p` would then delete the member it just made.
    // Skipping to the next number costs nothing and cannot collide.
    let protected = loaded.protected_keys();
    let mut jobs: Vec<(std::path::PathBuf, std::path::PathBuf)> = Vec::new();
    for (name, t) in &survey.targets {
        if matches!(t, Target::Found | Target::Missing) {
            continue;
        }
        let src = loaded.data_path(name);
        // Keep counting until a free name exists, as par2cmdline does.
        // This stopped at `.9`, and when all nine were taken the damaged
        // original got NO backup at all - silently, while the fold then
        // overwrote it in place. A repair that eats the evidence is the
        // one outcome a backup exists to prevent, and nine is not a
        // number the format or the reference puts any weight on.
        //
        // The ceiling is a runaway guard, not a policy: reaching it
        // means something else is wrong with the directory, and writing
        // no backup is still better than writing a millionth one.
        for n in 1..=u32::from(u16::MAX) {
            let dst = loaded.data_path(&format!("{name}.{n}"));
            if !dst.exists() && !protected.contains(&verify::path_key(&dst)) {
                jobs.push((src, dst));
                break;
            }
        }
    }
    if jobs.is_empty() {
        return BackupBatch::default();
    }
    let created = jobs.iter().map(|(_, dst)| dst.clone()).collect();
    let lanes = jobs.len().min(4);
    let queue = std::sync::Arc::new(std::sync::Mutex::new(jobs));
    // THE COPY ERROR IS KEPT, and until 20 Sep 2026 it was dropped at
    // this `fs::copy` with a `let _ =`. A read-only output DIRECTORY is
    // the shape that reaches it: the reference cannot rename its
    // original aside there and stops at exit 6, where parfast patches
    // in place and needs nothing from the directory, so it repaired and
    // exited 0 having silently not kept the one copy a backup exists to
    // be. The failure is reported by the caller, which knows when the
    // first write is about to happen; see `report_backup_failures`.
    let failed = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let lanes = (0..lanes)
        .map(|_| {
            let queue = std::sync::Arc::clone(&queue);
            let failed = std::sync::Arc::clone(&failed);
            std::thread::spawn(move || {
                loop {
                    let next = queue.lock().unwrap_or_else(|e| e.into_inner()).pop();
                    let Some((src, dst)) = next else { return };
                    if let Err(e) = std::fs::copy(&src, &dst) {
                        failed.lock().unwrap_or_else(|p| p.into_inner()).push((
                            src,
                            dst,
                            e.to_string(),
                        ));
                    }
                }
            })
        })
        .collect();
    BackupBatch {
        lanes,
        created,
        failed,
    }
}

/// Copy lanes and only their newly selected destinations. Existing numbered
/// backups remain donor candidates. Joining still precedes every target write.
#[derive(Default)]
struct BackupBatch {
    lanes: Vec<std::thread::JoinHandle<()>>,
    created: Vec<std::path::PathBuf>,
    /// `(source, destination, error)` for every copy that did not land.
    /// Shared with the lanes, which is why it is behind a lock rather
    /// than returned by a join: a lane reports its own failure and the
    /// join collects them all.
    failed: BackupFailures,
}

/// Damaged originals this run could not keep, as
/// `(source, destination, error)`.
type BackupFailures = std::sync::Arc<std::sync::Mutex<Vec<BackupFailure>>>;

type BackupFailure = (std::path::PathBuf, std::path::PathBuf, String);

/// Wait for every backup copy handed over. A lane that panicked has
/// nothing to report that the missing `.n` file does not already say.
///
/// THE WAIT IS TIMED, under the same `NZBFAST_REPAIR_TIMING` that prints
/// every other phase, and it reports the bytes as well as the seconds.
/// [`back_up_damaged`] says the copy runs BESIDE the fold and is
/// therefore free; that is true of the corpus it was measured on (21
/// members of 1 GiB, 0.06-0.45 s behind a 0.25-6 s fold) and false of
/// one large member, where the copy is the WHOLE member and the fold of
/// a one-block repair is a fraction of it. On the 8.86 GB single-member
/// set this wait is 3.7 s of a 5.9 s repair on a Core Ultra 9 and ~0 on
/// an M5 Max, because APFS clones and NTFS and ext4 copy - and until
/// this line existed the seconds landed inside the engine's `patch`
/// phase, where they read as a write that writes 4.4 MB.
/// `research/PARFAST-SINGLE-MEMBER-REPAIR-FIXED-COST-2026-09-16.md`.
fn join_backups(backups: BackupBatch) -> Vec<BackupFailure> {
    let timing = std::env::var_os("NZBFAST_REPAIR_TIMING").is_some();
    // Sized BEFORE the join, from the destinations this batch declared,
    // so a copy still in flight is counted at what it will be rather
    // than at how far it has got.
    let (n, bytes) = if timing {
        let n = backups.created.len();
        let b: u64 = backups
            .created
            .iter()
            .filter_map(|p| std::fs::metadata(p).ok().map(|m| m.len()))
            .sum();
        (n, b)
    } else {
        (0, 0)
    };
    let t0 = std::time::Instant::now();
    let lanes = backups.lanes.len();
    for h in backups.lanes {
        let _ = h.join();
    }
    if timing && lanes > 0 {
        let done: u64 = backups
            .created
            .iter()
            .filter_map(|p| std::fs::metadata(p).ok().map(|m| m.len()))
            .sum();
        tracing::info!(
            target: "repair-timing",
            "backup join: waited {:.2?} for {n} damaged-original cop{} on {lanes} lane(s),              {:.1} MB at join, {:.1} MB after",
            t0.elapsed(),
            if n == 1 { "y" } else { "ies" },
            bytes as f64 / 1e6,
            done as f64 / 1e6,
        );
    }
    // After the join, so a lane that was still copying when this was
    // called has had its say. A panicked lane leaves nothing here and
    // nothing at the destination, which `-p` and the `created` list
    // both tolerate.
    std::mem::take(&mut *backups.failed.lock().unwrap_or_else(|p| p.into_inner()))
}

/// Say which damaged originals could not be kept, one line each.
///
/// **THE POINT IS WHERE THIS IS CALLED, not what it prints.** The
/// caller on the engine's `before_write` runs it immediately before the
/// first byte reaches any target, which is the last moment the damaged
/// original is still whole: a user who reads it there can interrupt,
/// fix the directory and run again with the original intact. The same
/// words after the patch describe a loss already taken. That is the
/// whole reason this is not simply reported at the end of the run, and
/// it is why the `before_write` caller pays for a blocking handshake to
/// get the line out before the fold's meter starts writing.
///
/// `sink.err`, so `-q -q` does not swallow it: the ladder is silence
/// about progress, not about failure (see [`Sink::err`]). No row of the
/// conformance matrix reaches this - none induces an I/O failure
/// mid-repair - so it diverges from no captured table. par2cmdline has
/// no line to match here in any case: its rename FAILS the run at exit
/// 6 rather than warning, and repairing anyway is the behaviour this
/// crate keeps. `tools/conformance/README.md` records that divergence.
///
/// WHETHER THE REPAIR ITSELF THEN SUCCEEDS is not this function's to
/// promise, and it depends on which write route the engine took: a
/// rebuild staged through `par2repair`'s temp needs the directory just
/// as the reference's rename does and fails there too, where one
/// patched in place needs nothing from it and completes. Both print
/// this line.
fn report_backup_failures(failed: &[BackupFailure], sink: &mut Sink) {
    for (src, dst, err) in failed {
        let name = |p: &std::path::Path| {
            p.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| p.display().to_string())
        };
        sink.err(&format!(
            "Could not keep a backup of the damaged \"{}\" as \"{}\": {err}. \
             Repairing in place anyway, so the damaged original will not be recoverable.",
            name(src),
            name(dst),
        ));
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

#[cfg(test)]
mod tests {
    /// A full disk says so in the words SABnzbd's "Repairing failed,
    /// Disk full" verdict matches, on every platform - see
    /// [`super::failure_reason`] for why that is the Windows spelling
    /// and why it is deliberate. Everything else is reported verbatim.
    #[test]
    fn a_full_disk_is_reported_in_the_dialect_and_nothing_else_is() {
        let full = nzbkit::par2repair::RepairError::Io(std::io::Error::from(
            std::io::ErrorKind::StorageFull,
        ));
        assert_eq!(
            super::failure_reason(&full),
            "There is not enough space on the disk."
        );
        let other = nzbkit::par2repair::RepairError::Io(std::io::Error::from(
            std::io::ErrorKind::PermissionDenied,
        ));
        assert_ne!(
            super::failure_reason(&other),
            "There is not enough space on the disk."
        );
        let short = nzbkit::par2repair::RepairError::RecoveryShort { have: 1, need: 9 };
        assert_eq!(super::failure_reason(&short), short.to_string());
    }

    /// Nothing adopted prints nothing: the plan line already told the
    /// whole truth, and a "0 block(s) recovered" line would put a new
    /// sentence under every ordinary repair for no information.
    #[test]
    fn adoption_lines_are_silent_when_nothing_was_adopted() {
        assert!(super::adoption_lines(0, 350, &[]).is_empty());
        assert!(super::adoption_lines(0, 0, &["m01.bin".to_string()]).is_empty());
    }

    /// The near-copy field fixture: 349 of 350 blocks copied from a
    /// sibling member, one solved. The count line carries both numbers,
    /// and the donors are named.
    #[test]
    fn adoption_lines_name_the_count_and_the_donors() {
        let from = vec!["m01.bin".to_string(), "m02.bin".to_string()];
        let lines = super::adoption_lines(349, 1, &from);
        assert_eq!(
            lines,
            vec![
                "349 block(s) recovered from duplicate slices already on disk; 1 rebuilt from recovery data.".to_string(),
                "Duplicate slices found in: m01.bin, m02.bin".to_string(),
            ]
        );
    }

    /// Ten members means nine possible donors; the line names five and
    /// counts the rest rather than printing a paragraph.
    #[test]
    fn adoption_lines_truncate_a_long_donor_list() {
        let from: Vec<String> = (1..=9).map(|k| format!("m{k:02}.bin")).collect();
        let lines = super::adoption_lines(1398, 1, &from);
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[1],
            "Duplicate slices found in: m01.bin, m02.bin, m03.bin, m04.bin, m05.bin and 4 more"
        );
    }

    use super::wrote_bytes;

    /// The full-rebuild shortfall this function exists for: every member
    /// missing, the engine short of recovery blocks, nothing published.
    /// The line must not be printed at all - "Wrote 2147483648 bytes to
    /// disk" over an empty directory reads as a repair that wrote the
    /// WRONG bytes, and was reported as one.
    #[test]
    fn a_shortfall_that_published_nothing_claims_no_write() {
        let damaged = vec![("d.bin".to_string(), 2_147_483_648u64)];
        assert_eq!(wrote_bytes(&damaged, Some(&[]), &[]), None);
    }

    /// A shortfall that DID publish a member counts that member, and
    /// only that member - the courtesy publish is real bytes on disk.
    #[test]
    fn a_shortfall_counts_only_what_it_published() {
        let damaged = vec![("a.bin".to_string(), 10u64), ("b.bin".to_string(), 32u64)];
        let published = ["b.bin".to_string()];
        assert_eq!(wrote_bytes(&damaged, Some(&published), &[]), Some(32));
    }

    /// A whole-set repair keeps the reference's reading: every damaged
    /// member's declared length, whatever the engine physically wrote.
    #[test]
    fn a_completed_repair_counts_every_damaged_member() {
        let damaged = vec![("a.bin".to_string(), 10u64), ("b.bin".to_string(), 32u64)];
        assert_eq!(wrote_bytes(&damaged, None, &[]), Some(42));
        // ...including the degenerate "nothing was damaged" case, which
        // is a zero the caller still prints.
        assert_eq!(wrote_bytes(&[], None, &[]), Some(0));
    }

    /// A member landed by RENAMING its hash-named twin wrote none of
    /// its bytes, and the line must say so - this is the ordinary
    /// obfuscated post, where the reference does a directory operation
    /// per file and writes nothing at all.
    #[test]
    fn a_renamed_member_is_not_counted_as_written() {
        let damaged = vec![("a.bin".to_string(), 10u64), ("b.bin".to_string(), 32u64)];
        let renamed = ["a.bin".to_string()];
        assert_eq!(wrote_bytes(&damaged, None, &renamed), Some(32));
        // Every member a rename: the reference's "Wrote 0 bytes to
        // disk", which it still prints.
        // Every member a rename is the whole obfuscated post, and the
        // reference prints NO line for it - it never enters the write
        // its "Wrote" comes from.
        let all = ["a.bin".to_string(), "b.bin".to_string()];
        assert_eq!(wrote_bytes(&damaged, None, &all), None);
    }
}
