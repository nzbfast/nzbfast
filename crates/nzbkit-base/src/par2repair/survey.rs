//! What a SURVEYING caller is shown, and when.
//!
//! One subject per file, the way `linalg` is the fold's and `forney` is
//! the solve's: this is the half of a repair that a caller gets to SEE
//! and rule on. The verify pass is done, the packet walk is done, and
//! nothing has been written - so this is the one moment where a caller
//! can know the whole shape of the work and still decline it.
//!
//! Split out of `par2repair.rs` on 8 Sep 2026, at the ceiling, to make
//! room for the forecast below - which belongs to this subject and to no
//! other.

use super::*;

/// What the verify pass found about ONE member, before a byte is
/// repaired - the half of a repair a command-line tool has to PRINT.
///
/// Every field is the pass's own finding, not a re-derivation: `intact`
/// is the FileDesc whole-file MD5 over an exactly-sized file, and
/// `blocks_present` counts the IFSC block CRC32s that proved out. See
/// [`repair_dir_set_surveyed`] for why this exists at all.
#[derive(Clone, Debug)]
pub struct MemberSurvey {
    /// The FileDesc name, exactly as the packet spells it - NOT the
    /// on-disk path, which sanitizing and collision disambiguation may
    /// both have moved.
    pub name: String,
    /// Something is at the member's destination path.
    pub exists: bool,
    /// The whole-file FileDesc MD5 matched AND the length is exact.
    /// `verify_pass1`'s verdict verbatim, so false under its EARLY STOP
    /// is the tri-state's "not proven" - see
    /// [`repair_dir_set_surveyed`] for why an observer takes it as
    /// damaged rather than deciding it.
    pub intact: bool,
    /// Blocks the pass proved present, at most `blocks_total`.
    pub blocks_present: usize,
    /// Blocks the set declares for this member.
    pub blocks_total: usize,
}

/// One extra file the adoption pass took blocks from, in the shape
/// par2cmdline's "Scanning extra files:" section announces it.
///
/// WHY THE ENGINE BUILDS THIS AND NOT THE CALLER. A par2cmdline-dialect
/// CLI has to print a per-donor result line under that header, and
/// SABnzbd PARSES those lines: they are where it learns that an
/// obfuscated file is really `movie.mkv` (`renames`) and that the
/// incomplete original a repair consumed is now junk it should delete
/// (`reconstructed`). Deciding which donor fed which target is a
/// CHECKSUM question, and the only place it is answered is
/// [`adopt::adopt_blocks`] - a caller that answered it again would be
/// reading every candidate a second time to reach a conclusion this
/// repair already holds. So the decision is reported, not re-derived.
///
/// Only files under the repair's OWN directory appear here. A §293
/// donor-directory file and an in-set harvest source are both adoption
/// sources and neither is an "extra file" in the reference's sense: the
/// reference has no donor directories at all, and it announces a
/// member's own bytes under `Target:`, which is a different line that a
/// caller prints from its own survey.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtraFileMatch {
    /// The donor's name relative to the repair directory - the same
    /// out-relative vocabulary [`RepairReport::adopted_from`] speaks, so
    /// a nested candidate is a path a reader (or SABnzbd) can open.
    pub donor: String,
    /// The target its blocks belong to, as the recovery set names it,
    /// or `None` when they belong to MORE THAN ONE - the reference's
    /// "several target files" line. That third shape is the one
    /// SABnzbd's two rename regexes deliberately do not match, here as
    /// there: the line names no single target to rename to.
    pub target: Option<String>,
    /// Blocks this repair took from this donor for that target.
    pub blocks: usize,
    /// Blocks the target has in total. Zero when `target` is `None`.
    pub target_blocks: usize,
    /// The donor IS that target, whole: same length, and every one of
    /// its blocks adopted at its own aligned offset. The reference
    /// reaches this by comparing the whole-file MD5, and
    /// [`adopt::adopt_blocks`]'s fast path is that same comparison - a
    /// sliding-scan hit cannot reach it, because a file that hashed
    /// equal would have been claimed by the fast path first.
    pub whole_file: bool,
}

/// One validated packet the scan found, as a surveying caller's own
/// loader needs it: enough to print par2cmdline's per-file
/// `Loaded N new packets including M recovery blocks` line and to count
/// the set's recovery blocks, and nothing a caller could decide a
/// verdict from. The packet's own MD5 proved it, so a caller that
/// prints from this list prints what the reference prints - a corrupt
/// packet is not here, exactly as the reference's loader skips it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketSeen {
    /// The packet MD5 from its header - the identity duplicates across
    /// volumes share, and what a per-file "new packets" census dedupes on.
    pub md5: [u8; 16],
    pub set_id: [u8; 16],
    /// `Some` for a structurally valid recovery slice (a RecvSlic body
    /// carrying its 4-byte exponent), the rule the parser's own census
    /// applies.
    pub recovery: Option<RecoverySeen>,
}

/// The two things about a recovery slice a count needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoverySeen {
    pub exponent: u32,
    /// The slice payload length, past the exponent - what
    /// [`crate::par2::slice_fits_block`] judges.
    pub slice_len: u32,
}

/// One packet file the scan read, and every packet it validated in it,
/// in file order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketFileScan {
    pub path: PathBuf,
    pub packets: Vec<PacketSeen>,
}

/// Everything the packet scan validated, file by file in the catalog's
/// (sorted) order - see [`SurveyObserver::packets_scanned`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScanReport {
    pub files: Vec<PacketFileScan>,
}

/// What an observer wants done once it has seen the survey.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AfterSurvey {
    /// Go on and repair, exactly as the unobserved entry points do.
    Repair,
    /// Stop here. Nothing has been written yet - the verify pass and
    /// the packet walk only READ - so the directory is untouched.
    Stop,
}

/// What a surveying caller is shown, and when.
///
/// Two moments. [`after_survey`](Self::after_survey) is the one
/// [`repair_dir_set_surveyed`] was built for: the verify pass is done,
/// nothing is written yet, and the caller may still refuse.
/// [`before_write`](Self::before_write) is the other side of that same
/// promise: it runs on the repair's own thread immediately before the
/// FIRST byte is written to any target (after the feed, fold and solve,
/// before the patch opens a destination), so a caller that started
/// work on the targets' CURRENT bytes when it said `Repair` - parfast
/// copies each damaged original aside as `<name>.1`, the reference's
/// backup - can let that work run beside the fold and only wait for it
/// here. On Windows that copy is a real copy (no page-cache clone), and
/// it was serial: 1 GiB of it sat in front of every heavy repair.
///
/// A plain `FnMut(&[MemberSurvey]) -> AfterSurvey` implements this with
/// a no-op `before_write`, so an observer that only wants the survey
/// stays a closure.
pub trait SurveyObserver {
    /// The verify pass, before anything is written. See [`AfterSurvey`].
    fn after_survey(&mut self, members: &[MemberSurvey]) -> AfterSurvey;
    /// What the repair is about to cost, before
    /// [`after_survey`](Self::after_survey) is asked. Defaulted to
    /// nothing, so an observer that only wants the member list - a
    /// closure, or every impl written before 8 Sep 2026 - is unchanged.
    fn forecast(&mut self, _forecast: &RepairForecast) {}
    /// Every packet the scan validated, once the whole directory has
    /// been read and BEFORE [`after_survey`](Self::after_survey) - so a
    /// caller that has to print the reference's per-file `Loading` /
    /// `Loaded N new packets` lines can print them from this pass
    /// instead of reading and hashing every recovery volume a second
    /// time on its own thread. Fires once per attempt, on the repair's
    /// thread, after any provisional pass has been settled (see
    /// [`repair_dir_set_surveyed_as`]); never on the NTT retry, which
    /// has no observer. Defaulted to nothing, like `forecast`.
    ///
    /// `parfast` measured why: on a 2 GiB set with 100% parity its own
    /// load read and MD5'd the same 2 GiB the catalog was hashing on
    /// the worker, and once the catalog overlapped the verify pass that
    /// duplicate was the whole of the critical path
    /// (TODO 334).
    fn packets_scanned(&mut self, _report: &ScanReport) {}
    /// The extra files the adoption pass took blocks from, once that
    /// decision is final and BEFORE the fold - so a caller that prints
    /// the reference's "Scanning extra files:" results can print them
    /// where the reference does, ahead of "Repair is required.".
    ///
    /// THAT POSITION IS THE WHOLE POINT, and it is why this is a second
    /// handshake rather than a field on the final report. SABnzbd stops
    /// reading rename announcements the moment it sees "Repair is
    /// required." (`newsunpack.py`'s `verified` flag), so a donor named
    /// after the fold is a donor SAB never hears about. A caller that
    /// prints from here must therefore hold back the lines that follow
    /// the section until this fires - and an implementation that prints
    /// on another thread should make this call BLOCK until it has,
    /// which is what `crates/parfast` does.
    ///
    /// Fires ONCE per attempt, on the repair's thread, only on the path
    /// that goes on to repair something: a set that turns out clean, a
    /// caller that stopped at [`after_survey`](Self::after_survey) and
    /// a cancel all return before it. An empty slice is a real answer -
    /// the scan found nothing to adopt - and is the usual one.
    /// Defaulted to nothing, like `forecast`.
    fn extra_files_scanned(&mut self, _matches: &[ExtraFileMatch]) {}
    /// About to write the first target byte. Only reached after
    /// [`after_survey`](Self::after_survey) returned
    /// [`AfterSurvey::Repair`]; never reached when the repair has
    /// nothing to write or fails before the patch.
    fn before_write(&mut self) {}
    /// New output copies made by this observer from current targets. These
    /// duplicate existing target bytes and must not become external donors.
    /// Pre-existing backup files must never be included here.
    fn adoption_exclusions(&self) -> &[PathBuf] {
        &[]
    }
    /// Progress out, cancel in, pause parked - for the half of the
    /// repair that happens AFTER [`after_survey`](Self::after_survey)
    /// answered [`AfterSurvey::Repair`]. See
    /// [`control`](crate::par2repair::control), which carries the whole
    /// design.
    ///
    /// Asked ONCE, on the repair's own thread, before the verify pass -
    /// so an implementation must return the same control every time and
    /// must not build it lazily per phase. Defaulted to an inert one,
    /// which is what makes this widening rather than a second channel:
    /// `crates/parfast`, the daemon and every impl written before
    /// 12 Sep 2026 are unchanged and opt in when they want it.
    fn control(&self) -> RepairControl {
        RepairControl::default()
    }
}

impl<F: FnMut(&[MemberSurvey]) -> AfterSurvey> SurveyObserver for F {
    fn after_survey(&mut self, members: &[MemberSurvey]) -> AfterSurvey {
        self(members)
    }
}

/// [`repair_dir_set_with_donors`] that shows its caller the verify pass
/// and lets the caller call the repair off.
///
/// THE PROBLEM THIS SOLVES, because it is not obvious from the
/// signature. A par2cmdline-compatible CLI has to print an `Opening:`
/// and a `Target:` line for every member BEFORE it decides anything,
/// and those lines are a per-member verify verdict. Getting them out of
/// [`repair_dir_set_with_donors`] was impossible, so `parfast` surveyed
/// the whole set itself and then called that entry, which surveys the
/// whole set AGAIN: two complete passes over every payload byte on
/// every damaged repair. Measured on the 1 GiB / 21-member rig corpus,
/// retired instructions, 4 Sep 2026: the duplicate pass was 26.0G of
/// the 3-block leg's 40.4G and 29.2G of the 101-block leg's 106.3G,
/// against the engine harness's 14.4G and 77.0G for the same work.
///
/// The observer runs after the verify pass and before the fold, so it
/// sees what the repair is about to act on and may still refuse it
/// ([`AfterSurvey::Stop`] - the answer for "the reference prints
/// `Repair is not possible.` here", and for a rename-only run).
/// `Ok(None)` is that refusal; `Ok(Some(_))` is an ordinary verdict.
///
/// It fires ONCE. The NTT verify-failure retry re-runs the whole
/// attempt, verify pass included, and a caller that PRINTS would print
/// its table twice.
///
/// `intact` in the report is `verify_pass1`'s, EARLY STOP included, so
/// it is the tri-state's withheld-positive and not a decided verdict -
/// see `Pass1Out::md5_unfinished`. That is deliberate and it is the
/// same reading `parfast`'s own `verify::survey` settled on in
/// `89b2f4c0a`: on the M4-69 shape (a byte-exact member whose IFSC
/// contradicts its own FileDesc MD5) both call it damaged, the repair
/// rebuilds the disputed block to the bytes it already had, and the
/// file comes out identical. An observer that decided it here instead
/// would make one tool print two answers for one set.
///
/// Unlabelled: the retention admission census files it under `unknown`.
/// See [`repair_dir_set_surveyed_as`].
pub fn repair_dir_set_surveyed(
    dir: &Path,
    set_id: &[u8; 16],
    donors: &[PathBuf],
    observe: &mut dyn SurveyObserver,
) -> Result<Option<RepairStatus>, RepairError> {
    repair_dir_set_surveyed_as(dir, set_id, donors, observe, RetentionCaller::default())
}

/// [`repair_dir_set_surveyed`] with the calling site NAMED for the
/// retention admission census (TODO 331 item 1). The observer's STOP is
/// the reason this entry needs it: the engine spells a stop `NoDamage`,
/// so an observer-stopped DAMAGED survey looks exactly like a clean set
/// from outside - and it paid for the retained corpus either way.
pub fn repair_dir_set_surveyed_as(
    dir: &Path,
    set_id: &[u8; 16],
    donors: &[PathBuf],
    observe: &mut dyn SurveyObserver,
    caller: RetentionCaller,
) -> Result<Option<RepairStatus>, RepairError> {
    // LAZY, and the two name protections `DirContext` carries are
    // settled AFTER the scan rather than before the repair clock starts.
    //
    // Until 10 Sep 2026 this entry point built the catalog COMPLETE here,
    // because `declared_and_contested` needs every FileDesc in the
    // directory and `contested` is read by the collision disambiguation
    // BEFORE the verify pass. Measured 9 Sep 2026 on an M1 Ultra, 2 GiB
    // set, 64 KiB blocks: 583 ms of complete build against 1 ms on the
    // lazy entry the bench driver takes, net ~304 ms once the verify
    // pass's own reads were credited - the largest single component of
    // a 13-17% CLI-versus-driver gap
    // (`research/parfast-cli-gap-2026-09-09/REPORT.md`).
    //
    // Now `settle_names_after_scan` tells the inner pass to run its
    // verify PROVISIONALLY, with the recovery-volume scan overlapped
    // under it exactly as `repair_dir` does, derive the two name sets
    // once the catalog is complete, and - only if a name really is
    // contested - throw the provisional pass away and run the
    // complete-catalog path before the observer is shown anything or a
    // byte is written. `declared` is consumed after the scan anyway
    // (the spent-donor sweep); only `contested` was ever needed early,
    // and a directory with two sets claiming one name for different
    // content is the rare shape that pays the second pass. Neither
    // protection is weakened: the restart runs the very code that ran
    // here before, with the very same inputs.
    let mut cat = PacketCatalog::build_lazy_scoped(dir, PacketScope::Flat)?;
    let ctx = DirContext {
        settle_names_after_scan: true,
        donors: donors.to_vec(),
        patch_existing: false,
        caller,
        ..DirContext::default()
    };
    // The caller's answer, remembered here rather than smuggled through
    // `RepairStatus`: a new variant would have to be handled by every
    // match on it in the workspace, to describe a state only this entry
    // point can reach.
    let mut stopped = false;
    // Scoped so `watch`'s borrow of `stopped` ends before it is read -
    // the block IS the drop, and an explicit `drop` of a closure is a
    // clippy error.
    let status = {
        struct Watch<'a> {
            inner: &'a mut dyn SurveyObserver,
            stopped: &'a mut bool,
        }
        impl SurveyObserver for Watch<'_> {
            fn after_survey(&mut self, members: &[MemberSurvey]) -> AfterSurvey {
                let action = self.inner.after_survey(members);
                *self.stopped = action == AfterSurvey::Stop;
                action
            }
            fn forecast(&mut self, f: &RepairForecast) {
                self.inner.forecast(f);
            }
            fn packets_scanned(&mut self, r: &ScanReport) {
                self.inner.packets_scanned(r);
            }
            // EVERY defaulted method needs a line here. This wrapper
            // exists to remember the caller's `after_survey` answer and
            // forwards the rest verbatim - but a default it does NOT
            // name is a default it SILENTLY APPLIES, so an observer
            // method added to the trait and not to this list is dead on
            // this entry point, which is the only entry point a
            // par2cmdline-dialect CLI uses. Cost an hour on 17 Sep 2026.
            fn extra_files_scanned(&mut self, matches: &[ExtraFileMatch]) {
                self.inner.extra_files_scanned(matches);
            }
            fn before_write(&mut self) {
                self.inner.before_write();
            }
            fn adoption_exclusions(&self) -> &[PathBuf] {
                self.inner.adoption_exclusions()
            }
            fn control(&self) -> RepairControl {
                self.inner.control()
            }
        }
        let mut watch = Watch {
            inner: observe,
            stopped: &mut stopped,
        };
        repair_dir_set(&mut cat, Some(*set_id), &ctx, true, Some(&mut watch))?
    };
    Ok((!stopped).then_some(status))
}

/// Which solve a repair is about to run, which is the whole of what
/// separates a repair measured in SECONDS from one measured in TENS OF
/// MINUTES.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolveKind {
    /// A consecutive run of recovery exponents survives, so the matrix
    /// factors: `invert_vandermonde` or the Forney transform. Roughly
    /// LINEAR in the missing count - 8.9 s with every block of a
    /// 32,768-block set missing, on a 20-core arm64 desktop.
    Structured,
    /// Recovery packets were themselves lost, so no consecutive run of
    /// the needed length survives, the matrix is a generalized
    /// Vandermonde with no factorization, and the repair falls back to
    /// Gauss-Jordan on an explicit `m x m`. Grows much faster than
    /// linear: 67.8 s at m = 10,000 and 224 s at m = 16,384 on that same
    /// box, and about half an hour near the largest m that can be
    /// unstructured at all.
    Unstructured,
}

/// What the repair is about to cost, offered to the caller at the survey
/// point - the last moment before any byte is written.
///
/// This exists because "Repairing" on its own is not information: the
/// same word covers a second and half an hour, and a caller that cannot
/// tell them apart cannot decide anything. Everything here is known by
/// the time the verify pass ends.
#[derive(Clone, Copy, Debug)]
pub struct RepairForecast {
    /// Blocks that must be reconstructed - the `m` every cost below is
    /// a function of.
    pub missing_blocks: usize,
    /// The set's block size, so a caller can turn `m` into bytes.
    pub block_size: usize,
    /// Which solve will run. See [`SolveKind`].
    pub solve: SolveKind,
    /// An ORDER OF MAGNITUDE, not a countdown, and `None` when the shape
    /// is one nobody has measured.
    ///
    /// Fitted to two measured points on a 20-core arm64 desktop
    /// (67.8 s at m = 10,000, 224 s at m = 16,384), which put the
    /// unstructured arm at about `m^2.4` - between the quadratic fold
    /// and the cubic inverse, because the inverse is threaded. A
    /// different part will be a different constant, so a caller should
    /// present this as "minutes" or "well over an hour" and never as a
    /// time remaining. A structured repair is not estimated at all: it
    /// is seconds at every size the format allows, and a number would
    /// only invite the reader to watch it.
    pub est_secs: Option<u64>,
}

impl RepairForecast {
    /// Whether this is the shape worth warning a user about: the solve
    /// that is not linear, at a size where that stops being academic.
    /// The threshold is `MAX_REPAIR_DIM`, which is what the engine
    /// refused past until 8 Sep 2026 and is still the scale at which the
    /// explicit matrix reaches a quarter of a gigabyte.
    pub fn is_long(&self) -> bool {
        self.solve == SolveKind::Unstructured && self.missing_blocks > MAX_REPAIR_DIM
    }
}

/// The forecast, from what the survey point already holds.
///
/// ADVISORY, and deliberately so: it re-walks the recovery locations
/// rather than waiting for the real selection, because the selection
/// happens after the point a caller can still refuse. It shares the two
/// things that decide the answer - `slices::slice_fits_block`, the rule
/// for whether a packet can serve as a block, and
/// `catalog::select_consecutive_run`, the selector itself - so it cannot
/// disagree with the repair about WHICH arm will run. Only the traversal
/// is its own.
pub(super) fn forecast(
    rec_locs: &[RecLoc],
    missing_blocks: usize,
    block_size: usize,
) -> RepairForecast {
    let mut exps: Vec<u32> = rec_locs
        .iter()
        .filter(|loc| slices::slice_fits_block(loc.len as usize, block_size))
        .map(|loc| loc.exp)
        .collect();
    exps.sort_unstable();
    exps.dedup();
    let picked = catalog::select_consecutive_run(&exps, missing_blocks);
    // Consecutive exactly when the span matches the count, the same test
    // `Reconstructor::new` applies to the loaded slices.
    let consecutive = picked.len() == missing_blocks
        && missing_blocks > 0
        && picked
            .last()
            .zip(picked.first())
            .is_some_and(|(hi, lo)| hi.saturating_sub(*lo) as usize == missing_blocks - 1);
    let solve = if consecutive {
        SolveKind::Structured
    } else {
        SolveKind::Unstructured
    };
    let est_secs = match solve {
        SolveKind::Structured => None,
        SolveKind::Unstructured => {
            let m = missing_blocks as f64;
            Some((67.8 * (m / 10_000.0).powf(2.42)).round().max(1.0) as u64)
        }
    };
    RepairForecast {
        missing_blocks,
        block_size,
        solve,
        est_secs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::par2repair::catalog::{RecLoc, SliceSrc};

    /// One usable recovery slice at `exp`, sized to serve as a block.
    fn loc(exp: u32, bs: usize) -> RecLoc {
        RecLoc {
            file: 0,
            exp,
            off: 0,
            len: bs as u32,
            md5: [0u8; 16],
            src: SliceSrc::Own,
        }
    }

    /// An intact recovery set has consecutive exponents, so the matrix
    /// factors and the repair is seconds however large it is. No estimate
    /// is offered for that, on purpose: a number would only invite the
    /// reader to sit and watch a repair that is already over.
    #[test]
    fn an_intact_recovery_set_forecasts_the_structured_solve() {
        let bs = 65536;
        let locs: Vec<RecLoc> = (0..500u32).map(|e| loc(e, bs)).collect();
        let f = forecast(&locs, 400, bs);
        assert_eq!(f.solve, SolveKind::Structured);
        assert_eq!(f.missing_blocks, 400);
        assert_eq!(f.est_secs, None, "a structured solve is not estimated");
        assert!(!f.is_long(), "a structured repair is never the long shape");
    }

    /// Recovery packets themselves lost: no consecutive run of the needed
    /// length survives, so there is no factorization and the repair falls
    /// to Gauss-Jordan. THIS is the shape worth telling a user about.
    #[test]
    fn a_gapped_recovery_set_forecasts_the_unstructured_solve_and_estimates_it() {
        let bs = 65536;
        // Runs of 100, split by single gaps, so no run of 400 exists
        // while far more than 400 slices survive.
        let locs: Vec<RecLoc> = (0..2000u32)
            .filter(|e| !e.is_multiple_of(100))
            .map(|e| loc(e, bs))
            .collect();
        let f = forecast(&locs, 400, bs);
        assert_eq!(f.solve, SolveKind::Unstructured);
        let est = f.est_secs.expect("the unstructured solve is estimated");
        assert!(est >= 1, "an estimate is at least a second: {est}");
    }

    /// The estimate has to GROW with the missing count, or it says
    /// nothing - the whole reason to warn is that this arm is not linear.
    #[test]
    fn the_unstructured_estimate_grows_faster_than_the_missing_count() {
        let bs = 65536;
        let locs: Vec<RecLoc> = (0..40_000u32)
            .filter(|e| !e.is_multiple_of(1000))
            .map(|e| loc(e, bs))
            .collect();
        let small = forecast(&locs, 5_000, bs).est_secs.unwrap();
        let big = forecast(&locs, 10_000, bs).est_secs.unwrap();
        assert!(
            big > small * 3,
            "doubling m must more than triple the estimate ({small} -> {big}); the arm is \
             about m^2.4 and an estimate that grows linearly would understate it"
        );
    }

    /// A slice too short to serve as a block is not a slice. The rule is
    /// `slices::slice_fits_block`, shared with the real selection, and a
    /// forecast that ignored it would promise a fast solve over exponents
    /// the repair cannot use.
    #[test]
    fn short_slices_do_not_count_toward_a_consecutive_run() {
        let bs = 65536;
        let mut locs: Vec<RecLoc> = (0..300u32).map(|e| loc(e, bs)).collect();
        // Cut the middle of the run down to an unusable length.
        for e in 100..200usize {
            locs[e].len = (bs / 2) as u32;
        }
        let f = forecast(&locs, 250, bs);
        assert_eq!(
            f.solve,
            SolveKind::Unstructured,
            "a run broken by unusable slices is not a run"
        );
    }

    /// `is_long` is the warn/inform switch and must turn on BOTH
    /// conditions: the non-linear arm, at a size where that matters.
    #[test]
    fn is_long_needs_the_unstructured_arm_and_the_size() {
        let bs = 65536;
        let gapped: Vec<RecLoc> = (0..40_000u32)
            .filter(|e| !e.is_multiple_of(1000))
            .map(|e| loc(e, bs))
            .collect();
        assert!(!forecast(&gapped, 100, bs).is_long(), "small is not long");
        assert!(
            forecast(&gapped, MAX_REPAIR_DIM + 1, bs).is_long(),
            "unstructured past the matrix scale is the long shape"
        );
        let intact: Vec<RecLoc> = (0..40_000u32).map(|e| loc(e, bs)).collect();
        assert!(
            !forecast(&intact, MAX_REPAIR_DIM + 1, bs).is_long(),
            "a structured solve at the same m is seconds, not minutes"
        );
    }
}
