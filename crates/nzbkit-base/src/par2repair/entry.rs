//! The directory REPAIR entry points, and the caller label each one
//! carries into the retention admission census.
//!
//! Split out of `par2repair.rs` on 8 Sep 2026 (size gate; the parent
//! was at its 4,000-line ceiling exactly) along the seam TODO 331 item
//! 1 drew anyway: these are precisely the functions that OPEN a
//! directory repair, and therefore precisely the ones that know who
//! asked. Everything below the seam - `repair_dir_set`, the verify
//! pass, the fold - stays in the parent.
//!
//! Every entry point comes in two forms. The plain one is the historic
//! signature and lands in the census's explicit `unknown` bucket; the
//! `_as` one names its [`RetentionCaller`]. The surveying entry point
//! is the exception: it lives in `par2repair/survey.rs` beside the
//! observer trait it exists for, and carries both forms there. The
//! label is a PARAMETER
//! and not a thread-local on purpose: it has to survive the survey and
//! the verify workers, and a caller that forgot to set one must show up
//! as unlabelled rather than inherit whatever ran last on this thread
//! (`research/PAR2-RETENTION-CALLER-CENSUS-2026-09-08.md`, the minimum
//! useful measurement contract).

use super::*;

/// Repair the PAR2 recovery set found in `dir`: parse every `*.par2`
/// file (packets only - data files are located by their FileDesc names),
/// verify each recovery-set file block-by-block from disk, reconstruct
/// missing/corrupt blocks from recovery slices, and patch them in place.
/// Files longer than declared are truncated; absent files are recreated.
/// Success requires every touched file to pass a final proof, and
/// WHICH proof depends on the fast-check tier ([`crate::par2::set_fast_check`],
/// whose precedence is CLI flag, then setting, then
/// `NZBFAST_VERIFY_IFSC_ONLY`). With the tier off - this crate's own
/// default for a caller that never chooses - that proof is the
/// whole-file MD5 from the FileDesc packet. With it on - which is what
/// both shipped surfaces select, `parfast` unless `--slow` and the
/// daemon's `fast_final_check`, on by default since 15 Sep 2026 - the
/// proof is per block instead: exact length, the 16 KiB FileDesc head,
/// and every block's IFSC MD5 and CRC32, with the whole-file MD5 used
/// only where the IFSC does not span the file. The one spec-legal set
/// on which the two tiers disagree is written up at
/// `ifsc_only_attempt` in `crate::par2`'s verify module.
///
/// When the dir carries packets from more than one recovery set, the
/// first set seen (sorted packet-file order) is the one repaired.
///
/// Unlabelled: the retention admission census files it under `unknown`.
/// [`repair_dir_as`] is the same call with its caller named.
pub fn repair_dir(dir: &Path) -> Result<RepairStatus, RepairError> {
    repair_dir_as(dir, RetentionCaller::default())
}

/// [`repair_dir`] with the calling site NAMED, so the retention
/// admission census can tell offline extraction from a nested layer
/// from `parfast r` (TODO 331 item 1). The label changes nothing about
/// the repair.
pub fn repair_dir_as(dir: &Path, caller: RetentionCaller) -> Result<RepairStatus, RepairError> {
    // Lazy build keeps the historical shape: criticals from the first
    // file(s), the recovery-volume tail scanned in the background under
    // the target-verify pass.
    let mut cat = PacketCatalog::build_lazy(dir)?;
    let ctx = DirContext {
        caller,
        ..DirContext::default()
    };
    repair_dir_set(&mut cat, None, &ctx, true, None)
}

/// [`repair_dir`] with DONOR directories (§293): each donor's files
/// join the extra-file adoption scan as candidates, so a block the
/// recovery set cannot rebuild and the wire will not serve again can
/// still be found in a failed predecessor's output. Donor files are
/// read-only to the repair - never patched, never recreated, never
/// reported in `consumed_sources` - and an unreadable donor directory
/// degrades to "no donation" rather than failing the repair. Adoption
/// still runs only when its gate fires (a file unidentified outright,
/// or damage past the recovery on disk); donors widen what the scan
/// can find, not when it runs.
pub fn repair_dir_with_donors(dir: &Path, donors: &[PathBuf]) -> Result<RepairStatus, RepairError> {
    let mut cat = PacketCatalog::build_lazy(dir)?;
    let ctx = DirContext {
        donors: donors.to_vec(),
        ..DirContext::default()
    };
    repair_dir_set(&mut cat, None, &ctx, true, None)
}

/// [`repair_dir_with_donors`] scoped to ONE recovery set, named by id
/// rather than left to "whichever set the sorted packet walk saw first".
///
/// A directory-scoped verdict is a verdict about ONE set, and on a
/// multi-set post that set is not the caller's. Not theory:
/// `fetch_and_repair` runs once per set the mapped route declined, and
/// on the directory-scoped entry every one of those passes repaired the
/// FIRST set - passes two and three then found it verifying, answered
/// [`RepairStatus::NoDamage`], and the job printed `repair complete ✔`
/// and exited 0 over two payload files holed with 49,805 zero bytes.
/// Measured on origin/main `b5e8f0717`; the private notes for 29 Aug
/// 2026 on directory-scoped multi-set repair carry the mechanism and
/// name what it deliberately does NOT change.
///
/// A wanted set with no Main packet on disk is
/// [`RepairError::NoMainPacket`] - the honest answer, which lets the
/// caller reach its own backstop instead of accepting a green about
/// somebody else's files. The donors are [`repair_dir_with_donors`]'s
/// exactly; the catalog and the two `DirContext` name sets are not,
/// and deliberately - see [`repair_dir_set_with_donors_scoped`], which
/// this forwards to, for why a set picked out of a shared directory has
/// to be told what its neighbours declare.
///
/// Unlabelled; see [`repair_dir_set_with_donors_as`].
pub fn repair_dir_set_with_donors(
    dir: &Path,
    set_id: &[u8; 16],
    donors: &[PathBuf],
) -> Result<RepairStatus, RepairError> {
    repair_dir_set_with_donors_as(dir, set_id, donors, RetentionCaller::default())
}

/// [`repair_dir_set_with_donors`] with the calling site NAMED for the
/// retention admission census. Both of this entry's production callers
/// need it: the download's native disk-repair pass runs it once as the
/// pre-purchase adoption PROBE and once for real, and those are two
/// paid attempts rather than one job counted twice.
pub fn repair_dir_set_with_donors_as(
    dir: &Path,
    set_id: &[u8; 16],
    donors: &[PathBuf],
    caller: RetentionCaller,
) -> Result<RepairStatus, RepairError> {
    repair_dir_set_with_donors_scoped_as(
        dir,
        set_id,
        donors,
        PacketScope::Flat,
        false,
        None,
        caller,
    )
}

/// [`repair_dir_set_with_donors`] with packet DISCOVERY scope named.
///
/// Only the packet walk widens: the data files this set speaks for are
/// still resolved against `dir` through
/// [`crate::disk::join_out_name`], because a FileDesc name is relative
/// to the JOB, never to wherever its packets happen to have landed.
/// That is what makes `META/inner.par2` naming a root payload work, and
/// it is the same rule the flat walk always applied.
///
/// This is "one set out of a directory that may hold SEVERAL" by
/// construction - `get::latesets` applies every non-activated set in
/// turn through it - so it owes its caller both of `DirContext`'s
/// protections, and neither survives a lazy catalog: a name is declared
/// by a critical packet, and which files carry which set's criticals is
/// not known until they have been read. The bytes are read either way
/// (the volume scan always finishes before the repair does), so the
/// price of building COMPLETE is the overlap with the verify pass and
/// not the I/O. What the default cost is measured, not reasoned, and
/// pinned in `crates/nzbkit/tests/integration/par2repair_namepath.rs`.
///
/// `applicable` is the OTHER half of that answer, and only a caller
/// applying sets in turn can give it: the ids it will actually attempt.
/// A Nested walk discovers sets a caller may permanently refuse (an
/// extracted subdirectory carrying its own recovery set, which
/// `get::latesets`' `published_here` will not let run), and a set that
/// can never land a file must not disambiguate a running set's target
/// away from its declared name - F6, 1 Sep 2026. `None` keeps the
/// directory-wide reading; see `PacketCatalog::declared_and_contested`
/// for why only the CONTESTED half narrows.
///
/// Unlabelled; see [`repair_dir_set_with_donors_scoped_as`].
pub fn repair_dir_set_with_donors_scoped(
    dir: &Path,
    set_id: &[u8; 16],
    donors: &[PathBuf],
    scope: PacketScope,
    patch_existing: bool,
    applicable: Option<&HashSet<[u8; 16]>>,
) -> Result<RepairStatus, RepairError> {
    repair_dir_set_with_donors_scoped_as(
        dir,
        set_id,
        donors,
        scope,
        patch_existing,
        applicable,
        RetentionCaller::default(),
    )
}

/// [`repair_dir_set_with_donors_scoped`] with the calling site NAMED
/// for the retention admission census. `get::latesets` is the caller
/// that needs it: a clean late set returns `NoDamage` and writes NO
/// user-visible log at all, so it is invisible to every log parser
/// while still having paid for a whole retained corpus.
pub fn repair_dir_set_with_donors_scoped_as(
    dir: &Path,
    set_id: &[u8; 16],
    donors: &[PathBuf],
    scope: PacketScope,
    patch_existing: bool,
    applicable: Option<&HashSet<[u8; 16]>>,
    caller: RetentionCaller,
) -> Result<RepairStatus, RepairError> {
    scoped_with_observer(
        dir,
        set_id,
        donors,
        scope,
        patch_existing,
        applicable,
        caller,
        None,
    )
}

/// The body both scoped entries share: the complete catalog, the two
/// name protections settled BEFORE the repair, and the observer slot.
///
/// ONE COPY, because the two entries must not be able to drift. They
/// differ in exactly one argument - `observe` - and the whole claim of
/// [`repair_dir_set_with_donors_scoped_controlled_as`] is that nothing
/// else about them differs, which a second copy of this struct literal
/// could quietly stop being true the next time a `DirContext` field is
/// added.
///
/// The one behavioural consequence of passing an observer at all is
/// that `repair_dir_set` builds a [`ScanReport`] for it - a copy of
/// every packet identity in the set, once, on the driver thread, while
/// the volume scan has already read those bytes. Tens of kilobytes
/// against a repair that reads gigabytes, so it is named here rather
/// than avoided; a caller that wanted to avoid it would need the
/// trait to say it does not want the report, which is surface for one
/// call site.
#[allow(clippy::too_many_arguments)]
fn scoped_with_observer(
    dir: &Path,
    set_id: &[u8; 16],
    donors: &[PathBuf],
    scope: PacketScope,
    patch_existing: bool,
    applicable: Option<&HashSet<[u8; 16]>>,
    caller: RetentionCaller,
    observe: Option<&mut dyn SurveyObserver>,
) -> Result<RepairStatus, RepairError> {
    let mut cat = PacketCatalog::build_scoped(dir, scope)?;
    let (declared, contested) =
        cat.declared_and_contested(crate::disk::case_insensitive_dir(dir), applicable);
    let ctx = DirContext {
        contested,
        declared,
        donors: donors.to_vec(),
        patch_existing,
        caller,
        settle_names_after_scan: false,
    };
    repair_dir_set(&mut cat, Some(*set_id), &ctx, true, observe)
}

/// [`repair_dir_set_with_donors_scoped_as`] with a
/// [`RepairControl`](super::RepairControl) - progress out of the
/// repair, a cancel its loops poll, a pause they park on.
///
/// # Why this and not `repair_dir_set_surveyed_as`
///
/// The surveying entry is the CLI's, and three of its properties are
/// wrong for a caller that only wants the control: it builds the
/// catalog LAZY and settles the two name protections after the scan
/// (`settle_names_after_scan`), it fires `after_survey` so an observer
/// can refuse the repair, and it answers `Ok(None)` for that refusal -
/// a third verdict every `match` has to grow an arm for. The daemon
/// wants none of the three. It wants the catalog semantics it already
/// has, unchanged, plus a channel.
///
/// So the control is carried by a trivial private observer that
/// answers [`AfterSurvey::Repair`] always and hands the control back
/// from [`SurveyObserver::control`]. Everything about the catalog,
/// `declared_and_contested`, `patch_existing` and the census label is
/// the sibling's BY CONSTRUCTION: both entries are one call to
/// `scoped_with_observer` differing in the observer argument alone,
/// so there is no second copy of that struct literal to drift. (The
/// one thing an observer costs either way is named on that function.)
///
/// An INERT control (`RepairControl::default()`) is the sibling call
/// exactly: every hook in the driver short-circuits on it, and the
/// observer's own two methods are what the driver would have done with
/// no observer at all. So a caller with nothing to report may pass one
/// rather than choosing between two entry points.
///
/// Passing a control that carries BOTH halves also lifts the
/// unattended unstructured ceiling for THIS repair - see
/// [`RepairControl::is_attended`](super::RepairControl::is_attended)
/// and `reconstruct::check_repair_dim_dense`. That is not a side
/// effect to be surprised by: it is the same fact, said once. A caller
/// that can see a repair and stop it is attended whatever process it
/// is in.
pub fn repair_dir_set_with_donors_scoped_controlled_as(
    dir: &Path,
    set_id: &[u8; 16],
    donors: &[PathBuf],
    scope: PacketScope,
    patch_existing: bool,
    applicable: Option<&HashSet<[u8; 16]>>,
    caller: RetentionCaller,
    control: super::RepairControl,
) -> Result<RepairStatus, RepairError> {
    /// The whole of the door: a control, and the two answers the
    /// driver would have given itself with no observer.
    ///
    /// `after_survey` must say `Repair` and not merely "whatever the
    /// default is" - there is no default, because the trait's one
    /// required method is the refusal hook and this observer exists
    /// precisely to refuse nothing.
    struct Controlled(super::RepairControl);
    impl SurveyObserver for Controlled {
        fn after_survey(&mut self, _members: &[MemberSurvey]) -> AfterSurvey {
            AfterSurvey::Repair
        }
        fn control(&self) -> super::RepairControl {
            self.0.clone()
        }
    }
    let mut observe = Controlled(control);
    scoped_with_observer(
        dir,
        set_id,
        donors,
        scope,
        patch_existing,
        applicable,
        caller,
        Some(&mut observe),
    )
}

/// [`repair_dir_set_with_donors_as`] with a
/// [`RepairControl`](super::RepairControl).
///
/// The flat, non-patching, directory-wide reading its uncontrolled
/// twin has - the pairing is kept so a call site that grows a control
/// changes one word rather than six arguments. See
/// [`repair_dir_set_with_donors_scoped_controlled_as`] for the whole
/// argument.
pub fn repair_dir_set_with_donors_controlled_as(
    dir: &Path,
    set_id: &[u8; 16],
    donors: &[PathBuf],
    caller: RetentionCaller,
    control: super::RepairControl,
) -> Result<RepairStatus, RepairError> {
    repair_dir_set_with_donors_scoped_controlled_as(
        dir,
        set_id,
        donors,
        PacketScope::Flat,
        false,
        None,
        caller,
        control,
    )
}

/// Repair every recovery set in `dir` whose data files are actually
/// there. A nested layer can land beside packets that describe files
/// which never touched this dir (the downloaded set's own index next to
/// an in-stream-extracted payload: its volumes exist only as the
/// extracted output) - repairing such a set would at best re-derive
/// "everything missing" noise and at worst resurrect volume files, so a
/// set only qualifies when at least one of its FileDesc names exists on
/// disk. Sets are repaired in first-seen (sorted packet-file) order;
/// per-set failures don't stop later sets. `Ok(vec![])` = nothing
/// relevant here at all.
///
/// Unlabelled; see [`repair_present_sets_as`].
pub fn repair_present_sets(dir: &Path) -> Result<Vec<SetOutcome>, RepairError> {
    repair_present_sets_as(dir, RetentionCaller::default())
}

/// [`repair_present_sets`] with the calling site NAMED for the
/// retention admission census. The nested-extraction caller passes its
/// DEPTH here: an outer archive can be clean while the set inside it is
/// not, so a nested attempt is a population of its own and must never
/// be pooled with the outer one.
pub fn repair_present_sets_as(
    dir: &Path,
    caller: RetentionCaller,
) -> Result<Vec<SetOutcome>, RepairError> {
    repair_sets_inner(dir, false, caller, None)
}

/// [`repair_present_sets_as`] with a
/// [`RepairControl`](super::RepairControl) - progress out of each
/// repair, a cancel its loops poll - for the nested extraction ladder
/// (`nzbfast-unpack`'s `unpack::nested_par2_repair`), which was the
/// last daemon repair path with no channel at all.
///
/// # Why a SUPPLIER and not a control, which is the only way this
/// differs from the other family's door
///
/// [`repair_dir_set_with_donors_scoped_controlled_as`] takes one
/// [`RepairControl`](super::RepairControl) because it repairs ONE named
/// set. This family repairs EVERY present set in the directory, in
/// turn, and the loop is the engine's - so a caller cannot wrap each
/// set in its own reporting window the way `get::latesets` wraps its
/// per-set `RepairProgress::enter()` guard. Handed one control for the
/// directory, a caller whose bar is monotone (the daemon's is, by
/// `fetch_max`, so a slabbed solve cannot make it read as a restart)
/// would sit at 100% for every set after the first: the "Repairing,
/// 100%" stall this whole mechanism exists to remove, on a repair that
/// is genuinely running.
///
/// So the control is asked for ONCE PER SET, at the instant that set's
/// repair starts - `repair_dir_set_inner` fetches it from
/// [`SurveyObserver::control`] at the top of the repair and nowhere
/// else, so the supplier fires exactly there. That is the set boundary,
/// and it is the caller's to do what it likes with: the daemon puts its
/// bar back, a caller with nothing to reset returns the same clone
/// every time.
///
/// Everything else is [`repair_present_sets_as`] BY CONSTRUCTION: both
/// are one call to `repair_sets_inner` differing in the observer
/// argument alone, so the `DirContext` literal and the present-name
/// gate have no second copy to drift. A supplier returning
/// `RepairControl::default()` is the uncontrolled call exactly, branch
/// for branch.
///
/// # Where a cancelled set stops
///
/// On the set it was cancelled in. The walk BREAKS rather than going on
/// to the next set with a sticky cancel raised, so a cancelled
/// directory pass reports the sets it finished plus the one it was
/// stopped in, and never a run of `Cancelled` verdicts that read like N
/// broken sets. See `repair_sets_catalog`.
pub fn repair_present_sets_controlled_as(
    dir: &Path,
    caller: RetentionCaller,
    control: &dyn Fn() -> super::RepairControl,
) -> Result<Vec<SetOutcome>, RepairError> {
    let mut observe = ControlledSets(control);
    repair_sets_inner(dir, false, caller, Some(&mut observe))
}

/// The whole of the controlled door on this family, and the
/// uncontrolled sibling's (absent) observer exactly but for calling a
/// supplier rather than cloning one value: a control, and the two
/// answers the driver would have given itself with no observer.
///
/// ONE COPY, and `pub(super)` for it: both controlled entries of this
/// family need it - [`repair_present_sets_controlled_as`] here and
/// [`PacketCatalog::repair_present_or_renamed_sets_controlled`](
/// super::PacketCatalog::repair_present_or_renamed_sets_controlled),
/// the no-set obfuscated arm's door - and a second copy is a second
/// place for `after_survey` to drift away from `Repair`.
pub(super) struct ControlledSets<'a>(pub(super) &'a dyn Fn() -> super::RepairControl);

impl SurveyObserver for ControlledSets<'_> {
    fn after_survey(&mut self, _members: &[MemberSurvey]) -> AfterSurvey {
        AfterSurvey::Repair
    }
    fn control(&self) -> super::RepairControl {
        (self.0)()
    }
}

/// [`repair_present_sets`], plus a content fallback for the wholly
/// renamed obfuscated post: when not a single FileDesc name is on disk,
/// the sets are attempted anyway and the verdicts speak (issue #9's
/// single-file shape, where not even a companion .nfo keeps its name).
///
/// A separate entry point because the fallback is WRONG for the other
/// caller. The nested disk post-pass leans on the name gate to skip an
/// outer index whose volumes never touched disk - attempted anyway,
/// `repair_dir_set` would RECREATE those volumes on disk from recovery
/// slices and adoption, materializing files the one-pass pipeline just
/// proved it never needed to write. Only the no-set obfuscated arm,
/// which owns a directory where everything already landed, wants this.
pub fn repair_present_or_renamed_sets(dir: &Path) -> Result<Vec<SetOutcome>, RepairError> {
    repair_sets_inner(dir, true, RetentionCaller::default(), None)
}

/// The body every entry of this family shares - the catalog build and
/// the directory walk - with the observer slot that is the only thing
/// [`repair_present_sets_controlled_as`] adds. ONE COPY, for the reason
/// [`scoped_with_observer`] carries at length.
fn repair_sets_inner(
    dir: &Path,
    renamed_fallback: bool,
    caller: RetentionCaller,
    observe: Option<&mut dyn SurveyObserver>,
) -> Result<Vec<SetOutcome>, RepairError> {
    let mut cat = PacketCatalog::build(dir)?;
    repair_sets_catalog(&mut cat, renamed_fallback, caller, observe)
}
