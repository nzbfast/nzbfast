//! What a directory repair hands back: [`RepairReport`] and
//! [`RepairStatus`]. A child module of `par2repair` (the `adopt` /
//! `donate` pattern) so par2repair.rs stays inside its size-gate
//! entry; `use super::*` keeps the parent's bindings in scope exactly
//! as they were inline.

use super::*;

#[derive(Debug)]
pub struct RepairReport {
    /// Input blocks reconstructed via Reed-Solomon.
    pub blocks_rebuilt: usize,
    /// Input blocks whose content was found intact under another name or
    /// offset by the extra-file adoption scan.
    pub blocks_adopted: usize,
    /// File names (as found on disk) that adopted blocks came from.
    pub adopted_from: Vec<String>,
    /// Files whose bytes were patched (includes created ones).
    pub files_patched: Vec<String>,
    /// Subset of `files_patched` that were missing entirely.
    pub files_created: Vec<String>,
    /// Full paths of the extra files this repair CONSUMED as adoption
    /// sources - obfuscated copies whose bytes now also exist under the
    /// name the PAR2 set gives them. The engine never deletes them (it
    /// does not own the directory), so a caller that DOES own it is told
    /// which files are now redundant; on an obfuscated post this is the
    /// difference between a finished folder and two copies of it.
    ///
    /// Recovery-set targets are excluded: a candidate can share a path
    /// with a target (exactly what `used_sources` forces through the
    /// temp+rename path below), and there the "source" IS the restored
    /// payload. Deleting it would undo the repair.
    pub consumed_sources: Vec<PathBuf>,
    /// The same accounting PER TARGET - one [`FileRepair`] for every
    /// file the set covers, in the set's own file order, damaged or
    /// not. Every field above it is a total, and a total cannot say
    /// WHICH file a donor fed; [`RepairReport::file_had_bytes_on_disk`]
    /// is the question this exists to answer.
    pub per_file: Vec<FileRepair>,
}

#[derive(Debug)]
pub enum RepairStatus {
    /// Every recovery-set file already verifies - nothing written.
    NoDamage,
    /// Damage found and repaired; every patched file re-verified by MD5.
    Repaired(RepairReport),
    /// Not enough recovery slices on disk for the damage found, with
    /// what adoption found and already subtracted - see [`adopt`].
    ///
    /// The set as a whole is not repairable; individual MEMBERS of it
    /// may still be, and `partial` is what this pass managed to publish
    /// anyway - see the field's own note.
    Unrepairable {
        needed: usize,
        have: usize,
        adopted: usize,
        /// What was published DESPITE the shortfall: every target of
        /// this set whose own blocks were all accounted for (present on
        /// disk, or found by the adoption scan) got written under its
        /// FileDesc name and whole-file-MD5 verified, exactly as a
        /// successful repair writes one.
        ///
        /// Empty of publishes on a set where every damaged member still
        /// owes blocks to recovery data - which is the everyday case,
        /// and was the ONLY case until 31 Aug 2026: the engine used to
        /// return this verdict before it wrote anything at all, so a
        /// member proven byte-exact by adoption was thrown away with the
        /// set. `crates/nzbkit/src/par2repair/unit_tests/
        /// unrepairable_partial.rs` is the reproduction that pinned it.
        ///
        /// # Two fields do not mean here what they mean on a `Repaired`
        ///
        /// `blocks_rebuilt` is 0, on the report and per file it is 0
        /// wherever a target was published, because a shortfall runs no
        /// Reed-Solomon pass at all. Per file it is therefore the
        /// target's own SHORTFALL - blocks of it nothing could account
        /// for - and `== 0` is exactly the set that was publishable.
        ///
        /// # A FAILED publish is a member that does not land, not an error
        ///
        /// SETTLED 31 Aug 2026, claim
        /// `shortfall-publish-error-degrades-verdict`. For a few hours
        /// after 6c71c020d a publish failure - an I/O error reading a
        /// donor, a final whole-file MD5 that did not match, a rename
        /// the filesystem refused - returned `Err` from
        /// `repair_dir_set_inner`, where a short set had returned this
        /// verdict for the whole life of the engine before it. Nobody
        /// decided that; the courtesy publish was added on top of a
        /// verdict already reached, and the error path fell out of the
        /// implementation. It now costs the member and nothing else:
        /// [`publish_failed`] carries the ruling and the argument, and
        /// [`drop_unpublished`] takes the member back out of the report
        /// so this field describes what is actually on disk.
        ///
        /// What that protects is the ARITHMETIC, and it is worth more
        /// than a tidier log line. `needed` / `have` are what
        /// `nzbfast::repair::blocks_over_set` sizes a recovery fetch by,
        /// and `nzbfast::repair::nativepass` answers `Backstop` (run
        /// par2cmdline) on an `Err` where it answers `NoRecovery` on
        /// this verdict - which
        /// `nzbfast::repair::adoption_narrowed_need` turns into the FULL
        /// unnarrowed buy instead of the narrowed one, on a probe pass
        /// that publishes. Bandwidth spent for nothing.
        ///
        /// THE DATA WAS SAFE THROUGHOUT, and still is: `publishable`
        /// admits only non-existent targets, so every publish goes via
        /// temp-and-rename, the temp is cleaned up, and nothing already
        /// on disk is touched by a failure.
        ///
        /// `consumed_sources` is ALWAYS empty. A donor is proven
        /// redundant by its bytes now existing under a name the set
        /// declares, and while a sibling target is still absent from
        /// disk that proof is not available for any donor that may also
        /// have fed it. So this verdict publishes files and spends
        /// nothing: it can only ever ADD a verified file to the
        /// directory, never remove one. Widening that is a separate
        /// decision and wants the deferred sweep
        /// (`nzbfast::get::latesets`'s `sweep_spent_sources`) reasoned
        /// through for a set that has NOT healed.
        partial: RepairReport,
    },
}

/// The verdict a directory repair ends on, given what it published.
///
/// One place rather than two `return`s, because the difference between
/// them is only whether the recovery data ran out: both run the same
/// write, verify and rename path over whatever targets were publishable,
/// and both hand the caller the same [`RepairReport`] shape.
pub(super) fn finish(
    shortfall: Option<usize>,
    needed: usize,
    adopted: usize,
    report: RepairReport,
) -> RepairStatus {
    match shortfall {
        Some(have) => RepairStatus::Unrepairable {
            needed,
            have,
            adopted,
            partial: report,
        },
        None => RepairStatus::Repaired(report),
    }
}

/// May this target be published out of a set that is short of recovery
/// data?
///
/// TWO conditions, and the second is a NARROWING that keeps this whole
/// verdict strictly additive to the directory.
///
/// FIRST, every one of its OWN blocks must already be accounted for -
/// present on disk under its own name, or matched by the adoption scan -
/// so that nothing about it waits on the Reed-Solomon pass a shortfall
/// never runs. `per_file_census` counts exactly that into
/// [`FileRepair::blocks_rebuilt`] (it partitions the global `missing`
/// list by owning target), so this is a read of the census and not a
/// second walk that could disagree with it.
///
/// SECOND, an existing target may be patched only where the CALLER has
/// OPTED IN (`DirContext::patch_existing`). Until 31 Aug 2026 the rule
/// was `!t.exists` flat - a shortfall could only ever CREATE a file that
/// was not there - and this is claim `shortfall-publish-patch-existing`.
///
/// THE OPT-IN says this verdict is the LAST WORD on the set, and only a
/// caller knows that. `nzbfast::get::latesets` is the one that sets it:
/// a bounded fixpoint at the end of the job with nothing after it to buy
/// anything. `repair::nativepass`' PROBE pass is the counter-example
/// that forced the flag to exist - it calls the same engine before a
/// single recovery volume has been bought, and its own report line is
/// documented "the repair did not happen and nothing was written". A
/// first cut gated on the survey alone, so the probe patched too, and
/// the members it healed early were exactly the ones the real pass would
/// have adopted: `e2e_norar::twin_adopt` and
/// `e2e_norar::ondisk_recovery` both went red, each on the adoption
/// count in its own success line.
///
/// THE SURVEY is the ownership evidence, and it is a STRUCTURAL
/// guarantee here rather than a second condition: `patch_existing` is a
/// private field of `DirContext` and the ONLY site that can set it true
/// is `repair_dir_set_with_donors_scoped`, which surveys the directory
/// unconditionally on the line above. That is what makes the opt-in
/// safe - a surveyed directory has already disambiguated every
/// destination `contested` names onto a `.dup-<fid>` path of its own, in
/// EVERY set, so a `t.path` here is a destination no other set can land
/// on. What can still sit there is this set's own damaged member or a
/// file nobody declares, and patching either with bytes proved against
/// this file's own FileDesc/IFSC hashes is what an ordinary repair does
/// unconditionally.
///
/// IT IS WRITTEN AS ONE CONDITION ON PURPOSE. A first cut ANDed a
/// `!ctx.declared.is_empty()` test in beside the flag as a fail-closed
/// belt; it is unreachable - no constructor grants the flag without
/// surveying - so no case could kill a mutation of it, which is the
/// unfalsifiable-guard shape this repo refuses in as many words. If a
/// future constructor ever wants `patch_existing` WITHOUT surveying,
/// that constructor is where the question belongs: survey there, or do
/// not offer the flag.
///
/// THE ORIGINAL REASON FOR `!t.exists` was a different one and it is
/// worth keeping: the late-set path used to hand the engine a
/// `DirContext::default()` - both name sets empty, nothing able to say
/// whose file it was (claim `latesets-empty-dircontext`), so there was
/// no ownership evidence anywhere. `92828385d` fixed that;
/// `repair_dir_set_with_donors_scoped` builds the context from the
/// catalog. A caller that never reaches that entry point - `repair_dir`,
/// single-set by definition - never gets the flag and keeps the old rule
/// exactly.
///
/// A MECHANICAL CONSEQUENCE MOVED WITH IT, and it is load-bearing:
/// `!exists` used to make `identified` false in the patch loop, so every
/// shortfall publish went via temp-and-rename and a member that failed
/// its final MD5 left the directory untouched. An existing target IS
/// identified, so it would have been patched IN PLACE - and a set that
/// has already failed leaving a half-written member behind is worse than
/// the refusal this replaces. The patch loop therefore forces the temp
/// path for every shortfall publish, so the widening keeps the property
/// it was worth having: a member lands whole and MD5-proved, or nothing
/// about it moved.
///
/// STATED LIMIT on that half: it is not directly pinned, and what
/// pinning it would cost is why. The temp path and the in-place path
/// produce identical bytes whenever the verify PASSES, so the two are
/// distinguishable only on a member that clears every block hash and
/// then fails its whole-file MD5 - an internally inconsistent PAR2 set
/// (the `ifsc_contradicting_the_filedesc_md5` shape), which the
/// directory-level `par2_index` fixture builder cannot express without a
/// per-file whole-file-MD5 override. What IS pinned is the widening
/// itself, by the three `unrepairable_partial` rows: the surveyed
/// opt-in that patches, the opt-out that refuses, and the unsurveyed
/// entry point that refuses.
///
/// The safety case rests on nothing new. A PAR2 FileDesc packet carries
/// a whole-file MD5 and the IFSC packet a CRC32+MD5 per block, and
/// nothing in the format binds one file's hashes to a sibling's - so
/// "do these bytes match this file's own declared hashes" is already,
/// by construction, a question with no dependency on any other member's
/// state. [`RepairReport::file_had_bytes_on_disk`] and its test already
/// treat that evidence as sufficient per file ("a SIBLING's donor is not
/// this member's evidence"); this asks the same question one branch
/// earlier, when the WHOLE set fails rather than only when it succeeds.
pub(super) fn publishable(f: &FileRepair, t: &Target, ctx: &DirContext) -> bool {
    f.blocks_rebuilt == 0 && (!t.exists || ctx.patch_existing)
}

/// One member of a SHORT set failed to write or failed its whole-file
/// MD5. Is that an error for the whole call, or simply a member that
/// does not land?
///
/// RULED 31 Aug 2026 (claim `shortfall-publish-error-degrades-verdict`):
/// a member that does not land. On a set that is NOT short this is
/// unchanged and still an `Err` - that is the engine's self-proving
/// contract, and the whole reason a native bug can never ship bad bytes.
///
/// # Why a shortfall answers differently
///
/// Between 6c71c020d and this ruling a failed publish returned `Err`
/// from `repair_dir_set_inner`, where a short set had returned
/// `Ok(Unrepairable { .. })` for the whole life of the engine before it.
/// That was never a decision anybody took: the courtesy publish was
/// added on top of a verdict that had already been reached, and the
/// error path fell out of the implementation.
///
/// THREE THINGS DECIDED IT.
///
/// FIRST, THE VERDICT IS OLDER THAN THE PUBLISH. `needed` / `have` come
/// out of the solve census, before a byte is written; the publish is a
/// best-effort courtesy layered on afterwards. A courtesy that fails
/// cannot make the arithmetic untrue, so it must not be able to
/// withdraw it.
///
/// SECOND, PER-MEMBER INDEPENDENCE IS THIS FEATURE'S OWN PREMISE.
/// [`publishable`]'s note is explicit that nothing in the PAR2 format
/// binds one file's hashes to a sibling's. An `Err` return makes ONE
/// member's write failure decide the whole set's answer - exactly the
/// cross-member dependency the design rests on not existing.
///
/// THIRD, AND THIS IS THE ONE THAT COSTS BYTES: the lost arithmetic
/// SIZES A FETCH. `nzbfast::repair::adoption_narrowed_need` turns
/// `NativeVerdict::NoRecovery { needed, have }` into
/// `NarrowedNeed::Buy(after - on_disk)` - the narrowed buy - and turns
/// `Backstop` into `Buy(needed)`, the full unnarrowed one. That probe
/// pass PUBLISHES (`probe` changes only the wording of the log line), so
/// before this ruling one failed courtesy write made the job buy the
/// whole unnarrowed amount; and on the `NarrowedNeed::Final` arm, which
/// exists to say "not buying recovery that cannot close it", it made the
/// job buy recovery the engine had just proven cannot close the gap -
/// downloaded bytes that provably cannot fix the job.
///
/// # What the `Backstop` safety net is for, and why it is not this
///
/// Falling through to par2cmdline exists so a native BUG cannot ship bad
/// bytes: it re-runs a repair with an engine we trust. On a shortfall
/// there is no repair to salvage - the set is short by arithmetic this
/// pass has already proven - so the net is being asked to do the one
/// thing already established as impossible, in place of a number the
/// caller needed. Note also that a shortfall with NO publish failure
/// does not run par2cmdline today, so letting an unrelated courtesy
/// write flip that choice made the engine selection turn on something
/// that has nothing to do with it.
///
/// NOTHING IS SWALLOWED. The verdict stays a failure - `good = false` in
/// `nzbfast::get::latesets`, `every_set_ok = false` in
/// `nzbfast::get::settle::noset` - and the member gets this warn line
/// naming itself and its error, so a native bug is still visible. What
/// it no longer does is cost the caller its arithmetic.
///
/// THREE SITES CALL IT AND A FOURTH DELIBERATELY DOES NOT: the in-place
/// `write_blocks` arm of the patch loop still answers a bare `Err`. That
/// is not an omission - `via_temp` is forced whenever `shortfall` is
/// some (see [`publishable`]'s "mechanical consequence"), so a shortfall
/// never reaches that arm, and a bare `Err` IS this ruling's
/// non-shortfall answer.
pub(super) fn publish_failed(
    shortfall: Option<usize>,
    name: &str,
    e: RepairError,
) -> Result<(), RepairError> {
    if shortfall.is_none() {
        return Err(e);
    }
    warn!(
        target: "repair",
        "{name} could not be published out of a recovery set that was already \
         short ({e}) - it is left unwritten and the set's own verdict is \
         unchanged"
    );
    Ok(())
}

/// The whole-file MD5 verdicts turned into the list of targets that did
/// NOT land, deciding each one through [`publish_failed`].
///
/// Out of line in this module rather than inline in the verify pass for
/// the reason [`finish`] is: the question is what the call HANDS BACK,
/// and `par2repair.rs` was at 2,993 of the size gate's 3,000-line
/// ceiling when this landed.
pub(super) fn verify_results(
    checks: &[(PathBuf, usize, bool)],
    results: Vec<Option<Result<bool, RepairError>>>,
    targets: &[Target],
    shortfall: Option<usize>,
) -> Result<Vec<usize>, RepairError> {
    let mut unpublished = Vec::new();
    for ((_, ti, _), r) in checks.iter().zip(results) {
        let e = match r.expect("verify worker filled every slot") {
            Ok(true) => continue,
            Ok(false) => RepairError::VerifyFailed(targets[*ti].file.name.clone()),
            Err(e) => e,
        };
        publish_failed(shortfall, &targets[*ti].file.name, e)?;
        unpublished.push(*ti);
    }
    Ok(unpublished)
}

/// Take the members that did not land back out of the publish, so the
/// report describes what is actually on disk.
///
/// BOTH LISTS, and dropping only `renames` is a live trap rather than a
/// tidier half-measure: the rename pass builds `temp_set` FROM
/// `renames` and then credits every `damaged` target NOT in it to
/// `report.files_patched`, on the reasoning that such a target was
/// patched in place. So a member removed from `renames` alone is
/// reported as published - and [`published_clause`] counts exactly that
/// list, so the user would be told a file landed whose temp this
/// function has just deleted.
///
/// The temps go here rather than at the failure sites because a verify
/// failure is found with the temp already parked in `renames`; removing
/// it in one place keeps that from depending on which site rejected it.
pub(super) fn drop_unpublished(
    unpublished: &[usize],
    damaged: &mut Vec<usize>,
    renames: &mut Vec<(PathBuf, usize)>,
) {
    if unpublished.is_empty() {
        return;
    }
    renames.retain(|(tmp, ti)| {
        let keep = !unpublished.contains(ti);
        if !keep {
            let _ = std::fs::remove_file(tmp);
        }
        keep
    });
    damaged.retain(|ti| !unpublished.contains(ti));
}

/// Per-target block accounting: what ONE file of the recovery set got,
/// and - the question the totals above cannot answer - where it came
/// from.
///
/// [`RepairReport`]'s `blocks_adopted` / `adopted_from` /
/// `consumed_sources` are totals over the whole repair, so they say
/// that SOME file of the set had bytes already on disk and never which
/// one. A set that adopts one member out of a hash-named donor and
/// rebuilds another purely from parity reports the same thing as a set
/// that adopted every block of both, and a caller gating on "did this
/// repair have bytes of its own to work from" then credits the second
/// file with what the first earned (`nzbfast::get::latesets`'s X5-24
/// gate, which is why this exists).
#[derive(Debug)]
pub struct FileRepair {
    /// The FileDesc name, spelled exactly as [`RepairReport::files_patched`]
    /// and [`RepairReport::files_created`] spell it. NOT unique on its
    /// own: two FileDescs may declare the same name (they are given
    /// distinct PATHS, but the report's vocabulary is names), so match
    /// on it the way [`RepairReport::file_had_bytes_on_disk`] does
    /// rather than by building a map keyed on it.
    pub name: String,
    /// Input blocks of THIS file reconstructed via Reed-Solomon.
    pub blocks_rebuilt: usize,
    /// Input blocks of THIS file whose content the adoption scan found
    /// intact under another name or offset - in a donor, in an extra
    /// file, or in one of the set's own targets (`adopt::harvest_in_set`).
    /// Zero on a file in `files_created` means it was rebuilt from
    /// PARITY ALONE: no bytes of it were anywhere on disk, under its own
    /// name or anybody else's.
    pub blocks_adopted: usize,
    /// Where this target actually LANDED, which is the field `name`
    /// cannot stand in for and the reason this one exists (X-8,
    /// 31 Aug 2026).
    ///
    /// The repair resolves a destination as
    /// `join_out_name(dir, &sanitize_out_name(&d.name))` and then
    /// DISAMBIGUATES it where two descriptors would otherwise share a
    /// file: the second becomes `<name>.dup-<first 6 bytes of file_id>`
    /// (see the claim loop in `par2repair.rs`). So a caller that
    /// rebuilds a path out of `name` is looking at a file the repair
    /// may never have written - and on `nzbfast::get::latesets`'s
    /// `!mine` arm that meant a disambiguated rebuild was never gated
    /// at all, another release's payload left in this download's output
    /// directory while both of the gate's declines landed on the ONE
    /// path it could see. Measured 31 Aug 2026; the pin is
    /// `crates/nzbkit/tests/integration/par2repair_namepath.rs` and
    /// `nzbfast`'s `e2e_lateset::x8_*`.
    ///
    /// Absolute, because it is the path the repair itself used. A
    /// caller wanting the report's NAME vocabulary still has `name`
    /// beside it; the two are deliberately both here rather than one
    /// derived from the other, since neither direction is a function.
    pub path: PathBuf,
}

/// The `, N block(s) adopted from a.001, a.002` clause of a SUCCESSFUL
/// repair's report - the rendering of [`RepairReport::blocks_adopted`]
/// and [`RepairReport::adopted_from`], and it lives beside them because
/// TWO surfaces print it: `nzbfast`'s in-place repair report and its
/// settle-time disk fallback.
///
/// ONE spelling and not two, because a TEST reads it. The daemon and
/// e2e suites' `adoptguard::refuse_a_solve_that_solved_nothing` parses
/// these counts out of the log to refuse a repair that rebuilt nothing
/// from parity and adopted the lot; a clause hand-copied at two sites
/// is one the next rename catches and one it misses, and the half it
/// misses reads to that parser as a repair that adopted NOTHING. The
/// settle-time report went without any adoption clause at all until
/// 31 Aug 2026, for want of somewhere to share this from.
///
/// Empty when nothing was adopted, so the everyday line is unchanged.
pub fn adopted_from_clause(adopted: usize, from: &[String]) -> String {
    if adopted == 0 {
        String::new()
    } else {
        format!(", {adopted} block(s) adopted from {}", from.join(", "))
    }
}

/// The `, N file(s) published anyway` clause of a SHORTFALL verdict -
/// the rendering of what [`RepairStatus::Unrepairable`]'s `partial`
/// managed to land.
///
/// ONE spelling and not four, for [`adopted_from_clause`]'s reason: the
/// same sentence is printed by the in-place repair report, the nested
/// set report, the settle-time disk fallback and the late-set pass, and
/// a clause hand-copied at four sites is one the next rename catches and
/// three it misses.
///
/// Empty when a shortfall published nothing, which is the everyday case,
/// so the ordinary UNREPAIRABLE line is unchanged.
pub fn published_clause(partial: &RepairReport) -> String {
    if partial.files_patched.is_empty() {
        String::new()
    } else {
        format!(
            ", {} file(s) individually verified and published anyway",
            partial.files_patched.len()
        )
    }
}

impl RepairReport {
    /// Did this repair have bytes of `name` ALREADY ON DISK to work
    /// from - so that the set has matched one of its own FileDesc/IFSC
    /// hashes against bytes something else put here?
    ///
    /// That match is cryptographic evidence the set belongs where it
    /// ran, and it is the question a caller deciding whether to KEEP a
    /// reconstructed file needs answered per FILE. Two ways to be true:
    /// the file already existed and was patched, or it was created and
    /// the adoption scan found blocks of it elsewhere.
    ///
    /// # It fails CLOSED, on purpose
    ///
    /// `true` is the ungated answer, and every uncertainty resolves to
    /// it: a name this repair never mentions, a name with no census
    /// entry, or one of two same-named entries adopting. Granting a
    /// file evidence it may not own leaves a rebuild in place that a
    /// tighter rule would have dropped; withholding evidence a file DOES
    /// own deletes bytes the repair verified. The first is recoverable
    /// and the second is not, so the doubt goes that way.
    pub fn file_had_bytes_on_disk(&self, name: &str) -> bool {
        // Not created means it was on disk when the repair began - that
        // IS bytes of its own, whatever adoption did or did not find.
        if !self.files_created.iter().any(|n| n == name) {
            return true;
        }
        let mut seen = false;
        for f in self.per_file.iter().filter(|f| f.name == name) {
            seen = true;
            if f.blocks_adopted > 0 {
                return true;
            }
        }
        // A created file the census does not know about: the census is
        // built from the same targets `files_created` is, so this is a
        // defect rather than a state - and an unknown answer is the
        // ungated one.
        !seen
    }
}

/// One entry per target, in the set's own file order, counting the
/// blocks each one owes to Reed-Solomon and to adoption.
///
/// Attribution is by GLOBAL SLICE INDEX rather than by anything the
/// patch loop records, because that loop runs later and only over
/// damaged targets: this is the same `first_slice .. first_slice +
/// n_slices` layout the repair itself resolves `g` through, read the
/// other way round.
pub(super) fn per_file_census(
    targets: &[Target],
    adopted: &HashMap<usize, AdoptSrc>,
    missing: &[usize],
) -> Vec<FileRepair> {
    let mut out: Vec<FileRepair> = targets
        .iter()
        .map(|t| FileRepair {
            name: t.file.name.clone(),
            blocks_rebuilt: 0,
            blocks_adopted: 0,
            path: t.path.clone(),
        })
        .collect();
    // The last target whose range STARTS at or below `g`, then a bounds
    // check against its own length. A zero-length FileDesc owns no
    // slices and shares its `first_slice` with whatever follows, so the
    // `<=` lands on the follower and never on the empty one.
    let owner = |g: usize| -> Option<usize> {
        let i = targets
            .partition_point(|t| t.first_slice <= g)
            .checked_sub(1)?;
        (g < targets[i].first_slice.saturating_add(targets[i].n_slices)).then_some(i)
    };
    for &g in missing {
        if let Some(i) = owner(g) {
            out[i].blocks_rebuilt += 1;
        }
    }
    for &g in adopted.keys() {
        if let Some(i) = owner(g) {
            out[i].blocks_adopted += 1;
        }
    }
    out
}

/// Beside the type rather than in `par2repair/unit_tests.rs`, where it
/// was first written: that file is the DIRECTORY repair path's suite -
/// real packet files, real repairs - and this needs no filesystem at
/// all, only a `RepairReport` built by hand. It also put that file over
/// the size gate's ceiling on the way past, which is what prompted
/// reading where it actually belonged.
#[cfg(test)]
mod tests {
    use super::*;

    /// `RepairReport::file_had_bytes_on_disk` fails CLOSED, and the arms
    /// that do so cannot be reached through a real repair.
    ///
    /// The method is the X5-24 gate's question (see
    /// `nzbfast::get::latesets`), so `false` is the answer that DELETES a
    /// rebuilt file. Every uncertainty therefore has to answer `true`: a
    /// name the repair never mentions, a created name the census somehow
    /// does not carry, and - the one no fixture on disk can produce,
    /// because it needs two FileDescs declaring the SAME name - a duplicate
    /// where only one of the two adopted.
    #[test]
    fn file_had_bytes_on_disk_answers_true_wherever_it_cannot_be_sure() {
        let rep = |created: &[&str], per: &[(&str, usize)]| RepairReport {
            blocks_rebuilt: 0,
            blocks_adopted: per.iter().map(|&(_, a)| a).sum(),
            adopted_from: Vec::new(),
            files_patched: created.iter().map(|s| s.to_string()).collect(),
            files_created: created.iter().map(|s| s.to_string()).collect(),
            consumed_sources: Vec::new(),
            per_file: per
                .iter()
                .map(|&(n, a)| FileRepair {
                    name: n.to_string(),
                    blocks_rebuilt: 0,
                    blocks_adopted: a,
                    path: PathBuf::from(n),
                })
                .collect(),
        };

        // The two real answers.
        let r = rep(&["a.bin", "b.bin"], &[("a.bin", 3), ("b.bin", 0)]);
        assert!(r.file_had_bytes_on_disk("a.bin"), "it adopted");
        assert!(
            !r.file_had_bytes_on_disk("b.bin"),
            "a SIBLING's donor is not this member's evidence - the whole \
             point of the per-file census"
        );

        // Not created at all: it was on disk when the repair began.
        assert!(
            r.file_had_bytes_on_disk("never.mentioned.bin"),
            "a name outside files_created was not created by this repair"
        );

        // Created, but the census does not carry it. A defect rather than a
        // state, and the ungated answer is the one that keeps the file.
        assert!(
            rep(&["c.bin"], &[]).file_had_bytes_on_disk("c.bin"),
            "an absent census entry must not read as `no adoption`"
        );

        // Two FileDescs, one name. They get distinct PATHS, so a caller
        // cannot tell which of the two the file on disk is; ANY of them
        // adopting therefore has to excuse it.
        let dup = rep(&["d.bin"], &[("d.bin", 0), ("d.bin", 2)]);
        assert!(
            dup.file_had_bytes_on_disk("d.bin"),
            "one of two same-named targets adopted - that is doubt, and \
             doubt keeps the file"
        );
        let dup_none = rep(&["d.bin"], &[("d.bin", 0), ("d.bin", 0)]);
        assert!(
            !dup_none.file_had_bytes_on_disk("d.bin"),
            "neither of them adopted, so there is no doubt to resolve"
        );
    }
}
