//! The external par2cmdline rung: whether to take it, the invocation it
//! builds, the run itself with our own handles released, and the
//! clear-up afterwards.
//!
//! Its own file for `nativepass`'s and `volbase`'s reason. On 31 Aug 2026
//! repair.rs sat at 2,990 of the size gate's flat 3,000-line FILE
//! ceiling - ten lines free, the narrowest file margin in the tree, and
//! no `BASELINE_FILES` entry to absorb it - having gone +192 lines in
//! under four hours across sixteen commits, and having already been
//! split once inside that window. PAST TENSE on purpose: this move is
//! what fixed the margin, so a present-tense "is at the ceiling" here
//! would be false the moment it was written.
//!
//! ONE SUBJECT, MOVED VERBATIM. The only edits are visibility prefixes,
//! on the items the parent or one of its descendants names. Nothing in
//! here CALLS anything that stayed behind: the references to
//! [`super::fetch_and_repair`], [`super::shortfall_is_final`],
//! [`super::recovery_candidates`] and [`super::pick_volumes`] are every
//! one of them prose, which is what made the call graph closed enough to
//! lift in one piece.

use super::*;

/// Run the external par2 binary over `out_dir` with OUR handles released.
///
/// par2cmdline 0.8.1 opens every target and every extra file with no
/// sharing, so a handle we still hold makes its open fail - and it does not
/// treat that as an error to report, it treats the file as ABSENT. Measured
/// on Windows before this parked anything, on a set with one corrupt article:
///
/// ```text
/// Could not open ".\testset.par2": ...used by another process.
/// Could not open ".\payload.bin":  ...used by another process.
/// Target: "payload.bin" - missing.
/// Repair is required. Repair is not possible.
/// You need 1600 more recovery blocks to be able to repair.
/// ```
///
/// A whole-file "missing" verdict needs the entire file's worth of recovery
/// blocks, so the fallback could never repair anything on Windows no matter
/// how much recovery the poster shipped. Unix does not enforce sharing, which
/// is why this went unnoticed until the suite first ran on Windows.
///
/// The VERSION is part of that claim and the paragraph above used to state
/// it flat. Measured on x86-64 Windows 11, 22 Aug 2026, holding a reader
/// handle across a repair: 0.8.1 fails as above, 1.2.0 and 1.3.0 both repair
/// fine. So the park is no longer load-bearing on a current par2 - and it
/// stays anyway, because a Windows user runs whatever par2 they installed.
/// The full matrix is in `nzbfast/tests/integration/stream_repair.rs`,
/// which drives this function for real. What does NOT vary across those
/// three: none of them repairs in place, all rename the damaged target
/// aside (see `purge_par2_backups`).
///
/// The writers are unparked on EVERY path - including a failed park and a
/// failed spawn - because `finish()` still has to settle groups, verify inner
/// CRCs and run the decrypt pass through these same writers. Returning early
/// from a half-parked extractor would instead fail each of those writes one by
/// one, a long way from the cause.
///
/// The two failure kinds are kept apart deliberately. The OUTER result is a
/// handle-discipline failure and aborts the job: a park failure is a SYNC
/// failure (buffered pwrites never reached disk, so par2 would "repair"
/// against a stale file and overwrite bytes we were about to land), and an
/// unpark failure means our own outputs are no longer openable. Neither is
/// something to continue past. The INNER result is just "did the tool run",
/// which the caller already handles - a missing par2 binary is an ordinary
/// outcome here, and folding it in with the above would report a broken sync
/// as "no par2 installed".
pub(crate) fn run_external_par2(
    par2_bin: &std::path::Path,
    par2_arg: &std::path::Path,
    extra_args: &[std::path::PathBuf],
    out_dir: &std::path::Path,
    // (name, length) of every file the recovery set declares - the repair
    // targets, and so the only names whose `.N` siblings may be purged
    // below. Read for its names only; the caller already has this vector
    // for `publish_external_coverage`.
    targets: &[(String, u64)],
    extractor: &nzbkit::extract::Extractor,
) -> Result<std::io::Result<std::process::ExitStatus>> {
    // Taken before the child runs, and the whole reason the purge below
    // can be safe: it names exactly the backups par2 made THIS run.
    let before = dir_entry_names(out_dir);
    if before.is_none() {
        warn!(target: "repair", "could not snapshot {} before the external repair - its backups stay", out_dir.display());
    }
    let parked = extractor.park_outputs_for_repair();
    let status = parked.is_ok().then(|| {
        std::process::Command::new(par2_bin)
            .arg("repair")
            .arg("-q")
            .arg(par2_arg)
            .args(extra_args)
            .current_dir(out_dir)
            .status()
    });
    // Unconditional, and BEFORE either `?` below.
    let unparked = extractor.unpark_outputs();
    parked.context("releasing our output handles for the external par2")?;
    unparked.context("reopening our output handles after the external par2")?;
    let status = status.expect("status is Some whenever the park succeeded");
    if let Some(before) = &before
        && matches!(&status, Ok(st) if st.success())
    {
        purge_par2_backups(out_dir, targets, before);
    }
    Ok(status)
}

/// File names directly in `dir`, or `None` when the directory or ANY
/// entry could not be read. The purge treats a name absent from this
/// set as par2's new backup, so a partial snapshot would make every
/// pre-existing `<target>.N` look new and delete it (22 Aug 2026, Codex
/// F-06): an incomplete snapshot therefore disables the purge instead.
pub(super) fn dir_entry_names(
    dir: &std::path::Path,
) -> Option<std::collections::HashSet<std::ffi::OsString>> {
    std::fs::read_dir(dir)
        .ok()?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<std::io::Result<_>>()
        .ok()
}

/// Remove the `<target>.1` backups par2cmdline leaves behind on a
/// successful repair.
///
/// par2 does not repair a damaged target in place: it renames the damaged
/// file to `<name>.1` (`.2`, `.3`… if that is taken) and writes the
/// repaired data to a new file under the original name. Nothing cleared
/// those, and on a multi-volume RAR set one of them FAILS THE WHOLE JOB:
/// the post-unpack sweep collects candidates by `Rar!` magic rather than
/// by extension, reads a leftover `r.part3.rar.1` as an obfuscated set of
/// its own, cannot unpack a middle volume that has no first part, and
/// reports "an archive in the output directory could not be unpacked" -
/// with the correct payload sitting beside it. Found 22 Aug 2026 while
/// verifying sweep 8 M4 on the external path
/// (`tests/integration/stream_repair.rs`), reproduced on macOS and on
/// Windows.
///
/// **Why not par2's own `-p`.** One flag, and it purges its backups for
/// us - but it also purges the `.par2` files, which is not ours to
/// decide: whether those survive the job is the user's `cleanup_exts`
/// setting, and `-p` would delete them under every setting. It is also a
/// flag we cannot count on - par2cmdline 0.8.1 is still in the field on
/// Windows (see the version table in the M4 write-up), and an unknown
/// switch does not degrade, it fails the repair. Measured against
/// par2cmdline 1.2.0: `-p` removed the par2 files and its own new backup
/// and left EARLIER `.1`/`.2` backups exactly where they were, so it does
/// not even subsume this.
///
/// Three guards, because this deletes from a user's output directory:
///
///  * **only on a successful repair.** par2 exits 0 only when every
///    target verifies afterwards, so the backup is then a damaged
///    duplicate of a file we have just proved good. After a FAILED
///    repair the backup may be the only copy of the original bytes, and
///    nothing here touches it.
///  * **only names that appeared during the run.** A `.1` that predates
///    the child is not par2's backup and is not ours to delete.
///  * **only `<target>.<digits>` for a name the recovery set declares**,
///    and never a name the set declares itself - a set carrying both
///    `foo.rar` and `foo.rar.1` as targets keeps both.
///
/// The delete goes through the sweeps' own `remove_swept_file`, so it
/// honours the trash-vs-delete setting exactly like the junk and par2
/// sweeps do. A failure is logged and otherwise ignored: a backup we
/// could not remove is untidy, never a reason to fail a repaired job.
pub(super) fn purge_par2_backups(
    out_dir: &std::path::Path,
    targets: &[(String, u64)],
    before: &std::collections::HashSet<std::ffi::OsString>,
) {
    let names: std::collections::HashSet<&str> = targets.iter().map(|(n, _)| n.as_str()).collect();
    if names.is_empty() {
        return;
    }
    let recoverable = smart::cleanup_recoverable();
    let staging = smart::trash_staging_dir(out_dir);
    let mut purged = 0usize;
    for entry in std::fs::read_dir(out_dir).into_iter().flatten().flatten() {
        let raw = entry.file_name();
        if before.contains(&raw) {
            continue;
        }
        let Some(name) = raw.to_str() else { continue };
        // A set target is never a backup, whatever it is named.
        if names.contains(name) {
            continue;
        }
        let Some((stem, ordinal)) = name.rsplit_once('.') else {
            continue;
        };
        if ordinal.is_empty() || !ordinal.bytes().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if !names.contains(stem) || !entry.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        match smart::remove_swept_file(&entry.path(), recoverable, staging.as_deref()) {
            Ok(_) => purged += 1,
            Err(e) => warn!(target: "repair", "leftover par2 backup {name}: {e}"),
        }
    }
    if purged > 0 {
        info!(target: "repair", "removed {purged} par2 backup file(s) left by the external repair");
    }
}

/// Hand a verified external repair's new bytes to the live readers
/// (sweep 8, M5).
///
/// par2cmdline exits 0 only when every file in the set verifies AFTER
/// the repair, which is the verification this publication is tied to -
/// never the mere fact that the child exited. The writers' interval map
/// survives the park/unpark unchanged, so without this the ranges par2
/// filled in are still holes as far as `/stream` is concerned: a reader
/// that held its handle across the repair waits out its grace period on
/// bytes that are already correct on disk, and then zero-fills them.
pub(super) fn publish_external_coverage(
    extractor: &nzbkit::extract::Extractor,
    verified: &[(String, u64)],
) {
    let n = extractor.publish_repaired_coverage(verified);
    if n > 0 {
        info!(
            target: "repair",
            "published repaired coverage for {n} live output(s)"
        );
    }
}

/// Why the in-process Reed-Solomon pass did not finish the job - which
/// is what decides what the par2cmdline fallback is allowed to CLAIM
/// about itself. §282 item 16.
///
/// `nzbkit::par2repair` is a complete GF(2^16) implementation that goes
/// past par2cmdline in two documented ways (recovery volumes hidden
/// under junk names, found by packet magic where par2cmdline only loads
/// packets from files with ".par2" in the name; and identified-but-
/// damaged targets rescanned when damage still exceeds recovery). The
/// external binary is a CORRECTNESS BACKSTOP for a native bug - the
/// native path is self-proving, so it declines rather than shipping bad
/// bytes - plus the one real capability limit, `MAX_REPAIR_DIM`.
///
/// None of that applies to a set with no parity on disk, and telling a
/// user to install a tool in that case is telling them the wrong thing:
/// on the §282 incident the line above it read "145 block(s) damaged,
/// only 0 recovery block(s) on disk", and no par2 implementation can
/// rebuild data it has no parity for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NativeVerdict {
    /// The set is whole. Nothing below this runs.
    Done,
    /// The damage outruns the recovery blocks ON DISK. par2cmdline
    /// reads the same directory and would reach the same arithmetic.
    NoRecovery { needed: usize, have: usize },
    /// A native bug, the repair-dimension guard, an I/O error, or the
    /// kill switch: the cases the external backstop exists for.
    Backstop,
}

/// The "and adoption already found some of it" half of an unrepairable
/// verdict, shared by every surface that prints one.
///
/// `RepairReport::blocks_adopted` only reaches a caller through
/// `RepairStatus::Repaired`, so until 29 Aug 2026 a donation that
/// bridged SOME of the damage and still came up short left no trace on
/// any surface: the shortfall lines named `needed` and `have` and
/// nothing else. That is not a cosmetic gap. A bench round on 28 Aug
/// 2026 read `grep -c "block(s) adopted from" == 0` over a whole daemon
/// log and recorded "adoption bridged nothing" as an open question,
/// when the arithmetic in that same log (290 blocks bad at verify, 268
/// needed at the native verdict) says adoption had in fact found 22 of
/// them. The count is what tells a partial donation from no donation,
/// and it belongs wherever the shortfall is reported.
///
/// IT DOES NOT SAY WHERE, and until 31 Aug 2026 it did: the sentence
/// read "in files outside the recovery set", which is false on two of
/// the three paths that feed the count. `repair_dir_set_inner` fills
/// ONE `adopted` map from three writers and then reports its length -
/// `adopt::adopt_blocks` (extra files in the repair directory and the
/// §293 donor dirs, genuinely outside the set), `adopt::harvest_in_set`
/// (one member of the set standing in for a missing slice of another,
/// INSIDE it by definition), and the last-resort escalation's
/// `adopt::sliding_scan` over identified damaged targets, which are the
/// set's own declared members. On the two in-set paths the sentence
/// told the user the opposite of what had happened. Observed live on
/// `e2e_norar::twin_adopt::a_claimed_twin_donates_the_shared_head_it_declares_twice`,
/// which logs "adoption already found 10 of them in files outside the
/// recovery set" two lines above "10 block(s) adopted from
/// Twin.Beta.vob" - a file the set declares. The escalation predates
/// the clause by five weeks (0b04420b7, 21 Jul 2026, against c8aa87e78,
/// 28 Aug), so the claim was never true across all paths; it was
/// written from the donor path it was measured on.
///
/// "already on disk" is what survives, and it is not a retreat to
/// vagueness: it is true on all three paths, it pairs with the
/// `only {have} recovery block(s) on disk` half of the same sentence,
/// and it carries the contrast the original was reaching for - these
/// blocks cost no fetch and no solve, they were simply already there.
///
/// WHY THE SOURCES ARE NOT PLUMBED THROUGH INSTEAD, so this is not
/// reopened. `RepairReport::adopted_from` already holds the donor
/// names, and threading them onto `RepairStatus::Unrepairable` beside
/// the count is perhaps twenty sites of mechanical work: the two
/// construction sites in `par2repair`, the five callers of this
/// function, and the handful of matches that destructure the variant
/// rather than taking `..`. It was considered and declined on two
/// grounds. FIRST, nothing downstream of this line acts on the answer.
/// This is a FAILURE line - the repair did not happen and nothing was
/// written - and the verdict ("you do not have enough recovery data")
/// and the remedy (more parity, or the missing articles) are the same
/// whichever file the found blocks came out of. What changes the
/// reading is the ARITHMETIC, which is why the count is here at all.
/// SECOND, and this is the one that decided it: a per-source claim has
/// to be re-derived every time an adoption path is added, and failing
/// to do that is exactly how this defect was born. A count is true of
/// a fourth writer the day it lands; a location is not. If the names
/// are ever wanted here, take them from `adopted_from` rather than
/// classifying inside-versus-outside at the construction sites - the
/// success line already spells them that way ("N block(s) adopted from
/// <names>"), and one spelling is the whole point.
///
/// Empty when nothing was adopted, so the everyday line is unchanged.
pub(crate) fn adopted_clause(adopted: usize) -> String {
    if adopted == 0 {
        String::new()
    } else {
        format!(" (adoption already found {adopted} of them in files already on disk)")
    }
}

/// Report the native pass's shortfall and turn it into a verdict.
///
/// Out of line only because [`fetch_and_repair`] was at 498 of the size
/// gate's 500-line ceiling on 28 Aug 2026; the wording is the whole
/// point of it, so keep the two
/// together if that ever changes.
pub(super) fn native_shortfall(
    needed: usize,
    have: usize,
    adopted: usize,
    probe: bool,
) -> NativeVerdict {
    // The PROBE pass says the same arithmetic about a different moment,
    // and the ordinary phrasing reads as a defeat there: it runs BEFORE
    // any recovery volume has been bought, so "only 0 recovery block(s)
    // on disk" is the premise rather than the finding, and the caller
    // goes on to buy exactly `needed` of them. What that pass has to
    // report is the one number the fetch is about to be sized by.
    if probe {
        info!(
            target: "repair",
            "adoption scan first: {needed} block(s) still missing once the scan had \
             looked{}",
            adopted_clause(adopted)
        );
    } else {
        warn!(
            target: "repair",
            "native repair: {needed} block(s) damaged, only {have} recovery block(s) on disk{}",
            adopted_clause(adopted)
        );
    }
    NativeVerdict::NoRecovery { needed, have }
}

/// §293: the donor directories' files as par2cmdline extra-file
/// arguments - the fallback engine's version of the native scan's
/// donor candidates, so both engines see the same donors. ABSOLUTE
/// paths, unlike the `./`-prefixed in-dir names beside them: a donor
/// dir is outside par2's cwd, and the directory half of the path is
/// ours (the daemon built it from a job record), not subject-derived,
/// so the leading-dash switch trap does not apply to it; the file
/// names inside can still be hostile, which joining under the
/// absolute donor dir already defuses. Same skip rules as the native
/// scan: no .par2, no .nzbfast bookkeeping, same 1000-file bound.
fn donor_extra_args(donor_dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for donor in donor_dirs {
        out.extend(
            std::fs::read_dir(donor)
                .into_iter()
                .flatten()
                .filter_map(|e| {
                    let e = e.ok()?;
                    let p = e.path();
                    let name = p.file_name()?.to_string_lossy().into_owned();
                    (e.file_type().ok()?.is_file()
                        && !name.starts_with(".nzbfast")
                        && !p
                            .extension()
                            .is_some_and(|x| x.eq_ignore_ascii_case("par2")))
                    .then_some(p)
                })
                .take(1000),
        );
    }
    out
}

/// What a [`shortfall_is_final`] fall-through should actually BUY, once
/// the adoption scan has been allowed to look first (follow-up 13a-1,
/// 31 Aug 2026).
///
/// THE ORDER WAS BACKWARDS. That gate answers "is there anything on
/// disk for adoption to read"; it does NOT answer "how much of the
/// damage does adoption cover", and nothing did before the money was
/// spent. Its whole population is the branch where `have < needed`, so
/// [`fetch_and_repair`]'s `target` collapses to `have` and
/// [`pick_volumes`] buys EVERY recovery volume the NZB declares - for a
/// shape finding F7's own write-up says assembles "with zero recovery
/// spend". The adoption scan needs no recovery blocks at all: only the
/// Reed-Solomon solve does. So the engine runs FIRST, on whatever is
/// already on disk, and says what is still missing once it has looked.
///
/// MEASURED 31 Aug 2026 on 512 MB / 4 files / 768 KB blocks, real
/// `par2 create`, every recovery volume deleted so the directory is in
/// the state this function is called in. The rig and the raw runs are
/// in `research/ADOPT-SCAN-ORDER-2026-08-31.md`. Three arms, cheaper on
/// all three:
///
///   * ADOPTION CLOSES IT (an F7 obfuscated leftover): repairs in
///     0.83 s having bought NOTHING, where the old order first buys all
///     27 MB the NZB declares and then adopts 171 blocks and rebuilds
///     none. This arm pays no probe cost at all - the probe IS the
///     repair.
///   * ADOPTION BRIDGES PART OF IT: reports `needed: 69, adopted: 102`
///     against a ledger `needed` of 171, so the fetch is sized at 69
///     blocks rather than at the whole 103-block (80.6 MB) declared
///     set - about 27% of the recovery bytes. This is the ONLY arm that
///     pays an extra verify-plus-scan pass.
///   * ADOPTION CANNOT GET UNDER `have`: reports the honest
///     post-adoption arithmetic (`needed: 120` where the ledger said
///     171 against 34) and returns [`NarrowedNeed::Final`] having
///     bought nothing, where the old order buys all 27 MB and then
///     fails anyway. Here the probe REPLACES the post-fetch pass it now
///     never reaches, so it is cheaper in time as well as in bytes.
///
/// WHAT IT COSTS: 0.2-1.7 s over 512 MB on a loaded shared box, roughly
/// 0.4-3.4 s per GB of payload, CPU-bound here (verify ~1.9 GB/s, the
/// sliding scan ~1.7 GB/s) rather than disk-bound. Against it: recovery
/// is 5-15% of the payload, so 50-150 MB per GB, metered, and slower
/// than the probe over any line below a gigabit.
///
/// THE CHEAP GATE STAYS AND IS CONSULTED FIRST, which is the one place
/// this departs from what 13a-1 proposed. When [`shortfall_is_final`]
/// says FINAL there is nothing on disk worth reading and bailing costs
/// no I/O at all; probing to rediscover that is the single case where
/// this order would be strictly worse. So
/// [`repeated_block_donor_possible`], [`in_set_harvest_possible`] and
/// [`adoption_candidates_present`] are NOT retired - they keep their
/// value as the free pre-filter. What changes is the price of a FALSE
/// YES from any of them: one scan of files this job has just written,
/// instead of every recovery volume the post has.
///
/// That is also how follow-up 13a-2 is settled, and it is settled
/// differently from how it was framed. Those predicates still cannot
/// tell WHICH member is damaged. They no longer have to: they were
/// asked to be right because their answer was the last word, and they
/// are now asked only to be cheap, because the engine gets the last
/// word.
///
/// A PROBE THAT COMES UP SHORT WRITES NOTHING, which is what makes
/// running the engine twice safe. `repair_dir_set_inner` returns
/// `Unrepairable` before `check_repair_dim`, before the solve and
/// before any patch or rename, so the only writes on that path are
/// none. Verified rather than reasoned: sha256 over every file in the
/// directory either side of a failing probe, on both the no-adoption
/// and the all-targets-damaged fixture. Byte-identical both times.
///
/// TWO DIFFERENT QUANTITIES MEET HERE and the subtraction between them
/// is load-bearing. The engine reports its TOTAL post-adoption missing
/// count alongside what it already holds on disk; this function's
/// `needed` is the caller's, and that one is ADDITIONAL - `settle.rs`
/// builds it as `damage_by_set[si] - on_hand[si]`, and
/// [`recovery_candidates`] drops the `already_fetched` volumes to
/// match. Comparing the engine's total against the caller's remainder
/// overstates the need by every block a bootstrap, sniffed or
/// resume-recognised volume already put on disk, which on the
/// [`NarrowedNeed::Final`] arm would declare a BUYABLE post
/// unrepairable. The in-stream bootstrap volume is the ordinary case,
/// not a corner.
///
/// SKIPPED WHEN A DECLINED MAPPED ATTEMPT BANKED VOLUMES. The reuse
/// comparison in [`fetch_and_repair`] is [`pick_volumes`] over the same
/// `needed` reaching the same subset, and narrowing `needed` breaks
/// that identity and re-buys volumes already on disk. Narrow case - it
/// needs a mapped repair that fetched and then declined - and the old
/// order is correct there, so it keeps it.
///
/// A BACKSTOP VERDICT KEEPS THE OLD ORDER TOO. With
/// `NZBFAST_NO_NATIVE_REPAIR` set, or on an engine error, there is no
/// post-adoption count to size a fetch with: par2cmdline adopts as
/// well, but its exit code cannot say how many blocks it found. So that
/// path buys what it always bought.
///
/// [`NarrowedNeed::Final`] DECLINES WITHOUT GIVING par2cmdline A TURN,
/// and that is the same decision [`shortfall_is_final`] already makes
/// two lines above it - when that gate says FINAL the external backstop
/// never runs either, and nobody calls it a defect. The difference is
/// only the evidence: that one bails on the ledger's arithmetic with
/// nothing scanned, this one bails on the engine's own post-adoption
/// count with everything on disk read. Falling through instead would
/// buy nothing here and then buy EVERYTHING at the escalation, which is
/// the cost this whole reordering exists to stop.
///
/// TWO STATED LIMITS. This is scoped to `have < needed`, so a post that
/// adoption alone could fix while carrying ample declared parity still
/// buys parity it does not need - probing there would tax every
/// ordinary repair for nothing. And sizing the fetch at `after` plus
/// the margin means par2's own accounting can outrun it, in which case
/// the escalation buys the remainder: the same bytes as the old order
/// plus one probe, never a worse verdict. The escalation's gate is
/// `missing.len() > by_exp.len()`, which is exactly "I am short", so it
/// self-corrects - and that same gate is why the probe (which runs with
/// no recovery on disk, so it always escalates) adopts at least as much
/// as the post-fetch pass will, making its `needed` a lower bound in
/// the safe direction.
///
/// THE FIRST OF THOSE TWO IS HALF WRONG, AND THE SCOPE IS STILL RIGHT.
/// Priced 31 Aug 2026 in
/// `research/ADOPT-PROBE-AMPLE-PARITY-2026-08-31.md` (claim
/// `adopt-probe-ample-parity-price`), which reproduced the defect: on
/// that branch a job buys a right-sized 39.05 MB of recovery and then
/// repairs by adopting every block and rebuilding NONE. What is wrong
/// is "would tax every ordinary repair" - the tax is avoidable, since a
/// stat per declared name excludes the ordinary repair in under a tenth
/// of a millisecond, where `adoption_candidates_present` would admit it
/// merely for carrying an `.nfo` the recovery set does not cover.
///
/// What holds the scope where it is, is frequency and arithmetic. The
/// shape that limit has in mind - a whole file present on disk under a
/// hash name - is claimed by CONTENT long before this runs, by
/// `nzbkit::live`'s md5-16k tier, so it never prices as damage at all;
/// the one surviving route that could be common turns on an open
/// question about what an obfuscated post's FileDescs NAME; and the
/// break-even hit rate is 4.5% on a 100 Mbit line against 45% at
/// gigabit, because the probe costs 0.24-0.66 s per GB of PAYLOAD while
/// the fetch it saves is sized by the missing MEMBER. So do not widen
/// this on the strength of the defect being real - it is, and it
/// reproduces. Section 7 of that document lists the four things that
/// would flip it, and section 6 says to build the cheap probe rather
/// than this one if it is ever built at all.
pub(super) fn adoption_narrowed_need(
    needed: usize,
    have: usize,
    banked: &[usize],
    native_repair: &dyn Fn(bool) -> NativeVerdict,
) -> NarrowedNeed {
    if needed <= have || !banked.is_empty() {
        return NarrowedNeed::Buy(needed);
    }
    match native_repair(true) {
        NativeVerdict::Done => NarrowedNeed::Repaired,
        // THE TWO SIDES ARE DIFFERENT QUANTITIES AND SUBTRACTING IS
        // NOT OPTIONAL. `after` is the engine's TOTAL post-adoption
        // missing count - `missing.len()`, the recovery blocks the
        // solve would consume - and `on_disk` is `by_exp.len()`, what
        // it already holds. This function's `needed` is the caller's,
        // and that one is ADDITIONAL: `settle.rs` builds it as
        // `damage_by_set[si] - on_hand[si]`, and `recovery_candidates`
        // drops the `already_fetched` volumes from `vols` to match. So
        // the comparable figure is `after - on_disk`, and using `after`
        // raw overstates the need by every block a bootstrap, sniffed
        // or resume-recognised volume already put on disk - which on
        // the [`NarrowedNeed::Final`] arm would declare a BUYABLE post
        // unrepairable. The in-stream bootstrap volume is the ordinary
        // case, not a corner.
        NativeVerdict::NoRecovery {
            needed: after,
            have: on_disk,
        } => {
            let extra = after.saturating_sub(on_disk);
            if extra > have {
                warn!(
                    target: "repair",
                    "unrepairable after the adoption scan: {extra} more recovery \
                     block(s) still needed, only {have} left in the NZB - not \
                     buying recovery that cannot close it"
                );
                return NarrowedNeed::Final { needed: extra };
            }
            if extra < needed {
                info!(
                    target: "repair",
                    "the adoption scan covered {} of {needed} block(s) - buying \
                     recovery for the remaining {extra}, not for all {have}",
                    needed - extra
                );
            }
            NarrowedNeed::Buy(extra)
        }
        NativeVerdict::Backstop => NarrowedNeed::Buy(needed),
    }
}

/// [`adoption_narrowed_need`]'s three answers.
///
/// `Debug` for the assertion messages in `shortfall_gate_tests`: the
/// figure carried is the whole finding on two of the three arms, so a
/// failure that cannot print it says nothing useful.
#[derive(Debug)]
pub(super) enum NarrowedNeed {
    /// The scan closed the whole gap: the set is repaired and no
    /// recovery volume was ever bought.
    Repaired,
    /// Buy for this many blocks - the ledger's own count where the
    /// probe did not run, the POST-ADOPTION shortfall where it did.
    Buy(usize),
    /// Nothing the NZB still has to sell can close it.
    Final { needed: usize },
}

/// The par2cmdline invocation for this set: (binary, set argument, extra
/// file arguments).
///
/// Out of line only because [`fetch_and_repair`] was at 498 of the size
/// gate's 500-line ceiling on 28 Aug 2026; the body is a verbatim move, and the reasoning inside it is
/// all about arguments par2cmdline reads, so it travels with them.
pub(super) fn par2cmdline_invocation(
    main_par2: &Path,
    out_dir: &Path,
    donor_dirs: &[PathBuf],
) -> (PathBuf, PathBuf, Vec<PathBuf>) {
    // Sibling binary, else PATH (see tools.rs).
    let par2_bin = tools::resolve("par2");
    // par2cmdline 1.2.0 rejects absolute par2 paths ("failed to set the
    // main par file") - pass the bare name and set cwd.
    let par2_name = main_par2
        .file_name()
        .map(|n| n.to_owned())
        .unwrap_or_else(|| main_par2.to_path_buf().into_os_string());
    // Every non-par2 file in the dir rides along as an extra file so
    // par2cmdline's sliding scan can adopt misnamed/shifted data - bare
    // `par2 repair <set>` never looks at files it wasn't told about.
    //
    // Our OWN bookkeeping is excluded (`.nzbfast*`, the house convention for
    // internal names - see disk.rs). `.nzbfast.journal` is the live record of
    // what is still missing and it is held open for the whole download: naming
    // it here made par2 try to open it, fail on Windows, and print a scary
    // "could not access" line about a file that was never a repair candidate.
    // It cannot contribute blocks either - it is not in the recovery set.
    let extra_files: Vec<std::ffi::OsString> = std::fs::read_dir(out_dir)
        .into_iter()
        .flatten()
        .filter_map(|e| {
            let e = e.ok()?;
            let p = e.path();
            let name = p.file_name()?.to_owned();
            (e.file_type().ok()?.is_file()
                && !name.to_string_lossy().starts_with(".nzbfast")
                && !p
                    .extension()
                    .is_some_and(|x| x.eq_ignore_ascii_case("par2")))
            .then_some(name)
        })
        .take(1000)
        .collect();
    // par2cmdline parses any leading-dash argument as a SWITCH, and both the
    // set name and every extra filename are attacker-controlled (they come
    // from yEnc/subject names; sanitize_filename keeps a leading '-'). A file
    // named `-p` would trigger "purge", `-B<path>` would redirect the
    // basepath, etc. Prefix each with `./` (platform-correct via Path::join,
    // cwd is out_dir) so they can only ever be read as paths.
    let dot = std::path::Path::new(".");
    let par2_arg = dot.join(&par2_name);
    let mut extra_args: Vec<std::path::PathBuf> = extra_files.iter().map(|f| dot.join(f)).collect();
    extra_args.extend(donor_extra_args(donor_dirs));
    (par2_bin, par2_arg, extra_args)
}
