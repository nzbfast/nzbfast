//! Extra-file adoption: finding a missing slice's bytes in a file the
//! recovery set never named. Moved out of par2repair.rs bodily under the
//! size gate (TODO 106), same child-module shape as `reconstruct` - a
//! child of the defining module, so the parent's private types
//! (`Target`, `AdoptSrc`, `RollingCrc`) and `use` bindings stay in scope
//! exactly as they were inline.
//!
//! Candidates are INDEPENDENT files, so both passes fan out across them
//! (R2 / N11 - this was the last serial payload-sized pass in a file
//! where the syndrome feed, the hash verify and the patch write were all
//! parallelized already), and since 16 Sep 2026 the sliding scan also
//! fans out WITHIN one, because across-candidates alone leaves the
//! shape that pays adoption most - a single wholly-unidentified member,
//! `indices.len() == 1` - on one core of a wide box (claim
//! `par2-adoption-scan-within-candidate-16sep`,
//! `research/PAR2-ADOPTION-DOUBLE-READ-2026-09-16.md`). The whole point of the parallel shape is that
//! it must not change a single adoption decision: `adopted_from`,
//! `consumed_sources` and the bytes a slice is read from are all
//! reported, so "first candidate in sorted order wins, at its first
//! matching offset" has to survive the fan-out exactly. How each pass
//! earns that is spelled out at [`sliding_scan`] and [`adopt_blocks`].

//! WHY A PARTIAL DONATION IS REPORTED ON THE *UNREPAIRABLE* VERDICT
//! (29 Aug 2026). [`RepairReport::blocks_adopted`] only reaches a
//! caller through `RepairStatus::Repaired`, so a donation that bridged
//! SOME of the damage and still came up short used to leave no trace
//! on any surface: every shortfall line named `needed` and `have` and
//! nothing else. That is not cosmetic. A bench round on 28 Aug 2026
//! counted `block(s) adopted from` over a whole daemon log, found
//! zero, and recorded "the donor bridged nothing" as an open question
//! - while the arithmetic in that same log (290 blocks bad at verify,
//! 268 needed at the native verdict) says adoption had in fact found
//! 22 of them and the repair was simply still short. The count is what
//! separates a partial donation from no donation, so
//! `RepairStatus::Unrepairable` carries it too.
//!
//! What that round also measured, and it is the thing to check before
//! reading a low adoption count as a defect: adoption is a BLOCK-level
//! mechanism, so two postings damaged at disjoint ARTICLE positions
//! are not disjoint to it. That set's PAR2 block was 1,536,000 bytes
//! and its articles 768,000, exactly two per block, so a stride-2
//! article mask poisons every block spanning an eligible pair in BOTH
//! postings - the two logs report the identical `13/14 blocks bad` per
//! volume. Only the block at the edge of the damaged range can be
//! donated. `a_donor_damaged_at_the_complementary_article_phase_*` in
//! `unit_tests.rs` pins both halves of that arithmetic.

use super::*;
use std::io::Seek;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The name of the environment variable [`disabled_for_screen`] reads.
pub(crate) const NO_ADOPTION_ENV: &str = "NZBFAST_TEST_NO_ADOPTION";

/// **The deterministic screen for the repeating-payload trap** (4 Sep
/// 2026, `research/PAYLOAD-TRAP-PATH-DEPENDENT-CENSUS-2026-09-04.md`).
/// When true, every writer of a repair's `adopted` map is skipped, so a
/// repair can only come out of the recovery set.
///
/// WHY THIS EXISTS. `adoptguard::refuse_a_solve_that_solved_nothing`
/// sees only the route a run actually took. A fixture whose repair
/// route is decided by a thread-scheduling race - which tier claims a
/// damaged slot in `live/twintier.rs` is one such race, with a
/// microsecond margin - can be in the trap on its MINORITY path and
/// stay green for months, and the concurrency needed to see it is in no
/// local sweep. Replaying races is slow, probabilistic, and a clean
/// result proves very little. Turning adoption OFF asks the question
/// directly instead: a fixture that still repairs is trap-free on every
/// path, whether or not a race has ever shown one.
///
/// OUT OF PRODUCTION REACH, the way `nzbfast_core::identity::may_call_out`
/// is. The env read is behind a `cfg!` that is const-false in a build
/// without `test-support`, so the shipped binary
/// (`cargo build -p nzbfast`, no dev-dependencies) does not contain it
/// and no variable can reach it. `crates/nzbfast/Cargo.toml` turns the
/// feature on through a DEV dependency on `nzbkit`, which is what puts
/// the lever in the `nzbfast` binary the e2e suite SPAWNS - the
/// production cfg is untouched, and must stay so.
///
/// NOT A GATE and not on by default: nothing in CI sets it. It is an
/// instrument a lane points at the suite, and the census it produced is
/// the record.
pub(crate) fn disabled_for_screen() -> bool {
    if cfg!(test) || cfg!(feature = "test-support") {
        return std::env::var_os(NO_ADOPTION_ENV).is_some();
    }
    false
}

/// Files eligible as adoption sources: every regular file under `dir`
/// that is not this directory's own recovery data (see
/// [`is_recovery_by_name_and_content`] - `.par2` is where that question
/// starts and no longer where it ends) and not an identified target
/// (identified files' bytes are already pinned block-by-block -
/// scanning them again is the perf trap this gate exists to avoid),
/// followed by every such file under each
/// DONOR directory (§293 - a failed predecessor's output, offered to
/// this set's adoption scan).
///
/// UNDER, not IN, since wave-4 row X6-02 (31 Aug 2026). This was a flat
/// `read_dir` filtered on `is_file()`, and the relpath-preserve ruling
/// (29 Aug 2026) means targets resolve INTO subdirectories - `par2repair.rs`
/// joins every FileDesc through `sanitize_out_name`, so a set spelling
/// `VIDEO_TS/VTS_01_1.VOB` has its target a directory down. A directory
/// fails `is_file()` in one step, so on such a set the candidate list
/// and the `identified` set were disjoint BY CONSTRUCTION: nothing was
/// ever excluded as identified because nothing was ever a candidate,
/// and a member sitting intact one directory away - here or on a
/// donor - was priced wholly missing with no error and no log line.
///
/// It walks through [`super::nested::walk_files`], which is the SAME
/// walk `walk_candidates` and `nested_subdirs` use at its existing
/// unbudgeted arm, so depth, directories, entries and the symlink rule
/// are decided in one place rather than by a scanner of this module's
/// own. Symlinks are still not followed - a `DirEntry`'s file type is
/// an `lstat`, which is the historical answer for a symlinked FILE and
/// is what makes "no yielded path leaves `dir`" true now that there is
/// depth to escape through. That matters most for a DONOR, which is a
/// directory this job does not own.
///
/// One tolerance moved with the walk and is worth knowing: a file whose
/// metadata cannot be read DURING the walk is now skipped rather than
/// failing the repair, in `dir` as well as on a donor. The ownership
/// split below is about the READS after the walk and is unchanged.
///
/// Order is load-bearing: the repair dir's own files come FIRST, then
/// each donor directory in the order given, each group sorted - so the
/// first-candidate-wins adoption semantics prefer the bytes that
/// already live where the repair lands over a donor's copy of them.
///
/// Within a group a candidate at a name a NEIGHBOURING set in this
/// directory declares sorts LAST, and that is the whole of the
/// 20 Sep 2026 ordering change (claim
/// `parfast-adoption-order-demote-declared-20sep`,
/// `research/PARFAST-WHOLE-DIR-EXTRA-SCAN-COST-2026-09-20.md`
/// section 7 option B). DEMOTED, NEVER EXCLUDED: a neighbour that
/// really does hold our bytes is still found, just after ours - which
/// is the difference between this and the narrowed wildcard that makes
/// par2cmdline-turbo FAIL the multi-set job this engine completes
/// (`research/SAB-MULTISET-WILDCARD-2026-09-20.md`).
///
/// It is worth what it is worth because of [`sliding_scan`]'s early
/// exit: `ScanShared::settled_at` cuts the scan from a position
/// onwards once every wanted slice is covered, so the order decides how
/// much of the folder is read before the cut fires. That note measured
/// 8 GiB of neighbouring set costing +192.87 G instructions when the
/// obfuscated donor's token happened to sort BEFORE the neighbour's
/// members and +313.66 G when it sorted after - the only difference
/// being the token's first character - and the `late` slope is linear
/// and unbounded at 39.3 G per neighbour GiB, where `early` saturates
/// at the fan-out. This makes every post the `early` arm.
///
/// The predicate is `ctx.declared`, threaded down: the directory-wide
/// set of every FileDesc name any set declares, already computed by
/// `PacketCatalog::declared_and_contested` before this runs, and
/// already the rule [`is_somebodys_payload`] states. It lands the right
/// way round by construction - an obfuscated donor is NOT at a declared
/// name, which is what makes it obfuscated, so it is never demoted,
/// while a neighbour's member at the name its own set gives it always
/// is. OUR OWN set's declared names are taken back out
/// ([`declared_by_name`] says why): an unidentified target of this set
/// is a candidate deliberately - a member whose bytes are SHIFTED is
/// found by rolling over its own file - and demoting it would give away
/// the single-set case to buy the multi-set one.
///
/// WHAT IT DOES NOT REACH: a neighbouring set whose members are
/// themselves obfuscated. No declared name matches, nothing is demoted,
/// and that folder costs what it always did.
///
/// Within a group the sort key is (DEPTH, path) and not the path alone,
/// which is a consequence of the widening above rather than a
/// preference. A plain path sort puts `VIDEO_TS/z.bin` in FRONT of
/// `zz.bin`, so it reorders the root against itself on any tree post;
/// depth first keeps the shallowest copy of a name winning that race,
/// and gives the stronger property that a directory with no
/// subdirectories yields byte-for-byte the list it always did, in its
/// old order. That is the standard the fan-out in this module is held
/// to at [`sliding_scan`], applied to the reach: it may widen, an
/// adoption decision on an unchanged tree may not.
///
/// DUPLICATES ARE FOLDED, by the same filesystem identity key as the
/// exclusions below, first occurrence kept. `get::latesets` hands this
/// function `par2repair::nested_subdirs(out_dir)` as DONORS - a
/// workaround for this very defect, offering each subdirectory of the
/// job as though it were a foreign directory - so with the walk fixed
/// every file under it arrives TWICE, once from the repair dir's own
/// recursion and once as a donor. Folding makes that redundancy
/// harmless rather than a candidate list scanned and proven twice, and
/// keeps `consumed_sources` from naming one file two ways. Retiring the
/// workaround belongs to whoever owns that caller; it is now redundant,
/// not wrong.
///
/// The returned `usize` is the donor boundary: candidates at or past it
/// are donor-directory files. The split matters because the tolerance
/// above extends to the FILE level - a donor file that vanishes between
/// this walk and the read that wanted it (the same racing cleanup, one
/// step later) is dropped by the passes below, while an unreadable file
/// in the repair's own `dir` stays fatal exactly as it always was. The
/// reads AFTER the adoption decision - the solve feed and the patch -
/// are covered separately: [`pin_donor_sources`] holds the surviving
/// donors open through both.
fn adoption_candidates(
    dir: &Path,
    donors: &[PathBuf],
    targets: &[Target],
    exclude: &HashSet<PathBuf>,
    declared: &HashSet<String>,
) -> Result<(Vec<(PathBuf, u64)>, usize), RepairError> {
    // Keyed by filesystem identity, not by spelling: the PAR2-declared name
    // and the on-disk name routinely differ in case, and on a case-insensitive
    // volume an exact compare would hand an identified target's OWN file to
    // the sliding scan as an adoption source.
    let fold = crate::disk::case_insensitive_dir(dir);
    let identified: HashSet<PathBuf> = targets
        .iter()
        .filter(|t| t.exists && (t.intact || t.present.iter().any(|&p| p)))
        .map(|t| path_identity_key(fold, &t.path))
        .collect();
    // The demotion set: every name SOME set in this directory declares,
    // less the names OUR OWN set declares. See the header. Our own
    // targets' names are removed rather than never added because
    // `declared` is directory-wide by construction and includes them -
    // and an unidentified target of this set is a candidate on purpose.
    let ours: HashSet<String> = targets
        .iter()
        .map(|t| name_identity_key(fold, &t.file.name))
        .collect();
    let demote_names: HashSet<String> = declared.difference(&ours).cloned().collect();
    let mut seen: HashSet<PathBuf> = HashSet::new();
    let walk = |d: &Path,
                out: &mut Vec<(PathBuf, u64)>,
                seen: &mut HashSet<PathBuf>|
     -> Result<(), RepairError> {
        let start = out.len();
        for c in super::nested::walk_files(d, super::PacketScope::Nested)? {
            let p = c.path;
            if is_recovery_by_name_and_content(&p)
                || identified.contains(&path_identity_key(fold, &p))
                || exclude.contains(&p)
                // Folded by the same identity key as the exclusions
                // above, first occurrence kept - see the header.
                || !seen.insert(path_identity_key(fold, &p))
            {
                continue;
            }
            let len = c.meta.len();
            if len > 0 {
                out.push((p, len));
            }
        }
        // A NEIGHBOURING SET'S DECLARED PAYLOAD LAST, then DEPTH, then
        // path - see the header. The partition is stable because the
        // (depth, path) pair below is already a total order, so within
        // each of the two classes the list is byte-for-byte what it was.
        out[start..].sort_by_key(|(p, _)| {
            (
                declared_by_name(d, fold, p, &demote_names),
                p.strip_prefix(d).unwrap_or(p).components().count(),
                p.clone(),
            )
        });
        Ok(())
    };
    let mut out = Vec::new();
    walk(dir, &mut out, &mut seen)?;
    let donor_from = out.len();
    for d in donors {
        if d == dir {
            continue;
        }
        // A donor may name a FILE rather than a directory - that is what
        // par2cmdline's trailing `[files]` arguments are, and parfast
        // passes them straight through. `walk` would fail its root
        // `read_dir` on one and the tolerance below would drop it in
        // silence, so the single file is admitted here under the same
        // screens the walk applies to a directory's entries.
        if let Ok(meta) = std::fs::metadata(d)
            && meta.is_file()
        {
            if meta.len() > 0
                && !is_recovery_by_name_and_content(d)
                && !identified.contains(&path_identity_key(fold, d))
                && !exclude.contains(d)
                && seen.insert(path_identity_key(fold, d))
            {
                out.push((d.clone(), meta.len()));
            }
            continue;
        }
        // A donor that cannot be read is skipped, not fatal: the donor
        // is a predecessor's directory this repair does not own, and a
        // concurrent cleanup racing it must degrade to "no donation",
        // never to a failed repair.
        let _ = walk(d, &mut out, &mut seen);
    }
    Ok((out, donor_from))
}

/// What [`RepairReport::adopted_from`] says: WHERE, for a reader, each
/// donated block came from.
///
/// X6-02c (31 Aug 2026). This was `file_name()` at the call site, and
/// a bare leaf stopped being an answer the day the adoption scan
/// learned to walk a TREE: `disc1/x.vob` and `disc2/x.vob` print
/// identically, and a candidate from a DONOR directory prints as
/// though it were in this one. The string is what
/// [`adopted_from_clause`](super::status::adopted_from_clause) puts on
/// the console after a repair, so what the reader is told about where
/// the bytes came from was, on exactly the trees X6-02 made reachable,
/// not a location.
///
/// TWO PRODUCERS, and they get different answers because only one of
/// them HAS an out-relative name:
///
/// * A candidate under `dir` is named [`crate::disk::out_name_of`] -
///   the same out-relative vocabulary every other tree-aware surface in
///   this repair speaks, so `disc1/x.vob` is a path the reader can go
///   and open.
/// * A DONOR is not under `dir` and has no out-relative name to give.
///   Its leaf is kept and marked, because the defect there is not
///   ambiguity between two of ours, it is a file reading as if it were
///   ours at all. Naming the donor DIRECTORY was refused: an absolute
///   path in a console line is a disclosure decision this row is not,
///   and a bare donor-relative form (`otherjob/x.vob`) reads exactly
///   like a subdirectory of this job - the same lie in a new spelling.
///
/// THE MARKER IS LOAD-BEARING TO THE ONE MACHINE CONSUMER, not just to
/// the reader. `nzbfast::get::latesets::repair_accounts_for_the_shortfall`
/// matches a short slot's own path against these entries, and that rule
/// is one of the few in the tree that turns a failed job GREEN. Under
/// the old spelling a DONOR's basename could collide with a short
/// slot's and be credited as its source - a job passing on somebody
/// else's evidence. A donor is never a short slot's partial (a short
/// slot's file is inside the job directory by construction), so the
/// marked form can equal no out-relative name and that credit is gone.
/// The consumer moved to out-relative matching in the same commit; the
/// two halves cannot be split.
///
/// `donors` is the RANGE the §293 donor walk produced, not an index to
/// compare against: the escalation appends damaged in-set targets to
/// `cands` after that range is fixed, so `cand >= donor_from` calls an
/// in-set harvest source a donor. Measured - it did, in
/// `par2repair_parity::mid_file_insertion_escalates_to_target_scan` and
/// `the_in_set_harvest_rebuilds_a_join_from_its_own_intact_parts`, both
/// of which are exactly that shape.
pub(super) fn adopted_from_names(
    dir: &Path,
    cands: &[(PathBuf, u64)],
    donors: &std::ops::Range<usize>,
    adopted: &HashMap<usize, AdoptSrc>,
) -> Vec<String> {
    let mut out: Vec<String> = adopted
        .values()
        .map(|s| {
            let p = &cands[s.cand].0;
            if donors.contains(&s.cand) {
                format!(
                    "{} {DONOR_MARK}",
                    p.file_name().unwrap_or_default().to_string_lossy()
                )
            } else {
                crate::disk::out_name_of(dir, p)
            }
        })
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    out.sort();
    out
}

/// What a donor's entry in [`adopted_from_names`] carries instead of a
/// directory. Spelled once, because a reader and a test both read it.
pub(super) const DONOR_MARK: &str = "(donor directory)";

/// WHY "EVERY BLOCK, ALIGNED, RIGHT LENGTH" IS NOT "THIS FILE IS THAT
/// MEMBER", and what has to be asked instead.
///
/// [`adopt_blocks`]'s fast path compares the candidate's WHOLE-FILE MD5
/// against the target's declared `md5` and adopts every slice at an
/// aligned offset; the derivation "same length, all slices, every offset
/// aligned" reads that decision back out of the adoption map. It was
/// documented here as exact, on the argument that a sliding-scan hit
/// could not counterfeit it - a candidate whose bytes hashed equal would
/// have been claimed by the fast path first.
///
/// THAT ARGUMENT IS FALSE, measured 17 Sep 2026 against the existing
/// fixture `unrepairable_partial::on_a_repairable_set_a_failed_member_verify_is_still_an_error`,
/// whose set declares a whole-file MD5 that DISAGREES with its own block
/// hashes (`index_lying_about_md5`). The fast path refuses such a
/// candidate, the sliding scan then matches every block of it at its
/// aligned offset, and the derivation says "whole file" about a file the
/// set's own FileDesc says is not. The engine's self-proving contract
/// catches it at the final whole-file verify and returns
/// `RepairError::VerifyFailed` - so a caller that SKIPPED that verify on
/// the strength of the derivation alone would ship bytes the set does
/// not vouch for, which is the one thing that contract exists to
/// prevent.
///
/// So the fast path's own claim is carried out of it explicitly, and
/// both consumers - the reference's `is a match for` announcement and
/// the rename - require it. The reference reaches its line by the same
/// whole-file comparison, so requiring it is also strictly closer to
/// what the reference prints: on the lying set above it says "found N of
/// N data blocks", which is what the scan really established.
/// Per candidate, per target: how many of that target's slices came
/// from it, and whether every one sat at its own aligned offset.
///
/// ONE COPY of the whole-file derivation's raw material. Two callers
/// read it and they must never disagree: [`extra_file_matches`]
/// ANNOUNCES the match in the reference's words, and
/// [`whole_file_renames`] ACTS on it by moving the donor onto the
/// target's name. A second copy of this walk would be a repair whose
/// report and whose filesystem outcome could drift apart.
///
/// The `cand < donor_from` boundary is [`extra_file_matches`]'s own and
/// its docstring carries the argument: everything at or past it is a
/// §293 donor directory's file or one of the two IN-SET sources the
/// caller appends after it, and none of the three is an extra file in
/// the directory the reference would have scanned.
fn adoption_tally(
    donor_from: usize,
    targets: &[Target],
    adopted: &HashMap<usize, AdoptSrc>,
    bs: usize,
) -> HashMap<usize, HashMap<usize, (usize, bool)>> {
    let mut per: HashMap<usize, HashMap<usize, (usize, bool)>> = HashMap::new();
    for (ti, t) in targets.iter().enumerate() {
        for i in 0..t.n_slices {
            let Some(src) = adopted.get(&(t.first_slice + i)) else {
                continue;
            };
            if src.cand >= donor_from {
                continue;
            }
            let e = per
                .entry(src.cand)
                .or_default()
                .entry(ti)
                .or_insert((0, true));
            e.0 += 1;
            e.1 &= src.offset == i as u64 * bs as u64;
        }
    }
    per
}

/// The target one candidate's [`adoption_tally`] row mostly fed, or
/// `None` when two of them tie for the lead.
///
/// The whole of [`extra_file_matches`]' attribution rule; its docstring
/// carries the argument and the measurement. A one-entry row is its own
/// strict maximum, so this is the identity on every unambiguous donor
/// and the function exists only for the rest.
///
/// Iteration order is a `HashMap`'s, and the answer must not be: a tie
/// resolves to `None` whichever of the tied entries is seen first, and
/// a strict maximum is reached from any order.
///
/// An EMPTY row would also answer `None`, and cannot arrive:
/// [`adoption_tally`] inserts a candidate only when a slice was adopted
/// from it. The caller's branch for `None` is therefore the tie, which
/// is what its comment says.
fn dominant_target(by_target: &HashMap<usize, (usize, bool)>) -> Option<usize> {
    let mut best: Option<(usize, usize)> = None;
    let mut tied = false;
    for (&ti, &(n, _)) in by_target {
        match best {
            Some((_, bn)) if n < bn => {}
            Some((_, bn)) if n == bn => tied = true,
            _ => {
                best = Some((ti, n));
                tied = false;
            }
        }
    }
    best.filter(|_| !tied).map(|(ti, _)| ti)
}

/// What the reference's "Scanning extra files:" section announces, read
/// back out of the adoption decision this repair already made.
///
/// See [`ExtraFileMatch`] for what the three shapes are and why only
/// files under `dir` are in them. The rule is `cand < donor_from`:
/// everything at or past that boundary is either a §293 donor
/// directory's file or one of the two IN-SET sources the caller appends
/// after it ([`harvest_in_set`] and the escalation's damaged targets),
/// and none of the three is an extra file in the directory the
/// reference would have scanned. It is the same boundary
/// [`adopted_from_names`] reads, taken the other way round: that
/// function MARKS what is past it, this one drops it.
///
/// WHOLE-FILE IS THE FAST PATH'S OWN CLAIM, carried in `whole_claims`,
/// AND the derivation over the adoption map. It was the derivation
/// alone until 17 Sep 2026, on the argument that a sliding-scan hit
/// could not counterfeit it - and a set whose declared whole-file MD5
/// disagrees with its own block hashes does exactly that. The
/// measurement, the fixture that shows it and why the pair is also
/// closer to what the reference prints are in [`adoption_tally`].
///
/// THE COUNT IS "BLOCKS THIS REPAIR TOOK", which is the reference's
/// count on every shape that arises in practice and not by definition:
/// the reference counts what its scan matched IN the file, and this
/// counts what was still missing when the scan ran. The two differ only
/// for an extra file that also holds blocks the target already had
/// intact on disk - the reference would count those too. Reporting what
/// was actually adopted is the honest half of that pair: it is what
/// this repair did.
///
/// A DONOR THAT FED SEVERAL TARGETS IS NAMED FOR THE ONE IT MOSTLY FED
/// (20 Sep 2026, claim `parfast-donor-attribution-several-vs-reference-20sep`,
/// `research/PARFAST-DONOR-ATTRIBUTION-2026-09-20.md`). The rule was
/// `by_target.len() > 1 -> None`, and on an ORDINARY posting shape -
/// two members of one set sharing a leading header, both landing under
/// obfuscated names - that shipped a file. SABnzbd fills
/// `reconstructed` off `PAR2_BLOCK_FOUND_RE`
/// (`File: "x" - found N of M data blocks from "y"`, newsunpack.py:84)
/// and DELETES what that line names; the several-variant matches
/// neither of its two regexes, so the donor survived into the completed
/// folder as junk. Measured end to end: four files shipped where three
/// were the payload.
///
/// THE RULE IS A STRICT PLURALITY AND HAS NO THRESHOLD IN IT. One
/// target holding the unique maximum is named; two tied for it are the
/// several-variant, which is what that line is FOR and stays reachable
/// on exactly the shape it describes - a donor feeding two members
/// equally. There is nothing to tune: the discriminator is "is there a
/// single largest", not "is the largest big enough".
///
/// WHAT IT IS HELD AGAINST. par2cmdline-turbo 1.4.0 over two members of
/// one set sharing a leading prefix, swept from 0 to 100% shared: it
/// names one target per donor at EVERY point, never printing several,
/// because it assigns a whole extra FILE to one source file and
/// consumes it. This rule reproduces that answer, donor for donor and
/// count for count, everywhere except the fully-duplicate end of the
/// sweep, where our adoption is block-level and one donor legitimately
/// supplies both members. (Upstream par2cmdline 1.2.0 prints several
/// for BOTH donors from 11 shared blocks up, so the reference being
/// followed here is turbo's improvement and not the dialect's floor.)
///
/// THE COUNT ON A DOMINANT DONOR IS THAT TARGET'S BLOCKS, not the
/// donor's total: the cross-target blocks it also fed are not announced
/// under a line that names one target. That is the SAME count the
/// single-target branch always printed - the docstring above is
/// unchanged by this - and it is the reference's number to the block on
/// every swept point.
///
/// `whole_file` ALSO REQUIRES A SOLE TARGET, which is not redundant
/// with `whole_claims`. It is what keeps this function and
/// [`whole_file_renames`] from disagreeing, the thing
/// [`adoption_tally`]'s docstring forbids: the rename path gates on
/// `by_target.len() == 1` and ACTS by moving a file, so a dominant
/// donor promoted to `is a match for` here would announce a rename that
/// never happened.
pub(super) fn extra_file_matches(
    dir: &Path,
    cands: &[(PathBuf, u64)],
    donor_from: usize,
    targets: &[Target],
    adopted: &HashMap<usize, AdoptSrc>,
    bs: usize,
    whole_claims: &HashSet<usize>,
) -> Vec<ExtraFileMatch> {
    if adopted.is_empty() {
        // The ordinary repair adopts nothing, and the walk below is over
        // every slice of every target - so the section's builder costs
        // exactly nothing on the repairs that have nothing to announce.
        return Vec::new();
    }
    let mut out: Vec<ExtraFileMatch> = adoption_tally(donor_from, targets, adopted, bs)
        .into_iter()
        .map(|(ci, by_target)| {
            let donor = crate::disk::out_name_of(dir, &cands[ci].0);
            let sole = by_target.len() == 1;
            let Some(ti) = dominant_target(&by_target) else {
                return ExtraFileMatch {
                    donor,
                    target: None,
                    blocks: by_target.values().map(|(n, _)| n).sum(),
                    target_blocks: 0,
                    whole_file: false,
                };
            };
            let (n, aligned) = by_target[&ti];
            let t = &targets[ti];
            ExtraFileMatch {
                donor,
                target: Some(t.file.name.clone()),
                blocks: n,
                target_blocks: t.n_slices,
                whole_file: sole
                    && whole_claims.contains(&ci)
                    && aligned
                    && n == t.n_slices
                    && cands[ci].1 == t.file.length,
            }
        })
        .collect();
    // Candidate order is a HashMap's, so the printed section would
    // otherwise move between runs of the same repair.
    out.sort_by(|a, b| a.donor.cmp(&b.donor).then_with(|| a.target.cmp(&b.target)));
    out
}

/// Is the candidate at `p` somebody's PAYLOAD rather than this job's
/// junk - a target of the set being repaired, or a file some set in
/// this directory declares by name?
///
/// The protection half of `par2repair.rs`'s proven-spent sweep, which
/// reports `consumed_sources` for the caller to DELETE. It lives here
/// beside the scan that produces the candidates because that scan is
/// what decides which files it ever has to judge, and since wave-4 row
/// X6-02 (31 Aug 2026) that includes files in SUBDIRECTORIES.
///
/// BOTH SPELLINGS OF THE NAME, and the second one is why this is worth
/// a function. The names in `declared_names` are FileDesc names, which
/// under the relpath-preserve ruling carry their directory
/// (`VIDEO_TS/VTS_01_1.VOB`), while the guard compared a BASENAME -
/// equivalent for a flat candidate, and blind for a nested one. Blind
/// in the direction that DELETES: a member ANOTHER set declares at a
/// tree path, byte-identical to one of this set's targets, cleared the
/// guard, matched the target MD5 and was reported as spent. The
/// out-relative name is what the sets and the publication both spell,
/// so it is the arm that matters; the basename stays as the belt it
/// always was, and covers a candidate that is not under `dir` at all.
///
/// `fold` is the directory's case-folding answer, threaded rather than
/// re-derived: an exact compare hands an identified target's OWN file
/// to the scan on a case-insensitive volume, which is
/// [`adoption_candidates`]' own reason for keying on identity.
pub(super) fn is_somebodys_payload(
    dir: &Path,
    fold: bool,
    p: &Path,
    target_keys: &HashSet<PathBuf>,
    declared_names: &HashSet<String>,
) -> bool {
    target_keys.contains(&path_identity_key(fold, p))
        || declared_by_name(dir, fold, p, declared_names)
}

/// The NAME half of [`is_somebodys_payload`], both spellings, factored
/// out because a second caller asks exactly this and no more.
///
/// [`adoption_candidates`] uses it to DEMOTE a candidate in the scan
/// order rather than to protect it from a sweep, and there the target
/// arm above would be wrong - an unidentified target of THIS set is a
/// candidate on purpose (a shifted or prepended member is found by
/// rolling over its own file) and must keep its place. The two
/// spellings and the `fold` rule are the same question in both
/// callers, so they stay in one place; read this function's reasoning
/// at [`is_somebodys_payload`].
fn declared_by_name(dir: &Path, fold: bool, p: &Path, declared_names: &HashSet<String>) -> bool {
    let out_rel = name_identity_key(fold, &crate::disk::out_name_of(dir, p));
    declared_names.contains(&out_rel)
        || p.file_name()
            .map(|n| name_identity_key(fold, &n.to_string_lossy()))
            .is_some_and(|n| declared_names.contains(&n))
}

/// Targets this repair can land by RENAMING an extra file onto them
/// instead of rebuilding them out of that same file's bytes.
///
/// # What this is for
///
/// The ordinary obfuscated Usenet post: every member complete, every
/// name a hash. par2cmdline does a directory operation per file and
/// writes nothing; until 17 Sep 2026 this engine adopted every block of
/// every member from its hash-named twin and wrote the whole payload a
/// SECOND time, leaving the donor in the job folder. Measured on a
/// three-member fixture with one whole match: the reference wrote
/// 300,000 bytes and left one name, this engine wrote 600,000 and left
/// both. Three costs, none of them the repair's answer - which was
/// correct either way: the write I/O, a peak disk of 2x the payload
/// where the reference needs 1x, and the leftover, which SABnzbd does
/// not delete because `is a match for` maps to a rename in its
/// bookkeeping and not to `reconstructed`.
///
/// # The proof
///
/// `whole_claims` is [`adopt_blocks`]'s fast path saying it compared the
/// candidate's WHOLE-FILE MD5 against the target's declared one and they
/// agreed - the same comparison the reference renames on, and a proof
/// about every byte. That is what licenses skipping the final verify:
/// the donor IS the target, so there is nothing left to prove.
///
/// The derivation over the adoption map ("same length, all slices, every
/// offset aligned") is kept beside it as the belt, and is NOT sufficient
/// on its own - [`adoption_tally`] carries the fixture that counterfeits
/// it and what skipping the verify on it would have shipped.
///
/// # The guards, and why each one is here
///
/// * `shortfall` refuses the whole thing. A short set publishes what it
///   can and SPENDS NOTHING (`RepairStatus::Unrepairable`'s
///   `consumed_sources` note) - a rename is a spend of the donor's name,
///   and on a repair that failed, the name the file arrived under is
///   evidence. The old copy-and-keep behaviour stands there.
/// * `!t.exists` - the destination must be free. This is the missing-
///   member case the fixture measures and the only one worth taking:
///   where something already occupies the target's name, rebuilding
///   through the temp+rename path is what keeps the old file until the
///   new one is proven, and that is worth more than the write it saves.
/// * `p.starts_with(dir)` - never a §293 donor directory's file. Those
///   are a PREDECESSOR JOB's payload, and moving one is the same
///   destruction the spent sweep refuses for the same reason.
/// * [`is_somebodys_payload`] - a name any set in this directory
///   declares is somebody's payload whatever it hashes to. A rename
///   REMOVES that name, so it owes the same proof a delete does.
/// * exactly one target per candidate, and all of that target's slices.
///   The tally's shape gives both: a donor feeding two targets can be
///   renamed onto neither, and a target short of its slice count still
///   needs the fold.
///
/// # What the caller owes
///
/// The renames must land through the SAME path the rebuild temps do,
/// past every `cleanup` call site - `cleanup` DELETES what is in that
/// list, and a donor is not this repair's to delete - and the donor's
/// candidate index must be kept out of the spent sweep, because its
/// path no longer exists and naming it would have the caller delete a
/// file this repair already moved.
pub(super) struct WholeMatches {
    /// (donor path, target index), in donor-path order - the same shape
    /// the rebuild temps are landed in, so one loop lands both.
    pub renames: Vec<(PathBuf, usize)>,
    /// Target indices in `renames`, for the caller's damaged-list
    /// exclusion: a renamed target opens no destination and writes no
    /// byte.
    pub targets: HashSet<usize>,
    /// Candidate indices in `renames` - what the spent sweep must skip.
    pub cands: HashSet<usize>,
}

/// Which donors this repair PROVED spent - the paths a caller that owns
/// the directory may delete, as `RepairReport::consumed_sources`.
///
/// Moved out of `repair_dir_set_inner` bodily under the size gate on
/// 17 Sep 2026, unchanged except for the `renamed` arm below; it belongs
/// here beside [`is_somebodys_payload`] and [`proven_spent`], which are
/// the two proofs it drives.
///
/// One adopted block authenticates ONE window of the donor - a legal
/// PAR2 block can be four bytes - and says nothing whatever about the
/// donor's other bytes. Handing the caller every path that donated
/// anything, which it deletes outright, therefore destroyed complete
/// files over a shared block: zero padding, a common container header,
/// or a neighbouring recovery set's payload (foreign targets are
/// unidentified here, so they are ordinary adoption candidates).
///
/// The case this cleanup exists for - issue #9, the obfuscated post -
/// is the one where the hash-named donor IS the payload byte for byte,
/// and the repair has just landed those same bytes under the FileDesc
/// name. So require exactly that: the donor must match a target of this
/// set in declared length AND in declared whole-file MD5. That is a
/// proof about every byte, which is what deletion needs, and it is
/// cheap to reach because the length test rejects almost everything
/// before a hash is computed.
///
/// A name any set in the directory declares is somebody's payload and
/// is never swept, whatever it hashes to.
///
/// `renamed` is [`WholeMatches::cands`] and is the arm added on 17 Sep
/// 2026: a donor that was RENAMED onto its target is not a consumed
/// source but the file itself, and its old path no longer exists.
/// Naming it would have the caller delete a path this repair already
/// moved - a no-op today and a warn in the daemon's sweep, and a
/// genuine loss if the rename had failed and left the donor where it
/// was. Nothing downstream is weakened by the omission: a renamed donor
/// can only ever have cleared the EXACT-MD5 arm below, and the one
/// caller that reads `consumed_sources` for accounting rather than for
/// deletion (`nzbfast-engine`'s `repair_accounts_for_the_shortfall`)
/// asks it about a SHORT slot's partial, which by construction is not
/// byte-exact for the member it is short of.
#[expect(clippy::too_many_arguments)]
pub(super) fn spent_donors(
    dir: &Path,
    fold: bool,
    cands: &[(PathBuf, u64)],
    targets: &[Target],
    adopted: &HashMap<usize, AdoptSrc>,
    rebuilt_set: &HashSet<usize>,
    bs: usize,
    declared: &HashSet<String>,
    donors: HashSet<usize>,
    renamed: &HashSet<usize>,
    shortfall: bool,
) -> Vec<PathBuf> {
    let declared_names: HashSet<String> = declared
        .iter()
        .cloned()
        .chain(
            targets
                .iter()
                .map(|t| name_identity_key(fold, &t.file.name)),
        )
        .collect();
    let target_keys: HashSet<PathBuf> = targets
        .iter()
        .map(|t| path_identity_key(fold, &t.path))
        .collect();
    let mut spent: Vec<PathBuf> = Vec::new();
    // A shortfall publishes files and spends NOTHING: see the
    // `consumed_sources` note on `status::RepairStatus::Unrepairable`.
    for ci in donors
        .into_iter()
        .filter(|ci| !shortfall && !renamed.contains(ci))
    {
        let (p, len) = &cands[ci];
        // §293: a candidate from a DONOR directory is a predecessor
        // job's payload, not this directory's junk - byte-identical to
        // a target is exactly the good case there, and sweeping it
        // would delete another job's files. Only the repair dir's own
        // files can ever be spent.
        if !p.starts_with(dir) {
            continue;
        }
        if is_somebodys_payload(dir, fold, p, &target_keys, &declared_names) {
            continue;
        }
        let want: Vec<[u8; 16]> = targets
            .iter()
            .filter(|t| t.file.length == *len)
            .map(|t| t.file.md5)
            .collect();
        // A hash that cannot be read decides nothing: keep the file.
        if !want.is_empty() && md5_of_file(p, None).is_ok_and(|h| want.contains(&h)) {
            spent.push(p.clone());
            continue;
        }
        // The damaged-twin and fully-donated arms - the per-byte proofs
        // for a source the exact-MD5 test can never clear. See
        // [`proven_spent`].
        if proven_spent(p, *len, ci, targets, adopted, rebuilt_set, cands, bs) {
            spent.push(p.clone());
        }
    }
    spent.sort();
    spent
}

pub(super) fn whole_file_renames(
    dir: &Path,
    fold: bool,
    cands: &[(PathBuf, u64)],
    donor_from: usize,
    targets: &[Target],
    adopted: &HashMap<usize, AdoptSrc>,
    bs: usize,
    declared: &HashSet<String>,
    whole_claims: &HashSet<usize>,
    shortfall: bool,
) -> WholeMatches {
    let mut out = WholeMatches {
        renames: Vec::new(),
        targets: HashSet::new(),
        cands: HashSet::new(),
    };
    if shortfall || adopted.is_empty() {
        return out;
    }
    let declared_names: HashSet<String> = declared
        .iter()
        .cloned()
        .chain(
            targets
                .iter()
                .map(|t| name_identity_key(fold, &t.file.name)),
        )
        .collect();
    let target_keys: HashSet<PathBuf> = targets
        .iter()
        .map(|t| path_identity_key(fold, &t.path))
        .collect();
    for (ci, by_target) in adoption_tally(donor_from, targets, adopted, bs) {
        if by_target.len() != 1 {
            continue;
        }
        let (ti, (n, aligned)) = by_target
            .into_iter()
            .next()
            .expect("a candidate with no target is never inserted");
        let t = &targets[ti];
        let (p, len) = &cands[ci];
        if !(whole_claims.contains(&ci)
            && aligned
            && n == t.n_slices
            && t.n_slices > 0
            && *len == t.file.length)
        {
            continue;
        }
        if t.exists || !p.starts_with(dir) {
            continue;
        }
        if is_somebodys_payload(dir, fold, p, &target_keys, &declared_names) {
            continue;
        }
        // Two candidates cannot reach one target - the fast path
        // consumes a candidate and breaks out of its target's loop, and
        // `adopted` is filled with `or_insert` so a later one writes
        // nothing. Refused rather than relied on: a rename is a
        // destructive write, and a second one for the same target would
        // land on top of the first with a HashMap's iteration order
        // deciding which survived.
        if !out.targets.insert(ti) {
            continue;
        }
        out.renames.push((p.clone(), ti));
        out.cands.insert(ci);
    }
    // Candidate order is a HashMap's, so two runs of the same repair
    // would otherwise land the renames in different orders - which a
    // report a caller prints, and a conformance row that fingerprints
    // the directory, both read.
    out.renames.sort();
    out
}

/// Does `dir` hold ANY file that could serve as an adoption source -
/// that is, anything under it which is not one of `packet_set`'s own
/// packet files?
///
/// The DOOR onto [`adoption_candidates`], and it lives beside it since
/// wave-4 row X6-02 (31 Aug 2026) because the two have to reach the
/// same distance or the pair fails in one of two ways with nothing to
/// say which. `repair_sets_catalog`'s renamed-fallback arm asks this
/// before attempting a set no FileDesc name matches: packets alone can
/// only rebuild what recovery slices recreate, so a directory offering
/// no source is one that arm must not run in.
///
/// It was a flat `read_dir(dir)` on `is_file()` and the reach below was
/// a flat walk too, so on a wholly renamed obfuscated post whose
/// FileDesc names carry a directory (`VIDEO_TS/...`) the payload landed
/// a directory down, this test saw a DIRECTORY where the candidate was,
/// and the set was NEVER ATTEMPTED - the caller reads the resulting
/// empty Vec as "no repair happened" and the job finishes with its
/// payload still wearing a hash. That is M4-102's door-and-reach split
/// one path over: widen the door alone and the scan behind it prices
/// the member wholly missing, widen the reach alone and this gate never
/// opens to let it run. Both go through [`super::nested::walk_files`].
///
/// Deliberately NOT filtered the way the reach is - `.par2` content, an
/// identified target, an excluded path - because that was never this
/// question. It asks the flat gate's own predicate over the tree, and
/// nothing more: this arm is only reachable on a job that was already
/// failing (see its call site), so a directory it lets through that
/// then offers nothing costs an Unrepairable verdict where the caller
/// had an empty Vec, and both report failure.
pub(super) fn any_adoption_source(
    dir: &Path,
    packet_set: &HashSet<&Path>,
) -> Result<bool, RepairError> {
    Ok(super::nested::walk_files(dir, super::PacketScope::Nested)?
        .into_iter()
        .any(|c| !packet_set.contains(c.path.as_path())))
}

/// Whether a candidate is this directory's own recovery data, and so
/// no use to anybody as an adoption SOURCE.
///
/// The extension is where the question starts and, until wave-4 row
/// M4-52 (30 Aug 2026), was where it ended. That is a NAME deciding
/// what a file IS, and an obfuscated post can put any name it likes on
/// a payload: the row's composition posts the movie with a yEnc
/// `name=` of `<hash>.par2`, so it lands under that extension, and the
/// recovery set that would have called it `movie.mkv` then had no
/// donor to find its bytes in. The set reported the payload wholly
/// missing while it sat in the same directory.
///
/// So the name still NOMINATES and the content decides: a file wearing
/// the extension is skipped only if it opens with the packet magic.
/// Eight bytes, read only for `.par2` names, and a read that fails
/// keeps the historical answer - a candidate that cannot be opened is
/// no donor either way.
///
/// This is the ONLY thing the magic buys here. It is not a claim that
/// the file parses, which is a different question with a different
/// answer at a different seam (`is_recovery_volume_shape`, which gates a
/// DELETION and therefore demands the whole file).
///
/// PUBLIC SINCE 31 Aug 2026, re-exported as
/// `par2repair::is_recovery_by_name_and_content`, because a caller
/// outside this crate has to ask the identical question and was
/// answering it by NAME. `nzbfast::repair::adoption_candidates_present`
/// exists to PREDICT what `adoption_candidates` finds, and it screened
/// `.par2` on the extension alone - so on M4-52's own composition (an
/// obfuscated payload landing under a `<hash>.par2` yEnc name) the gate
/// said NO where this says YES, and that NO is an arm of
/// `shortfall_is_final` which can take the give-up branch without ever
/// reaching the probe that would have found the bytes. The rule is
/// SHARED rather than spelled twice: two spellings of one row is what
/// M4-52 cost in the first place, and the walk the two share
/// ([`super::nested::source_candidate_files`]) was folded together on
/// the same grounds hours earlier.
///
/// THE WINDOW, NOT BYTE 0, SINCE 31 Aug 2026 - and until then this was
/// the LAST packet sniff in the product still reading offset 0. Seven
/// production sites ask "does this file open a PAR2 packet chain"; the
/// other six go through [`par2::head_is_packet_file`], which row M4-65
/// widened to "the magic BEGINS within [`par2::SNIFF_WINDOW`] bytes"
/// because a volume behind a short prefix - a UTF-8 BOM from a producer
/// that touched it as text - is still the post's parity. This one read
/// eight bytes at zero and nothing else, so it answered the OPPOSITE
/// question about the same file. `collect.rs`'s own header states the
/// convention it was outside of, which is why the content half is now a
/// CALL rather than a second spelling: this function keeps the NAME
/// test, which is its own, and asks `par2` the content question every
/// other reader asks.
///
/// MEASURED, on one BOM-prefixed but otherwise ordinary volume covering
/// a set that declares one member. Before: `head_is_packet_file` true,
/// this false, `nzbfast::repair::adoption_candidates_present` true - the
/// same bytes recovery data to every reader in the repair and a PAYLOAD
/// here. And it was not a paper disagreement. A real `repair_dir` over
/// that directory reported `blocks_adopted: 1` and `adopted_from:
/// ["post.vol000+01.par2"]`, so the set's OWN PARITY was named to the
/// user as a donor, in a repair that was loading the same file as
/// recovery data at the same time. The identical rig with the prefix
/// removed adopts nothing. That is one file in two roles in one repair,
/// which is a contradiction rather than a conservative narrowness, and
/// is the thing this closes.
///
/// WHY THE DONATION IS NOT A COINCIDENCE, because a reader will
/// reasonably assume parity bytes cannot match payload bytes and stop
/// worrying: for exponent 0 every input's Reed-Solomon coefficient is
/// `base^0 = 1`, so a set with exactly ONE input block has a
/// `vol000+01` slice byte-identical to that block. Measured with
/// `par2gen::create_into`: the source block appears verbatim at offset
/// 472 of the generated volume. The sliding scan matches at any byte
/// offset, so it finds it every time, not at 2^-160.
///
/// THE DELETION PATH WAS THE SHARP RISK AND IT IS NOT REACHED, measured
/// rather than reasoned, because the reasoning goes the wrong way:
/// `par2repair.rs`'s proven-spent sweep guards with
/// `is_somebodys_payload`, which asks whether a candidate is a TARGET
/// of this set or a name some set DECLARES - and parity is declared by
/// nobody, so a volume clears that guard outright. What actually keeps
/// it is the three spend proofs, each of which wants evidence about
/// EVERY byte of the candidate: exact whole-file MD5 against a
/// same-length target, `proven_spent`'s damaged-twin arm (same length,
/// plus an ALIGNED majority, and the donated span sits at 472, which is
/// not a block boundary), and its fully-donated arm, which needs merged
/// coverage reaching the candidate's end and can never start at 0
/// because a volume's slice sits behind its packet header. The same rig
/// reports `consumed_sources: []`. So the protection is real and it is
/// INCIDENTAL - it rests on packet framing, not on any rule written
/// about volumes - and anybody loosening a spend proof should know this
/// seam was leaning on it.
///
/// WHICH DIRECTION IS CONSERVATIVE HERE, since the sibling seam
/// `nzbfast::get::latesets`' `has_par2_magic` warns in as many words
/// against assuming one settles the other. Widening makes MORE files
/// count as recovery, so FEWER are offered as adoption sources, and the
/// file that could hide is M4-52's own: an obfuscated payload under a
/// `<hash>.par2` name whose first `SNIFF_WINDOW + 8` bytes happen to
/// contain the magic. Re-derived rather than copied: the magic is 8
/// bytes and may begin at any of 65 offsets, so a file nobody chose
/// those bytes for is 65 x 2^-64, about 2^-58 - and that is 65x the
/// byte-0 rule's 2^-64, not 65x of 2^-58. `latesets`' own "roughly
/// 2^-58" is already the WINDOW figure for the same predicate at the
/// sibling seam, which is the precedent rather than a looser bar. Set
/// against a prefixed volume, which was misclassified EVERY time.
///
/// The read grows from 8 bytes to 72 and stays one `open` plus one
/// sub-page read, asked only of names carrying the extension - the cost
/// `adoption_candidates_present`'s header measures at 8.1-10.7 us a file
/// is the `open`, and 72 bytes does not add a page to it.
///
/// A file too short to carry the magic still reads as recovery data,
/// deliberately, and it is the one arm that had to be written out rather
/// than inherited: `read_exact` of eight bytes USED to fail on such a
/// file, so it fell into the unreadable arm below, where a 72-byte
/// `read_to_end` succeeds and would call it a payload. A file that
/// cannot carry the magic can no more be shown NOT to be parity than an
/// unopenable one can, and turning every truncated volume into an
/// adoption scan is not the direction to fail in.
pub fn is_recovery_by_name_and_content(p: &Path) -> bool {
    if !p
        .extension()
        .is_some_and(|x| x.eq_ignore_ascii_case("par2"))
    {
        return false;
    }
    const WANT: usize = par2::SNIFF_WINDOW + 8;
    let mut head: Vec<u8> = Vec::with_capacity(WANT);
    match File::open(p).and_then(|f| f.take(WANT as u64).read_to_end(&mut head)) {
        Ok(n) if n < par2::MAGIC.len() => true,
        Ok(_) => par2::head_is_packet_file(&head),
        Err(_) => true,
    }
}

pub(super) fn md5_of_file(path: &Path, limit: Option<u64>) -> Result<[u8; 16], RepairError> {
    let mut f = File::open(path)?;
    let mut hasher = Md5::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut left = limit.unwrap_or(u64::MAX);
    while left > 0 {
        let want = buf.len().min(left.min(usize::MAX as u64) as usize);
        let n = f.read(&mut buf[..want])?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        left -= n as u64;
    }
    Ok(hasher.finalize().into())
}

/// The machine half of the adoption fan-out, with no per-file term.
///
/// Both passes are a mix of one sequential whole-file read and per-byte
/// arithmetic over it (MD5, or the rolling CRC32 plus MD5 on a hit), so
/// the work is CPU-shaped and the cap is really about not turning one
/// repair into a deep queue of concurrent whole-file reads on a
/// spinning disk or a network share - the same 8 the syndrome feed
/// readers settled on.
///
/// THE 8 STILL BINDS NOW THAT THE SLIDING SCAN SPLITS ONE CANDIDATE
/// (16 Sep 2026, claim `par2-adoption-scan-within-candidate-16sep`).
/// The stated reason above is about FILES, and the obvious reading is
/// that it does not transfer to chunks of a single file, so it was
/// re-derived rather than inherited. It does transfer, for a different
/// reason on each side of the trade: N chunks of one file are N
/// concurrent sequential read streams at N distant offsets, which is
/// the seek pattern the cap was bought to avoid on a spinning disk or
/// a share whatever the file count says; and on the CPU-bound side
/// where the widening pays, the measured single-thread rate
/// (820 MiB/s, `research/PAR2-ADOPTION-DOUBLE-READ-2026-09-16.md`)
/// means 8 already carries a repair-sized pass to the point where it
/// stops being the phase worth chasing. Raising it is a measurement on
/// a wide box, not a free win - and the ring-buffer cap in
/// [`sliding_scan`] is the OTHER term, which a raise here would not
/// relax.
fn adoption_fanout() -> usize {
    crate::mem::cpu_workers().clamp(1, 8)
}

/// How many candidate files may be read at once - [`adoption_fanout`]
/// with the per-file term the whole-file passes are bounded by.
fn adoption_workers(files: usize) -> usize {
    adoption_fanout().min(files).max(1)
}

/// One unit of sliding-scan work: a candidate's position in `indices`,
/// plus the half-open range of WINDOW START offsets inside that
/// candidate this unit is answerable for. `start == 0 && end == len` is
/// the whole file, which is what every unit was before 16 Sep 2026.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ScanUnit {
    pos: usize,
    start: u64,
    end: u64,
}

/// The smallest window-start range worth a thread of its own.
///
/// Two terms, and the first is the one that decides it. A chunk has to
/// read `bs - 1` bytes past its own range to close the window that
/// straddles the boundary (see [`scan_candidate`]), so the overlap is a
/// fixed `bs` per split and the block multiple here IS the overlap
/// budget: a floor of `M * bs` caps the wasted fraction at `1 / M`
/// whenever it is the floor rather than the width that limits the cut.
/// The 4 MiB floor is the second term and binds only on small blocks
/// (`bs <= 1 MiB`), where four blocks would be a chunk too short to pay
/// for a thread at all.
///
/// THE MULTIPLE WAS 8 UNTIL 16 Sep 2026 AND IS NOW 4, MEASURED - claim
/// `adoption-fanout-constants-measure-16sep`, written up in
/// `research/PAR2-ADOPTION-WITHIN-CANDIDATE-2026-09-16.md`. The rig
/// (`rig_sliding_scan_costs` in the tests beside this file) swept the
/// chunk count over a real 192 MiB candidate at 1 MiB and 16 MiB block
/// sizes and found NO per-unit fixed cost to speak of: process CPU
/// tracked the planned byte count to within a few percent from 1 chunk
/// to 32, and the per-thread rate stayed flat at 316-346 MiB/s across
/// the whole ladder. So the ring allocation, the thread start-up and
/// the units finishing unevenly are all below the noise, the straddle
/// overlap is the ONLY cost of a split, and the trade is exactly
/// arithmetic: each halving of the multiple doubles the reachable chunk
/// count for one more `bs` of reread per split.
///
/// 8 -> 4 takes the note's stated gap - a 192 MiB member at a 16 MiB
/// block, 12 blocks, which did not split at all - to a 3-way cut worth
/// a measured 2.69x on the pass, for 15% more bytes read. It changes
/// NOTHING on the 1 MiB shape the landed A/B measured: there the width
/// cap already limited the cut to 8 and still does, so there is no
/// regression risk on the arm that has a number behind it.
///
/// IT DID NOT GO TO 2, and the reason is the axis this box cannot
/// measure rather than the CPU: the overlap is re-read I/O as well as
/// re-hashed bytes, 2 would put that at 50% of the candidate, and a
/// spinning disk or a network share is the same unmeasured risk that
/// keeps [`adoption_fanout`] at 8. 2 is worth 4.59x at that corner and
/// is the next rung IF that reading is ever taken.
fn min_scan_chunk(bs: usize) -> u64 {
    (bs as u64).saturating_mul(4).max(4 << 20)
}

/// Cut `indices` into the units the scan's workers pull from, in SERIAL
/// SCAN ORDER - candidate by candidate, and within a candidate by
/// ascending offset. That order is the whole contract: `ScanShared`'s
/// early exits and the merge in [`sliding_scan`] are keyed on a unit's
/// index in this list, and every one of their arguments is "an earlier
/// unit is earlier in the serial walk", which the lexicographic order
/// below is exactly.
///
/// A candidate is split only when there is width going spare: with at
/// least `width` candidates the plan is one unit each, byte for byte
/// what it always was, so the ordinary many-candidate repair cannot
/// reach any of the new arithmetic.
fn plan_units(
    cands: &[(PathBuf, u64)],
    indices: &[usize],
    width: usize,
    floor: u64,
) -> Vec<ScanUnit> {
    let whole = |pos: usize| ScanUnit {
        pos,
        start: 0,
        end: cands[indices[pos]].1,
    };
    if width < 2 || indices.len() >= width {
        return (0..indices.len()).map(whole).collect();
    }
    let per = (width.div_ceil(indices.len().max(1))) as u64;
    let mut out: Vec<ScanUnit> = Vec::with_capacity(indices.len());
    for pos in 0..indices.len() {
        let len = cands[indices[pos]].1;
        let chunks = per.min(len / floor.max(1)).max(1);
        let (base, rem) = (len / chunks, len % chunks);
        let mut start = 0u64;
        for k in 0..chunks {
            let n = base + u64::from(k < rem);
            out.push(ScanUnit {
                pos,
                start,
                end: start + n,
            });
            start += n;
        }
        debug_assert_eq!(start, len, "the chunks of a candidate must cover it");
    }
    out
}

/// Hash the candidates named by `want` in parallel, filling the matching
/// `cache` slots. `limit` is [`md5_of_file`]'s.
///
/// Errors are DROPPED, deliberately: this is a prefetch for a decision
/// loop that is still free to hash anything it finds missing, and the
/// prefetch reads files the serial loop might never have opened. A
/// candidate that vanished between the directory walk and here must
/// therefore fail (or not) where it always did - inside the loop, on the
/// probe that actually needed it.
fn prefetch_md5s(
    cands: &[(PathBuf, u64)],
    want: &[usize],
    limit: Option<u64>,
    cache: &mut [Option<[u8; 16]>],
) {
    let want: Vec<usize> = want
        .iter()
        .copied()
        .filter(|&ci| cache[ci].is_none())
        .collect();
    if want.len() < 2 {
        if let Some(&ci) = want.first() {
            cache[ci] = md5_of_file(&cands[ci].0, limit).ok();
        }
        return;
    }
    let out: Mutex<Vec<Option<[u8; 16]>>> = Mutex::new(vec![None; want.len()]);
    let next = AtomicUsize::new(0);
    let workers = adoption_workers(want.len());
    std::thread::scope(|s| {
        for _ in 0..workers {
            let (want, out, next) = (&want, &out, &next);
            s.spawn(move || {
                loop {
                    let wi = next.fetch_add(1, Ordering::Relaxed);
                    let Some(&ci) = want.get(wi) else { break };
                    let h = md5_of_file(&cands[ci].0, limit).ok();
                    out.lock_ok()[wi] = h;
                }
            });
        }
    });
    for (wi, h) in out
        .into_inner()
        .unwrap_or_else(|e| e.into_inner())
        .into_iter()
        .enumerate()
    {
        cache[want[wi]] = h;
    }
}

/// Locate missing blocks' content in the candidate files. Fast path
/// first: a candidate that is a missing file whole (same length + MD5,
/// prefiltered on md5_16k) adopts every slice at aligned offsets - the
/// common renamed-file case, no per-byte scan. Whatever is still missing
/// then goes through the sliding scan: roll the block-size CRC32 window
/// over each candidate (continuing with virtual zeros past end-of-file,
/// matching the spec's zero-padded tail checksums), confirm CRC hits by
/// block MD5, and record the first source found per slice.
///
/// The fast path's matching loop is UNCHANGED and still serial - it is
/// pure bookkeeping over two content-derived caches, so pre-filling
/// those caches in parallel cannot move a decision. What is prefetched
/// is chosen to be what the loop would have asked for anyway: heads for
/// every candidate whose length some unidentified target declares, and
/// whole-file MD5s for one head-matching candidate per target (the
/// greedy pairing the loop itself performs when a head match is a real
/// match, which is the case unless two candidates share a 16 KB prefix).
/// Anything the pairing guessed wrong about is simply hashed lazily by
/// the loop, exactly as before.
///
/// The second of the returned four is [`adoption_candidates`]'s donor
/// boundary, passed through so the caller can classify candidate slots
/// by ownership after this returns - [`pin_donor_sources`] needs it, and
/// the caller appends its own escalation candidates past it.
///
/// The FOURTH is the candidate indices THE FAST PATH CLAIMED, and it is
/// the only surface that says a candidate cleared the declared
/// WHOLE-FILE MD5 rather than merely every block hash. See
/// [`adoption_tally`] for why the two are not the same question and
/// what read them apart.
pub(super) fn adopt_blocks(
    dir: &Path,
    ctx: &super::DirContext,
    targets: &[Target],
    missing: &[usize],
    bs: usize,
    exclude: &HashSet<PathBuf>,
) -> Result<
    (
        Vec<(PathBuf, u64)>,
        usize,
        HashMap<usize, AdoptSrc>,
        HashSet<usize>,
    ),
    RepairError,
> {
    let (cands, donor_from) =
        adoption_candidates(dir, &ctx.donors, targets, exclude, &ctx.declared)?;
    let mut adopted: HashMap<usize, AdoptSrc> = HashMap::new();
    let mut whole_claims: HashSet<usize> = HashSet::new();
    if cands.is_empty() {
        return Ok((cands, donor_from, adopted, whole_claims));
    }
    let missing_set: HashSet<usize> = missing.iter().copied().collect();

    let mut consumed = vec![false; cands.len()];
    // Each candidate is hashed at most once, however many targets probe
    // it (renamed multi-volume sets pair N missing files with N
    // candidates - without the cache that's N² hashing passes).
    let mut head_cache: Vec<Option<[u8; 16]>> = vec![None; cands.len()];
    let mut md5_cache: Vec<Option<[u8; 16]>> = vec![None; cands.len()];
    let probing: Vec<&Target> = targets
        .iter()
        .filter(|t| {
            let unidentified = !(t.exists && (t.intact || t.present.iter().any(|&p| p)));
            t.n_slices > 0 && t.file.length > 0 && unidentified
        })
        .collect();
    prefetch_heads(&cands, &probing, &mut head_cache);
    prefetch_wholes(&cands, &probing, &head_cache, &mut md5_cache);

    for t in targets {
        let unidentified = !(t.exists && (t.intact || t.present.iter().any(|&p| p)));
        if t.n_slices == 0 || t.file.length == 0 || !unidentified {
            continue;
        }
        for (ci, (p, len)) in cands.iter().enumerate() {
            if consumed[ci] || *len != t.file.length {
                continue;
            }
            // A donor file that cannot be read anymore - vanished or
            // unreadable since the walk - is dropped for good (consumed
            // keeps it out of the sliding scan too), never fatal: the
            // directory-level tolerance in `adoption_candidates`, kept
            // at file granularity. The distinction is OWNERSHIP, not
            // error kind - the same error on one of the repair's own
            // `dir` files still fails the repair exactly as before.
            let head = match head_cache[ci] {
                Some(h) => h,
                None => match md5_of_file(p, Some((*len).min(16384))) {
                    Ok(h) => {
                        head_cache[ci] = Some(h);
                        h
                    }
                    Err(_) if ci >= donor_from => {
                        consumed[ci] = true;
                        continue;
                    }
                    Err(e) => return Err(e),
                },
            };
            if head != t.file.md5_16k {
                continue;
            }
            let whole = match md5_cache[ci] {
                Some(h) => h,
                None => match md5_of_file(p, None) {
                    Ok(h) => {
                        md5_cache[ci] = Some(h);
                        h
                    }
                    Err(_) if ci >= donor_from => {
                        consumed[ci] = true;
                        continue;
                    }
                    Err(e) => return Err(e),
                },
            };
            if whole != t.file.md5 {
                continue;
            }
            // PAST THE WHOLE-FILE MD5, which is the only place in this
            // module that compares one - see [`adoption_tally`].
            whole_claims.insert(ci);
            for i in 0..t.n_slices {
                let g = t.first_slice + i;
                if missing_set.contains(&g) {
                    adopted.entry(g).or_insert(AdoptSrc {
                        cand: ci,
                        offset: i as u64 * bs as u64,
                    });
                }
            }
            consumed[ci] = true;
            break;
        }
    }

    let indices: Vec<usize> = (0..cands.len()).filter(|&ci| !consumed[ci]).collect();
    sliding_scan(
        &cands,
        &indices,
        donor_from..cands.len(),
        targets,
        &missing_set,
        bs,
        &mut adopted,
    )?;
    Ok((cands, donor_from, adopted, whole_claims))
}

/// The IN-SET harvest: fill a missing slice from another slice of the
/// SAME recovery set that verify already proved present on disk.
///
/// WHY THE BYTE-SCANNING PASSES ABOVE CANNOT REACH IT (M4-01, 30 Aug
/// 2026). One PAR2 set may name a file AND the pieces it was split
/// into - `Rawsplit.mkv.001`, `Rawsplit.mkv.002` AND `Rawsplit.mkv`.
/// The halves post honestly under hashes, get claimed by their own
/// FileDescs and land intact; the join is then a wholly-missing file
/// whose every block is already on disk next door. [`adoption_candidates`]
/// excludes identified targets by design - rolling a block window over
/// every intact file in a 50 GB set is the perf trap that exclusion
/// exists for - and the caller's last-resort escalation only appends
/// identified DAMAGED targets. So nothing looks at the halves, and a
/// fully intact post dies "1000 blocks needed, only 200 recovery
/// blocks". This is the inverse of the split-join case that works
/// (`e2e_norar` n19), which works precisely BECAUSE its halves stay
/// unclaimed and reach the sliding scan as ordinary candidates.
///
/// It needs no scan at all, which is the whole point: PAR2 already
/// publishes a CRC32 and an MD5 for every slice of every target, and
/// verify has already decided which of those slices are on disk. Two
/// slices carrying the same declared checksums are the same bytes, so
/// the lookup is one in-memory map over data this repair computed
/// anyway. Deciding costs no I/O; only the blocks actually harvested
/// are ever read. That is why it runs unconditionally rather than as a
/// shortfall fallback: at a redundancy that covers the whole join,
/// waiting for the shortfall would let reconstruct spend a full copy of
/// bytes the set already had - which passes the end-state hash and is
/// still the bug.
///
/// Every harvested block is RE-PROVED from the source file's own bytes
/// before it is adopted, CRC32 then MD5, the same bar [`sliding_scan`]
/// clears. Verify may have priced a slice present from a whole-file
/// MD5 rather than per-slice, so the declared block checksums this is
/// keyed on are not by themselves evidence about what is on the disk.
///
/// WHAT IT DECLINES, and this bound is not optional. A target that is
/// not on disk at all AND whose declared length and whole-file MD5
/// match an intact target's is a DUPLICATE DESCRIPTOR asking to be
/// materialized, not damage asking to be recovered. Copying it is a
/// product decision with a cap on it already - `land_duplicate_filedescs`
/// and `DUPLICATE_FANOUT_CAP` (W4-14, 30 Aug 2026), which exists because
/// a kilobyte of packet naming 200 aliases for one posted payload bought
/// 200 full-file reads and 200 full-file writes bounded by nothing.
/// Harvesting them here would be a SECOND door onto the same
/// amplification with no cap on it, and it measurably was: without this
/// rule `e2e_norar::a_dedupe_fanout_past_the_cap_refuses_the_remainder`
/// lands all 200. A duplicate of a target that EXISTS and is damaged is
/// a different question and stays in scope - repairing a file from its
/// twin is recovery, and it is bounded by what is on the disk already.
///
/// The appended candidates are the repair's OWN files, and the caller
/// appends them past the donor boundary: an I/O error here stays fatal,
/// exactly as it does for `dir`'s own files in [`adoption_candidates`].
pub(super) fn harvest_in_set(
    targets: &[Target],
    missing: &[usize],
    bs: usize,
    cands: &mut Vec<(PathBuf, u64)>,
    adopted: &mut HashMap<usize, AdoptSrc>,
) -> Result<(), RepairError> {
    if missing.is_empty() || bs == 0 {
        return Ok(());
    }
    // Where every present-on-disk slice lives, keyed by what PAR2 says
    // its bytes hash to. Lowest target then lowest slice wins, so the
    // source chosen is deterministic in Main-packet order.
    let mut by_hash: HashMap<(u32, [u8; 16]), (usize, usize)> = HashMap::new();
    for (ti, t) in targets.iter().enumerate() {
        if !t.exists || t.file.blocks.len() < t.n_slices {
            continue;
        }
        for (i, &ok) in t.present.iter().enumerate().take(t.n_slices) {
            if ok {
                let b = t.file.blocks[i];
                by_hash.entry((b.crc32, b.md5)).or_insert((ti, i));
            }
        }
    }
    if by_hash.is_empty() {
        return Ok(());
    }
    // (length, whole-file MD5) of every target proven whole on disk -
    // what a wholly-absent target has to differ from to be damage
    // rather than a clone request. See the DECLINES note above.
    let whole_on_disk: HashSet<(u64, [u8; 16])> = targets
        .iter()
        .filter(|t| t.exists && t.intact)
        .map(|t| (t.file.length, t.file.md5))
        .collect();
    // Global slice id -> (target, slice within it). `first_slice` is
    // assigned in target order, but this is sorted rather than assumed
    // so the lookup cannot silently attribute a slice to the wrong file.
    let mut starts: Vec<(usize, usize)> = targets
        .iter()
        .enumerate()
        .map(|(ti, t)| (t.first_slice, ti))
        .collect();
    starts.sort_unstable();
    // One open handle per source file, however many of its slices get
    // harvested, and a candidate slot claimed the first time one of its
    // blocks actually clears the re-proof below - a file whose bytes are
    // all refused leaves nothing behind in `cands`.
    let mut sources: HashMap<usize, (Option<usize>, u64, File)> = HashMap::new();
    // Allocated on the first candidate match, never on the way past.
    // `bs` is wire-supplied up to `par2::MAX_BLOCK_SIZE` (256 MiB) and this pass
    // runs on every repair that has a missing block, so an eager buffer
    // would be a metadata-driven spike on sets with nothing to harvest -
    // the trap `verify_pass1`'s own clamped read buffer is written for.
    let mut buf: Vec<u8> = Vec::new();
    for &g in missing {
        if adopted.contains_key(&g) {
            continue;
        }
        let k = starts.partition_point(|&(s, _)| s <= g);
        if k == 0 {
            continue;
        }
        let (first, ti) = starts[k - 1];
        let t = &targets[ti];
        let i = g - first;
        if i >= t.n_slices || t.file.blocks.len() < t.n_slices {
            continue;
        }
        if !t.exists && whole_on_disk.contains(&(t.file.length, t.file.md5)) {
            continue;
        }
        let want = t.file.blocks[i];
        let Some(&(tj, j)) = by_hash.get(&(want.crc32, want.md5)) else {
            continue;
        };
        let slot = match sources.entry(tj) {
            std::collections::hash_map::Entry::Occupied(o) => o.into_mut(),
            std::collections::hash_map::Entry::Vacant(v) => {
                let f = File::open(&targets[tj].path)?;
                let len = f.metadata()?.len();
                v.insert((None, len, f))
            }
        };
        let off = j as u64 * bs as u64;
        if buf.is_empty() {
            buf = vec![0u8; bs];
        }
        // Past end of file is the zero padding the block checksum was
        // taken over, the same reading [`CandReader`] gives it.
        let avail = crate::disk::chunk_len(slot.1.saturating_sub(off), bs);
        crate::disk::read_exact_at(&slot.2, &mut buf[..avail], off)?;
        buf[avail..].fill(0);
        if crc32fast::hash(&buf) != want.crc32 {
            continue;
        }
        let mut h = Md5::new();
        h.update(&buf);
        if <[u8; 16]>::from(h.finalize()) != want.md5 {
            continue;
        }
        let ci = match slot.0 {
            Some(ci) => ci,
            None => {
                cands.push((targets[tj].path.clone(), slot.1));
                *slot.0.insert(cands.len() - 1)
            }
        };
        adopted.insert(
            g,
            AdoptSrc {
                cand: ci,
                offset: off,
            },
        );
    }
    Ok(())
}

/// Ceiling on the handles [`pin_donor_sources`] holds open through the
/// solve and the patch. A donor adoption references about one file per
/// recovery-set target in practice, so the everyday count is single
/// digits; the cap exists so a pathological adoption pattern cannot walk
/// the process toward its fd limit (macOS ships a 256 soft default).
/// Candidates past it stay on the lazy-open path, with the pre-pin
/// vanish window that implies.
pub(super) const PIN_DONOR_FDS: usize = 64;

/// Close the patch-time half of the donor-vanish window (sweep S3's
/// residue, one phase later than a564adebf's scan-time fix): open every
/// §293 donor file the FINAL adoption references and hand the handles to
/// the caller's [`CandReader`], so the solve feed and the patch read the
/// donor's bytes through fds the racing cleanup cannot invalidate - an
/// unlinked inode stays readable on unix, and std's `File::open` shares
/// FILE_SHARE_DELETE on Windows, so a delete or a rename after this
/// point is a non-event on both. Truncation is NOT survived, and that
/// limit is stated rather than chased: the delete-files cleanup this
/// defends against deletes and trash-moves, it does not truncate.
///
/// A donor that cannot be opened HERE vanished after its bytes were
/// scanned, and degrades exactly as a scan-time vanish does (§293's
/// ownership rule): its adoptions are dropped and their slices returned
/// to `missing` - the caller's escalation scan and needed/have
/// arithmetic then judge the shortfall, never an I/O error. This is
/// strictly better than failing later, because at this point nothing has
/// planned around the donor yet. Only slots inside `donor_cands` are
/// pinned or dropped; the repair's own files keep their lazy open and
/// their fatal errors.
pub(super) fn pin_donor_sources(
    cands: &[(PathBuf, u64)],
    donor_cands: &std::ops::Range<usize>,
    adopted: &mut HashMap<usize, AdoptSrc>,
    missing: &mut Vec<usize>,
) -> HashMap<usize, File> {
    let mut wanted: Vec<usize> = adopted
        .values()
        .map(|s| s.cand)
        .filter(|ci| donor_cands.contains(ci))
        .collect();
    wanted.sort_unstable();
    wanted.dedup();
    let mut open: HashMap<usize, File> = HashMap::new();
    let mut dropped: Vec<usize> = Vec::new();
    for ci in wanted {
        if open.len() >= PIN_DONOR_FDS {
            break;
        }
        match File::open(&cands[ci].0) {
            Ok(f) => {
                open.insert(ci, f);
            }
            Err(_) => dropped.push(ci),
        }
    }
    if !dropped.is_empty() {
        let back: Vec<usize> = adopted
            .iter()
            .filter(|&(_, s)| dropped.contains(&s.cand))
            .map(|(&g, _)| g)
            .collect();
        for g in back {
            adopted.remove(&g);
            missing.push(g);
        }
        // `missing` is consumed in ascending slice order downstream
        // (rebuilt_of, the Reconstructor's row mapping) - restore it.
        missing.sort_unstable();
    }
    open
}

/// Prefetch: every candidate whose length some probing target declares
/// is a candidate the loop can reach, and a head is 16 KB - cheap enough
/// that hashing a few the loop skips costs less than the open latency
/// the fan-out hides.
fn prefetch_heads(
    cands: &[(PathBuf, u64)],
    probing: &[&Target],
    head_cache: &mut [Option<[u8; 16]>],
) {
    let lens: HashSet<u64> = probing.iter().map(|t| t.file.length).collect();
    let want: Vec<usize> = cands
        .iter()
        .enumerate()
        .filter(|(_, (_, len))| lens.contains(len))
        .map(|(ci, _)| ci)
        .collect();
    // The head limit is per-candidate (`min(len, 16384)`), but every
    // candidate here has a length some target declares and the target's
    // own hash16k covers `min(length, 16384)` too, so one limit serves.
    prefetch_md5s(cands, &want, Some(16384), head_cache);
}

/// Prefetch: the whole-file MD5s, which are the expensive half. Pair
/// each probing target with the first head-matching candidate no earlier
/// target has taken - the loop's own greedy walk, assuming a head match
/// holds up. At most one whole-file read per target, so the degenerate
/// "a directory of identical copies" shape stays at the serial count
/// instead of hashing every copy.
fn prefetch_wholes(
    cands: &[(PathBuf, u64)],
    probing: &[&Target],
    head_cache: &[Option<[u8; 16]>],
    md5_cache: &mut [Option<[u8; 16]>],
) {
    let mut taken = vec![false; cands.len()];
    let mut want: Vec<usize> = Vec::new();
    for t in probing {
        let hit = cands
            .iter()
            .enumerate()
            .find(|&(ci, (_, len))| {
                !taken[ci] && *len == t.file.length && head_cache[ci] == Some(t.file.md5_16k)
            })
            .map(|(ci, _)| ci);
        if let Some(ci) = hit {
            taken[ci] = true;
            want.push(ci);
        }
    }
    prefetch_md5s(cands, &want, None, md5_cache);
}

/// Sliding-scan the candidate slots named by `indices` for the content
/// of every slice in `missing_set` not already adopted. Slices without
/// IFSC data can only be found by the whole-file fast path.
///
/// The work is cut into UNITS by [`plan_units`] - a candidate, or a
/// byte range of one - and the workers pull units off a shared cursor,
/// each building its own adoption list, merged afterwards in unit
/// order. Three things keep the answer identical to the serial walk it
/// replaces:
///
/// * The merge is a first-writer-wins fold over the units in order, so
///   the earliest candidate holding a slice's content still wins, at
///   the first offset it found it - and the fold stops the moment every
///   wanted slice is covered, which is the serial loop's own early exit.
///   A worker past that point simply has its list dropped, and its I/O
///   error with it: an error only propagates from a candidate the serial
///   walk would actually have opened.
///
///   THAT IS ONE FOLD OVER ONE ORDER, not two axes, and it is why
///   splitting a candidate needed no second tie-break (16 Sep 2026,
///   claim `par2-adoption-scan-within-candidate-16sep`). The serial
///   walk visits candidate 0's offsets in order, then candidate 1's;
///   `plan_units` emits units in exactly that lexicographic order; so
///   "lowest unit index wins" IS "first candidate, then first offset",
///   and every `pos`-keyed argument below reads as a unit index with
///   nothing else changed. Within one unit the offsets ascend as they
///   always did, and the ranges of one candidate's units are disjoint
///   and ascending, so the concatenation the fold walks is the serial
///   sequence of hits.
///
/// `donor_cands` names the candidate slots whose files live in a §293
/// donor directory. An I/O error on one of THOSE never propagates -
/// the candidate is dropped and the merge continues, so a donor file
/// vanishing under a racing cleanup degrades to "no donation" instead
/// of failing the repair (the file-level half of the tolerance
/// `adoption_candidates` grants per directory). The cost of dropping an
/// errored donor mid-scan is only ever LOST adoptions, never wrong
/// ones: claims it published before erroring may have let later workers
/// skip confirming those slices, and the merge then drops its list, but
/// every adoption that does survive was CRC+MD5 confirmed by the worker
/// that recorded it, and an unadopted slice just stays with the
/// recovery math. Errors on the repair's own files fail as before.
/// * Workers publish each adoption into `best[ord]` (a monotone
///   `fetch_min` of the adopting position), so a worker at position `k`
///   can skip a CRC hit's MD5 confirmation, or stop reading altogether,
///   once every wanted slice reads `best <= k`. Monotonicity is what
///   makes that safe: a slice already held by an earlier position can
///   never come back to `k`, and one `k` holds itself was found at an
///   earlier offset than any later window.
/// * `best` is only consulted through those two skips. Nothing a worker
///   records depends on what another worker found, so the lists - and
///   therefore the merge - do not depend on the interleaving.
pub(super) fn sliding_scan(
    cands: &[(PathBuf, u64)],
    indices: &[usize],
    donor_cands: std::ops::Range<usize>,
    targets: &[Target],
    missing_set: &HashSet<usize>,
    bs: usize,
    adopted: &mut HashMap<usize, AdoptSrc>,
) -> Result<(), RepairError> {
    // Each worker holds a `bs`-byte ring; PAR2 block sizes run to
    // hundreds of MB, so cap the fan-out by that too rather than let a
    // wide machine turn one repair into gigabytes of window buffers.
    let ring_cap = ((256 << 20) / bs.max(1)).max(1);
    sliding_scan_planned(
        cands,
        indices,
        donor_cands,
        targets,
        missing_set,
        bs,
        adopted,
        adoption_fanout().min(ring_cap),
        min_scan_chunk(bs),
    )
}

/// [`sliding_scan`] with the fan-out plan named rather than derived, so
/// the differential tests can drive the WIDE path over a fixture small
/// enough to also drive the narrow one - which is the only way to
/// compare the two on the same bytes. `width` is the worker ceiling and
/// `floor` is [`min_scan_chunk`]'s.
#[expect(clippy::too_many_arguments)]
fn sliding_scan_planned(
    cands: &[(PathBuf, u64)],
    indices: &[usize],
    donor_cands: std::ops::Range<usize>,
    targets: &[Target],
    missing_set: &HashSet<usize>,
    bs: usize,
    adopted: &mut HashMap<usize, AdoptSrc>,
    width: usize,
    floor: u64,
) -> Result<(), RepairError> {
    // Wanted slices get a dense ordinal in target-then-slice order, which
    // is the order the serial `by_crc` buckets were built in - so a CRC
    // bucket still confirms its slices in the same order, and the hot
    // loop indexes a Vec instead of hashing a slice number.
    let mut gs: Vec<usize> = Vec::new();
    let mut md5s: Vec<[u8; 16]> = Vec::new();
    let mut tail: Vec<usize> = Vec::new();
    let mut by_crc: HashMap<u32, Vec<usize>> = HashMap::new();
    for t in targets {
        for (i, c) in t.file.blocks.iter().enumerate() {
            let g = t.first_slice + i;
            // An UNPROVEN slice (a short IFSC, fitted rather than
            // dropped - see `par2::fit_ifsc`) can never be adopted: no
            // donor's MD5 is the placeholder's. Indexing it would put
            // its zero CRC in the prefilter and buy an MD5 per hit for
            // an answer that is always no.
            if missing_set.contains(&g) && !adopted.contains_key(&g) && c.is_proven() {
                by_crc.entry(c.crc32).or_default().push(gs.len());
                gs.push(g);
                md5s.push(c.md5);
                let start = (i as u64) * bs as u64;
                tail.push(crate::disk::chunk_len(
                    t.file.length.saturating_sub(start),
                    bs,
                ));
            }
        }
    }
    if by_crc.is_empty() {
        return Ok(());
    }
    // 65536-bit prefilter on the CRC's low 16 bits: the per-byte hot
    // path is one table probe, not a HashMap lookup.
    let mut filter = vec![0u64; 1024];
    for &crc in by_crc.keys() {
        filter[(crc & 0xFFFF) as usize >> 6] |= 1 << (crc & 63);
    }
    let roll = RollingCrc::new(bs);
    let shared = ScanShared {
        best: (0..gs.len())
            .map(|_| AtomicUsize::new(usize::MAX))
            .collect(),
        covered: AtomicUsize::new(0),
        stop_from: AtomicUsize::new(usize::MAX),
        next: AtomicUsize::new(0),
    };
    let ctx = ScanCtx {
        bs,
        roll: &roll,
        filter: &filter,
        by_crc: &by_crc,
        md5s: &md5s,
        tail: &tail,
        shared: &shared,
    };
    let units = &plan_units(cands, indices, width, floor)[..];
    let found: Mutex<Vec<Option<Result<Vec<(usize, u64)>, RepairError>>>> =
        Mutex::new((0..units.len()).map(|_| None).collect());
    let workers = width.min(units.len()).max(1);
    if workers < 2 {
        run_scans(cands, indices, units, &ctx, &found);
    } else {
        std::thread::scope(|s| {
            for _ in 0..workers {
                let (ctx, found) = (&ctx, &found);
                s.spawn(move || run_scans(cands, indices, units, ctx, found));
            }
        });
    }

    let slots = found.into_inner().unwrap_or_else(|e| e.into_inner());
    // The donor-file half of the racing-cleanup tolerance: an I/O error
    // from a donor-owned slot (vanished file, the shrank-mid-scan EOF)
    // drops that candidate's list and moves on. It drops EVERY unit of
    // that candidate, not just the one that erred: the property the
    // header claims - that dropping an errored donor costs only lost
    // adoptions, never wrong ones - rests on the whole candidate's
    // claims going with it, and a candidate's claims are spread across
    // its units.
    let mut dead: HashSet<usize> = HashSet::new();
    for (u, slot) in slots.iter().enumerate() {
        if matches!(slot, Some(Err(_))) && donor_cands.contains(&indices[units[u].pos]) {
            dead.insert(units[u].pos);
        }
    }
    let mut remaining = gs.len();
    for (u, slot) in slots.into_iter().enumerate() {
        if remaining == 0 {
            break;
        }
        let pos = units[u].pos;
        if dead.contains(&pos) {
            continue;
        }
        for (ord, offset) in slot.transpose()?.unwrap_or_default() {
            if let std::collections::hash_map::Entry::Vacant(v) = adopted.entry(gs[ord]) {
                v.insert(AdoptSrc {
                    cand: indices[pos],
                    offset,
                });
                remaining -= 1;
            }
        }
    }
    Ok(())
}

/// Cross-worker state for one [`sliding_scan`]. `best[ord]` is the
/// lowest UNIT index known to hold slice `ord`'s content (`usize::MAX`
/// = nobody yet); it only ever decreases.
///
/// A unit index, not a candidate position, since 16 Sep 2026 - and
/// that is the whole of the restatement, because [`plan_units`] emits
/// units in serial scan order, so "a lower unit index" means what "an
/// earlier candidate" meant before: earlier in the walk this fan-out
/// reproduces. When no candidate is split the two are the same number.
struct ScanShared {
    best: Vec<AtomicUsize>,
    /// How many ordinals have left `usize::MAX`, so the O(slices) sweep
    /// below only runs once everything has been found by somebody.
    covered: AtomicUsize,
    /// Lowest unit that observed "every slice settled at or before me".
    /// The condition is monotone in the unit index, so every later unit
    /// inherits it without re-deriving it.
    stop_from: AtomicUsize,
    next: AtomicUsize,
}

impl ScanShared {
    /// Can a scan at unit `pos` still change any decision? False once
    /// every wanted slice is held by `pos` itself or by an earlier unit.
    ///
    /// Held BY `pos` ITSELF is still safe with a candidate split across
    /// units, and it is the one arm worth spelling out: only the unit
    /// that owns an offset range can claim from it, so `best[o] == pos`
    /// means this very unit found `o` at an offset it has already
    /// passed, and every window left in the unit is a higher offset
    /// that would lose the merge anyway. A unit stopping therefore
    /// forfeits nothing, whatever its siblings over the same candidate
    /// are doing.
    fn settled_at(&self, pos: usize) -> bool {
        if pos >= self.stop_from.load(Ordering::Relaxed) {
            return true;
        }
        if self.covered.load(Ordering::Relaxed) != self.best.len() {
            return false;
        }
        let all = self.best.iter().all(|b| b.load(Ordering::Relaxed) <= pos);
        if all {
            self.stop_from.fetch_min(pos, Ordering::Relaxed);
        }
        all
    }

    /// Record that unit `pos` holds `ord`'s content.
    fn claim(&self, ord: usize, pos: usize) {
        if self.best[ord].fetch_min(pos, Ordering::Relaxed) == usize::MAX {
            self.covered.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// The read-only half of a [`sliding_scan`], shared by every worker.
struct ScanCtx<'a> {
    bs: usize,
    roll: &'a RollingCrc,
    filter: &'a [u64],
    by_crc: &'a HashMap<u32, Vec<usize>>,
    md5s: &'a [[u8; 16]],
    /// Real content length of each wanted slice: `bs` for every slice
    /// but a file's last, which is `length % bs` when that is nonzero.
    /// The window's virtual zero padding may only ever stand in for a
    /// slice's OWN zero padding - see [`scan_candidate`].
    tail: &'a [usize],
    shared: &'a ScanShared,
}

/// Pull scan units off the shared cursor until they run out.
fn run_scans(
    cands: &[(PathBuf, u64)],
    indices: &[usize],
    units: &[ScanUnit],
    ctx: &ScanCtx<'_>,
    found: &Mutex<Vec<Option<Result<Vec<(usize, u64)>, RepairError>>>>,
) {
    loop {
        let u = ctx.shared.next.fetch_add(1, Ordering::Relaxed);
        let Some(unit) = units.get(u) else { break };
        if ctx.shared.settled_at(u) {
            continue;
        }
        let (p, len) = &cands[indices[unit.pos]];
        let r = scan_candidate(p, *len, ctx, u, unit.start, unit.end);
        found.lock_ok()[u] = Some(r);
    }
}

/// Slide the block-size window over one candidate file (plus `bs - 1`
/// virtual zero bytes so tail blocks match at end-of-file) and return
/// every still-wanted slice whose CRC32 and MD5 both match, as
/// `(ordinal, offset)` in the order found. `pos` is this UNIT's place
/// in the scan order - see [`sliding_scan`] for what it is allowed to
/// skip on the strength of it.
///
/// `from`..`to` is the half-open range of window START offsets this
/// unit owns; the whole file is `0..len`. A window starting at `to - 1`
/// still needs the `bs - 1` bytes after it, so the unit reads that far
/// into its successor's range - the fixed overhead [`min_scan_chunk`]
/// sizes a chunk against. Nothing else about the pass is range-local:
/// the rolling register is warmed over this unit's own first `bs`
/// bytes, which is what makes the window position-independent and the
/// split possible at all.
///
/// THE VIRTUAL PADDING BELONGS TO THE FILE, NOT TO A CHUNK. `total` is
/// derived from `len`, so only the unit whose range ends at `len` ever
/// reads a zero out of the tail; an interior unit stops at a real byte
/// and the `real = len - offset` bound is computed against the FILE's
/// length in both. A chunk boundary is therefore invisible to the
/// M4-40 rule below - which it has to be, or a split would let an
/// interior window fabricate content the way the one-byte decoy did.
///
/// M4-40 (no-RAR matrix, third extreme pass): the virtual padding is
/// what makes a PARTIAL last block findable at a candidate's own EOF -
/// a PAR2 tail slice is zero-padded to `bs`, so the last `bs - r` bytes
/// of its checksum cover padding, not content. Unbounded, that same
/// padding also GENERATES content: every window that runs off the end
/// is real bytes followed by manufactured zeros, so a one-byte `0x00`
/// junk file yields one all-zero window and can donate any all-zero
/// block of any target. Measured before the bound: a 1-byte decoy
/// donated a full block of a wholly-missing file, the repair finished
/// on it, and `proven_spent`'s fully-donated arm - one adoption covers
/// every byte of a one-byte file - reported the decoy spent and it was
/// deleted.
///
/// So a window carrying virtual bytes may only claim a slice whose own
/// padding is at least as long: `real >= tail[o]`, where `real` is the
/// count of bytes that came off the file. Every virtual byte then lands
/// inside the slice's own zero padding and stands in for nothing. The
/// legitimate case is untouched - a candidate ending with a target's
/// partial tail has exactly `r` real bytes there, and one holding a
/// full block has `bs` - and the rule is free for every window that
/// ends at or before EOF, where `real == bs >= tail[o]` always.
fn scan_candidate(
    path: &Path,
    len: u64,
    ctx: &ScanCtx<'_>,
    pos: usize,
    from: u64,
    to: u64,
) -> Result<Vec<(usize, u64)>, RepairError> {
    let bs = ctx.bs;
    let mut mine: Vec<(usize, u64)> = Vec::new();
    let mut f = File::open(path)?;
    if from > 0 {
        f.seek(std::io::SeekFrom::Start(from))?;
    }
    let mut ring = vec![0u8; bs];
    let mut rpos = 0usize; // ring slot of the window's oldest byte
    let mut reg = 0xFFFF_FFFFu32;
    let mut buf = vec![0u8; 1 << 18];
    let mut i: u64 = from; // stream index: file bytes, then virtual zeros
    // The stream index at which this unit's FIRST window closes, and so
    // the point the rolling register stops being warmed and starts
    // rolling. It is `bs` for a unit that starts at the file's head,
    // which is what it always was.
    let first = from + bs as u64;
    let total = len + bs as u64 - 1;
    // ...and the point it stops, one `bs` past the last start it owns.
    let stop = (to + bs as u64 - 1).min(total);
    'stream: while i < stop {
        let n = if i < len {
            let want = crate::disk::chunk_len(len.min(stop) - i, buf.len());
            let got = f.read(&mut buf[..want])?;
            if got == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "candidate file shrank mid-scan",
                )
                .into());
            }
            got
        } else {
            let want = crate::disk::chunk_len(stop - i, buf.len());
            buf[..want].fill(0);
            want
        };
        for &b in &buf[..n] {
            let old = ring[rpos];
            reg = if i < first {
                ctx.roll.push(reg, b)
            } else {
                ctx.roll.roll(reg, old, b)
            };
            ring[rpos] = b;
            rpos += 1;
            if rpos == bs {
                rpos = 0;
            }
            i += 1;
            if i < first {
                continue;
            }
            let crc = reg ^ 0xFFFF_FFFF;
            if ctx.filter[(crc & 0xFFFF) as usize >> 6] & (1 << (crc & 63)) == 0 {
                continue;
            }
            let Some(slices) = ctx.by_crc.get(&crc) else {
                continue;
            };
            if slices
                .iter()
                .all(|&o| ctx.shared.best[o].load(Ordering::Relaxed) <= pos)
            {
                continue;
            }
            let mut h = Md5::new();
            h.update(&ring[rpos..]);
            h.update(&ring[..rpos]);
            let md5: [u8; 16] = h.finalize().into();
            let offset = i - bs as u64;
            // How many of this window's bytes came off the file rather
            // than out of the virtual padding. `offset < len` always
            // (the last window starts at `len - 1` at the latest), so
            // this is >= 1, and it is `bs` for every window that ends
            // at or before EOF.
            let real = len - offset;
            for &o in slices {
                if real < ctx.tail[o] as u64 {
                    // M4-40: the padding may only stand in for the
                    // slice's OWN zero padding. Past that it is
                    // FABRICATING target content out of bytes this
                    // candidate does not have - which is how a
                    // one-byte `0x00` junk file donated a full
                    // all-zero block and was then swept as a
                    // fully-donated source (`proven_spent`).
                    continue;
                }
                if ctx.md5s[o] == md5 && ctx.shared.best[o].load(Ordering::Relaxed) > pos {
                    ctx.shared.claim(o, pos);
                    mine.push((o, offset));
                }
            }
        }
        // Checked per buffer refill, not per byte: the fast half is one
        // atomic load, and the O(slices) sweep behind it only runs once
        // every slice has been found by somebody.
        if ctx.shared.settled_at(pos) {
            break 'stream;
        }
    }
    Ok(mine)
}

#[cfg(test)]
mod tests;

/// X6-02's pins on which files [`adoption_candidates`] offers, kept out
/// of `tests` because that module is a differential oracle against the
/// pre-fan-out code and this is a statement about the walk's REACH.
#[cfg(test)]
mod walk_tests;

/// Claim `proven-spent-majority-bar`: what [`proven_spent`]'s
/// damaged-twin arm can decide, and the measurement showing it cannot
/// be tuned with the evidence it is handed.
#[cfg(test)]
mod spend_tests;

/// Reads adopted block bytes from candidate files, keeping each source
/// open across calls. Bytes past a candidate's end are the zero padding
/// the block checksum was verified against. §293 donor sources arrive
/// already open ([`pin_donor_sources`] - the handle keeps a deleted
/// donor readable); the repair's own files open lazily, fatal.
///
/// Lives here rather than in the parent because it is the READ side of
/// this module's own decisions - `cands` is [`adoption_candidates`]'s
/// list and `AdoptSrc` its verdict - and because the parent is over the
/// size gate's ceiling while this file is nowhere near it.
pub(super) struct CandReader<'a> {
    pub(super) cands: &'a [(PathBuf, u64)],
    /// Every candidate this repair has read from, still OPEN.
    ///
    /// The cache is what makes the per-block reads cheap, and it is
    /// also a handle the caller has to get rid of before it MOVES one
    /// of these files. [`whole_file_renames`] renames a donor onto its
    /// target, and a donor is read here whether or not its target is
    /// written: adopted blocks are fed into the syndrome as present
    /// data, so a set with anything left to rebuild opens every donor
    /// it adopted from, including a whole-file match's.
    ///
    /// POSIX renames an open file without complaint, and Windows
    /// permits it only because Rust's std opens with FILE_SHARE_DELETE.
    /// ref-gate: that share mode is set in the RUST TOOLCHAIN's own
    /// source, not in this workspace - `library/std/src/sys/fs/
    /// windows.rs` under the rustup toolchain, read there on 17 Sep
    /// 2026. It is named so a reader can re-check the one claim this
    /// argument rests on, and it is deliberately not a path in this
    /// repo. That is a share mode no
    /// test on this fleet has ever exercised on this path, and an
    /// antivirus or indexer handle taken WITHOUT it would fail the
    /// rename intermittently with os error 5 or 32 - which reads as a
    /// flake and is not one. [`CandReader::close_all`] removes the
    /// dependency rather than resting on it.
    pub(super) open: HashMap<usize, File>,
}

impl CandReader<'_> {
    pub(super) fn read(&mut self, s: AdoptSrc, take: usize) -> Result<Vec<u8>, RepairError> {
        let (path, len) = &self.cands[s.cand];
        let f = match self.open.entry(s.cand) {
            std::collections::hash_map::Entry::Occupied(o) => o.into_mut(),
            std::collections::hash_map::Entry::Vacant(v) => v.insert(File::open(path)?),
        };
        let avail = crate::disk::chunk_len(len.saturating_sub(s.offset), take);
        let mut v = vec![0u8; take];
        crate::disk::read_exact_at(f, &mut v[..avail], s.offset)?;
        Ok(v)
    }

    /// Close every cached handle. See [`CandReader::open`] for why a
    /// caller that renames a candidate must call this first, and why
    /// dropping the reader itself is not available at that point (the
    /// patch closure still borrows it).
    pub(super) fn close_all(&mut self) {
        self.open.clear();
    }
}

/// Findings F9 and F13-adjacent residue (capability corpus, 30 Aug
/// 2026): the two per-byte spend proofs for a repair-dir-own source
/// the exact-MD5 test can never clear - the DAMAGED TWIN and the
/// FULLY-DONATED split part. Both return true only on evidence about
/// EVERY byte of the candidate; anything less keeps the file (the
/// near-twin decoy corpus row is the attack this bar exists for).
///
/// EVERY ARM HERE ASSUMES A NOW-VERIFIED TARGET, and that is why the
/// caller's spend loop is gated on `shortfall.is_none()`
/// (`RepairStatus::Unrepairable`'s `consumed_sources` note, departure 2
/// of `6c71c020d`). Read this before lifting that gate - the recorded
/// blocker understates it, and the understatement is in the direction
/// that deletes files:
///
/// * `rebuilt_set` is the caller's `missing` IN FULL, and a shortfall
///   rebuilds NONE of it. The twin arm's `None if rebuilt_set.contains`
///   branch excuses a mismatch there on the promise that the target
///   carries better bytes at that offset - which on a shortfall it does
///   not. That is precisely where a damaged twin differs, so the arm
///   would excuse the whole difference and report an unrelated
///   same-length file spent.
/// * the caller's exact-MD5 arm above has the same premise from the
///   other side: a candidate byte-identical to a target that was NOT
///   published is the only whole copy of that member on the disk.
///
/// So a shortfall-aware version has to narrow BOTH - the rebuilt set to
/// `missing[..rebuilt.len()]`, and the target population to the ones
/// now provably whole on disk (intact pre-repair, or published and
/// MD5-verified in this run) - and that is a change to the DELETE path
/// with its own measurement, not a gate lift. Claim
/// `shortfall-publish-patch-existing` (31 Aug 2026) found this while
/// building departure 1 and deliberately left departure 2 alone.
#[expect(clippy::too_many_arguments)]
pub(super) fn proven_spent(
    p: &Path,
    len: u64,
    ci: usize,
    targets: &[Target],
    adopted: &HashMap<usize, AdoptSrc>,
    rebuilt_set: &HashSet<usize>,
    cands: &[(PathBuf, u64)],
    bs: usize,
) -> bool {
    let len = &len;
    // The DAMAGED-TWIN arm (finding F9, capability corpus 30 Aug
    // 2026): a hash-named copy of the payload whose damage kept
    // every hash tier from claiming it, whose GOOD blocks this
    // repair just adopted into the now-verified target. The
    // exact-MD5 proof above can never fire on it - the damage is
    // the difference - so it lingered in a finished job forever.
    // The proof standard stays per-byte, reached differently:
    // every block of a same-length target must be identical to
    // the candidate's bytes at that offset, EXCEPT blocks this
    // repair itself sourced from recovery data or from another
    // candidate (verify had declared those absent, and their good
    // bytes are in the target) - and blocks adopted FROM this
    // candidate are identical by construction. A file passing
    // that holds no byte range the target does not carry better.
    // Per-block proof, and WHICH bytes each block is proven against
    // matters more than it looks. From-this-candidate blocks are
    // identical by construction. Blocks rebuilt from RECOVERY are
    // the only excused mismatches - they are exactly where a
    // damaged twin differs. Blocks adopted from ANOTHER candidate
    // are NOT excused: they must byte-match this candidate, read
    // from that donor's own file (on disk now, where a RECREATED
    // target's final file is not - temp-and-rename-last). Without
    // that rule a same-length DECOY sharing only the payload's
    // head would have every differing tail block excused as
    // "adopted elsewhere" and be deleted with its unique bytes -
    // the near-twin-decoy corpus row's exact attack. Blocks the
    // verify found PRESENT in the target compare against t.path.
    use std::io::{Read, Seek, SeekFrom};
    let read_span = |path: &Path, at: u64, buf: &mut [u8]| -> bool {
        File::open(path)
            .is_ok_and(|mut f| f.seek(SeekFrom::Start(at)).is_ok() && f.read_exact(buf).is_ok())
    };
    let twin = targets.iter().any(|t| {
        if t.file.length != *len || *len == 0 {
            return false;
        }
        let mut fed_by_ci = 0usize;
        let mut cb = vec![0u8; bs];
        let mut ob = vec![0u8; bs];
        for li in 0..t.n_slices {
            let g = t.first_slice + li;
            let start = (li as u64) * bs as u64;
            let take = crate::disk::chunk_len(len.saturating_sub(start), bs);
            match adopted.get(&g) {
                Some(s) if s.cand == ci => {
                    // Proof only when the donated bytes sit at THIS
                    // slice's offset. `sliding_scan` matches at any byte
                    // offset, so an unaligned adoption says the
                    // candidate carries the block SOMEWHERE - never that
                    // `p[start..start+take]` IS the target's block,
                    // which is the thing the twin proof is about. An
                    // unaligned one is neither proof nor a mismatch, so
                    // it is excused without being counted.
                    if s.offset == start {
                        fed_by_ci += 1;
                    }
                    continue;
                }
                Some(s) => {
                    // Sourced from another candidate: this one must
                    // carry the same bytes there or it is its own
                    // file, not a twin.
                    if !read_span(p, start, &mut cb[..take])
                        || !read_span(&cands[s.cand].0, s.offset, &mut ob[..take])
                        || cb[..take] != ob[..take]
                    {
                        return false;
                    }
                }
                None if rebuilt_set.contains(&g) => continue,
                None => {
                    // Present in the target pre-repair: compare in
                    // place.
                    if !read_span(p, start, &mut cb[..take])
                        || !read_span(&t.path, start, &mut ob[..take])
                        || cb[..take] != ob[..take]
                    {
                        return false;
                    }
                }
            }
        }
        // No block fed from this candidate means no evidence tying
        // it to this target at all - never spend on that.
        //
        // A MAJORITY, not one block (30 Aug 2026 sweep). `fed_by_ci > 0`
        // alone is not a per-byte proof of anything when the target was
        // WHOLLY unidentified, and that is precisely the target class
        // that turns adoption on in the first place (`any_unidentified`).
        // For such a target every slice is in `adopted` or in
        // `rebuilt_set`, so the two arms above that actually READ the
        // candidate - the compare against another donor, and the compare
        // against `t.path` - are unreachable, the loop performs ZERO byte
        // comparisons, and the whole test collapses to "did this file
        // donate at least one block". `sliding_scan` has no entropy floor
        // and matches at any offset, so a single shared block-sized run
        // (container padding, a zero fill, a shared header) is enough:
        // an unrelated same-length file was then reported spent and
        // `sweep_spent_sources` unlinked every one of its bytes.
        //
        // A genuine damaged twin - the shape the F9 arm exists for -
        // donates most of the payload, because its GOOD blocks are what
        // this repair adopted. A coincidence donates one. The majority is
        // the only discriminator available here, and the direction it
        // fails in is the safe one: too strict merely leaves a spent twin
        // on disk as clutter, which is the pre-F9 behaviour, where too
        // loose destroys a file nothing can bring back.
        fed_by_ci * 2 > t.n_slices
    });
    if twin {
        return true;
    }
    // The FULLY-DONATED arm (the split-post shape): a raw half or
    // quarter posted under a hash name, whose EVERY byte the
    // repair just read into the verified join. The donated spans
    // are identical by construction, so merged coverage of the
    // whole candidate is a proof about every byte of it - nothing
    // the file holds is absent from the target. A partial donor
    // (the near-twin decoy, a damaged fragment) never reaches full
    // coverage and is kept.
    //
    // M4-62 (wave-4 matrix read, 30 Aug 2026) is the bound on that
    // proof, and it is M4-40's rule on the SPEND side rather than the
    // claim side. The target's last slice is `r` real bytes followed by
    // `bs - r` of zero PADDING, and the padding is not in the target
    // file at all - a 200-byte file's last block is 64 bytes of which 8
    // exist. So donating that slice authenticates `r` bytes of the
    // candidate and NOT the window's full width. Uncapped, a
    // `bs`-length junk file whose entire content IS a padded last-block
    // window scored merged coverage of itself, read as fully donated,
    // and was handed to `sweep_spent_sources` to unlink - with `bs - r`
    // of its bytes provably absent from the target. Measured on the
    // 30 Aug baseline: `consumed_sources: ["junkZq62.bin"]` for a
    // 64-byte file of which 8 bytes were ever wanted.
    //
    // A window is therefore worth `min(bytes it read off this
    // candidate, real target bytes in that slice)`. Every legitimate
    // shape is untouched: a mid-file block is `min(bs, bs)`, and a
    // split part or whole renamed copy that ends where the target ends
    // has exactly `r` bytes there on BOTH sides, so `min(r, r) = r` and
    // coverage still reaches the candidate's end. A slice belonging to
    // no target proves nothing (0) rather than defaulting to the
    // window - the direction that keeps a file rather than deletes one,
    // which is the standing tie-break here.
    let real_bytes_of = |g: usize| -> u64 {
        targets
            .iter()
            .find_map(|t| {
                let li = g.checked_sub(t.first_slice)?;
                (li < t.n_slices).then(|| {
                    crate::disk::chunk_len(
                        t.file.length.saturating_sub((li as u64) * bs as u64),
                        bs,
                    ) as u64
                })
            })
            .unwrap_or(0)
    };
    let mut spans: Vec<(u64, u64)> = adopted
        .iter()
        .filter(|(_, s)| s.cand == ci)
        .map(|(&g, s)| {
            let avail = crate::disk::chunk_len(len.saturating_sub(s.offset), bs) as u64;
            (s.offset, avail.min(real_bytes_of(g)))
        })
        .collect();
    if !spans.is_empty() {
        spans.sort_unstable();
        let mut end = 0u64;
        let mut full = true;
        for (off, take) in spans {
            if off > end {
                full = false;
                break;
            }
            end = end.max(off + take);
        }
        if full && end >= *len {
            return true;
        }
    }
    false
}

/// Which of a set's declared blocks are findable at ANY byte offset
/// inside the members' own files - par2cmdline's DEFAULT verify pass,
/// for a caller that has already run the ALIGNED one.
///
/// WHY IT IS PUBLIC AND WHO ASKS. par2cmdline verifies by rolling a
/// block-sized CRC32 window over every source file it opens, so a
/// member that has been SHIFTED - a prefix prepended, a run of bytes
/// inserted - still reports every block present at its real offset.
/// `parfast`'s verify hashed the aligned grid and nothing else, so the
/// same set read `Found 0 of 30 data blocks` where the reference reads
/// `Found 30 of 30`, and the repair that followed refused work the
/// reference completes (`research/CLI-SUBSTITUTION-2026-09-03.md`, G4;
/// measured 30-of-30 against 0-of-30 on the DEFAULT no-switch verify).
/// The capability was already here - `sliding_scan` is the same
/// rolling window, and the engine's own repair reaches it through
/// `adopt_blocks` and the caller's escalation - but only ever behind
/// a repair that had already decided to run. A CLI has to PRINT the
/// count before it decides anything, which is what this door is for.
///
/// It is the SAME scan, not a second one: one spelling of "these
/// bytes carry this slice", one prefilter, one CRC-then-MD5 bar.
///
/// WHAT IT SCANS, and the bound is the whole cost story. Only members
/// that EXIST, are not already fully proven by `proven`, and whose
/// on-disk length is not the length the set declares - so a clean set
/// scans nothing at all, and neither does a set damaged IN PLACE. The
/// argument for that second screen, and the one shape it gives up, are
/// at the screen itself. A block is credited to the
/// member that DECLARES it wherever it is found, which is what lets a
/// mid-file insertion in one member still account for a neighbour's
/// slice; extra files that no FileDesc names are NOT walked here,
/// because the reference prints its `Target:` lines before it opens
/// them and `parfast`'s repair hands that half to the engine.
///
/// `paths` and `proven` are indexed like `files`. `proven[i]` may be
/// shorter than the member's slice count (an empty bitmap is "nothing
/// proven"); anything past its end counts as unproven. The answer is
/// the MERGED bitmap - what the aligned pass proved plus what the scan
/// found - so a caller counts `true`s and nothing else.
///
/// An I/O error on any scanned file drops that file's contribution
/// rather than failing: this answers a verify, which is read-only and
/// reports what it could read, and the aligned pass has already had its
/// own say about a member it could not open.
pub fn scan_members_for_blocks(
    files: &[Par2File],
    paths: &[Option<PathBuf>],
    proven: &[Vec<bool>],
    bs: usize,
) -> Vec<Vec<bool>> {
    let mut out: Vec<Vec<bool>> = Vec::with_capacity(files.len());
    for (i, f) in files.iter().enumerate() {
        let n = if bs == 0 {
            0
        } else {
            f.length.div_ceil(bs as u64) as usize
        };
        let mut bits = vec![false; n];
        if let Some(have) = proven.get(i) {
            for (b, &ok) in bits.iter_mut().zip(have.iter()) {
                *b = ok;
            }
        }
        out.push(bits);
    }
    if bs == 0 {
        return out;
    }
    // WHAT TO OPEN, decided BEFORE anything is built, and this is the
    // whole cost story. Two screens, both cheap:
    //
    // * a member the aligned pass settled whole is never reopened, so a
    //   set with no unproven slice anywhere leaves here having touched
    //   no file and cloned no packet - the ordinary CLEAN verify, which
    //   this must not tax and measurably does not (A/B 1.005 against an
    //   A/A floor of 1.005 over 25 interleaved 512 MiB verifies, 9 Sep
    //   2026);
    // * a member whose on-disk length is EXACTLY the length the set
    //   declares is not scanned either.
    //
    // THE LENGTH SCREEN IS THE ONE THAT NEEDS ARGUING. Misplacing a
    // block means moving the bytes after it, and every shape that does
    // so changes the file's size: a prepended prefix, a mid-file
    // insertion, a concatenation, a truncation. What keeps the size is
    // damage IN PLACE - a bad article, a flipped bit, a zero-filled gap
    // - and in-place damage leaves every surviving block exactly on the
    // grid the aligned pass already read, so a rolling window over that
    // file re-finds precisely what is already proven and nothing more.
    // Without the screen it costs a full extra pass to learn that:
    // measured on a 512 MiB set with one bad block, a damaged verify
    // went 2.9x and the repair behind it 2.1x, against an A/A floor of
    // 0.92 and 0.72 respectively (9 Sep 2026).
    //
    // WHAT THE SCREEN GIVES UP, stated rather than implied: a file
    // holding an insertion AND a deletion that cancel to the declared
    // length keeps misplaced blocks this will not look for. No shape in
    // the substitution audit, the parity suite or any corruption a
    // download produces is that; par2cmdline finds it because it rolls
    // over every file unconditionally, and it is the one case where we
    // still would not.
    let mut cands: Vec<(PathBuf, u64)> = Vec::new();
    for (i, bits) in out.iter().enumerate() {
        if !bits.iter().any(|&ok| !ok) {
            continue;
        }
        let Some(p) = paths.get(i).and_then(Option::as_ref) else {
            continue;
        };
        if let Ok(m) = std::fs::metadata(p)
            && m.len() > 0
            && m.len() != files[i].length
        {
            cands.push((p.clone(), m.len()));
        }
    }
    if cands.is_empty() {
        return out;
    }
    // The global slice space, in `files` order, exactly as the repair's
    // own target walk lays it out - `sliding_scan` speaks that space and
    // nothing else.
    let mut targets: Vec<Target> = Vec::with_capacity(files.len());
    let mut first = 0usize;
    let mut missing_set: HashSet<usize> = HashSet::new();
    for (i, f) in files.iter().enumerate() {
        let n = out[i].len();
        for (j, &ok) in out[i].iter().enumerate() {
            if !ok {
                missing_set.insert(first + j);
            }
        }
        let on_disk = paths.get(i).and_then(Option::as_ref);
        targets.push(Target {
            file: f.clone(),
            path: on_disk.cloned().unwrap_or_default(),
            first_slice: first,
            n_slices: n,
            present: out[i].clone(),
            intact: false,
            exists: on_disk.is_some(),
            resume: None,
            md5_unfinished: false,
        });
        first += n;
    }
    let indices: Vec<usize> = (0..cands.len()).collect();
    let mut adopted: HashMap<usize, AdoptSrc> = HashMap::new();
    // Every candidate sits in the tolerant range: see the header - a
    // verify reports what it could read and never fails on a file the
    // aligned pass has already ruled on.
    if sliding_scan(
        &cands,
        &indices,
        0..cands.len(),
        &targets,
        &missing_set,
        bs,
        &mut adopted,
    )
    .is_err()
    {
        return out;
    }
    // Global index back to (member, slice), by the same walk that laid
    // it out. Spelled as a dense table rather than a search over the
    // first-slice offsets, because a set MAY declare a zero-length
    // member: two members then share one offset and a search cannot say
    // which of them owns the slice after it.
    let mut owner: Vec<(usize, usize)> = Vec::with_capacity(first);
    for (i, bits) in out.iter().enumerate() {
        for j in 0..bits.len() {
            owner.push((i, j));
        }
    }
    for g in adopted.into_keys() {
        if let Some(&(i, j)) = owner.get(g) {
            out[i][j] = true;
        }
    }
    out
}
