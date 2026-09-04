//! Which recovery-volume BASE NAMES provably belong to one PAR2 set,
//! read off the indexes already on disk.
//!
//! Its own file rather than a block in repair.rs, which the merge that
//! brought this in left at 3,026 of the size gate's 3,000-line ceiling
//! - the same reason `sidefetch`, `ladder_tests` and `vol_affinity_tests`
//! are each out here. One subject, one caller
//! ([`super::recovery_candidates`]), and nothing else in the file
//! reaches it.

use super::*;

/// How much of ONE on-disk PAR2 index this reads to learn which
/// recovery set it belongs to.
///
/// A PAR2 packet declares its recovery set id at bytes 32..48 of its
/// own header, so the FIRST complete packet in the window answers the
/// question and the rest of the file is never needed. The window is
/// generous rather than tight because packet order is the writer's
/// choice: par2cmdline puts the tiny Main packet first, and a window
/// that holds no complete packet simply does not count - it costs the
/// none-affine fallback, never a wrong answer.
const INDEX_HEAD_BYTES: u64 = 1 << 20;

/// Total bytes [`index_bases_on_disk`] will read across one directory.
///
/// A bomb guard and nothing more, in the shape the rest of this file
/// already uses (see `MAX_RECREATED_FILES`): an ordinary post has one
/// index per set, GH #63's eighteen-set shape has eighteen and all of
/// them are tens of kilobytes, so 64 files at the per-file window is
/// already an order of magnitude past anything real. It is here so an
/// output directory holding thousands of index-shaped names cannot turn
/// a naming question into a scan. Running out costs the none-affine
/// fallback, exactly as an unreadable index does.
const INDEX_SCAN_BUDGET: u64 = 64 << 20;

/// The volume BASE NAMES that PROVABLY belong to `set`, read off the
/// PAR2 index files already on disk in `out_dir`.
///
/// TODO 311's naming rule, answered by CONTENT instead of by guesswork,
/// and it costs nothing: par2cmdline gives a set's index and every one
/// of its volumes the same base (`cd1.par2`, `cd1.vol00+01.par2`, ...),
/// the index is small and was downloaded long before any repair, and
/// [`nzbkit::par2::Par2Set::set_id_of`] reads a set id out of exactly
/// those bytes. So "which set does this volume belong to" has a
/// zero-round-trip, zero-extra-byte answer for every volume named after
/// its own index - which is every volume par2cmdline ever wrote.
///
/// WHY THIS IS NOT THE PER-VOLUME PROBE, which was priced and refused
/// (`research/VOLUME-ATTRIBUTION-PRICE-2026-08-31.md`): that one asks
/// the volume, and NNTP's unit is an ARTICLE, so asking costs
/// `min(article_size, volume_size)` per candidate - measured at 2.7x to
/// 5.3x the purchase it was guarding. This one asks the INDEX, whose
/// bytes are already here.
///
/// INDEX FILES ONLY, and the volumes on disk are skipped deliberately
/// rather than overlooked: a volume's base is by construction its own
/// index's base, so reading one adds no base this does not already
/// have, and reading it would mean slurping the head of every recovery
/// volume an earlier pass banked. THE SKIP IS A COST GUARD, and there is
/// deliberately no test pinning it, which is said here because it looks
/// like there should be: [`nzbkit::nzb::SubjectClass::par2_stem`]
/// resolves a volume to the SAME base its index gives, so wherever the
/// index is on disk a volume that reached this far contributes a base
/// already contributed. Measured by mutation 31 Aug 2026 (and again
/// against the earlier `.par2`-stripping shape, where a volume
/// contributed nothing at all): deleting the skip reddens nothing
/// either way. A test that cannot bite is worse than none.
///
/// THE ONE CASE IT COULD COST is a set whose index never reached
/// `out_dir` while a volume of it did, where dropping the skip would
/// find a base this cannot. It is left unclaimed rather than chased: a
/// set only exists here because its index packets were parsed, and a
/// NAMED index is an ordinary downloaded file, while an obfuscated one
/// classifies as `Data` and is skipped whatever this rule does - its
/// volumes reach the list through the sniff instead. Against that, the
/// escalation runs with every banked volume sitting in the directory,
/// so dropping the skip buys a head read of each.
///
/// THE NAME RULE IS THE CLASSIFIER'S, never a second copy: `par2_stem`
/// is the one place that answers "where does this PAR2 name's set stem
/// end", across both the index and the volume spelling, and reading it
/// here is what keeps this comparison's two sides from parting company
/// (`tools/par2-rule-gate.py`, and N6-04/N6-05 for what a second copy
/// costs). A bare filename classifies under the RAW-subject rule, which
/// is correct for one: nothing quoted it out of a subject.
///
/// FAILING TO FIND IS NOT FAILING HERE, which is the one place this
/// file departs from the house rule, and it is deliberate: an empty
/// answer leaves [`recovery_candidates`] exactly as it was before this
/// existed - the name heuristic, then the none-affine fallback - so an
/// obfuscated post (whose index is a hash and whose volumes are hashes)
/// is untouched, and a missing, unreadable or truncated index costs a
/// tightening rather than a volume.
pub(super) fn index_bases_on_disk(out_dir: &Path, set: &nzbkit::par2::Par2Set) -> Vec<String> {
    use std::io::Read as _;
    let Ok(rd) = std::fs::read_dir(out_dir) else {
        return Vec::new();
    };
    let mut bases: Vec<String> = Vec::new();
    let mut budget = INDEX_SCAN_BUDGET;
    for e in rd.flatten() {
        if budget == 0 {
            break;
        }
        if !e.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        let class = nzbkit::nzb::classify_subject_detail(&name);
        // An INDEX is the PAR2 kind that is not a volume, which is what
        // `Par2Main` means; its stem is everything before `.par2`, and a
        // volume's is everything before `.vol...`. One rule, one place.
        if class.kind() != FileKind::Par2Main {
            continue;
        }
        let Some(base) = class.par2_stem().filter(|b| !b.is_empty()) else {
            continue;
        };
        let base = base.to_ascii_lowercase();
        let Ok(fh) = std::fs::File::open(e.path()) else {
            continue;
        };
        let mut head = Vec::new();
        if fh
            .take(INDEX_HEAD_BYTES.min(budget))
            .read_to_end(&mut head)
            .is_err()
        {
            continue;
        }
        budget = budget.saturating_sub(head.len() as u64);
        if nzbkit::par2::Par2Set::set_id_of(&head) == Some(set.recovery_set_id) {
            bases.push(base);
        }
    }
    bases
}
