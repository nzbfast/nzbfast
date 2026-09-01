//! In-place extraction of a completed download directory: nested/obfuscated/SFX archive handling, password harvesting, PAR2 scan and verify_dir.
//!
//! The download side went to `instream` under TODO 106's size gate -
//! `FileSlot`, issue #14's in-stream PAR2 sniff and M15b's
//! pre-activation backfill, which are what this file holds that belongs
//! to a job still fetching rather than to the directory it left behind.
//! The on-disk arms are `obfuscated`, `passwords`, `published_names` and
//! `slot_name`; every one of them, `instream` included, is re-exported
//! here, so no caller's path changed when they moved.
//!
//! Split out of main.rs verbatim; behaviour unchanged.

use crate::*;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// verify - PAR2 verification of a directory (M2; also runs after `get`)
// ---------------------------------------------------------------------------

/// Returns Ok(true) if a PAR2 set was found and every present file verified.
/// Offline repair+extract of an assembled directory (no network). Mirrors
/// the daemon's post-download tail: PAR2-repair from on-disk recovery, then
/// extract RAR archives (native first, unrar and recovery-record repair as
/// fallbacks). Returns whether the directory ended in a usable state:
/// extracted payload for an archive set, or verified/repaired data files
/// when the set is bare files under PAR2 with nothing to unpack.
pub(crate) fn extract_local(dir: &std::path::Path, password: Option<&str>) -> Result<bool> {
    use nzbkit::par2repair::{RepairStatus, repair_dir};

    // --- Phase 1: PAR2 repair (only if a set is present) ---------------
    // Detect the set by `.par2` name OR the `PAR2\0PKT` packet magic:
    // obfuscated posts rename recovery volumes to extensionless hex, and
    // repair_dir already magic-sniffs packets and restores data files
    // under their true FileDesc names (it also hash-matches obfuscated
    // data files during the adoption scan), so the only thing that ever
    // hid an obfuscated set from repair was this gate checking the name.
    let has_par2 = dir_has_par2(dir)?;
    let mut par2_ok = true;
    if has_par2 {
        match repair_dir(dir) {
            Ok(RepairStatus::NoDamage) => info!(target: "par2", "no damage, set verifies ✔"),
            Ok(RepairStatus::Repaired(r)) => {
                info!(
                    target: "par2",
                    "repaired ✔ ({} block(s) rebuilt, {} adopted, {} file(s) patched)",
                    r.blocks_rebuilt,
                    r.blocks_adopted,
                    r.files_patched.len()
                );
            }
            Ok(RepairStatus::Unrepairable {
                needed,
                have,
                adopted,
                partial,
            }) => {
                warn!(
                    target: "par2",
                    "UNREPAIRABLE - need {needed} recovery block(s), have {have}{}{}",
                    crate::repair::adopted_clause(adopted),
                    nzbkit::par2repair::published_clause(&partial)
                );
                par2_ok = false;
            }
            Err(e) => {
                warn!(target: "par2", "repair error - {e}");
                par2_ok = false;
            }
        }
    }

    // --- Phase 2: extract archives (if any), then recurse into any
    //     archive those produced (nested releases go a few deep) ----------
    // A payload we cannot actually produce must fail loudly (rc=1), never
    // exit 0 leaving the wrong bytes on disk - that guarantee is what lets
    // the daemon trust an "extract succeeded".
    //
    // The one softening: a zip we cannot unpack fails only when it IS the
    // payload. A `Subs/subs.zip` beside a feature that unpacked fine is
    // reported and forgiven - the descent that now finds subfolder zips
    // would otherwise turn a great many complete releases into rc=1. The
    // softening keys off the pass's own cause, never off "is there a zip
    // anywhere": a failed RAR/7z beside an unrelated sidecar zip is a
    // payload we did not produce, and must still fail.
    let archives_ok = match extract_nested(dir, password, 0)? {
        NestOutcome::Produced => true,
        NestOutcome::ZipGap => match unsupported_archive_present(dir) {
            Some(u) => {
                u.log();
                !u.blocking
            }
            None => false,
        },
        NestOutcome::Failed => false,
    };
    Ok(par2_ok && archives_ok)
}

/// How an extraction pass ended. The CAUSE travels with the failure
/// because exactly one cause may ever be forgiven - the documented zip
/// gap - and only the pass itself knows which archive stopped it. Deriving
/// it afterwards from a directory scan let an unrelated `Subs/subs.zip`
/// absolve a failed RAR/7z, completing the job with nothing importable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum NestOutcome {
    /// Nothing left packed, or there was nothing to unpack at all.
    Produced,
    /// The pass stopped at a zip - the known gap. The caller may forgive
    /// this one, and only when the zip is a sidecar rather than the payload.
    /// Reported only once everything ELSE in the tree was attempted and
    /// produced: a level that hits a zip still descends into the
    /// subdirectories it was seeded with, so an archive we support but could
    /// not unpack outranks the gap with `Failed`.
    ZipGap,
    /// An archive we do support could not be produced. Never forgivable.
    Failed,
}

impl NestOutcome {
    pub(crate) fn produced(self) -> bool {
        self == NestOutcome::Produced
    }
    /// A pass's own result for a format we support.
    pub(crate) fn from_produced(ok: bool) -> Self {
        if ok {
            NestOutcome::Produced
        } else {
            NestOutcome::Failed
        }
    }
    /// Combine sibling/child results: a hard failure outranks a zip gap,
    /// which outranks success.
    pub(crate) fn and(self, other: Self) -> Self {
        use NestOutcome::*;
        match (self, other) {
            (Failed, _) | (_, Failed) => Failed,
            (ZipGap, _) | (_, ZipGap) => ZipGap,
            _ => Produced,
        }
    }
}

/// The depth [`crate::get::tail`] enters this pass at, once the in-stream
/// half has already run - as against the disk-only path
/// ([`extract_local`]), which enters at 0.
///
/// ONE is right for the reason the name says: by the time the tail
/// reaches the nested pass, one layer of the release is already
/// unpacked - the downloaded volume set itself, by the in-stream chain
/// or by the ladder arms above the call. It is also what arms this
/// pass's nested-level PAR2 repair on its FIRST level, through the
/// `depth > 0` gate in [`extract_nested_capped`]; depth 0 is the top
/// level `extract_local` already repaired.
///
/// IT IS A LOWER BOUND ON THE LAYERS ALREADY SPENT AND NOT A COUNT OF
/// THEM, which is a decision and not an omission. A job that DEMOTES
/// mid-ladder spends several in-stream levels before this pass runs -
/// the in-stream chain enables a child while `depth < cap`
/// (`Extractor::ensure_child` in `nzbkit::extract`), so it unpacks `cap`
/// layers and materializes the next - and this entry depth does not
/// carry that history. The two counts therefore COMPOSE rather than
/// share one budget: a demoted job traverses up to `cap` layers in
/// stream plus `cap - TAIL_NESTED_ENTRY_DEPTH` on disk, which at the
/// default cap of 5 is 9 layers against a setting that reads as 5. Same
/// arithmetic one level up for a proven-store ladder, whose raise each
/// site clamps at [`nzbkit::extract::NESTED_MAX_DEPTH_HARD_CEILING`]
/// independently.
///
/// A SINGLE NUMBER CANNOT BE MADE CORRECT HERE, which is why threading
/// the in-stream depth in was measured and refused rather than deferred
/// as too costly. This pass is a flat walk of `dir`, and the in-stream
/// chain writes EVERY depth's output into that one directory - so an
/// archive the depth-1 child demoted and one the depth-4 child demoted
/// arrive here indistinguishable, and a level that demotes only SOME of
/// its inners leaves both at once. One entry depth has to serve every
/// branch, and the two ways to pick it are both wrong: the deepest
/// under-serves the shallow branch, which turns a release that unpacks
/// today into one left materialized, and the shallowest is this
/// constant. Per-file depth attribution is what a single budget would
/// need, and it does not exist. Recorded in
/// `research/NESTED-DEPTH-TWO-SITE-BUDGET-2026-08-31.md`; pinned by
/// `nested_depth_tests::the_tail_entry_depth_costs_exactly_one_level`.
///
/// So the guard is TWO budgets by construction, both bounded, and that
/// is the contract to keep: the cap is a decompression-bomb backstop
/// and 2n - 1 layers of it is still a backstop. Do not "fix" a
/// disagreement between this number and the documented cap by raising
/// the entry depth - that is the under-serving direction, and it fails
/// silently, as a release that stops unpacking one layer short.
pub(crate) const TAIL_NESTED_ENTRY_DEPTH: usize = 1;

/// Extract the archives in `dir`, then recurse into any archive that
/// extraction just produced (a nested release: a RAR whose payload is one
/// more RAR/7z, occasionally in a release subfolder). Returns `Produced`
/// when there was nothing to extract (the data files ARE the payload) or
/// every archive present was fully produced; otherwise the cause that
/// stopped it. Bounded to [`nzbkit::extract::nested_depth_cap`]
/// passes COUNTED FROM `depth` (the shared daemon `nested_max_depth`
/// setting), plus one more level per layer PROVEN to store everything it
/// holds - see [`layer_stores_everything`]; at the cap the deepest layer
/// is left materialized on disk and the job still succeeds - the design
/// guarantee that a too-deep chain degrades, never fails.
///
/// FROM `depth` IS THE WHOLE OF THE BOUND, and a job that DEMOTES gets
/// this budget on top of the one the in-stream chain already spent
/// rather than sharing it. Read [`TAIL_NESTED_ENTRY_DEPTH`] before
/// treating this sentence as a statement about a whole job.
///
/// The bool-shaped twin: [`extract_local`] and the tests read the
/// outcome and nothing else. A caller that composes a user-facing job
/// failure wants [`extract_nested_why`], because a `Failed` here does
/// not say whether the archive was the problem or the disk was.
pub(crate) fn extract_nested(
    dir: &std::path::Path,
    password: Option<&str>,
    depth: usize,
) -> Result<NestOutcome> {
    extract_nested_why(dir, password, depth, &mut None)
}

/// [`extract_nested`] carrying the pass's own reason back out, on the
/// one class of refusal that has one.
///
/// Same contract and same reasoning as
/// [`crate::rarfix::try_unrar_spent_why`] and
/// [`crate::repair::reextract_dir_why`], and it is the last of the three
/// entry points into the disk ladder to get it: a bomb refused inside
/// this pass used to arrive at the tail as a bare `Failed`, which the
/// tail reported as "the payload … could not be unpacked (damaged,
/// encrypted, or an unsupported compression method)". Wrong blame, and
/// the one an *arr acts on by blocklisting a release that is perfectly
/// good.
///
/// `why` is written at most once, by whichever level and arm refused
/// first, and it survives the descent: a bomb two layers down is still
/// this job's failure. It is NOT cleared by a later level succeeding -
/// nothing below can make the disk bigger, and the outcome the caller
/// judges is `ok`, which a refusal has already fixed at `Failed`.
pub(crate) fn extract_nested_why(
    dir: &std::path::Path,
    password: Option<&str>,
    depth: usize,
    why: &mut Option<String>,
) -> Result<NestOutcome> {
    extract_nested_capped(
        dir,
        password,
        depth,
        nzbkit::extract::nested_depth_cap(),
        why,
    )
}

/// [`extract_nested_why`] carrying the effective depth cap DOWN the
/// recursion instead of re-resolving it at every level.
///
/// It has to be carried, because the cap is no longer a constant of the
/// job: a layer proven to store everything hands its children one more
/// level than it had ([`nzbkit::extract::nested_cap_after_store_layer`]),
/// so the number in force at depth 4 is a function of what the four
/// layers above it turned out to be. Re-resolving the global at every
/// level - which is what this site did until now - throws that history
/// away, and is why a store ladder the in-stream half unpacks whole
/// stopped short here on a resumed or disk-only job.
fn extract_nested_capped(
    dir: &std::path::Path,
    password: Option<&str>,
    depth: usize,
    cap: usize,
    why: &mut Option<String>,
) -> Result<NestOutcome> {
    use nzbkit::extract::release_stem;
    // Nested-level PAR2 repair - the per-level twin of extract_local's
    // phase 1. A poster can pack [damaged inner volumes + the inner
    // .par2 set that fixes them] INSIDE the outer archive; when that
    // layer lands here (unpacked by the pass above, or materialized by
    // a nested-extraction demotion), its recovery set must run before
    // the extraction attempt or the level fails with the cure sitting
    // next to the disease. Depth 0 is the top level extract_local
    // already repaired; the archive gate keeps a bare-file payload
    // (data + its recovery set, nothing packed) from being re-hashed -
    // that set was settled by the stream/top-level pass. Runs before
    // the `before` snapshot so recreated/adopted files count as this
    // level's input, never as freshly-produced nested archives.
    if depth > 0 && dir_has_nested_extractable(dir)? {
        nested_par2_repair(dir);
    }
    let before = snapshot_recursive(dir)?;
    // The cap this level's CHILDREN get. Only COMPRESSING layers count
    // against the nested depth cap - it is a decompression-bomb backstop,
    // and a stored layer is the same bytes with a header on the front, so
    // it cannot expand. Read BEFORE any arm runs: the arms delete the
    // volumes they spend, so the evidence is gone by the time the
    // recursion below needs it.
    let child_cap = if layer_stores_everything(&before) {
        nzbkit::extract::nested_cap_after_store_layer(cap)
    } else {
        cap
    };
    // Volume-set stems present before this pass: a volume REBUILT during
    // extraction (.rev reconstruction, RR repair) lands in the diff as a
    // "new" file but belongs to the outer set - never descend into it.
    let pre_stems: std::collections::HashSet<String> = before
        .iter()
        .filter(|p| looks_like_named_rar(p))
        .filter_map(|p| p.file_name().map(|n| release_stem(&n.to_string_lossy())))
        .collect();
    // Magic-only (obfuscated) outer volumes have no name grammar for the
    // stem guard above, so remember whether the input set held any: a
    // NEW extensionless Rar!-magic file appearing beside such a set is a
    // rebuilt member of it (.rev/RR output), not a nested archive -
    // archives a pass genuinely produces carry their packed names. A
    // final payload (.cbr, .cb7) is RAR magic without RAR grammar too,
    // but it is the download, not an outer volume - counting it here
    // made an unrelated comic beside the set suppress recursion into a
    // genuinely nested extensionless RAR (Codex sweep 13 Aug U3). Same
    // exclusion its sibling censuses already apply.
    let pre_obfuscated = before.iter().any(|p| {
        !looks_like_named_rar(p) && nzbkit::extract::archive_sniff_eligible(p) && rar_magic(p)
    });
    let is_new_nested_archive = |p: &PathBuf| {
        if !is_extractable_archive(p) {
            return false;
        }
        if looks_like_named_rar(p) {
            let stem = p
                .file_name()
                .map(|n| release_stem(&n.to_string_lossy()))
                .unwrap_or_default();
            if pre_stems.contains(&stem) {
                return false; // rebuilt member of the outer set
            }
        } else if pre_obfuscated && rar_magic(p) {
            return false; // rebuilt member of the obfuscated outer set
        }
        true
    };
    // Subdirectories that ALREADY hold an extractable archive when this
    // pass starts. The after/before diff below only finds archives a pass
    // PRODUCED - but an on-disk unpack writes its entry paths as real
    // subdirectories (the in-stream extractor flattens them), so a nested
    // archive can sit in a subfolder before any pass here ran (CD1/CD2
    // layouts, a fallback unpack's subfoldered payload). Seed the
    // recursion with the TOPMOST such dirs only: each seeded call
    // snapshots its own subtree and seeds deeper pre-existing layers
    // itself, so nothing is entered twice. Our scratch dirs (parked
    // leftover volumes, the nest staging dir) are never seeded. Named-RAR
    // matching is by NAME (like the nested PAR2 gate): a volume whose
    // signature bytes were destroyed still needs its subdir visited for
    // the repair chance.
    let pre_sub_dirs: Vec<PathBuf> = {
        let mut dirs: Vec<PathBuf> = before
            .iter()
            .filter(|p| looks_like_named_rar(p) || is_extractable_archive(p))
            .filter_map(|p| p.parent().map(|d| d.to_path_buf()))
            .filter(|d| d.as_path() != dir)
            .filter(|d| {
                d.strip_prefix(dir).is_ok_and(|rel| {
                    !rel.components()
                        .any(|c| c.as_os_str().to_string_lossy().starts_with(".nzbfast"))
                })
            })
            .collect();
        dirs.sort();
        dirs.dedup();
        let all: std::collections::HashSet<PathBuf> = dirs.iter().cloned().collect();
        dirs.retain(|d| !d.ancestors().skip(1).any(|a| all.contains(a)));
        dirs
    };
    // This level's INPUT archives, decided before anything unpacks. The
    // list is drawn from `before`, but `is_extractable_archive` asks the
    // disk, so evaluating it after the extraction would describe what is
    // left rather than what arrived - and `sweep_spent_entry` below turns
    // "how many release sets were here" into a delete. The obfuscated
    // extractor now removes the volumes IT consumed, so an unswept
    // `Rar!`-magic file beside them (a `.rev`) would be the lone survivor
    // and read as "exactly one set present": the guard that exists to
    // refuse ambiguity would have deleted the recovery data instead.
    let entry_archives: Vec<PathBuf> = before
        .iter()
        .filter(|p| p.parent() == Some(dir) && is_extractable_archive(p))
        .cloned()
        .collect();
    // The MEMBERSHIP of any split container among them, captured here for
    // exactly the reason `entry_archives` is: the sweep below has to know
    // what a head belongs to before anything moves.
    //
    // `is_extractable_archive` is a per-PATH question, and a split
    // container answers it on part 1 only - part 1 carries the signature
    // (`.7z.001`, or a bare `hash.001`) and parts 2..=n are raw
    // continuation bytes with nothing to sniff and, in the obfuscated
    // shape, nothing in the name either. So the sweep listed the head
    // alone and deleted the head alone, leaving 61 of a 62-part set on
    // disk beside the payload: bytes that can no longer be retried,
    // re-extracted or repaired, because the part it just removed is the
    // one carrying the container's start header. Measured on a plain
    // split 7z past the holds slice, `research/SEVENZ-PLAIN-HOLDS-2026-08-26.md`
    // section 4 - the single-file arm of the same round cleaned its
    // container up in full, which is what this shape was asking for and
    // not getting. Sibling of TODO 299/301 and of `container_part_set`'s
    // own header, which is this defect read from the other end (a sweep
    // that spared the head and deleted the payload behind it).
    //
    // The grammar is the extractor's own - gapless from 1, one file per
    // index, one numbering width, uniform part sizes, a head on part 1
    // and on none of the others - rather than a second opinion about the
    // same files. Asked only where the sweep can fire; depth 0 never
    // deletes, so it never pays the scan.
    let entry_split_sets: Vec<Vec<PathBuf>> = if depth == 0 {
        Vec::new()
    } else {
        crate::splitjoin::collect_container_split_sets(dir)
            .unwrap_or_default()
            .into_iter()
            .map(|s| s.parts)
            .collect()
    };
    let mut refused: Vec<PathBuf> = Vec::new();
    let top = extract_one_level_at(dir, password, depth, true, &mut refused, why)?;
    if top == Some(NestOutcome::Failed) {
        // A format we support, present and not produced -> loud fail.
        // Nothing deeper can redeem it, so stop here.
        return Ok(NestOutcome::Failed);
    }
    // A zip gap is the ONE forgivable cause, so it may only be reported once
    // the rest of the tree has actually been ATTEMPTED. `extract_one_level`
    // sees a single level: returning here would name the forgivable zip while
    // a supported archive sat untouched in a pre-existing subfolder, and the
    // caller's sidecar test would then forgive on the strength of a
    // still-packed `.rar` nobody ever tried. Carry the gap through the
    // descent instead - anything down there we cannot produce outranks it.
    let mut ok = top.unwrap_or(NestOutcome::Produced);
    if top.is_none() && pre_sub_dirs.is_empty() {
        return Ok(NestOutcome::Produced); // no archive anywhere: repaired data is the payload
    }
    // Directories that gained an extractable archive during this pass are
    // the nested layers. The outer volumes stay in `before`, so they are
    // never re-processed.
    // Spent-intermediate sweep: an archive we were handed at this level and
    // then fully denested (its payload now sits beside it) is disposable
    // furniture; leaving it behind is what stranded `level2.rar,level3.rar`
    // on disk after a password-chain nest. `depth >= 1` is the safety gate:
    // depth 0 is the user's actual downloaded set (or an offline `extract`
    // target) - never swept here, its retention is finalize/policy's call -
    // whereas a deeper level is only ever reached because an outer pass
    // (or the in-stream store extractor) already produced these archives,
    // so they ARE intermediates. Runs only on a fully-successful denest;
    // a partial failure keeps every volume for a manual retry. Captured
    // from `before` (the input set), whose files the Case A dance leaves in
    // place, so these paths stay valid at sweep time. Only top-level input
    // archives - a pre-existing SUBFOLDER archive (a `pre_sub_dirs` seed)
    // is swept when its own recursion reaches it as that level's input.
    // `entry_archives` is captured above, before the extraction runs.
    let sweep_spent_entry = |succeeded: bool| {
        if !succeeded || depth == 0 || entry_archives.is_empty() {
            return;
        }
        use std::collections::HashSet;
        // A file an arm REFUSED is not an intermediate this level spent:
        // nothing opened it, so nothing produced its payload, and it is
        // only here because the ladder forgave it (a mid-set fragment -
        // `ObfReport::strays`). Dropped before the stem COUNT as well as
        // before the delete, or one stray beside one real set reads as
        // two sets and strands the real one.
        let entry_archives: Vec<PathBuf> = entry_archives
            .iter()
            .filter(|p| !refused.contains(p))
            .cloned()
            .collect();
        if entry_archives.is_empty() {
            return;
        }
        let stems: HashSet<String> = entry_archives
            .iter()
            .filter_map(|a| a.file_name())
            .map(|n| release_stem(&n.to_string_lossy()))
            .collect();
        // Exactly one release set present: extract_one_level denested it in
        // full, so every volume is spent. Two independent sets (unusual for
        // a nested release) can't both be proven consumed - keep them all.
        if stems.len() != 1 {
            return;
        }
        let stem = stems.into_iter().next().unwrap_or_default();
        // A head that is part 1 of a split container takes the rest of
        // its set with it. Expanded HERE - after the refusal filter and
        // after the stem count - and not into `entry_archives` itself,
        // so neither of those judgements changes: a refused head expands
        // to nothing, and "how many release sets were here" still counts
        // sets rather than parts.
        //
        // That ordering is load-bearing rather than tidy, and it is
        // measured: `release_stem` cuts a numbered tail only when it sits
        // behind a container extension, so `set.7z.001` and `set.7z.002`
        // both read `set.7z` while `hash.001` and `hash.002` read
        // themselves. Expanded into `entry_archives` instead, the
        // obfuscated shape would present three stems where the extractor
        // sees one set, trip the ambiguity guard above, and quietly stop
        // sweeping the very shape this reaches.
        let spent_volumes: Vec<PathBuf> = {
            let mut v: Vec<PathBuf> = Vec::new();
            for p in &entry_archives {
                v.push(p.clone());
                if let Some(set) = entry_split_sets.iter().find(|s| s.contains(p)) {
                    v.extend(set.iter().filter(|q| *q != p).cloned());
                }
            }
            v.sort();
            v.dedup();
            v
        };
        // The spent archive volumes, plus any recovery/verification sidecar
        // for THIS set (`.par2`/`.sfv`/`.rev` sharing the stem). A par2 for a
        // different stem - e.g. the outer post's own `a3.par2` riding along
        // beside a `level2.rar` - has a different stem and is left alone.
        for p in spent_volumes.into_iter().chain(
            before
                .iter()
                .filter(|p| p.parent() == Some(dir))
                .filter(|p| {
                    p.extension()
                        .map(|e| e.to_string_lossy().to_ascii_lowercase())
                        .is_some_and(|e| matches!(e.as_str(), "par2" | "sfv" | "rev"))
                })
                .filter(|p| {
                    p.file_name()
                        .map(|n| release_stem(&n.to_string_lossy()) == stem)
                        .unwrap_or(false)
                })
                .cloned(),
        ) {
            // A plain remove_file, deliberately NOT the trash-aware
            // helpers (see the delete_to_trash audit): this branch only
            // runs at depth > 0, so every one of these volumes was
            // MATERIALIZED BY OUR OWN outer extraction seconds ago - the
            // exact bytes a clean one-pass job consumes in-stream and
            // never writes at all. The user's post (the outer set) is
            // untouched, and the volumes' content survives as the
            // extracted payload beside them, so there is nothing here a
            // user could want back - routing multi-GB scratch through
            // the Trash would only fill it with files they never saw.
            match std::fs::remove_file(&p) {
                Ok(()) => info!(target: "nest", "removed spent intermediate {}", p.display()),
                Err(e) => warn!(
                    target: "nest",
                    "could not remove spent intermediate {}: {e}",
                    p.display()
                ),
            }
        }
    };

    // Snapshot whenever any arm ran and the level did not hard-fail. Since
    // the ladder became record-and-carry-on, one level can hold real output
    // from its RAR/7z arms and still combine to ZipGap (Produced.and(ZipGap)
    // = ZipGap); reusing `before` for that shape made the diff empty, so a
    // healthy nested archive an earlier arm just produced was never
    // descended into while the zip gap was forgiven as a sidecar.
    let after = if matches!(top, Some(NestOutcome::Produced | NestOutcome::ZipGap)) {
        snapshot_recursive(dir)?
    } else {
        before.clone() // nothing extracted at this level: empty diff
    };
    if depth + 1 >= child_cap {
        // Depth cap reached. Anything still packed here - an archive this
        // pass produced, or a pre-existing subfolder archive we would
        // otherwise descend into - is the deepest reached layer, already
        // materialized on disk as a healthy archive. The design guarantee
        // is that a chain deeper than the cap degrades to a materialized
        // deepest layer, NEVER a failed job - so we warn (naming what was
        // left, and how to go deeper) and succeed. The disk post-pass
        // already treats a materialized archive as valid output; the caller
        // must not propagate a hard failure here.
        let mut leftover: Vec<String> = after
            .difference(&before)
            .filter(|p| is_new_nested_archive(p))
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .collect();
        for d in &pre_sub_dirs {
            if let Some(name) = d.file_name() {
                leftover.push(format!("{}/", name.to_string_lossy()));
            }
        }
        if !leftover.is_empty() {
            leftover.sort();
            leftover.dedup();
            // The remedy is only a remedy below the hard ceiling. A store
            // ladder raises its own cap a level at a time and the raise is
            // clamped there, so at the ceiling the setting is not what
            // stopped this and telling the user to raise it is the wrong
            // blame on a job that did not fail.
            let remedy = if child_cap >= nzbkit::extract::NESTED_MAX_DEPTH_HARD_CEILING {
                "this is the hard ceiling on nesting, not the nested_max_depth setting"
            } else {
                "raise the nested_max_depth setting to unpack further"
            };
            warn!(
                target: "extract",
                "nested archives deeper than {child_cap} levels - deepest layer left \
                 materialized on disk ({}); {remedy}",
                leftover.join(", ")
            );
        }
        // A zip gap carried in from this level outlives the cap: a packed
        // deepest layer is acceptable output, an unpackable zip is still the
        // caller's call. Passing `ok` also keeps the sweep off a zip that
        // this level never spent.
        sweep_spent_entry(ok.produced());
        return Ok(ok);
    }
    let mut inner_dirs: Vec<PathBuf> = after
        .difference(&before)
        .filter(|p| is_new_nested_archive(p))
        .filter_map(|p| p.parent().map(|d| d.to_path_buf()))
        .collect();
    inner_dirs.extend(pre_sub_dirs);
    inner_dirs.sort();
    inner_dirs.dedup();

    for idir in inner_dirs {
        if idir == dir {
            // An inner archive at the top level shares the directory with
            // the outer volume set - move just this pass's new top-level
            // files into a scratch subdir so the inner whole-dir scan can't
            // see the outer set, extract there, then lift the results back.
            let sub = nest_scratch_dir(dir)?;
            for p in snapshot_files(dir)? {
                // Move this pass's output only - and never a rebuilt member
                // of the outer volume set (.rev/RR repairs land in the diff
                // too, but they belong beside their siblings).
                let rebuilt_outer = looks_like_named_rar(&p)
                    && p.file_name()
                        .map(|n| pre_stems.contains(&release_stem(&n.to_string_lossy())))
                        .unwrap_or(false);
                if !before.contains(&p)
                    && !rebuilt_outer
                    && let Some(name) = p.file_name()
                {
                    let dest = sub.join(name);
                    if let Err(e) = std::fs::rename(&p, &dest) {
                        // Never swallow a staging move - the file left
                        // behind is invisible to the scratch-dir scan
                        // below, so reporting success would call a pass
                        // that lost output whole (same rule as the
                        // lift-back path further down).
                        warn!(
                            target: "extract",
                            "nest staging move failed ({} -> {}): {e} - keeping it in place",
                            p.display(),
                            dest.display()
                        );
                        ok = ok.and(NestOutcome::Failed);
                    }
                }
            }
            ok = ok.and(extract_nested_capped(
                &sub,
                password,
                depth + 1,
                child_cap,
                why,
            )?);
            if lift_nest_outputs(&sub, dir) {
                let _ = std::fs::remove_dir_all(&sub);
            } else {
                // Never sweep a scratch dir that still holds payload - a
                // swallowed rename here once deleted the stranded output
                // and reported success.
                warn!(
                    target: "extract",
                    "nest lift-back incomplete - keeping {} in place",
                    sub.display()
                );
                ok = ok.and(NestOutcome::Failed);
            }
        } else {
            // A fresh subdir holds only this pass's output - safe to recurse
            // in place (the outer volumes are elsewhere).
            ok = ok.and(extract_nested_capped(
                &idir,
                password,
                depth + 1,
                child_cap,
                why,
            )?);
        }
    }
    // The nested layer(s) this level held are now denested (or not, if a
    // deeper level failed): sweep the spent input archives on full success.
    sweep_spent_entry(ok.produced());
    Ok(ok)
}

/// Does every archive this level is about to unpack PROVE that it stores
/// everything it holds?
///
/// The disk half of the store exemption, and the answer to the question
/// `c0b1c788a` left open when it changed only the in-stream half: that
/// site learns an entry's compression method from the RAR mapper as the
/// articles arrive and latches it on the layer
/// (`nzbkit::extract`'s `Inner::saw_store` / `saw_compressed`), while
/// this one walks files that are already on disk and had no such
/// evidence at all. The evidence IS cheaply available here - a header
/// walk that seeks past each member's data area, which
/// [`nzbkit::rar::volume_is_store_only`] performs - and it is read
/// immediately before this same level extracts those same archives in
/// full. Measured 31 Aug 2026 on this box: 0.22 ms for a 64 MiB store
/// volume and 1.2 ms for a level holding one, so a hundred-volume set
/// costs about 22 ms per level against an extraction that reads every
/// byte of it. Short-circuiting on the first candidate that fails keeps
/// a mixed level cheaper still.
///
/// POSITIVE EVIDENCE ONLY, exactly as in-stream, and `false` means
/// UNKNOWN rather than "compressed": a zip, 7z or tar layer proves
/// nothing about compression here (no method to read), an unreadable or
/// signature-destroyed volume proves nothing, and a level with no
/// archive at all proves nothing. Every one of those keeps the cap where
/// it was. The failure mode of getting this backwards is a bomb guard
/// that does not guard, so the conservative direction is the one that
/// declines to raise.
///
/// EVERY candidate must prove it, not the first one: a level holding a
/// store RAR set beside a compressing archive is a level that can
/// expand, and it is the OTHER archive that would do the expanding. The
/// in-stream latch says the same thing by being sticky in the compressed
/// direction - one compressed entry makes the whole layer count.
///
/// The subtree, not just `dir`: `before` is the recursive snapshot, so a
/// pre-existing subfolder archive this level is about to seed the
/// recursion with is judged too. That is the conservative reading -
/// including more files can only ever withhold the raise.
fn layer_stores_everything(before: &std::collections::HashSet<PathBuf>) -> bool {
    let mut saw = false;
    for p in before {
        // The same population the recursion itself treats as archives:
        // by magic (any family), or by RAR name grammar, which catches a
        // volume whose signature bytes were destroyed. The second is in
        // scope deliberately - such a volume is exactly one this cannot
        // read, and an unreadable archive must withhold the raise rather
        // than be skipped past.
        if !is_extractable_archive(p) && !looks_like_named_rar(p) {
            continue;
        }
        if !nzbkit::rar::volume_is_store_only(p) {
            return false;
        }
        saw = true;
    }
    saw
}

/// A nest scratch directory this call PROVABLY created.
///
/// This used to be a fixed `.nzbfast-nest` preceded by an unconditional
/// `remove_dir_all`. The recursive snapshot skips `.nzbfast*`, so a
/// legitimate archive payload extracted to `.nzbfast-nest/` was invisible
/// to every protection and simply deleted the moment a sibling `inner.rar`
/// triggered nesting. `create_dir` fails if the path exists at all, so we
/// can never adopt - or destroy - something that was already there.
pub(crate) fn nest_scratch_dir(dir: &std::path::Path) -> Result<PathBuf> {
    for n in 0..1024 {
        let candidate = match n {
            0 => dir.join(".nzbfast-nest"),
            n => dir.join(format!(".nzbfast-nest{n}")),
        };
        match std::fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    anyhow::bail!("no free nest scratch name in {}", dir.display())
}

/// Move everything the nest scratch dir holds up into `dir`.
pub(crate) fn lift_nest_outputs(sub: &std::path::Path, dir: &std::path::Path) -> bool {
    lift_scratch_into(sub, dir, "nested", "nest lift-back")
}

/// Move everything scratch dir `sub` holds up into `dir`. Directories
/// merge recursively (an unpack can produce a subdir that already exists
/// at the top level - a blind rename fails ENOTEMPTY and used to be
/// swallowed right before the scratch sweep deleted the stranded
/// payload); a file that would land on a pre-existing path gets a
/// `{prefix}-N-` name instead of silently replacing output (or an outer
/// volume); a move that fails leaves the entry where it is and returns
/// false so the caller keeps the scratch dir instead of sweeping it.
///
/// Never replacing a pre-existing path is what makes this safe as the
/// publish step for `ExtractStaging`: it protects the source volumes,
/// `.rev` volumes, PAR2 sets and password sidecars an archive member
/// could be named after, without any list of protected names - and it
/// asks the filesystem, so a case-insensitive volume (macOS, Windows)
/// reports `release.RAR` as colliding with `release.rar` on its own.
pub(crate) fn lift_scratch_into(
    sub: &std::path::Path,
    dir: &std::path::Path,
    prefix: &str,
    what: &str,
) -> bool {
    let entries = match std::fs::read_dir(sub) {
        Ok(e) => e,
        Err(_) => return false,
    };
    let mut clean = true;
    for e in entries.flatten() {
        let p = e.path();
        let Some(name) = p.file_name().map(|n| n.to_os_string()) else {
            clean = false;
            continue;
        };
        let target = dir.join(&name);
        if e.file_type().is_ok_and(|t| t.is_dir()) && target.is_dir() {
            clean &= lift_scratch_into(&p, &target, prefix, what);
            // Only an emptied source dir goes; a stranded entry keeps it.
            clean &= std::fs::remove_dir(&p).is_ok();
            continue;
        }
        // symlink_metadata, not exists(): a dangling symlink at the target
        // is still an occupied name, and a rename onto it would replace the
        // link rather than reveal what it pointed at.
        let dest = if target.symlink_metadata().is_ok() {
            // CAPPED on the composed name. `name` is an extracted
            // member's own name, so it is a `sanitize_out_name` result
            // and is routinely AT the 255-byte component cap - capping
            // is what produced it - and a `{prefix}-{n}-` on the front
            // is a name no filesystem creates. Note the loop EXITS on
            // such a name rather than spinning, because
            // `symlink_metadata` answers Err for a name too long to look
            // up and that reads as free here; the `rename` below is what
            // then fails, loudly, leaving the member stranded in the
            // scratch directory.
            //
            // The composed name and not a stem reserve: nothing reads
            // this name back, but the ladder's distinctness is the whole
            // point of it, and `cap_component`'s hash tag is what keeps
            // successive rungs apart once the tail it would otherwise
            // rely on has been truncated away. Inside the cap it is the
            // plain `format!` byte for byte.
            let mut n = 1usize;
            loop {
                let cand = dir.join(nzbkit::disk::sanitize_filename_capped(&format!(
                    "{prefix}-{n}-{}",
                    name.to_string_lossy()
                )));
                if cand.symlink_metadata().is_err() {
                    break cand;
                }
                n += 1;
            }
        } else {
            target
        };
        if let Err(err) = std::fs::rename(&p, &dest) {
            warn!(target: "extract", "{what}: {} → {}: {err}", p.display(), dest.display());
            clean = false;
        }
    }
    clean
}

/// An isolated directory that holds extractor output until the whole set
/// has been produced, then publishes it into the job directory. Removed
/// on drop, so an extraction that fails part-way leaves nothing behind.
///
/// Extraction cannot write straight into the directory it reads from. A
/// parsed archive keeps PATH-backed sources and reopens each volume for
/// every range it needs (`ArchiveSource::File` in the vendored rars), so
/// an archive member named after one of those volumes - `release.rar`,
/// `release.part02.rar`, a `release.7z` inside `release.7z` - would
/// truncate the very file the decoder is still reading, fail the
/// extraction midstream, and hand an already-destroyed set to the unrar
/// fallback. Both the volume names and the member names come from the
/// post, so both are attacker-chosen.
///
/// A denylist of protected names cannot close that: `.rev` recovery
/// volumes, PAR2 sets and password sidecars are inputs too. Staging
/// removes the whole class instead. `sanitized_entry_path` rejects `..`,
/// absolute paths and drive prefixes, so every output resolves strictly
/// inside the staging dir - and no input is ever inside it, because it is
/// created empty for this one extraction.
pub(crate) struct ExtractStaging {
    pub(crate) dir: PathBuf,
    /// Publish left payload behind: the caller is failing, and the dir
    /// must survive for the operator instead of being swept.
    pub(crate) keep: bool,
}

impl ExtractStaging {
    /// Create a fresh staging dir INSIDE `dir`. Same filesystem on
    /// purpose: publishing is then a rename rather than a copy, and the
    /// decompression-bomb guard's `free_bytes` still measures the volume
    /// the payload actually lands on. The `.nzbfast` prefix is what the
    /// nested pass's tree walkers already skip as scratch.
    pub(crate) fn new(dir: &std::path::Path) -> Result<ExtractStaging> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        std::fs::create_dir_all(dir)?;
        // `create_dir`, never `remove_dir_all` - the same never-adopt
        // rule the nest scratch above earned. The name carries a pid and
        // a per-process counter, and the OS recycles pids: after a
        // restart, `.nzbfast-extract-<pid>-0` can be a dir a PREVIOUS run
        // deliberately kept (`keep` = publishing failed, payload left for
        // the operator), and clearing it destroys the only copy. Take the
        // next free name instead.
        for _ in 0..1024 {
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            let sub = dir.join(format!(".nzbfast-extract-{}-{n}", std::process::id()));
            match std::fs::create_dir(&sub) {
                Ok(()) => {
                    return Ok(ExtractStaging {
                        dir: sub,
                        keep: false,
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
        anyhow::bail!("no free extraction staging name in {}", dir.display())
    }

    pub(crate) fn path(&self) -> &std::path::Path {
        &self.dir
    }

    /// Did the extractor put anything here? Used by the unrar fallback,
    /// whose output directory is an argument we hand to another process:
    /// "exited 0 but wrote nothing" must read as failure, not as an
    /// extraction that produced an empty release.
    pub(crate) fn produced_anything(&self) -> bool {
        std::fs::read_dir(&self.dir).is_ok_and(|mut d| d.next().is_some())
    }

    /// Move the produced set into `dest`. A produced name that collides
    /// with anything already there is disambiguated rather than replacing
    /// it, so an archive that legitimately carries a member named like one
    /// of its own volumes yields both the member and the intact volume.
    pub(crate) fn publish_into(mut self, dest: &std::path::Path) -> Result<()> {
        if lift_scratch_into(&self.dir, dest, "extracted", "publishing extraction") {
            return Ok(()); // drop removes the emptied dir
        }
        self.keep = true;
        anyhow::bail!(
            "extracted output could not be published into {} - it is left in {}",
            dest.display(),
            self.dir.display()
        )
    }
}

impl Drop for ExtractStaging {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

/// The named-RAR arm of [`extract_one_level`], with its two recovery
/// rungs: destroyed or missing volumes may be rebuildable from `.rev`
/// recovery volumes, byte-damaged ones from embedded recovery records.
///
/// `why` takes the ladder's own reason for refusing, on the one class of
/// refusal that has one - a bomb verdict, which is about the DISK and
/// not about the archive. This arm read the ladder through
/// [`try_unrar`], the bool wrapper, so the reason stopped here and the
/// tail then reported the set as "damaged, encrypted, or an unsupported
/// compression method" - the exact wrong blame the 22 Aug 2026 incident
/// was reported as, one arm further out than
/// [`crate::rarfix::try_unrar_spent_why`] reached.
///
/// A named reason also ENDS the arm rather than falling through to the
/// rungs below. Both of those rebuild volumes and hand them straight
/// back to the engine that has just refused for want of space, so a
/// second and third attempt can only fill the disk further - the same
/// reason the tail runs [`bomb_fallback`] AHEAD of all three of its
/// unpack arms rather than beside them.
///
/// The third rung below carries its verdict out too, through
/// [`try_rar_rr_repair_why`] (TODO §249 item 1). It is reached only when
/// both attempts above failed for a reason that was NOT the disk, so a
/// verdict there means the repaired set bombed where the damaged one had
/// not got far enough to - narrow, but the blame it used to drop was the
/// same wrong blame as the two arms above.
fn unpack_named_rar(
    dir: &std::path::Path,
    password: Option<&str>,
    why: &mut Option<String>,
) -> NestOutcome {
    // TODO 205 follow-up: three rungs, all of them at the SAME set. Each
    // re-enters `try_unrar_outcome`, whose group loop banks one set per
    // group into the queue row's unpack lane - so without a rewind the
    // second and third rungs added a whole extra copy of this
    // directory's totals, and a set that needed a `.rev` reconstruction
    // reported twice the bytes it can ever produce. Rewinding at the top
    // of each rung is correct rather than merely harmless on the first:
    // there it restores the state to what it already is. See
    // [`crate::unpackprog::mark`].
    let mark = crate::unpackprog::mark();
    // The spent volumes this arm does not read: `try_unrar` never swept
    // them either, and the nested pass owns its own before/after diff.
    let mut attempt = |dir: &std::path::Path| {
        mark.rewind();
        match try_unrar_spent_why(dir, password) {
            Ok(_) => Some(NestOutcome::Produced),
            Err(Some(w)) => {
                *why = Some(w);
                Some(NestOutcome::Failed)
            }
            Err(None) => None,
        }
    };
    if let Some(o) = attempt(dir) {
        return o;
    }
    if try_rev_reconstruct(dir)
        && let Some(o) = attempt(dir)
    {
        return o;
    }
    warn!(target: "extract", "extraction failed - trying recovery-record self-repair…");
    mark.rewind();
    match try_rar_rr_repair_why(dir, password) {
        Ok(()) => NestOutcome::Produced,
        Err(Some(w)) => {
            *why = Some(w);
            NestOutcome::Failed
        }
        Err(None) => NestOutcome::Failed,
    }
}

/// [`extract_one_level_at`] with the rescue on and nothing reported back
/// - the three-argument shape the unit tests drive the ladder through.
#[cfg(test)]
pub(crate) fn extract_one_level(
    dir: &std::path::Path,
    password: Option<&str>,
    depth: usize,
) -> Result<Option<NestOutcome>> {
    extract_one_level_at(dir, password, depth, true, &mut Vec::new(), &mut None)
}

/// One extraction pass over `dir`, unpacking EVERY archive family present.
/// `Ok(None)` = no archive present; otherwise the pass's [`NestOutcome`],
/// which names WHICH format stopped it so only the zip gap gets forgiven.
///
/// `rescue` switches step 8's container rescue off: the rescue extracts
/// what it joined by calling back in here, and that call must not rescue
/// again - see [`rescue_split_of_container`]. `refused` collects what an
/// arm looked at and declined to own, which the caller must keep every
/// later pass off - see [`ObfReport::strays`].
///
/// `why` is the second out-channel and the same shape as the first: a
/// refusal that named its own reason, which today is only a bomb verdict
/// out of [`unpack_named_rar`]. [`NestOutcome`] deliberately does not
/// carry it. That enum is the FORGIVENESS decision - three `Copy` states
/// whose `and` lattice every arm and every nested level folds together -
/// and a reason is not something a lattice can combine: a payload or a
/// fourth variant would make `and` choose between two archives' reasons,
/// would break `Copy` and `==` at some forty sites, and would still have
/// to be unwrapped into the `Option<String>` that
/// [`crate::diag::unpack_failure`] already takes. Set-once and carried
/// alongside instead, exactly like `refused`.
pub(crate) fn extract_one_level_at(
    dir: &std::path::Path,
    password: Option<&str>,
    depth: usize,
    rescue: bool,
    refused: &mut Vec<PathBuf>,
    why: &mut Option<String>,
) -> Result<Option<NestOutcome>> {
    // Nested password-chain auto-unlock: an encrypted archive here may be
    // unlockable by a password sitting in a sibling text file the level
    // above just extracted. Harvest and verify a candidate before the
    // extraction attempt.
    //
    // A harvested value JOINS the candidate order, it must not replace
    // the caller's: replacing it starved every later container of the
    // password the user actually supplied, so a level with one
    // harvest-unlockable archive left the OTHER one packed with its
    // correct password in hand (Codex sweep 13 Aug U2). The arms with
    // per-container candidate sweeps (named RAR groups, zip, 7z) take
    // the ORIGINAL password and re-resolve per container - their sweeps
    // lead with it and re-harvest this same directory. Only the arms
    // without one (obfuscated RAR, SFX) take the level's resolved value.
    let harvested = resolve_level_password(dir, password);
    let level_pw = harvested.as_deref().or(password);
    // Phase 0(b) prevalence: one line per nested inner archive the disk
    // post-pass handles (a demoted-from-stream inner, or one never
    // eligible for streaming - RAR4, multipart 7z, a resumed job). Nested
    // levels only; a single-layer job is depth 0 and never counted. See
    // nzbkit::extract::note_nested_level for the shared counting model.
    if depth > 0
        && let Some(kind) = nested_inner_kind(dir)
    {
        nzbkit::extract::note_nested_level(depth, kind, nzbkit::extract::NestedDisposition::Disk);
    }
    // EVERY family present is unpacked, not just the first one to match.
    // The ladder used to return at its first claiming arm, so a directory
    // holding a RAR set and a zip extracted the RAR and left the zip
    // packed, unopened by any reader - which is exactly what cost the
    // torture round's advMA two oracle leaves, and what SABnzbd and
    // NZBGet do differently (TODO 159 item 5). The ARMS and their order
    // are unchanged; only "return" became "record and carry on".
    //
    // Every family's input set is collected BEFORE anything unpacks. A
    // collector run after an earlier arm would sweep up archives that arm
    // just PRODUCED, extracting a nested layer at this level: that would
    // bypass the `.nzbfast-nest` scratch dance, the depth cap and the
    // spent-intermediate sweep, all of which exist to handle produced
    // archives one level down. `entries_left` then drops anything an
    // earlier arm consumed on its way through (the RAR arms delete the
    // volumes they spend).
    let named_rar = dir_has_named_rar(dir)?;
    let obf = collect_obfuscated_rar_volumes(dir)?;
    let sevenz = collect_sevenz_archives(dir)?;
    let zips = nzbkit::zip::scan(dir);
    let tars = collect_tar_containers(dir)?;
    // The plain-split collector runs here for the same reason as the rest:
    // whatever it sees now is what the post ARRIVED with, so no arm's
    // output can be mistaken for a split part. Its arm still runs last -
    // see step 7, which re-scans and keeps only the sets that survive
    // unchanged.
    let arrived_splits = collect_split_sets(dir)?;
    // Step 8's input, taken here for the same reason and read the same way.
    let arrived_containers = if rescue {
        collect_container_split_sets(dir)?
    } else {
        Vec::new()
    };
    let entries_left =
        |ps: &[PathBuf]| -> Vec<PathBuf> { ps.iter().filter(|p| p.exists()).cloned().collect() };
    let mut out: Option<NestOutcome> = None;
    // The verdicts of the arms that can NOT own a split container's
    // head (SFX, 7z, zip, tar, plain split). Step 8's rescue replaces
    // the RAR arms' verdict on the container it joined, not the level's:
    // a broken `subs.7z` beside a rescued split RAR stayed broken (Codex
    // F-01, 22 Aug 2026), so these fold back in after the rescue.
    let mut others: Option<NestOutcome> = None;
    let claim = |o: NestOutcome, out: &mut Option<NestOutcome>| {
        *out = Some(out.map_or(o, |prev| prev.and(o)));
    };

    // 1. Normally-named RAR set (.rar/.rNN by name; rollover/numeric with
    //    the Rar! magic). Native rars first (bundled unrar fallback), then
    //    the two recovery rungs - see `unpack_named_rar`.
    if named_rar {
        claim(unpack_named_rar(dir, password, why), &mut out);
    }
    // 2. Obfuscated RAR: extensionless files carrying the Rar! magic, with
    //    no filename order - ordered by the RAR header volume number.
    let obf = entries_left(&obf);
    if !obf.is_empty() {
        let r = extract_obfuscated_rar(dir, &obf, level_pw, depth);
        refused.extend(r.strays.iter().cloned());
        // A pass whose ONLY casualty was a mid-set fragment claims
        // `Produced`, the identity of the `and` lattice: it cannot mask
        // another arm's `Failed` or `ZipGap`, it just stops this arm
        // inventing one. It must CLAIM rather than stay silent - leaving
        // `out` at `None` drops the level through the "no extractor
        // claimed it" backstop at the bottom of this function, which
        // reads the fragment's `Rar!` head and fails the job by the
        // other door.
        if r.failed {
            claim(NestOutcome::Failed, &mut out);
        } else {
            claim(NestOutcome::Produced, &mut out);
        }
    }
    // 3. SFX self-extractors: an .exe/.bin/.sfx whose head embeds the RAR
    //    signature past a stub. rars scans for the offset itself; only the
    //    detection lives here. Top level ONLY (depth 0 = the post itself is
    //    an SFX): a payload's setup.exe is often a legitimate WinRAR SFX
    //    installer and must never be auto-exploded by the nested pass or
    //    the daemon's post-extraction pass.
    //
    //    This is the ONE arm that keeps first-match precedence, and
    //    deliberately: it runs only when neither RAR arm claimed the
    //    directory, exactly as before. Letting it fire beside a downloaded
    //    RAR set would widen "the post IS an SFX" to "the post also
    //    contains one", and auto-explode an .exe posted alongside a
    //    release - a gate the SFX work narrowed on purpose.
    if depth == 0 && out.is_none() {
        let sfx = collect_sfx_archives(dir)?;
        if !sfx.is_empty() {
            let o = NestOutcome::from_produced(extract_sfx(dir, &sfx, level_pw));
            claim(o, &mut out);
            claim(o, &mut others);
        }
    }
    // 4. 7-Zip (native, incl. split .7z.001 multipart).
    let sevenz: Vec<Vec<PathBuf>> = sevenz
        .into_iter()
        .filter(|set| set.iter().all(|p| p.exists()))
        .collect();
    if !sevenz.is_empty() {
        let o = NestOutcome::from_produced(extract_sevenz(dir, &sevenz, password));
        claim(o, &mut out);
        claim(o, &mut others);
    }
    // 5. Zip is a KNOWN, documented gap: we cannot produce the payload, so
    //    say so instead of exiting 0 with the archive still packed.
    //    Detection is `nzbkit::zip`'s alone - single containers, the
    //    obfuscated extensionless ones, WinZip-spanned `.z01` sets and
    //    byte-split `.zip.001` sets all report here, and its two standing
    //    rules (never magic-sniff a named file, never touch a
    //    `.cbz`/`.epub` payload) hold unchanged.
    //
    //    This level cannot judge how much the gap matters - a `subs.zip`
    //    beside a landed feature is not the same problem as a post whose
    //    entire payload is still packed - so it reports uniformly and the
    //    top-level caller decides (`unsupported_archive_present`).
    let zips: Vec<_> = zips
        .into_iter()
        .filter(|f| f.parts.iter().all(|p| p.exists()))
        .collect();
    if !zips.is_empty() {
        // Store and deflate cover ~99% of real zips and are built in.
        // Anything else - an exotic codec, an encrypted entry - still
        // reports as a gap rather than a failure to open, so the message
        // names what was hit and the caller can still forgive a sidecar.
        let o = if extract_zip(dir, &zips, password) {
            NestOutcome::Produced
        } else {
            NestOutcome::ZipGap
        };
        claim(o, &mut out);
        claim(o, &mut others);
    }
    // 6. Tar containers (TODO 163 item 6's disk half). A `.tar` reaches
    //    a job directory three ways, none of them a fault: a chase that
    //    demoted, a resumed run (which never chases at all), and
    //    `NZBFAST_NO_TAR=1`. Until this arm existed all three left the
    //    payload packed inside it with the job reporting Completed.
    //
    //    The one arm that DECLINES rather than fails: a container it
    //    refuses claims `Produced` (the `and` lattice's identity, so it
    //    can neither mask another arm's failure nor invent one) and is
    //    recorded as REFUSED, which keeps the spent-intermediate sweep
    //    from deleting the container holding the payload we did not
    //    produce. See `rarfix::tar` for why a refusal is not a job
    //    failure here where it is one for a RAR or a 7z.
    let tars = entries_left(&tars);
    if !tars.is_empty() {
        refused.extend(extract_tar(dir, &tars));
        claim(NestOutcome::Produced, &mut out);
        claim(NestOutcome::Produced, &mut others);
    }
    // 7. Plain split files: an HJSplit-style `.001/.002/…` (or `.1/.2/…`)
    //    run whose parts carry NO archive header at all. There is no
    //    container to open - the poster byte-split a raw payload, and the
    //    extraction IS a concatenation in numeric order. SABnzbd's
    //    post-processing joiner does this; we used to land the parts loose.
    //
    //    LAST RESORT, explicitly - but last-resort in the LADDER, not
    //    conditional on it. The arm used to run only when `out.is_none()`,
    //    which made any archive anywhere in the directory suppress it: a
    //    `subs.zip` beside a byte-split `Movie.mkv` exited 0 with the
    //    subtitles extracted, both parts still on disk and no `Movie.mkv`
    //    (read-only sweep 2 M10). The two payloads are unrelated; one
    //    being packed says nothing about the other.
    //
    //    What that guard really bought is the invariant below, and it is
    //    kept explicitly instead: an arm's OUTPUT must never become this
    //    collector's INPUT (an extracted RAR can itself produce numeric
    //    parts). So the set list is the INTERSECTION of the scan taken
    //    before anything unpacked and a scan taken now - a set qualifies
    //    only if it is byte-for-byte the same set it was on arrival.
    //    Anything an arm produced is absent from the first scan; any set
    //    an arm consumed, extended, resized or whose output name an arm
    //    has since occupied is absent from (or different in) the second.
    //
    //    `collect_split_sets` refuses far more than it accepts - a hole in
    //    the run, an archive head on any part, a `.par2`/`.vol`/`.rar`/
    //    `.7z`/`.zip` base, mismatched part sizes - because a refusal
    //    simply leaves the parts on disk exactly as they arrived, while a
    //    wrong accept publishes a truncated file and DELETES its parts.
    if !arrived_splits.is_empty() {
        let sets: Vec<SplitSet> = collect_split_sets(dir)?
            .into_iter()
            .filter(|s| arrived_splits.contains(s))
            .collect();
        if !sets.is_empty() {
            let o = NestOutcome::from_produced(join_split_sets(dir, &sets));
            claim(o, &mut out);
            claim(o, &mut others);
        }
    }
    // 8. A byte split of a CONTAINER, once the arm that owns its head has
    //    failed on it (TODO 211). Strictly after everything above, and
    //    conditional on their verdict: this is the one set the ladder can
    //    be sure belongs to nobody, because the arm that would own it has
    //    just said so. `rescue_split_of_container` re-judges the joined
    //    container, so its answer replaces the RAR arms' verdict - and
    //    ONLY theirs: every other arm's verdict (`others`) still stands.
    if let Some(o) = out
        && !o.produced()
        && !arrived_containers.is_empty()
        && let Some(rescued) = rescue_split_of_container(dir, &arrived_containers, level_pw, depth)?
    {
        return Ok(Some(others.map_or(rescued, |x| x.and(rescued))));
    }
    if let Some(out) = out {
        return Ok(Some(out));
    }
    // Nothing above claimed it, but something here still has an archive's
    // head. `Ok(None)` means "there was nothing to unpack", and the
    // caller turns that into a COMPLETED job - so a file we can identify
    // and cannot route must not leave by this door. It went out that door
    // once: a 7z posted under an obfuscated name with an extension
    // (`hash.bin`) was sniffed as an archive everywhere EXCEPT the
    // collector that decides what to extract, so the pass reported
    // nothing to do and the job completed holding one unopened container.
    //
    // Zip is excluded because the branch above already spoke for it (its
    // gap is forgivable when the zip is a sidecar, and only the top level
    // can judge that). Both sniffs here read a head signature, so a
    // legitimate SFX installer - whose RAR marker sits past its stub - is
    // not caught by this.
    // Named payload files (`.cbr`, `.cb7`) carry an archive head by
    // design and are exactly what this door is FOR letting out: the file
    // is the deliverable, so "no extractor claimed it" is the job done
    // right, not a routing failure.
    let stray = std::fs::read_dir(dir)?.flatten().find(|e| {
        let p = e.path();
        e.file_type().is_ok_and(|t| t.is_file())
            && nzbkit::extract::archive_sniff_eligible(&p)
            && (rar_magic(&p) || sevenz_magic(&p))
    });
    if let Some(e) = stray {
        warn!(
            target: "extract",
            "{} looks like an archive but no extractor claimed it",
            e.file_name().to_string_lossy()
        );
        return Ok(Some(NestOutcome::Failed));
    }
    Ok(None)
}

/// Every regular file directly under `dir` (one level), as a set - the
/// before/after diff that tells `extract_nested` what a pass produced.
pub(crate) fn snapshot_files(dir: &std::path::Path) -> Result<std::collections::HashSet<PathBuf>> {
    let mut out = std::collections::HashSet::new();
    for e in std::fs::read_dir(dir)?.flatten() {
        if e.file_type().is_ok_and(|t| t.is_file()) {
            out.insert(e.path());
        }
    }
    Ok(out)
}

/// Every regular file anywhere under `dir` (recursive) - nested archives
/// can land in a release subfolder, so the before/after diff walks the
/// whole tree. Bounded traversal (skips our own scratch nest dirs).
pub(crate) fn snapshot_recursive(
    dir: &std::path::Path,
) -> Result<std::collections::HashSet<PathBuf>> {
    let mut out = std::collections::HashSet::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            let p = e.path();
            if ft.is_dir() {
                // Our own scratch dirs (the nest staging dir, parked
                // leftovers) are furniture, not payload - the
                // before/after diff must never look inside them.
                if e.file_name().to_string_lossy().starts_with(".nzbfast") {
                    continue;
                }
                stack.push(p);
            } else if ft.is_file() {
                out.insert(p);
            }
        }
    }
    Ok(out)
}

/// Does this file open with the `PAR2\0PKT` packet magic?
///
/// The one test that recognises an obfuscated recovery volume, whose name
/// carries nothing: the magic is unambiguous, no media container starts
/// with it, and it decides where the extension cannot. Three callers had
/// grown their own copy of these eight bytes; a fourth would have been
/// one too many, since the whole class of bug this answers (issue #9) is
/// a path that checked the NAME because the content test was somewhere
/// else. `smart::par2_magic` is the same test on the extraction side.
pub(crate) fn file_starts_with_par2_magic(path: &std::path::Path) -> bool {
    use std::io::Read;
    if !std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.len() >= 8) {
        return false;
    }
    let mut head = [0u8; 8];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut head))
        .is_ok_and(|()| &head == b"PAR2\x00PKT")
}

/// Is this still-damaged slot an open hole after a PAR2 repair of the
/// recovery sets on disk, or did the repair speak for it?
///
/// `covered` is [`nzbkit::par2repair::covered_names`] sanitized and
/// lowercased. Everything the sets never named is a hole EXCEPT:
///
/// * a recovery volume, by `.par2` name or by the packet magic. Its
///   articles are not payload, and a set that repairs without them
///   proves it never needed them.
/// * a slot whose file is gone from disk though the extractor opened one
///   - the repair renamed it under its FileDesc name, or a chase
///   consumed it. Treating an absent path as a hole would fail every
///   one-pass job.
///
/// `path` is `None` when the extractor never opened a file for the slot:
/// on a plain-file slot that means not one article of it arrived, and
/// the NZB's own name (`hint`) is then all there is to test coverage
/// against. A file whose subject spells a different name than its yEnc
/// header, posted outside the set and lost whole, therefore reads as a
/// hole - the safe direction: the job fails with its journal intact
/// rather than importing a gap.
pub(crate) fn slot_is_uncovered_hole(
    out_dir: &std::path::Path,
    path: Option<std::path::PathBuf>,
    hint: &str,
    covered: &std::collections::HashSet<String>,
) -> bool {
    let had_writer = path.is_some();
    let path = path.unwrap_or_else(|| {
        nzbkit::disk::join_out_name(out_dir, &nzbkit::disk::sanitize_out_name(hint))
    });
    // The out_dir-RELATIVE name: `covered` is keyed by the FileDesc
    // names' sanitized form, which for a tree-preserved member carries
    // its directories - the bare file name would never match and a
    // covered slot would read as an uncovered hole.
    let name = nzbkit::disk::out_name_of(out_dir, &path).to_lowercase();
    if covered.contains(&name) {
        return false;
    }
    if path
        .extension()
        .is_some_and(|x| x.eq_ignore_ascii_case("par2"))
    {
        return false;
    }
    if !path.exists() {
        // Nothing on disk under that name, and which of the two reasons
        // it is turns on whether the extractor ever opened a file: it
        // did and the file is gone (adopted, renamed under its FileDesc
        // name, consumed by a chase) - covered; it never opened one at
        // all - not a single article of the file arrived, so the whole
        // file is the hole.
        return !had_writer;
    }
    !file_starts_with_par2_magic(&path)
}

/// Does `dir` hold a `.par2` set by name OR by the `PAR2\0PKT` magic
/// (obfuscated recovery volumes lose their extension)?
pub(crate) fn dir_has_par2(dir: &std::path::Path) -> Result<bool> {
    Ok(std::fs::read_dir(dir)?.flatten().any(|e| {
        let path = e.path();
        path.extension()
            .is_some_and(|x| x.eq_ignore_ascii_case("par2"))
            || file_starts_with_par2_magic(&path)
    }))
}

/// The obfuscated-RAR arm: `Rar!`-magic files whose names carry no set
/// and no order, grouped into their original volume sets by header
/// continuity (TODO 106 size-gate split out of this file).
mod obfuscated;
pub(crate) use obfuscated::*;

/// Password candidate harvesting and the per-container key probes
/// (TODO 106 size-gate split out of this file).
mod passwords;
pub(crate) use passwords::*;

#[cfg(test)]
mod uncovered_hole_tests {
    use std::collections::HashSet;

    fn dir(tag: &str) -> std::path::PathBuf {
        let d =
            std::env::temp_dir().join(format!("nzbfast-uncovered-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn covered(names: &[&str]) -> HashSet<String> {
        names.iter().map(|n| n.to_lowercase()).collect()
    }

    /// The headline: a `.nfo` no recovery set names, lost whole, so the
    /// extractor never opened a file for it. A clean PAR2 verdict is not
    /// a verdict about this.
    #[test]
    fn an_uncovered_file_lost_whole_is_a_hole() {
        let d = dir("nfo");
        assert!(super::slot_is_uncovered_hole(
            &d,
            None,
            "release.nfo",
            &covered(&["movie.part01.rar"]),
        ));
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// The same file half-arrived: on disk, still not in any set.
    #[test]
    fn an_uncovered_file_partly_on_disk_is_a_hole() {
        let d = dir("partial");
        let p = d.join("release.nfo");
        std::fs::write(&p, vec![0u8; 64]).unwrap();
        assert!(super::slot_is_uncovered_hole(
            &d,
            Some(p),
            "release.nfo",
            &covered(&["movie.part01.rar"]),
        ));
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// A slot the repair spoke for: its name is in the set, damaged or
    /// not. This is the everyday obfuscated case, where the poster ran
    /// par2 over the hashed names, so the set covers them.
    #[test]
    fn a_set_member_is_covered_however_damaged() {
        let d = dir("member");
        let p = d.join("Lp3vWq8xNc2");
        std::fs::write(&p, vec![0u8; 64]).unwrap();
        assert!(!super::slot_is_uncovered_hole(
            &d,
            Some(p),
            "Lp3vWq8xNc2",
            &covered(&["lp3vwq8xnc2"]),
        ));
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// The extractor opened a file that is no longer there - adopted,
    /// renamed under its FileDesc name, or consumed by a chase. Reading
    /// that as a hole would fail every one-pass job.
    #[test]
    fn a_slot_whose_file_moved_is_covered() {
        let d = dir("moved");
        assert!(!super::slot_is_uncovered_hole(
            &d,
            Some(d.join("gone.tmp")),
            "gone.tmp",
            &covered(&["movie.part01.rar"]),
        ));
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// Recovery volumes are not payload, by extension or by magic. A set
    /// that repaired without one proves it never needed it - and on an
    /// obfuscated post the volume carries no extension at all, which is
    /// why the magic test has to be here.
    #[test]
    fn a_recovery_volume_is_not_a_hole() {
        let d = dir("vol");
        let named = d.join("movie.vol000+01.par2");
        std::fs::write(&named, vec![0u8; 64]).unwrap();
        assert!(!super::slot_is_uncovered_hole(
            &d,
            Some(named),
            "movie.vol000+01.par2",
            &covered(&["movie.part01.rar"]),
        ));
        let obf = d.join("Qk700zXm9rTb");
        let mut bytes = b"PAR2\x00PKT".to_vec();
        bytes.extend(std::iter::repeat_n(0u8, 64));
        std::fs::write(&obf, &bytes).unwrap();
        assert!(!super::slot_is_uncovered_hole(
            &d,
            Some(obf),
            "Qk700zXm9rTb",
            &covered(&["movie.part01.rar"]),
        ));
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// The dial, pinned: an obfuscated recovery volume lost whole leaves
    /// nothing on disk to sniff and nothing in the set to match, so it
    /// reads as a hole and the job fails with its journal intact. That
    /// is the conservative direction - a retry can still fetch the gap -
    /// but it IS a behaviour change against issue #9's class, so it is
    /// written down rather than left to be rediscovered.
    #[test]
    fn an_obfuscated_volume_lost_whole_reads_as_a_hole() {
        let d = dir("obfvol");
        assert!(super::slot_is_uncovered_hole(
            &d,
            None,
            "Qk700zXm9rTb",
            &covered(&["movie.part01.rar"]),
        ));
        std::fs::remove_dir_all(&d).unwrap();
    }
}

/// Does `dir` hold anything the nested pass could try to extract? Named
/// RAR volumes count by NAME alone - a damaged volume whose signature
/// bytes were destroyed (the exact case the nested PAR2 pass exists to
/// heal) fails every magic sniff but still announces itself as `.rar`.
pub(crate) fn dir_has_nested_extractable(dir: &std::path::Path) -> Result<bool> {
    Ok(std::fs::read_dir(dir)?.flatten().any(|e| {
        let p = e.path();
        e.file_type().is_ok_and(|t| t.is_file())
            && (looks_like_named_rar(&p) || is_extractable_archive(&p))
    }))
}

/// Run PAR2 repair over the recovery sets a nested layer carries, before
/// its extraction attempt. Only sets whose data files are actually in
/// `dir` run (repair_present_sets): the downloaded set's own index -
/// present beside an in-stream-extracted payload whose volumes never
/// touched disk - matches nothing and is left alone, so this never
/// re-verifies or resurrects the outer set. The extraction attempt that
/// follows is the level's verdict; an unrepairable set still gets its
/// .rev and recovery-record chances in extract_one_level.
pub(crate) fn nested_par2_repair(dir: &std::path::Path) {
    use nzbkit::par2repair::{RepairStatus, repair_present_sets};
    let results = match repair_present_sets(dir) {
        Ok(r) => r,
        Err(e) => {
            warn!(target: "par2", "nested set: scan error - {e}");
            return;
        }
    };
    for r in results {
        match r.status {
            Ok(RepairStatus::NoDamage) => {
                info!(target: "par2", "nested set: no damage, set verifies ✔")
            }
            Ok(RepairStatus::Repaired(rep)) => info!(
                target: "par2",
                "nested set: repaired ✔ ({} block(s) rebuilt, {} adopted, {} file(s) patched)",
                rep.blocks_rebuilt,
                rep.blocks_adopted,
                rep.files_patched.len()
            ),
            Ok(RepairStatus::Unrepairable {
                needed,
                have,
                adopted,
                partial,
            }) => {
                warn!(
                    target: "par2",
                    "nested set: UNREPAIRABLE - need {needed} recovery block(s), have {have}{}{}",
                    crate::repair::adopted_clause(adopted),
                    nzbkit::par2repair::published_clause(&partial)
                )
            }
            Err(e) => warn!(target: "par2", "nested set: repair error - {e}"),
        }
    }
}

/// The name grammar the RAR extract paths share: `.rar`/`.rNN` by name, or
/// a rollover (`.sNN`…) / numeric (`.001`) extension carrying the Rar!
/// magic. Factored out so obfuscation detection can ask the inverse.
pub(crate) fn looks_like_named_rar(path: &std::path::Path) -> bool {
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();
    let by_name = name.ends_with(".rar")
        || name.rfind('.').is_some_and(|p| {
            let t = &name[p + 1..];
            t.len() >= 3 && t.starts_with('r') && t[1..].bytes().all(|c| c.is_ascii_digit())
        });
    let rollover_or_numeric = name.rfind('.').is_some_and(|p| {
        let t = &name[p + 1..];
        (t.len() >= 3
            && (b's'..=b'z').contains(&t.as_bytes()[0])
            && t[1..].bytes().all(|c| c.is_ascii_digit()))
            || ((2..=4).contains(&t.len()) && t.bytes().all(|c| c.is_ascii_digit()))
    });
    by_name || (rollover_or_numeric && rar_magic(path))
}

/// Is a nested archive sitting in `dir` beside leftover outer volumes -
/// a named RAR of a foreign stem or a 7z at the top level (the fallback
/// unrar's own output when the payload is RAR-in-RAR), or any named
/// RAR/7z in a subdirectory (the unpack writes entry paths as real
/// subdirs; outer volumes only ever materialize at the top)? Obfuscated
/// (extensionless) top-level RARs are deliberately NOT counted: a
/// leftover volume that never earned its PAR2 rename would be
/// indistinguishable from payload, and re-processing the outer set is
/// the worse failure.
pub(crate) fn nested_archive_beside_leftovers(
    dir: &std::path::Path,
    outer_stems: &std::collections::HashSet<String>,
) -> bool {
    use nzbkit::extract::release_stem;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            let p = e.path();
            if ft.is_dir() {
                // Never look inside our own scratch dirs.
                if !p
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with(".nzbfast"))
                {
                    stack.push(p);
                }
            } else if ft.is_file() {
                // A payload file (`.cbr`/`.cb7`) is never a nested
                // archive - counting one would spin up a nested pass
                // with nothing to do.
                let hit = if !nzbkit::extract::archive_sniff_eligible(&p) {
                    false
                } else if d == dir {
                    if looks_like_named_rar(&p) {
                        p.file_name().is_some_and(|n| {
                            !outer_stems.contains(&release_stem(&n.to_string_lossy()))
                        })
                    } else {
                        sevenz_magic(&p)
                    }
                } else {
                    looks_like_named_rar(&p) || sevenz_magic(&p)
                };
                if hit {
                    return true;
                }
            }
        }
    }
    false
}

/// Parks the leftover outer volume files in a scratch subdir so the
/// nested pass can run without seeing (and re-processing) them, restoring
/// on drop - including unwind, because the volumes are the user's retry
/// currency and must be back in place whatever the pass does.
pub(crate) struct OuterHold {
    pub(crate) dir: PathBuf,
    pub(crate) hold: PathBuf,
}

impl OuterHold {
    pub(crate) fn park(
        dir: &std::path::Path,
        outer_stems: &std::collections::HashSet<String>,
    ) -> std::io::Result<Self> {
        use nzbkit::extract::release_stem;
        let hold = dir.join(".nzbfast-outer-hold");
        // A crashed earlier run may have left volumes parked - fold them
        // back first so this park starts from the dir's real state.
        if hold.is_dir() {
            Self::restore(&hold, dir);
        }
        std::fs::create_dir_all(&hold)?;
        // Construct before moving: an error mid-park drops `me`, which
        // restores whatever was already moved.
        let me = Self {
            dir: dir.to_path_buf(),
            hold: hold.clone(),
        };
        for e in std::fs::read_dir(dir)?.flatten() {
            let p = e.path();
            if e.file_type().is_ok_and(|t| t.is_file())
                && looks_like_named_rar(&p)
                && p.file_name()
                    .is_some_and(|n| outer_stems.contains(&release_stem(&n.to_string_lossy())))
                && let Some(name) = p.file_name()
            {
                std::fs::rename(&p, hold.join(name))?;
            }
        }
        Ok(me)
    }

    /// Move every parked volume back. Returns how many could NOT be
    /// returned, so the caller knows whether the hold is safe to delete.
    pub(crate) fn restore(hold: &std::path::Path, dir: &std::path::Path) -> usize {
        let mut stranded = 0;
        if let Ok(entries) = std::fs::read_dir(hold) {
            for e in entries.flatten() {
                let p = e.path();
                let Some(name) = p.file_name() else {
                    stranded += 1;
                    continue;
                };
                // NEVER replace. While the volumes were parked their
                // names were free, and the nested pass publishes through
                // `lift_scratch_into`, whose collision test is existence
                // only - so a nested member legitimately named like one
                // of the outer volumes lands at exactly this path. A bare
                // rename then destroys it (POSIX rename, and Windows
                // MoveFileEx with MOVEFILE_REPLACE_EXISTING, both replace
                // a regular file) and the job still completes green. The
                // same rename runs over a STALE hold in `park`, where the
                // older parked copy would eat the current run's volume.
                //
                // Move the occupant aside under `lift_scratch_into`'s own
                // scheme so both survive and the volume keeps the name its
                // set depends on. If even that fails, leave the volume in
                // the hold rather than replace: Drop keeps a non-empty
                // hold and says so, which is the module's standing rule.
                // A DIRECTORY in the way is left alone: rename refuses it
                // outright, which is already the loud, non-destructive
                // answer, and Drop then keeps the hold. Only the silent
                // replacement is ours to prevent.
                let dest = dir.join(name);
                if dest.symlink_metadata().is_ok_and(|m| !m.is_dir()) {
                    // CAPPED on the composed name, by the same door and
                    // for the same reason as `lift_scratch_into`'s ladder
                    // above, whose scheme this deliberately shares: the
                    // occupant's name is a `sanitize_out_name` result and
                    // is routinely at the 255-byte cap, so an
                    // `extracted-1-` prefix is a name the `rename` below
                    // cannot create - and the volume then stays in the
                    // hold rather than being published.
                    let mut n = 1usize;
                    let aside = loop {
                        let cand = dir.join(nzbkit::disk::sanitize_filename_capped(&format!(
                            "extracted-{n}-{}",
                            name.to_string_lossy()
                        )));
                        if cand.symlink_metadata().is_err() {
                            break cand;
                        }
                        n += 1;
                    };
                    if let Err(err) = std::fs::rename(&dest, &aside) {
                        warn!(
                            target: "hold",
                            "{} is occupied and the occupant could not be moved                              aside ({err}) - leaving the volume in the hold rather                              than overwriting",
                            name.to_string_lossy()
                        );
                        stranded += 1;
                        continue;
                    }
                    warn!(
                        target: "extract",
                        "{} was produced while the outer volume of that name was parked - kept as {}",
                        name.to_string_lossy(),
                        aside.file_name().unwrap_or(name).to_string_lossy()
                    );
                }
                if let Err(err) = std::fs::rename(&p, &dest) {
                    warn!(
                        target: "hold",
                        "could not put {} back: {err}",
                        name.to_string_lossy()
                    );
                    stranded += 1;
                }
            }
        }
        stranded
    }
}

impl Drop for OuterHold {
    fn drop(&mut self) {
        // Delete the hold only when it is EMPTY.
        //
        // This used to swallow every restore failure and then
        // `remove_dir_all` the hold regardless - so any volume that could not
        // be moved back was deleted instead. The hold exists precisely to
        // protect the outer volume set during nested extraction, which makes
        // "the restore failed, so destroy what we were protecting" the worst
        // possible response.
        //
        // `remove_dir` refuses a non-empty directory, so a stranded volume
        // survives where the user can find it. Same rule as the nest scratch:
        // never delete a path unless this code proved it is spent.
        let stranded = Self::restore(&self.hold, &self.dir);
        if stranded == 0 {
            let _ = std::fs::remove_dir(&self.hold);
        } else {
            warn!(
                target: "hold",
                "{stranded} volume(s) left in {} - not deleting it",
                self.hold.display()
            );
        }
    }
}

/// A `.rar` whose NAME says nothing about which set it belongs to, nor
/// where in that set it sits: an obfuscated stem, a bare `.rar`, and no
/// `.partNN` ordering.
///
/// The obfuscated-post handling assumed obfuscation meant EXTENSIONLESS
/// - `looks_like_named_rar` is true for anything ending in `.rar`, and
/// `collect_obfuscated_rar_volumes` excluded exactly that. Posters who
/// hash the stem but keep the extension therefore fell between the two
/// paths: 130 files called `<32 hex>.rar` are not one named set (no
/// shared stem to group by, no suffix to order by) and were not
/// collected as obfuscated either, so each was attempted as a
/// standalone archive and every one of them failed with "RAR 5 split
/// entry is missing its first part" (issue #47). Renaming the same
/// volumes extensionless unpacked them.
///
/// Deliberately narrow. A real stem (`Some.Release-GRP.rar`) keeps its
/// name-based path; so does `<hash>.part01.rar`, whose shared stem and
/// ordinal are exactly what that path needs. Only a name carrying
/// NEITHER is handed to the header-order grouping, which is the only
/// thing that can order it.
pub(crate) fn rar_name_carries_no_set(path: &std::path::Path) -> bool {
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_ascii_lowercase();
    let Some(head) = name.strip_suffix(".rar") else {
        // `.rNN` and the rollover tails order themselves by name.
        return false;
    };
    let ordered = head.rfind(".part").is_some_and(|p| {
        let tail = &head[p + 5..];
        !tail.is_empty() && tail.bytes().all(|c| c.is_ascii_digit())
    });
    // An old-style `.r00` sibling orders the set by name even when this
    // lead volume's own name says nothing: `<hash>.rar` + `<hash>.r00`
    // is the RAR4 analogue of the `.partNN` case above, and the `.rNN`
    // files already take the named path (they fail the strip_suffix
    // gate). Calling the lead obfuscated too would DOUBLE-claim the
    // set: the named arm extracts it and keeps the volumes, then the
    // obfuscated arm re-attempts the still-present first volume alone,
    // fails on the split entry, and its Failed poisons the level.
    let old_style_sibling = || {
        ["r00", "R00"]
            .iter()
            .any(|e| path.with_extension(e).is_file())
    };
    !ordered && !nzbkit::release::stem_is_a_name(head) && !old_style_sibling()
}

/// Is a normally-named RAR set present in `dir`?
pub(crate) fn dir_has_named_rar(dir: &std::path::Path) -> Result<bool> {
    Ok(std::fs::read_dir(dir)?.flatten().any(|e| {
        let p = e.path();
        // A volume the NAME cannot place belongs to the obfuscated arm,
        // even though it ends in `.rar`. Claiming it here would run the
        // named ladder over files it has no way to group, which is
        // precisely what failed 130 times in issue #47.
        looks_like_named_rar(&p) && !(rar_name_carries_no_set(&p) && rar_magic(&p))
    }))
}

/// Archive detector used for nested-layer descent: is this file an
/// archive a pass should descend into (RAR, 7z, or zip)? SFX stubs and
/// other executables are deliberately excluded - a payload executable
/// produced by an outer archive must never be re-exploded.
///
/// That exclusion is why the top-level SFX gate is [`is_sfx_archive`] and
/// lives in the two places that know the file was DOWNLOADED rather than
/// produced (`extract_one_level` step 3 at depth 0, and the get tail's
/// slot-path arm). Widening this predicate to cover SFX would reach every
/// consumer of it - `is_new_nested_archive`, `dir_has_nested_extractable`
/// and `entry_archives`, whose spent-intermediate sweep DELETES what it
/// lists - so a release's own `setup.exe` would become a nested layer,
/// then disposable furniture.
///
/// Zip counts even though we cannot yet unpack one: descent is what puts
/// the level in front of the reporting path, and a zip that nothing ever
/// descends into is a zip nobody ever hears about (a `Release/x.zip`
/// produced by an outer RAR used to vanish from every log). `nzbkit::zip`
/// keeps `.cbz`/`.epub` payloads out of that on its own; the RAR/7z arms
/// need the same guard here, or a `.cbr`/`.cb7` an outer archive produced
/// becomes a nested layer and then a spent intermediate - deleted.
///
/// That guard is [`nzbkit::extract::archive_sniff_eligible`] since 31 Aug
/// 2026 and was `is_final_file` before it, which is a WEAKER rule: it
/// refuses the two container extensions that are deliverables and says
/// nothing about a name that is not a container at all. So `Movie.mkv`,
/// `disc.iso` and `Subs.srt` carrying RAR5 magic all answered true here
/// (measured, 30 and 31 Aug 2026) - the identical hole matrix row M4-90
/// closed in the in-stream sniff, one layer down, which is why the
/// job-level outcome of that row did not change until this moved.
///
/// IT REACHES THE NESTED CASE TOO and that is the intended answer, not a
/// side effect. An archive an outer unpack PRODUCED is judged by the same
/// name rule as one that was posted, because the asymmetry is the same
/// either way: a wrongly-declined file is whole and openable, a wrongly-
/// unpacked one is gone and the job says Completed. It costs nothing real
/// - "archives a pass genuinely produces carry their packed names", and
/// none of `.rar`/`.rNN`/`.7z`/hash-named is a payload-content name, so
/// the only shape this declines is a nested archive somebody named
/// `Movie.mkv`.
///
/// Tar counts too, from TODO 163 item 6's disk half. The DESCENT
/// consumer gains nothing by it either way - a tar's own output lands
/// beside it and is found by the before/after diff whatever this
/// predicate says - so the reason is the SWEEP: a nested `.tar` the arm
/// has fully unpacked is scratch our own outer extraction materialized
/// seconds ago, the exact bytes a clean one-pass run never writes at
/// all, and leaving it behind doubles the payload on disk. The
/// widening hazard the SFX exclusion above guards against does not
/// arise here, because `is_tar_container`'s name gate is
/// `nzbkit::tar::chase_eligible_name` - `.tar` or nothing at all - so a
/// NAMED payload file never reaches the sniff to begin with. A tar the
/// arm REFUSES never reaches the sweep either: the ladder records it as
/// refused, which drops it before the stem count.
pub(crate) fn is_extractable_archive(path: &std::path::Path) -> bool {
    (nzbkit::extract::archive_sniff_eligible(path) && (rar_magic(path) || sevenz_magic(path)))
        || nzbkit::zip::is_container(path)
        || is_tar_container(path)
}

/// Phase 0(b): classify the nested inner archive the disk post-pass is
/// about to handle in `dir`, for the prevalence tally. Mirrors
/// `extract_one_level`'s detection order (RAR, then 7z, then the zip gap);
/// `None` when the dir holds no extractable archive. Cheap - a bounded
/// head read for the RAR sub-type, run once per nested level.
pub(crate) fn nested_inner_kind(dir: &std::path::Path) -> Option<&'static str> {
    // A RAR volume by name (a sig-destroyed member still announces `.rar`)
    // or by magic (obfuscated, extensionless) - sub-classify from its head.
    for e in std::fs::read_dir(dir).ok()?.flatten() {
        let p = e.path();
        if e.file_type().is_ok_and(|t| t.is_file())
            && nzbkit::extract::archive_sniff_eligible(&p)
            && (looks_like_named_rar(&p) || rar_magic(&p))
        {
            return Some(classify_rar_head(&p));
        }
    }
    // 7-Zip (native, incl. split .7z.001 multipart).
    if collect_sevenz_archives(dir).is_ok_and(|v| !v.is_empty()) {
        return Some("7z");
    }
    // Zip stays a documented extraction gap, but a zip inner is still a
    // nested layer worth counting. The tally has no zip bucket yet, so it
    // lands under the catch-all `other` - the prevalence LINE still names
    // it, which is what makes a zip-packed nest legible in a log.
    if nzbkit::zip::first(dir).is_some() {
        return Some("zip");
    }
    // Tar, last, matching the ladder's own order. Counted the same way
    // as zip and for the same reason: minting a `tar` COUNTER means a
    // new field on the stats API's `NestedPrevalence`, which is a
    // persisted wire value, and that is the piece of work the tar shape
    // badge was declined over too. The line names the kind either way.
    if first_tar_container(dir).is_some() {
        return Some("tar");
    }
    None
}

/// Read a RAR volume's head and name its shape for the prevalence line:
/// `rar-encrypted` (encryption is the salient blocker, header- or
/// file-level), else `rar-store` / `rar-compressed` from the first mapped
/// entry's method. `other` when the head parses no entry (a damaged or
/// exotic volume) - rare here, since nested PAR2 repair ran first.
pub(crate) fn classify_rar_head(path: &std::path::Path) -> &'static str {
    use nzbkit::rar::{Method, VolumeMapper};
    use std::io::Read;
    // Header-encrypted sets expose no entries without a password; the
    // crypt probe reads the record straight off the head.
    if nzbkit::rar::crypt_probe(path).is_some() {
        return "rar-encrypted";
    }
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let mut buf = vec![0u8; 512 * 1024];
    let mut n = 0;
    if let Ok(mut f) = std::fs::File::open(path) {
        while n < buf.len() {
            match f.read(&mut buf[n..]) {
                Ok(0) => break,
                Ok(k) => n += k,
                Err(_) => break,
            }
        }
    }
    let mut m = VolumeMapper::new(size);
    m.feed(0, &buf[..n]);
    match m.entries.first() {
        Some(e) if e.encrypted || e.crypt.is_some() => "rar-encrypted",
        Some(e) => match e.method {
            Method::Store => "rar-store",
            Method::Compressed => "rar-compressed",
        },
        None => "other",
    }
}

/// The PAR2 verified-name publish and the per-job output-name claim that
/// keeps two of them from landing on one path (TODO 106 size-gate split
/// out of this file).
mod published_names;

/// GH #63: which of the post's two names a slot's file is written
/// under. Carries `FileSlot::write_name` and `FileSlot::hint_beats`,
/// and - M4-70 - `FileSlot::contested_yenc_name`, which re-decides that
/// question at settle off what the ARTICLES declared.
pub(crate) mod slot_name;
pub(crate) use published_names::*;
pub(crate) use slot_name::NAME_UNDECIDED;

/// Does the file start with the 7-Zip signature (`7z\xBC\xAF\x27\x1C`)?
pub(crate) fn sevenz_magic(path: &std::path::Path) -> bool {
    use std::io::Read;
    let mut b = [0u8; 6];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut b))
        .map(|_| b == [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C])
        .unwrap_or(false)
}

/// Is this single path a 7z container or one part of a split set? The
/// per-path twin of `collect_sevenz_archives`' grouping grammar, for
/// callers that ask about one file rather than scanning a directory.
pub(crate) fn sevenz_archive_part(path: &std::path::Path) -> bool {
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();
    name.ends_with(".7z") || split_7z_part(&name).is_some() || sevenz_magic(path)
}

/// How many PAR2 bytes the diagnostic verify pass may hold at once.
///
/// A slice of the process budget, because nothing else on this path
/// consults it and the pass is pure printing: `verify_dir`'s bool is
/// discarded at both call sites, so trading a complete recovery-block
/// count for a bounded footprint costs nothing a caller can observe.
pub(crate) fn par2_scan_cap() -> u64 {
    (nzbkit::mem::process_budget().total / 8).clamp(64 << 20, 512 << 20)
}

/// Collect the PAR2 packet bytes in `dir` for the diagnostic verify pass,
/// bounded so an obfuscated recovery set cannot be resident all at once.
///
/// The magic sniff matches recovery VOLUMES, not just the index: on a
/// fully obfuscated post every one of them lands here under an
/// extensionless hash name, and a 10% recovery set on a 50 GB release is
/// several GB of them. Reading the lot into one live `Vec<Vec<u8>>` would
/// blow a container's memory clamp at settle, after the whole download.
/// Returns the bytes plus the number of candidates a cap kept out.
pub(crate) fn collect_par2_bytes(
    dir: &std::path::Path,
    total_cap: u64,
) -> Result<(Vec<Vec<u8>>, usize)> {
    /// Ceiling on one packet file, matching the sibling sniffer in
    /// `nzbkit::par2repair::collect_packet_files` so the two agree on what
    /// is too big to slurp. Generous on purpose: a legitimate `.par2` this
    /// large is rare, and the aggregate cap does the real work.
    const MAX_PACKET_FILE_BYTES: u64 = 1 << 30;

    let mut paths: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        // By name OR by the `PAR2\0PKT` packet magic. An obfuscated post
        // ships its index and recovery volumes as extensionless hashes,
        // and taking only the name meant this reported "no .par2 files"
        // over a directory holding a complete recovery set (issue #9).
        // Same rule `dir_has_par2` and `smart::par2_magic` use. The
        // eligibility test stays exactly that wide - it is the BYTES that
        // are capped below, never the sniff, because narrowing the sniff
        // is what issue #9 was.
        let by_name = path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("par2"));
        if !by_name && !file_starts_with_par2_magic(&path) {
            continue;
        }
        paths.push(path);
    }
    // Sorted, like `collect_packet_files`: `name.par2` sorts ahead of
    // `name.vol*.par2`, so the index - which carries the complete critical
    // packet set - is in hand before a cap starts dropping recovery slices.
    // `read_dir` order is arbitrary and would drop them at random.
    paths.sort();

    let mut par2_bytes: Vec<Vec<u8>> = Vec::new();
    let mut held: u64 = 0;
    let mut skipped = 0usize;
    for path in paths {
        let len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if len > MAX_PACKET_FILE_BYTES || held.saturating_add(len) > total_cap {
            skipped += 1;
            continue;
        }
        let data = std::fs::read(&path)?;
        held += data.len() as u64;
        par2_bytes.push(data);
    }
    Ok((par2_bytes, skipped))
}

pub(crate) fn verify_dir(dir: &std::path::Path) -> Result<bool> {
    use nzbkit::par2::verify_file_streaming;

    let cap = par2_scan_cap();
    let (par2_bytes, skipped) = collect_par2_bytes(dir, cap)?;
    if skipped > 0 {
        // Said out loud, because it is why the recovery-block count below
        // may understate what is actually on disk.
        warn!(
            target: "par2",
            "{skipped} PAR2 file(s) not read - scan capped at {} MiB",
            cap >> 20
        );
    }
    if par2_bytes.is_empty() {
        if skipped > 0 {
            warn!(
                target: "par2",
                "PAR2 files in {} are all over the scan cap - verification skipped",
                dir.display()
            );
        } else {
            info!(target: "par2", "no PAR2 files in {} - verification skipped", dir.display());
        }
        return Ok(false);
    }
    let refs: Vec<&[u8]> = par2_bytes.iter().map(|v| v.as_slice()).collect();
    // Every set in the directory, not one (TODO 311). `Par2Set::parse`
    // refuses a MIXED input outright, so this used to print "parse
    // failed (inputs mix recovery sets) - verification skipped" and
    // return false over a directory holding one set per file - GH #63's
    // shape, where every byte on disk is verifiable and none of it was
    // looked at. The live path had the same defect one layer up; see
    // `nzbkit::live::pick_sets`.
    let sets = match nzbkit::live::pick_sets(&refs) {
        Ok(s) => s,
        Err(e) => {
            warn!(target: "par2", "parse failed ({e}) - verification skipped");
            return Ok(false);
        }
    };
    for set in &sets {
        info!(
            target: "par2",
            "set: {} file(s), block size {}, {} recovery block(s) on hand",
            set.files.len(),
            set.block_size,
            set.recovery_blocks_seen
        );
    }

    let mut all_ok = true;
    for (set, f) in sets
        .iter()
        .flat_map(|s| s.files.iter().map(move |f| (s, f)))
    {
        let path = nzbkit::disk::join_out_name(dir, &nzbkit::disk::sanitize_out_name(&f.name));
        // Streamed, never slurped: a set member is a payload file, so this
        // is the 30 GB mkv in an obfuscated post's output dir, and
        // `std::fs::read` here made its whole length resident at once
        // outside any budget. `verify_file_streaming` returns the same
        // verdicts off a ~1 MiB window.
        match std::fs::File::open(&path).and_then(|fh| verify_file_streaming(f, set.block_size, fh))
        {
            Ok(v) => {
                let bad = v.blocks.iter().filter(|ok| !**ok).count();
                if bad == 0 && v.md5_ok {
                    info!(target: "par2", "✔ {} - {} blocks, MD5 ok", f.name, v.blocks.len());
                } else {
                    all_ok = false;
                    warn!(
                        target: "par2",
                        "✘ {} - {bad}/{} blocks bad, md5 {}",
                        f.name,
                        v.blocks.len(),
                        if v.md5_ok { "ok" } else { "MISMATCH" }
                    );
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                all_ok = false;
                warn!(target: "par2", "✘ {} - file missing", f.name);
            }
            // Reached only now that the bytes are read here rather than
            // up front: a mid-file read error is not a missing file and
            // must not be reported as one.
            Err(e) => {
                all_ok = false;
                warn!(target: "par2", "✘ {} - unreadable ({e})", f.name);
            }
        }
    }
    Ok(all_ok)
}

#[cfg(test)]
mod par2_scan_cap_tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nzbfast-p2cap-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A file that answers the `PAR2\0PKT` sniff, `len` bytes long. What a
    /// recovery volume from an obfuscated post looks like to this code:
    /// the magic and nothing else to go on.
    fn write_sniffable(dir: &std::path::Path, name: &str, len: usize) {
        let mut data = b"PAR2\x00PKT".to_vec();
        data.resize(len, 0u8);
        std::fs::write(dir.join(name), &data).unwrap();
    }

    /// The whole point: the sniffed set is read under a cap, not slurped.
    /// An obfuscated release drops its recovery VOLUMES in the output dir
    /// under extensionless hashes, and settle runs `verify_dir` over it on
    /// every download, damaged or clean.
    #[test]
    fn sniffed_volumes_are_capped_not_slurped() {
        let dir = temp_dir("sniffed");
        for i in 0..6 {
            write_sniffable(&dir, &format!("{i:02}b1946ac92492d234"), 256 << 10);
        }
        let cap: u64 = 512 << 10;
        let (bytes, skipped) = collect_par2_bytes(&dir, cap).unwrap();
        let held: u64 = bytes.iter().map(|b| b.len() as u64).sum();
        assert!(held <= cap, "held {held} bytes at once, cap is {cap}");
        assert_eq!(skipped, 4, "the volumes over the cap must be reported");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// No single file may be slurped whole either, however small the set.
    /// Same ceiling the sibling sniffer in `par2repair::collect_packet_files`
    /// applies.
    #[test]
    fn one_oversized_candidate_is_skipped_not_read() {
        let dir = temp_dir("oversize");
        write_sniffable(&dir, "small.par2", 1024);
        write_sniffable(&dir, "huge.par2", 8192);
        let (bytes, skipped) = collect_par2_bytes(&dir, 4096).unwrap();
        assert_eq!(bytes.len(), 1);
        assert_eq!(bytes[0].len(), 1024);
        assert_eq!(skipped, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The cap must bite on recovery slices, not on the index: sorted order
    /// puts `name.par2` ahead of `name.vol*.par2`, so the critical packets
    /// are in hand before anything is dropped.
    #[test]
    fn index_is_read_before_the_volumes() {
        let dir = temp_dir("order");
        write_sniffable(&dir, "obf.vol000+01.par2", 4096);
        write_sniffable(&dir, "obf.vol001+02.par2", 4096);
        write_sniffable(&dir, "obf.par2", 1024);
        let (bytes, skipped) = collect_par2_bytes(&dir, 6000).unwrap();
        assert_eq!(bytes.first().map(|b| b.len()), Some(1024), "index first");
        assert_eq!(bytes.len(), 2);
        assert_eq!(skipped, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A set that fits is still read in full - the cap must not cost a
    /// normal `nzbfast verify` its recovery-block count.
    #[test]
    fn a_set_under_the_cap_is_read_whole() {
        let dir = temp_dir("under");
        write_sniffable(&dir, "obf.par2", 1024);
        write_sniffable(&dir, "obf.vol000+01.par2", 1024);
        std::fs::write(dir.join("payload.mkv"), vec![0u8; 4096]).unwrap();
        let (bytes, skipped) = collect_par2_bytes(&dir, 64 << 20).unwrap();
        assert_eq!(bytes.len(), 2, "payload must not be picked up");
        assert_eq!(skipped, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

// ---------------------------------------------------------------------------
// get - the downloader (PLAN M1)
// ---------------------------------------------------------------------------

/// The download side of this module: [`FileSlot`], issue #14's in-stream
/// PAR2 sniff with its deferral and reconcile, M15b's pre-activation
/// backfill and set activation, and the post-age helper. Everything that
/// belongs to a job while it is still fetching, where the rest of this
/// file is about the directory once it has finished arriving.
mod instream;
pub(crate) use instream::*;

#[cfg(test)]
#[path = "unpack/pwfile_tests.rs"]
mod pwfile_tests;

#[cfg(test)]
#[path = "unpack/scratch_dir_tests.rs"]
mod scratch_dir_tests;

#[cfg(test)]
#[path = "unpack/backfill_tests.rs"]
mod backfill_tests;

#[cfg(test)]
#[path = "unpack/split_set_sweep_tests.rs"]
mod split_set_sweep_tests;

#[cfg(test)]
#[path = "unpack/nested_depth_tests.rs"]
mod nested_depth_tests;

/// The `<prefix>-<n>-<name>` collision ladders, on a member name already
/// AT the component cap.
#[cfg(test)]
#[path = "unpack/lift_name_cap_tests.rs"]
mod lift_name_cap_tests;

/// GitHub issue #40: a named `.cbr` comic is a RAR container whose file
/// IS the deliverable. The ladder used to sniff it into the obfuscated
/// arm, unpack it and delete it as a spent volume, leaving loose pages.
/// Mirrors `nzbkit::zip`'s `comic.cbz` pins for the RAR/7z families.
#[cfg(test)]
#[path = "unpack/named_payload_tests.rs"]
mod named_payload_tests;

#[cfg(test)]
mod obfuscated_rar_extension_tests {
    use super::*;

    fn p(name: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(name)
    }

    /// Issue #47: a poster who hashes the stem but KEEPS `.rar` produced
    /// a set that fell between both paths - not one named set (no shared
    /// stem to group by, no ordinal to sort by) and not collected as
    /// obfuscated either, because that collector excluded everything
    /// `looks_like_named_rar` claimed and `.rar` alone was enough to be
    /// claimed. 130 volumes were each attempted alone and each failed
    /// with "RAR 5 split entry is missing its first part".
    #[test]
    fn a_hash_stem_that_kept_its_rar_extension_carries_no_set() {
        assert!(rar_name_carries_no_set(&p(
            "0b47e3ccafff5cc68c0b77534e2e4c87e.rar"
        )));
        assert!(rar_name_carries_no_set(&p(
            "2768fdf3d8a6dc8001998da1e7ca5c66.rar"
        )));
        // The extension is what the old rule keyed on, so pin that this
        // name IS still claimed by it - the fix is the two rules
        // disagreeing on purpose, not the old one changing.
        assert!(looks_like_named_rar(&p(
            "0b47e3ccafff5cc68c0b77534e2e4c87e.rar"
        )));
    }

    /// The narrowness is the whole design: anything whose name can group
    /// OR order it keeps the name-based path, which is better at it.
    #[test]
    fn a_name_that_can_group_or_order_itself_keeps_the_named_path() {
        // A real stem: groups by stem, orders by ordinal.
        assert!(!rar_name_carries_no_set(&p("Some.Release-GRP.rar")));
        assert!(!rar_name_carries_no_set(&p("Some.Release-GRP.part01.rar")));
        // A hash stem WITH an ordinal: the stem is shared across the set
        // and the ordinal sorts it, which is all the named path needs.
        assert!(!rar_name_carries_no_set(&p(
            "deadbeefcafe1234deadbeefcafe1234.part1.rar"
        )));
        assert!(!rar_name_carries_no_set(&p(
            "deadbeefcafe1234deadbeefcafe1234.part011.rar"
        )));
        // `.rNN` and the rollover tails order themselves by name and
        // never reach this rule at all.
        assert!(!rar_name_carries_no_set(&p("whatever.r00")));
        assert!(!rar_name_carries_no_set(&p("whatever.001")));
        // Extensionless obfuscated volumes were always handled; they are
        // not this rule's business either.
        assert!(!rar_name_carries_no_set(&p(
            "0b47e3ccafff5cc68c0b77534e2e4c87e"
        )));
        // ".part" with no digits is part of somebody's title, not an
        // ordinal - the stem is still unreadable, so this IS ours.
        assert!(rar_name_carries_no_set(&p("a1b2c3d4e5f6a7b8.part.rar")));
    }

    /// A hash stem that kept OLD-STYLE extensions (`<hash>.rar` +
    /// `<hash>.r00`) is one named set: the `.rNN` siblings share the
    /// stem and order it, so the lead must keep the named path.
    /// Judged per-file it was double-claimed - the named arm extracted
    /// the whole set (keeping its volumes), then the obfuscated arm
    /// re-attempted the still-present lead alone, failed on the split
    /// entry, and its Failed poisoned the level (bug sweep 20 Aug).
    #[test]
    fn an_old_style_sibling_keeps_the_hash_lead_on_the_named_path() {
        let dir = std::env::temp_dir().join(format!("nzbfast-oldstyle-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let lead = dir.join("0b47e3ccafff5cc68c0b77534e2e4c87e.rar");
        std::fs::write(&lead, b"x").unwrap();
        assert!(
            rar_name_carries_no_set(&lead),
            "no sibling on disk: the lead is still the obfuscated arm's"
        );
        std::fs::write(dir.join("0b47e3ccafff5cc68c0b77534e2e4c87e.r00"), b"x").unwrap();
        assert!(
            !rar_name_carries_no_set(&lead),
            "an .r00 sibling orders the set by name - named path, once"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
