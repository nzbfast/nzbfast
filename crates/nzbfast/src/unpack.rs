//! In-place extraction of a completed download directory: nested/obfuscated/SFX archive handling, password harvesting, PAR2 scan and verify_dir, and the pre-activation backfill.
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
            Ok(RepairStatus::NoDamage) => println!("PAR2: no damage, set verifies ✔"),
            Ok(RepairStatus::Repaired(r)) => {
                println!(
                    "PAR2: repaired ✔ ({} block(s) rebuilt, {} adopted, {} file(s) patched)",
                    r.blocks_rebuilt,
                    r.blocks_adopted,
                    r.files_patched.len()
                );
            }
            Ok(RepairStatus::Unrepairable { needed, have }) => {
                println!("PAR2: UNREPAIRABLE - need {needed} recovery block(s), have {have}");
                par2_ok = false;
            }
            Err(e) => {
                println!("PAR2: repair error - {e}");
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
                println!("{}", u.message());
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

/// Extract the archives in `dir`, then recurse into any archive that
/// extraction just produced (a nested release: a RAR whose payload is one
/// more RAR/7z, occasionally in a release subfolder). Returns `Produced`
/// when there was nothing to extract (the data files ARE the payload) or
/// every archive present was fully produced; otherwise the cause that
/// stopped it. Bounded to [`nzbkit::extract::nested_depth_cap`]
/// passes (the shared daemon `nested_max_depth` setting); at the cap the
/// deepest layer is left materialized on disk and the job still succeeds -
/// the design guarantee that a too-deep chain degrades, never fails.
pub(crate) fn extract_nested(
    dir: &std::path::Path,
    password: Option<&str>,
    depth: usize,
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
    let pre_obfuscated = before
        .iter()
        .any(|p| !looks_like_named_rar(p) && !nzbkit::extract::is_final_file(p) && rar_magic(p));
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
    let top = extract_one_level(dir, password, depth)?;
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
        // The spent archive volumes, plus any recovery/verification sidecar
        // for THIS set (`.par2`/`.sfv`/`.rev` sharing the stem). A par2 for a
        // different stem - e.g. the outer post's own `a3.par2` riding along
        // beside a `level2.rar` - has a different stem and is left alone.
        for p in entry_archives.iter().cloned().chain(
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
    let cap = nzbkit::extract::nested_depth_cap();
    if depth + 1 >= cap {
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
            println!(
                "⚠ nested archives deeper than {cap} levels - deepest layer left \
                 materialized on disk ({}); raise the nested_max_depth setting to unpack further",
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
            // A scratch directory this call PROVABLY created.
            //
            // This used to be a fixed `.nzbfast-nest` preceded by an
            // unconditional `remove_dir_all`. The recursive snapshot skips
            // `.nzbfast*`, so a legitimate archive payload extracted to
            // `.nzbfast-nest/` was invisible to every protection and simply
            // deleted the moment a sibling `inner.rar` triggered nesting.
            // `create_dir` fails if the path exists at all, so we can never
            // adopt - or destroy - something that was already there.
            let sub = {
                let mut made = None;
                for n in 0..1024 {
                    let candidate = match n {
                        0 => dir.join(".nzbfast-nest"),
                        n => dir.join(format!(".nzbfast-nest{n}")),
                    };
                    match std::fs::create_dir(&candidate) {
                        Ok(()) => {
                            made = Some(candidate);
                            break;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                        Err(e) => return Err(e.into()),
                    }
                }
                made.ok_or_else(|| {
                    anyhow::anyhow!("no free nest scratch name in {}", dir.display())
                })?
            };
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
                    let _ = std::fs::rename(&p, sub.join(name));
                }
            }
            ok = ok.and(extract_nested(&sub, password, depth + 1)?);
            if lift_nest_outputs(&sub, dir) {
                let _ = std::fs::remove_dir_all(&sub);
            } else {
                // Never sweep a scratch dir that still holds payload - a
                // swallowed rename here once deleted the stranded output
                // and reported success.
                println!(
                    "⚠ nest lift-back incomplete - keeping {} in place",
                    sub.display()
                );
                ok = ok.and(NestOutcome::Failed);
            }
        } else {
            // A fresh subdir holds only this pass's output - safe to recurse
            // in place (the outer volumes are elsewhere).
            ok = ok.and(extract_nested(&idir, password, depth + 1)?);
        }
    }
    // The nested layer(s) this level held are now denested (or not, if a
    // deeper level failed): sweep the spent input archives on full success.
    sweep_spent_entry(ok.produced());
    Ok(ok)
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
            let mut n = 1usize;
            loop {
                let cand = dir.join(format!("{prefix}-{n}-{}", name.to_string_lossy()));
                if cand.symlink_metadata().is_err() {
                    break cand;
                }
                n += 1;
            }
        } else {
            target
        };
        if let Err(err) = std::fs::rename(&p, &dest) {
            println!("⚠ {what}: {} → {}: {err}", p.display(), dest.display());
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
fn unpack_named_rar(dir: &std::path::Path, password: Option<&str>) -> NestOutcome {
    if try_unrar(dir, password) {
        return NestOutcome::Produced;
    }
    if try_rev_reconstruct(dir) && try_unrar(dir, password) {
        return NestOutcome::Produced;
    }
    println!("extraction failed - trying recovery-record self-repair…");
    NestOutcome::from_produced(try_rar_rr_repair(dir, password))
}

/// One extraction pass over `dir`, unpacking EVERY archive family present.
/// `Ok(None)` = no archive present; otherwise the pass's [`NestOutcome`],
/// which names WHICH format stopped it so only the zip gap gets forgiven.
pub(crate) fn extract_one_level(
    dir: &std::path::Path,
    password: Option<&str>,
    depth: usize,
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
    // The plain-split collector runs here for the same reason as the rest:
    // whatever it sees now is what the post ARRIVED with, so no arm's
    // output can be mistaken for a split part. Its arm still runs last -
    // see step 6, which re-scans and keeps only the sets that survive
    // unchanged.
    let arrived_splits = collect_split_sets(dir)?;
    let entries_left =
        |ps: &[PathBuf]| -> Vec<PathBuf> { ps.iter().filter(|p| p.exists()).cloned().collect() };
    let mut out: Option<NestOutcome> = None;
    let claim = |o: NestOutcome, out: &mut Option<NestOutcome>| {
        *out = Some(out.map_or(o, |prev| prev.and(o)));
    };

    // 1. Normally-named RAR set (.rar/.rNN by name; rollover/numeric with
    //    the Rar! magic). Native rars first (bundled unrar fallback), then
    //    the two recovery rungs - see `unpack_named_rar`.
    if named_rar {
        claim(unpack_named_rar(dir, password), &mut out);
    }
    // 2. Obfuscated RAR: extensionless files carrying the Rar! magic, with
    //    no filename order - ordered by the RAR header volume number.
    let obf = entries_left(&obf);
    if !obf.is_empty() {
        claim(
            NestOutcome::from_produced(extract_obfuscated_rar(dir, &obf, level_pw, depth)),
            &mut out,
        );
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
            claim(
                NestOutcome::from_produced(extract_sfx(dir, &sfx, level_pw)),
                &mut out,
            );
        }
    }
    // 4. 7-Zip (native, incl. split .7z.001 multipart).
    let sevenz: Vec<Vec<PathBuf>> = sevenz
        .into_iter()
        .filter(|set| set.iter().all(|p| p.exists()))
        .collect();
    if !sevenz.is_empty() {
        claim(
            NestOutcome::from_produced(extract_sevenz(dir, &sevenz, password)),
            &mut out,
        );
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
        if extract_zip(dir, &zips, password) {
            claim(NestOutcome::Produced, &mut out);
        } else {
            claim(NestOutcome::ZipGap, &mut out);
        }
    }
    // 6. Plain split files: an HJSplit-style `.001/.002/…` (or `.1/.2/…`)
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
            claim(
                NestOutcome::from_produced(join_split_sets(dir, &sets)),
                &mut out,
            );
        }
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
            && !nzbkit::extract::is_final_file(&p)
            && (rar_magic(&p) || sevenz_magic(&p))
    });
    if let Some(e) = stray {
        println!(
            "⚠ {} looks like an archive but no extractor claimed it",
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
    let path = path.unwrap_or_else(|| out_dir.join(nzbkit::disk::sanitize_filename(hint)));
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();
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
            println!("nested PAR2: scan error - {e}");
            return;
        }
    };
    for r in results {
        match r.status {
            Ok(RepairStatus::NoDamage) => println!("nested PAR2: no damage, set verifies ✔"),
            Ok(RepairStatus::Repaired(rep)) => println!(
                "nested PAR2: repaired ✔ ({} block(s) rebuilt, {} adopted, {} file(s) patched)",
                rep.blocks_rebuilt,
                rep.blocks_adopted,
                rep.files_patched.len()
            ),
            Ok(RepairStatus::Unrepairable { needed, have }) => {
                println!("nested PAR2: UNREPAIRABLE - need {needed} recovery block(s), have {have}")
            }
            Err(e) => println!("nested PAR2: repair error - {e}"),
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
                let hit = if nzbkit::extract::is_final_file(&p) {
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
                    let mut n = 1usize;
                    let aside = loop {
                        let cand = dir.join(format!("extracted-{n}-{}", name.to_string_lossy()));
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
                    println!(
                        "⚠ {} was produced while the outer volume of that name was                          parked - kept as {}",
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

/// Is a normally-named RAR set present in `dir`?
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

/// RAR volumes whose names carry NO recognized RAR extension but which
/// start with the Rar! magic (obfuscated usenet posts strip extensions and
/// rename volumes to hex). Only consulted when no normally-named set was
/// found, so this never shadows the fast name-based path. A named payload
/// file (`.cbr`) is excluded: its bytes are a RAR, but the file IS the
/// deliverable, and this collector's caller deletes what it spends.
pub(crate) fn collect_obfuscated_rar_volumes(dir: &std::path::Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir)?.flatten() {
        let path = e.path();
        if e.file_type().is_ok_and(|t| t.is_file())
            && (!looks_like_named_rar(&path) || rar_name_carries_no_set(&path))
            && !nzbkit::extract::is_final_file(&path)
            && rar_magic(&path)
        {
            out.push(path);
        }
    }
    Ok(out)
}

/// The RAR5+ volume number from a parsed archive header, when present.
/// RAR5 volume sets carry it; older families and single archives do not
/// (they sort by filename, which for a real set already reflects order).
pub(crate) fn archive_volume_number(archive: &rars::Archive) -> Option<u64> {
    match archive {
        rars::Archive::Rar50Plus(a) => a.main.volume_number,
        _ => None,
    }
}

/// Extract obfuscated RAR volumes: parse each candidate, PARTITION the
/// volumes into their original sets (a directory can hold several
/// interleaved obfuscated sets - the volumes carry no usable names, so
/// grouping runs on headers: volume numbers plus split-member name
/// continuity across volume boundaries), order each set by header volume
/// number, and extract every set. Returns true only when every detected
/// set extracted.
pub(crate) fn extract_obfuscated_rar(
    dir: &std::path::Path,
    candidates: &[PathBuf],
    password: Option<&str>,
    depth: usize,
) -> bool {
    let options = nzbkit::mem::rar_read_options(password.map(str::as_bytes));
    // One parse session for the whole candidate set: an encrypted set
    // shares one salt across its volumes, and the per-volume PBKDF2
    // ladder dwarfed the parse itself on p99-sized sets.
    let mut parse = rars::ReadSession::new(options);
    let mut parsed: Vec<(Option<u64>, PathBuf, rars::Archive)> = Vec::new();
    for path in candidates {
        match parse.read_path(path) {
            Ok(archive) => parsed.push((archive_volume_number(&archive), path.clone(), archive)),
            // A Rar!-magic file that will not parse is not a usable volume;
            // skip it rather than abort the whole set.
            Err(e) => println!("  – skipping {}: {e}", path.display()),
        }
    }
    if parsed.is_empty() {
        return false;
    }
    parsed.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    // First/last member metadata drives the continuity linkage.
    let boundary = |archive: &rars::Archive| -> (Option<(Vec<u8>, bool)>, Option<(Vec<u8>, bool)>) {
        let mut first: Option<(Vec<u8>, bool)> = None;
        let mut last: Option<(Vec<u8>, bool)> = None;
        for member in archive.members() {
            let name = member.meta.name_bytes().to_vec();
            if first.is_none() {
                first = Some((name.clone(), member.meta.is_split_before));
            }
            last = Some((name, member.meta.is_split_after));
        }
        (first, last)
    };

    // Partition. Sets start at volumes with no volume number (a RAR5 set's
    // first volume, or a standalone archive); numbered volumes attach to
    // the open set whose tail's split-after member name matches their
    // split-before head - or, when the boundary member is not split, to
    // the only open set awaiting that number.
    let mut sets: Vec<Vec<(PathBuf, rars::Archive)>> = Vec::new();
    let mut open: Vec<usize> = Vec::new(); // indexes of sets still growing
    for (number, path, archive) in parsed {
        if number.is_none() {
            let closed = {
                let (_, last) = boundary(&archive);
                // A first volume whose last member is not split-after is a
                // complete single-volume archive.
                !last.is_some_and(|(_, split_after)| split_after)
            };
            sets.push(vec![(path, archive)]);
            if !closed {
                open.push(sets.len() - 1);
            }
            continue;
        }
        let number = number.unwrap_or(0);
        let (first, last) = boundary(&archive);
        // Candidate open sets currently ending at `number - 1` volumes past
        // their first (RAR5 numbers later volumes 1, 2, …).
        let expecting: Vec<usize> = open
            .iter()
            .copied()
            .filter(|&si| sets[si].len() as u64 == number)
            .collect();
        let chosen = match expecting.len() {
            0 => None,
            1 => Some(expecting[0]),
            _ => expecting.iter().copied().find(|&si| {
                let tail = &sets[si].last().expect("open set is non-empty").1;
                let (_, tail_last) = boundary(tail);
                match (&tail_last, &first) {
                    (Some((tail_name, true)), Some((head_name, true))) => tail_name == head_name,
                    _ => false,
                }
            }),
        };
        match chosen {
            Some(si) => {
                sets[si].push((path, archive));
                if !last.is_some_and(|(_, split_after)| split_after) {
                    open.retain(|&s| s != si);
                }
            }
            None => {
                // No open set expects this volume - treat it as starting
                // its own (best effort; extraction will surface gaps).
                println!(
                    "  – volume {} (#{number}) matches no open set - treating as its own set",
                    path.display()
                );
                sets.push(vec![(path, archive)]);
            }
        }
    }

    println!(
        "unpacking {} obfuscated RAR set(s) ({} volume(s)) by header order…",
        sets.len(),
        sets.iter().map(|s| s.len()).sum::<usize>()
    );
    let mut all_ok = true;
    // §101, the same refusal the named-stem ladder makes: a directory
    // holding more than one archive set must not eat. It was applied
    // only in `try_unrar_spent`'s loop, and this path partitions by
    // HEADER continuity rather than by stem, so a directory of two
    // obfuscated sets slipped past it entirely. Set one eats its volumes
    // and publishes; set two fails part-way with several of its own
    // volumes already hard-deleted - and the failure arm below still
    // says every volume of a failed set stays, "on a finished download
    // they are the only copy", which eating has just made untrue.
    // Held for the whole partitioned run, restored on drop.
    let _single_set_only = (sets.len() > 1).then(|| crate::eatvol::EatArm::new(false));
    for set in sets {
        // Keep each set's SOURCE paths instead of dropping them on the
        // floor: they are the exact files we parsed and are about to feed
        // the extractor, so a successful extraction proves them ours AND
        // spent. Nothing downstream can re-derive that. The nested pass's
        // `sweep_spent_entry` groups candidates by `release_stem`, and a
        // hash name matches none of the volume suffixes it strips - seven
        // obfuscated volumes read as seven separate releases, its
        // "exactly one set present" guard trips, and the whole set used
        // to be left sitting beside the extracted payload.
        let (sources, archives): (Vec<PathBuf>, Vec<rars::Archive>) = set.into_iter().unzip();
        // Does this set declare a real file to produce? A `.rev` recovery
        // volume also starts with `Rar!`, so it arrives here as a
        // candidate, and its payload can carry a RAR signature the SFX
        // scan latches onto - parsing as a memberless "set" of its own.
        // Deleting one destroys the recovery data a damaged set is
        // repaired FROM, which is the worst outcome available here.
        let has_member = archives
            .iter()
            .any(|a| a.members().any(|m| !m.meta.is_directory));
        // Taken per set, immediately before the extraction that fills it:
        // the diff against it names exactly what THIS set published.
        let before = snapshot_recursive(dir).ok();
        // `sources` and `archives` came off the same unzip, so index i of
        // one is index i of the other - the mapping §101's eating mode
        // needs to delete each volume as the extractor finishes with it.
        //
        // Withheld on the two gates the post-extraction sweep below
        // already applies, because eating happens INSIDE the extractor
        // and so runs before `sweep_spent_obfuscated` is ever consulted -
        // its refusals cannot protect a file that is already gone.
        //
        //  - `has_member`: a memberless set is the `.rev` shape. Such a
        //    file walks out of the extractor as a one-volume set with no
        //    files, which reports `consumed(0)` immediately, so eating
        //    hard-deleted the recovery data a damaged set is repaired
        //    FROM. The sweep's own doc calls that the worst outcome
        //    available here, and `repair.rs`'s
        //    `obfuscated_sweep_never_touches_a_memberless_rar_file`
        //    pins it as the property that must not bend - it passed only
        //    because eating is disarmed under test.
        //  - `depth >= 1`: depth 0 is the user's own set from the offline
        //    `extract` CLI, whose retention is finalize/policy's call.
        //    Unreachable today (the CLI never calls `eatvol::set_mode`,
        //    so its mode is always Off), but the two paths must not
        //    disagree about which volumes are spendable.
        //
        // An empty mapping is the off switch: `write_archives_to_spending`
        // requires one source per archive before it will eat anything.
        let eat_sources: &[PathBuf] = if has_member && depth >= 1 {
            &sources
        } else {
            &[]
        };
        match write_archives_to_spending(dir, &archives, password, eat_sources) {
            Ok(()) => {
                println!("native unpack complete ✔");
                // Same depth gate the named-set sweep uses, and for the
                // same reason: depth 0 is the user's own downloaded set or
                // an offline `extract` target, whose retention is
                // finalize/policy's call, not ours. Without this an
                // obfuscated set would be deleted where an identical named
                // set is kept, which is a difference the user never asked
                // for and cannot see coming.
                if depth >= 1 {
                    sweep_spent_obfuscated(dir, &sources, has_member, before.as_ref());
                }
            }
            Err(e) => {
                // Every volume of a failed set stays. PAR2 repair, `.rev`
                // reconstruction and a plain retry all read them, and on
                // a finished download they are the only copy.
                println!("⚠ obfuscated RAR unpack failed ({e})");
                all_ok = false;
            }
        }
    }
    all_ok
}

/// Remove the obfuscated volumes one set consumed, once that set has
/// extracted and published successfully.
///
/// `sources` is not a guess from a filename: it is the list of files this
/// pass opened, parsed as RAR headers and handed to the extractor, so each
/// entry is provably an input of the extraction that just succeeded.
/// Three separate refusals, any one of which keeps the ENTIRE set:
///
/// * `has_member` is false - the set declared no file member, so it never
///   produced one. That is the `.rev` shape, and recovery data must
///   survive its own misdetection.
/// * we could not snapshot `dir` beforehand, so nothing here can tell an
///   input from an output. No proof, no delete.
/// * the extraction published no file at all - there is no payload these
///   volumes could be spent ON.
///
/// and per path: never remove something the extraction just published.
/// `lift_scratch_into` refuses to replace an existing name, so a member
/// colliding with a volume lands as `extracted-N-…` and the volume is
/// still the volume - but this asks the before/after diff rather than
/// trusting that invariant to hold forever.
pub(crate) fn sweep_spent_obfuscated(
    dir: &std::path::Path,
    sources: &[PathBuf],
    has_member: bool,
    before: Option<&std::collections::HashSet<PathBuf>>,
) {
    if !has_member {
        return;
    }
    let Some(before) = before else { return };
    let Ok(after) = snapshot_recursive(dir) else {
        return;
    };
    let published: std::collections::HashSet<PathBuf> = after.difference(before).cloned().collect();
    if published.is_empty() {
        return;
    }
    // Trash-aware, unlike the nested-intermediate sweep above: these
    // volumes were DOWNLOADED - they are the obfuscated post itself, the
    // .rar set a user might well want to keep or re-share - and the
    // "spent" verdict is a heuristic chain, which is exactly what the
    // "Deleted files go to the Trash" setting promises to make
    // reversible. Read once for the whole sweep (remove_user_file's
    // contract), and parked for the deferred worker like the finalize
    // sweeps (§64) so a slow Finder never sits inside the job's tail.
    let recoverable = crate::smart::cleanup_recoverable();
    let staging = crate::smart::trash_staging_dir(dir);
    for path in sources {
        if published.contains(path) {
            info!(
                target: "extract",
                "keeping {} - the extraction published it",
                path.display()
            );
            continue;
        }
        // §101: under the volume-eating mode the extraction already
        // deleted this one as it read past it. Nothing left to sweep, and
        // nothing worth warning about - the two paths agree on the end
        // state, they just get there at different moments.
        if !path.exists() {
            continue;
        }
        match crate::smart::remove_swept_file(path, recoverable, staging.as_deref()) {
            Ok(_) => info!(target: "extract", "removed spent volume {}", path.display()),
            // warn!, not println: the daemon's log ring is where a user
            // asking "why is this file still here" will look.
            Err(e) => warn!(
                target: "extract",
                "could not remove spent volume {}: {e}",
                path.display()
            ),
        }
    }
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
pub(crate) fn is_extractable_archive(path: &std::path::Path) -> bool {
    (!nzbkit::extract::is_final_file(path) && (rar_magic(path) || sevenz_magic(path)))
        || nzbkit::zip::is_container(path)
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
            && !nzbkit::extract::is_final_file(&p)
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

/// Publish a PAR2-verified slot file under the name the FileDesc gives
/// it, replacing whatever sits there. No-op when it is already correct.
///
/// A previous run's copy may already sit at the real name (re-download
/// into the same folder). The bytes we just PAR2-verified are
/// authoritative - REPLACE, never strand this download under its
/// obfuscated post name.
///
/// Rename straight over it: `fs::rename` replaces atomically on unix AND
/// windows (MOVEFILE_REPLACE_EXISTING), so there is never a moment with
/// neither file. The old code removed the target first and then ignored
/// the rename's result, so a failed rename left the good previous copy
/// deleted and the verified bytes still under the obfuscated name.
pub(crate) fn publish_verified_name(
    path: &std::path::Path,
    pname: &str,
    out_dir: &std::path::Path,
) -> Option<std::path::PathBuf> {
    let real = nzbkit::disk::sanitize_filename(pname);
    if path.file_name().and_then(|n| n.to_str()) == Some(real.as_str()) {
        return None;
    }
    let target = out_dir.join(&real);
    let existed = target.exists();
    match std::fs::rename(path, &target) {
        Ok(()) => {
            println!(
                "  » renamed {} → {real}{}",
                path.file_name().unwrap_or_default().to_string_lossy(),
                if existed {
                    " (replaced the previous copy)"
                } else {
                    ""
                }
            );
            // The caller must tell any live writer (note_slot_renamed):
            // its handle survives the rename, but a by-path reopen
            // (unpark after the external par2) needs this name.
            Some(target)
        }
        Err(e) => {
            eprintln!(
                "  ✘ could not publish {real}: {e} - the verified file is still at {}",
                path.display()
            );
            None
        }
    }
}

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
    use nzbkit::par2::{Par2Set, verify_file_streaming};

    let cap = par2_scan_cap();
    let (par2_bytes, skipped) = collect_par2_bytes(dir, cap)?;
    if skipped > 0 {
        // Said out loud, because it is why the recovery-block count below
        // may understate what is actually on disk.
        println!(
            "{skipped} PAR2 file(s) not read - scan capped at {} MiB",
            cap >> 20
        );
    }
    if par2_bytes.is_empty() {
        if skipped > 0 {
            println!(
                "PAR2 files in {} are all over the scan cap - verification skipped",
                dir.display()
            );
        } else {
            println!("no PAR2 files in {} - verification skipped", dir.display());
        }
        return Ok(false);
    }
    let refs: Vec<&[u8]> = par2_bytes.iter().map(|v| v.as_slice()).collect();
    let set = match Par2Set::parse(&refs) {
        Ok(s) => s,
        Err(e) => {
            println!("PAR2 parse failed ({e}) - verification skipped");
            return Ok(false);
        }
    };
    println!(
        "PAR2 set: {} file(s), block size {}, {} recovery block(s) on hand",
        set.files.len(),
        set.block_size,
        set.recovery_blocks_seen
    );

    let mut all_ok = true;
    for f in &set.files {
        let path = dir.join(nzbkit::disk::sanitize_filename(&f.name));
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
                    println!("  ✔ {} - {} blocks, MD5 ok", f.name, v.blocks.len());
                } else {
                    all_ok = false;
                    println!(
                        "  ✘ {} - {bad}/{} blocks bad, md5 {}",
                        f.name,
                        v.blocks.len(),
                        if v.md5_ok { "ok" } else { "MISMATCH" }
                    );
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                all_ok = false;
                println!("  ✘ {} - file missing", f.name);
            }
            // Reached only now that the bytes are read here rather than
            // up front: a mid-file read error is not a missing file and
            // must not be reported as one.
            Err(e) => {
                all_ok = false;
                println!("  ✘ {} - unreadable ({e})", f.name);
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

pub(crate) struct FileSlot {
    pub(crate) hint: String,
    pub(crate) is_par2_main: bool,
    /// Issue #14: this slot was posted as payload (hash subject, hash yEnc
    /// name) but its offset-0 article decoded to the `PAR2\0PKT` magic -
    /// it IS recovery data, identified in-stream after the slot was built.
    /// Set once by whichever decode consumer sees the head article; never
    /// cleared.
    pub(crate) par2_sniffed: std::sync::atomic::AtomicBool,
    pub(crate) total_segments: usize,
    pub(crate) remaining: std::sync::atomic::AtomicUsize,
    pub(crate) missing: std::sync::atomic::AtomicUsize,
    /// Decode or write failures charged to THIS slot. The global
    /// `decode_errors` counter says a job hit one; only a per-slot count can
    /// say whether the file a PAR2 repair just healed is the one that hit it.
    pub(crate) errors: std::sync::atomic::AtomicUsize,
    /// Segments never fetched because the slot was identified as a PAR2
    /// volume in-stream and deferred (removed from the pool queue). Kept
    /// apart from `missing`: a deferred article is a choice, not damage.
    pub(crate) deferred: std::sync::atomic::AtomicUsize,
    /// PAR2-race experiment: segments deliberately abandoned mid-run
    /// because recovery blocks on hand already covered them with margin
    /// and repair beats the fetch remainder. A third category next to
    /// `missing` (damage we suffered) and `deferred` (a choice that is
    /// not damage): this is a choice that IS damage - the settle
    /// read-back counts the absent blocks as bad and repair heals them,
    /// so it must exempt the sparse-slot census like a deferral while
    /// still reading as damage evidence for the repair branches.
    pub(crate) abandoned: std::sync::atomic::AtomicUsize,
    /// The user asked for sample files to be skipped and this slot's
    /// posted name plus declared size said it is one
    /// (`smart::skippable_samples`), so NONE of its articles were
    /// queued. Decided once at plan time and never revised: the
    /// segments are booked into `deferred` - a choice, not damage -
    /// exactly as a resume-recognised recovery volume's are, which is
    /// what keeps the census and the uncovered-hole scan from failing
    /// the job over a file nobody wanted. The flag itself is read by
    /// the settle pass, which has to strike the file off the PAR2 set's
    /// missing list as well, or repair would fetch recovery volumes to
    /// rebuild the very bytes the setting declined.
    pub(crate) sample_skipped: bool,
    /// Par2-main slots capture decoded bytes in memory so the recovery set
    /// activates mid-download without re-reading from disk. `Some` from
    /// build time for slots the NZB names as par2; installed at sniff time
    /// for the in-stream bootstrap volume of an obfuscated post.
    pub(crate) capture: std::sync::Mutex<Option<Vec<u8>>>,
}

impl FileSlot {
    /// Recovery data by ANY route - NZB classification or the in-stream
    /// magic sniff. The settle/repair accounting that excludes par2 slots
    /// keys off this, not `is_par2_main` alone.
    pub(crate) fn is_par2(&self) -> bool {
        self.is_par2_main || self.par2_sniffed.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Cap on an in-memory par2 capture mirror. `begin` offsets are
/// poster-controlled and the mirror zero-fills REAL memory (unlike the
/// extractor's sparse disk writes), so an absurd declared offset must
/// drop the article rather than allocate a petabyte. A real main .par2
/// (or bootstrap volume) sits far below this.
pub(crate) const MAX_PAR2_CAPTURE: usize = 256 << 20;

/// Issue #14 (in-stream PAR2 identification): runtime state for slots
/// reclassified as recovery data by the offset-0 magic sniff. Built once
/// per download and shared by every decode consumer.
pub(crate) struct SniffCtl {
    pub(crate) nzb: Arc<Nzb>,
    /// Slot index → NZB file index (slots skip NZB-classified volumes,
    /// so the two numberings diverge).
    pub(crate) slot_file: Vec<usize>,
    /// May this run designate an in-stream bootstrap volume? False when
    /// the NZB already names a par2 main (or bootstrap volume) - the
    /// activation counter belongs to those slots, and sniffed volumes
    /// simply defer.
    pub(crate) allow_bootstrap: bool,
    pub(crate) state: std::sync::Mutex<SniffState>,
    pub(crate) deferred_articles: std::sync::atomic::AtomicUsize,
    pub(crate) deferred_bytes: std::sync::atomic::AtomicU64,
    /// The run's fetch-progress counter, so a deferral can settle the
    /// bytes it just cancelled (Codex sweep 2, 3 Aug ML2).
    ///
    /// Every payload-classified article contributes to `fetch_plan` when
    /// the plan is published, and a terminal outcome credits it back -
    /// including the ones that will never arrive, because "terminal is
    /// terminal" and holding the bar short of 100% through the whole
    /// repair is worse than counting a 430 as done. A live deferral is
    /// terminal in exactly that sense (the articles are cancelled and
    /// leave the pool without an outcome), and it was the one such exit
    /// that credited nothing - so the bar and the SAB-compatible
    /// `Remaining` sat short by the deferred bytes for the whole
    /// verify/repair tail. Resume-recognised deferrals have always been
    /// seeded into this counter; this is the live path catching up.
    pub(crate) fetch_done: Arc<std::sync::atomic::AtomicU64>,
}

#[derive(Default)]
pub(crate) struct SniffState {
    /// The sniffed slot elected to download in full and activate the set
    /// (the runtime analogue of `bootstrap_vol`). Switches to a smaller
    /// volume while unlocked - hash-named posts arrive in arbitrary size
    /// order, and the biggest volume can be half the recovery set.
    pub(crate) bootstrap: Option<usize>,
    /// Set (under this mutex) when the bootstrap slot completes: from
    /// then on the election is final, because activation is in flight.
    pub(crate) locked: bool,
    /// Every sniffed slot, bootstrap included, in sniff order.
    pub(crate) sniffed: Vec<usize>,
    /// Per sniffed slot: (md5 of the first min(16k, len) bytes, yEnc
    /// declared length). The reconcile pass matches these against the
    /// activated set's FileDesc table - a hit means the "volume" is
    /// really SET-COVERED PAYLOAD (a posted par2 file the set includes)
    /// and must be un-deferred, not recreated from recovery blocks.
    pub(crate) head16: std::collections::HashMap<usize, ([u8; 16], u64)>,
    /// Per deferred slot: the exact ids `cancel` removed (the only ids
    /// `requeue` may resurrect) and their encoded byte sum.
    pub(crate) cancelled_ids: std::collections::HashMap<usize, (Vec<std::sync::Arc<str>>, u64)>,
    /// Slots reconciled back to payload. A later duplicate offset-0
    /// article of such a slot still carries the magic - it must never
    /// re-defer what activation proved is payload.
    pub(crate) reconciled: std::collections::HashSet<usize>,
}

impl SniffCtl {
    pub(crate) fn any_sniffed(&self) -> bool {
        !self.state.lock_ok().sniffed.is_empty()
    }

    pub(crate) fn bootstrap_slot(&self) -> Option<usize> {
        self.state.lock_ok().bootstrap
    }

    /// Every sniffed slot EXCEPT the bootstrap - the deferred volumes.
    pub(crate) fn deferred_slots(&self) -> Vec<usize> {
        let st = self.state.lock_ok();
        st.sniffed
            .iter()
            .filter(|&&s| st.bootstrap != Some(s))
            .copied()
            .collect()
    }

    /// NZB file indexes of every sniffed slot EXCEPT the bootstrap - the
    /// deferred volumes a repair may fetch (exact-fit) later.
    pub(crate) fn deferred_files(&self) -> Vec<usize> {
        self.deferred_slots()
            .into_iter()
            .map(|s| self.slot_file[s])
            .collect()
    }

    /// Deferred slots whose head fingerprint (md5-16k + length) matches a
    /// file the active set COVERS: payload the sniff wrongly deferred.
    /// Read-only - the caller marks each slot reconciled only once it has
    /// actually secured the bytes.
    pub(crate) fn matched_deferred(&self, set: &nzbkit::par2::Par2Set) -> Vec<(usize, u64)> {
        let st = self.state.lock_ok();
        st.sniffed
            .iter()
            .filter(|&&s| st.bootstrap != Some(s))
            .filter_map(|&s| {
                let &(h, len) = st.head16.get(&s)?;
                set.files
                    .iter()
                    .any(|f| f.length == len && f.md5_16k == h)
                    .then_some((s, len))
            })
            .collect()
    }

    /// A matched slot's bytes are secured (requeued live, or side-fetched
    /// after the drain): retire its recovery-data standing for good.
    pub(crate) fn mark_reconciled(&self, sidx: usize) {
        let mut st = self.state.lock_ok();
        st.sniffed.retain(|&s| s != sidx);
        st.reconciled.insert(sidx);
        st.cancelled_ids.remove(&sidx);
        st.head16.remove(&sidx);
    }

    /// Completion hook for a sniffed slot: locks the election if this is
    /// the bootstrap and says whether the caller should run activation.
    pub(crate) fn note_completed(&self, sidx: usize) -> bool {
        let mut st = self.state.lock_ok();
        if st.bootstrap == Some(sidx) {
            st.locked = true;
            true
        } else {
            false
        }
    }
}

/// Article id → (owning slot index, the article's declared byte size from
/// the NZB). The size rides along beside the slot because the queue's
/// fetch-progress counters have to be paid in exactly the unit their
/// denominator is quoted in - declared NZB bytes - and this map is
/// already consulted once per terminal article. A parallel id→bytes map
/// would have duplicated every message-id string (~15 MB on a 128k
/// article job). Full u64 for the size on purpose: `fetch_plan` sums
/// the same declarations in u64, and a skewed NZB declaring a segment
/// past 4 GiB used to truncate here - crediting 1 byte against a 4 GB
/// denominator, wedging the bar short of 100% for the whole job.
pub(crate) type IdSlots = std::collections::HashMap<std::sync::Arc<str>, (u32, u64)>;

/// R9: the interned handle `id_to_slot` already holds for a segment's
/// bracketed id.
///
/// The fetch plan brackets and interns every segment id once
/// (get/plan.rs); a later pass over the same NZB - the in-stream PAR2
/// sniff, the par-race candidate walk - used to `format!` a second full
/// copy of every id it touched just to name articles the pool is
/// already holding. Looking the id up instead hands back the plan's
/// allocation for the price of a hash.
///
/// `buf` is caller-owned scratch reused across the walk, so the lookup
/// itself allocates nothing after the first segment. An id the plan
/// never recorded (a parser-dropped segment) interns fresh, so the
/// caller's set has exactly the members it had before.
pub(crate) fn interned_bracketed(
    buf: &mut String,
    id_to_slot: &IdSlots,
    message_id: &str,
) -> std::sync::Arc<str> {
    use std::fmt::Write;
    buf.clear();
    let _ = write!(buf, "<{message_id}>");
    match id_to_slot.get_key_value(buf.as_str()) {
        Some((interned, _)) => interned.clone(),
        None => std::sync::Arc::from(buf.as_str()),
    }
}

/// The offset-0 article of a payload-classified slot decoded to the
/// `PAR2\0PKT` magic: reclassify it. Elects (or switches) the bootstrap
/// volume, defers everything else by cancelling its still-queued articles,
/// and keeps the slot counters consistent with what will now never arrive.
/// `head` is the decoded offset-0 span, mirrored into the bootstrap's
/// capture so activation can parse it later.
#[allow(clippy::too_many_arguments)]
pub(crate) fn reclassify_sniffed_par2(
    ctl: &SniffCtl,
    slots: &[Arc<FileSlot>],
    sidx: usize,
    head: &[u8],
    file_size: u64,
    queue: &nzbkit::pool::QueueControl,
    id_to_slot: &IdSlots,
    par2_outstanding: &std::sync::atomic::AtomicUsize,
) {
    use std::sync::atomic::Ordering;
    let fbytes = |s: usize| ctl.nzb.files[ctl.slot_file[s]].bytes();
    // Election under the state lock; the queue cancel runs after it drops.
    let (is_bootstrap, demoted) = {
        let mut st = ctl.state.lock_ok();
        // Idempotence: two articles of the same slot can both claim yEnc
        // begin=1 (poster-controlled) and race here on two decode
        // threads; and a slot the reconcile pass proved to be payload
        // must never be re-deferred by a later magic-carrying article.
        if st.sniffed.contains(&sidx) || st.reconciled.contains(&sidx) {
            return;
        }
        slots[sidx].par2_sniffed.store(true, Ordering::Release);
        st.sniffed.push(sidx);
        // Remember the head fingerprint: if the set, once activated,
        // includes this file by md5-16k + length, the sniff was wrong
        // about its ROLE (payload, not recovery) and reconcile un-defers
        // it. None when the head span doesn't cover the 16k prefix.
        if let Some(h) = nzbkit::par2::md5_16k_of_head(head, file_size) {
            st.head16.insert(sidx, (h, file_size));
        }
        let mut demoted = None;
        if ctl.allow_bootstrap {
            match st.bootstrap {
                None => {
                    st.bootstrap = Some(sidx);
                    // First election: the activation counter now owes one
                    // completion (mirrors a static par2-main slot).
                    par2_outstanding.fetch_add(1, Ordering::AcqRel);
                }
                Some(b)
                    if !st.locked
                        && slots[b].remaining.load(Ordering::Acquire) > 0
                        && fbytes(sidx) < fbytes(b) =>
                {
                    // A smaller volume showed up while the current one is
                    // still incomplete: switch. The completion obligation
                    // moves with the election (net zero on the counter),
                    // and the old partial capture is dropped so
                    // recovery_blocks_seen counts exactly the volume the
                    // repair planner is told is already on hand.
                    st.bootstrap = Some(sidx);
                    *slots[b].capture.lock_ok() = None;
                    demoted = Some(b);
                }
                Some(_) => {}
            }
        }
        // The capture install stays INSIDE the state lock (order: state →
        // capture, same as the demote arm above). Installing after the
        // lock dropped opened a race: a concurrent sniff could demote
        // this slot and null its capture, and the stale install would
        // resurrect it - a deferred volume whose partial packets then
        // leak into activation and inflate recovery_blocks_seen.
        if st.bootstrap == Some(sidx) {
            let mut cap = slots[sidx].capture.lock_ok();
            let buf = cap.get_or_insert_with(Vec::new);
            if head.len() <= MAX_PAR2_CAPTURE {
                if buf.len() < head.len() {
                    buf.resize(head.len(), 0);
                }
                buf[..head.len()].copy_from_slice(head);
            }
        }
        (st.bootstrap == Some(sidx), demoted)
    };
    if is_bootstrap {
        println!(
            "  ▸ recovery volume identified in-stream ({}) - bootstrapping the PAR2 set from it",
            slots[sidx].hint
        );
        // The static path schedules par2-main articles FIRST so the set
        // activates within the first round-trips; a sniffed bootstrap's
        // body articles were queued as ordinary data at its file position
        // - possibly behind the whole payload, which would delay
        // activation (and with it in-stream verification and the live
        // reconcile) to the download's tail. Promote them the way the
        // extractor's offset-0 probe promotes: to the front, without
        // engaging stream mode.
        let mut buf = String::new();
        let promote: Vec<std::sync::Arc<str>> = ctl.nzb.files[ctl.slot_file[sidx]]
            .segments
            .iter()
            .map(|seg| interned_bracketed(&mut buf, id_to_slot, &seg.message_id))
            .filter(|b| id_to_slot.get(&**b).map(|&(s, _)| s as usize) == Some(sidx))
            .collect();
        queue.promote_opts(&promote, false);
    }
    for d in demoted.into_iter().chain((!is_bootstrap).then_some(sidx)) {
        let mb = defer_sniffed_slot(ctl, slots, d, queue, id_to_slot);
        println!(
            "  ▸ recovery volume identified in-stream ({}) - deferring {:.1} MB",
            slots[d].hint, mb
        );
    }
}

/// Cancel a sniffed slot's still-queued articles and account for them as
/// deferred. Articles already in flight resolve normally (their bytes are
/// written and harmless); ids owned by ANOTHER slot (duplicate-id NZBs)
/// are never touched. Returns the MB actually removed from the queue.
fn defer_sniffed_slot(
    ctl: &SniffCtl,
    slots: &[Arc<FileSlot>],
    sidx: usize,
    queue: &nzbkit::pool::QueueControl,
    id_to_slot: &IdSlots,
) -> f64 {
    use std::sync::atomic::Ordering;
    let f = &ctl.nzb.files[ctl.slot_file[sidx]];
    let mut want: std::collections::HashSet<std::sync::Arc<str>> = Default::default();
    let mut bytes_of: std::collections::HashMap<std::sync::Arc<str>, u64> = Default::default();
    let mut buf = String::new();
    for seg in &f.segments {
        let b = interned_bracketed(&mut buf, id_to_slot, &seg.message_id);
        if id_to_slot.get(&*b).map(|&(s, _)| s as usize) == Some(sidx) {
            bytes_of.insert(b.clone(), seg.bytes);
            want.insert(b);
        }
    }
    // `cancel` is best-effort under queue contention (bounded try_lock):
    // an empty answer can mean "nothing queued" OR "lock missed". A few
    // retries make a missed lock recoverable; a genuinely-empty queue
    // just answers empty again, cheaply, on a decode thread.
    let mut removed = Vec::new();
    for attempt in 0..3 {
        removed = queue.cancel(&want);
        if !removed.is_empty() {
            break;
        }
        if attempt < 2 {
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }
    if removed.is_empty() {
        return 0.0;
    }
    // Saturating fold, not .sum(): these are attacker-typed NZB byte
    // declarations, and a plain sum panics in debug / wraps in release.
    let bytes: u64 = removed
        .iter()
        .filter_map(|id| bytes_of.get(&**id))
        .fold(0u64, |a, b| a.saturating_add(*b));
    slots[sidx]
        .remaining
        .fetch_sub(removed.len(), Ordering::AcqRel);
    slots[sidx]
        .deferred
        .fetch_add(removed.len(), Ordering::Relaxed);
    ctl.deferred_articles
        .fetch_add(removed.len(), Ordering::Relaxed);
    ctl.deferred_bytes.fetch_add(bytes, Ordering::Relaxed);
    // These bytes will never produce a terminal outcome - the articles
    // left the pool queue - so settle them here or the bar stops short
    // by exactly this much for the rest of the run. Undone by
    // `reconcile_deferred_payload` if they are ever requeued, since
    // then the ordinary outcomes credit them again.
    ctl.fetch_done.fetch_add(bytes, Ordering::Relaxed);
    // The exact removed ids, kept for a possible un-defer: only these may
    // ever be requeued (the pool stashes their Work items whole).
    ctl.state
        .lock_ok()
        .cancelled_ids
        .entry(sidx)
        .and_modify(|(v, b)| {
            v.extend(removed.iter().cloned());
            *b = b.saturating_add(bytes);
        })
        .or_insert_with(|| (removed.clone(), bytes));
    bytes as f64 / 1e6
}

/// Issue #14 reconcile: the sniff classifies by CONTENT (`PAR2\0PKT`),
/// which cannot tell a recovery volume from set-covered payload that
/// happens to BE a par2 file (a posted recovery set as content). Once the
/// set is live its FileDesc table can: any deferred slot whose head
/// fingerprint (md5-16k + length) matches a set file was payload all
/// along - un-defer it (requeue the cancelled articles), hand its head
/// back to the verifier so the slot is claimed and verified in-stream,
/// and drop its recovery-data standing. Failing to do this made the
/// repair recreate (or fail to recreate) a file whose every article was
/// sitting on the server, fetchable.
pub(crate) fn reconcile_deferred_payload(
    ctl: &SniffCtl,
    slots: &[Arc<FileSlot>],
    set: &nzbkit::par2::Par2Set,
    queue: &nzbkit::pool::QueueControl,
    extractor: &nzbkit::extract::Extractor,
    verifier: &nzbkit::live::LiveVerifier,
) {
    use std::sync::atomic::Ordering;
    for (sidx, file_size) in ctl.matched_deferred(set) {
        let (ids, bytes) = ctl
            .state
            .lock_ok()
            .cancelled_ids
            .get(&sidx)
            .cloned()
            .unwrap_or_default();
        // All-or-nothing: a partial resurrection would leave a payload
        // slot short articles nothing will ever fetch. `requeue` itself
        // is all-or-nothing over the stash; ids it no longer holds
        // (never cancelled - e.g. the slot deferred nothing) count as
        // zero and the slot simply stays deferred. A refusal (short
        // post: the pool already wound down) is fine too - the drain
        // fallback in get.rs side-fetches whatever stayed deferred.
        let n = queue.requeue(&ids);
        if n == 0 || n != ids.len() {
            continue;
        }
        ctl.mark_reconciled(sidx);
        slots[sidx].remaining.fetch_add(n, Ordering::AcqRel);
        slots[sidx].deferred.fetch_sub(n, Ordering::Relaxed);
        ctl.deferred_articles.fetch_sub(n, Ordering::Relaxed);
        ctl.deferred_bytes.fetch_sub(bytes, Ordering::Relaxed);
        // Give the deferral's progress credit back: these articles are
        // in the pool again and will credit themselves when they land.
        // Keeping it would take the bar past 100%. The drain fallback in
        // get.rs is the opposite case - it side-fetches OUTSIDE the
        // pool, so no outcome follows and the credit must stand.
        ctl.fetch_done.fetch_sub(bytes, Ordering::Relaxed);
        // Payload again: articles arriving from the requeue take the
        // normal verifier path from here on.
        slots[sidx].par2_sniffed.store(false, Ordering::Release);
        // The head article never refetches (it completed before the
        // cancel), so the verifier would never see offset 0 and could
        // not claim the slot by md5-16k. Feed the on-disk head back:
        // write_verified put it there before the sniff fired. Disk
        // provenance (full-MD5 claims) - nothing in flight vouches for
        // the re-read.
        let want = file_size.min(16384) as usize;
        if want > 0
            && let Some(p) = extractor.slot_path(sidx)
        {
            let mut buf = vec![0u8; want];
            let ok = std::fs::File::open(&p)
                .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut buf))
                .is_ok();
            if ok {
                verifier.on_data_from_disk(sidx, "", file_size, 0, &buf);
            }
        }
        println!(
            "  ▸ {} is payload the recovery set covers - resuming its download \
             ({:.1} MB back on the queue)",
            slots[sidx].hint,
            bytes as f64 / 1e6
        );
    }
}

/// When the last outstanding par2-main slot completes, parse the captured
/// packets and switch the verifier to in-stream mode.
/// M15b: hash spans that were decoded before PAR2 activation by reading
/// them back from disk WHILE the download continues - the work that used
/// to be the settle pass's re-read (42 GB on the 87 GB run) overlaps the
/// network phase instead. Coverage-gated: a span not fully on disk yet
/// (or in a still-unclassified slot) is skipped and settles as before.
pub(crate) fn backfill_pre_activation(
    verifier: &nzbkit::live::LiveVerifier,
    extractor: &nzbkit::extract::Extractor,
    n_slots: usize,
    par2_slots: &[bool],
) -> u64 {
    let mut fed: u64 = 0;
    let mut buf = vec![0u8; 4 << 20];
    for sidx in 0..n_slots {
        if par2_slots[sidx] {
            continue;
        }
        // Spans this run decoded keep a fresh span's claim strength, so
        // their boundary blocks compose as CRC parts instead of demanding
        // a block-sized byte buffer each. take_pre_spans decides which
        // spans qualify and hands back the source to feed them under;
        // crash-resume seeds, and pcrc-absent articles outside lean mode,
        // take the full-MD5 disk path.
        let (spans, how) = verifier.take_pre_spans(sidx);
        for (off, len) in spans {
            let mut o = off;
            let end = off + len;
            while o < end {
                let n = ((end - o) as usize).min(buf.len());
                if !extractor.covered(sidx, o, n) {
                    break; // not (yet) on disk - leave for settle
                }
                if extractor.read_at(sidx, o, &mut buf[..n]).is_err() {
                    break;
                }
                match how {
                    nzbkit::live::PreSpanSrc::Backfill => {
                        verifier.on_data_backfill(sidx, "", 0, o, &buf[..n])
                    }
                    nzbkit::live::PreSpanSrc::Disk => {
                        verifier.on_data_from_disk(sidx, "", 0, o, &buf[..n])
                    }
                }
                fed += n as u64;
                o += n as u64;
            }
        }
    }
    fed
}

pub(crate) fn maybe_activate_par2(
    slots: &[Arc<FileSlot>],
    verifier: &nzbkit::live::LiveVerifier,
    outstanding: &std::sync::atomic::AtomicUsize,
    sniff: &SniffCtl,
    queue: &nzbkit::pool::QueueControl,
    extractor: &nzbkit::extract::Extractor,
) -> bool {
    use std::sync::atomic::Ordering;
    if outstanding.fetch_sub(1, Ordering::AcqRel) != 1 {
        return false;
    }
    let set = {
        let guards: Vec<std::sync::MutexGuard<Option<Vec<u8>>>> =
            slots.iter().map(|s| s.capture.lock_ok()).collect();
        let refs: Vec<&[u8]> = guards
            .iter()
            .filter_map(|g| g.as_ref().map(|v| v.as_slice()))
            .collect();
        verifier.activate(&refs)
    };
    match set {
        Ok(set) => {
            println!(
                "  ▶ PAR2 set live: {} file(s), block size {} - verifying in-stream",
                set.files.len(),
                set.block_size
            );
            // The FileDesc table can now correct the sniff: a deferred
            // slot the set COVERS is payload, not recovery - un-defer it
            // while the run is still live. After the capture guards drop
            // (this reads disk and takes pool locks).
            reconcile_deferred_payload(sniff, slots, &set, queue, extractor, verifier);
            true
        }
        Err(e) => {
            println!("  ⚠ PAR2 activation failed ({e}) - falling back to post-download verify");
            verifier.set_off();
            false
        }
    }
}

/// Age in whole days of an NZB `<file date="…">` unix timestamp. Absent,
/// zero, or future dates count as fresh (0) - retention exclusion must
/// never fire on posts we can't date.
pub(crate) fn nzb_age_days(date: i64) -> u32 {
    if date <= 0 {
        return 0;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    ((now - date).max(0) / 86_400) as u32
}

#[cfg(test)]
#[path = "unpack/pwfile_tests.rs"]
mod pwfile_tests;

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
