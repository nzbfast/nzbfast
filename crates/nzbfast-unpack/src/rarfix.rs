//! Disk-side archive extraction and RAR repair: the native unrar path, .rev reconstruction, RAR5 recovery-record repair, and the 7z/zip disk extraction twins.
//!
//! Split out of main.rs verbatim; behaviour unchanged.

use crate::*;
use tracing::{info, warn};

/// Whether the external `unrar` subprocess may be spawned at all.
///
/// Closed for the whole unit-test build, deliberately. `unrar` resolves
/// as a sibling of the running executable or off `$PATH` (tools.rs), so
/// whether a unit test reaches this subprocess is a property of the
/// MACHINE, not of the test - and no unit test can state which it wants,
/// because it cannot install one and cannot skip on finding one. CI does
/// not install `unrar` and the dev boxes have none, so the ladder in
/// [`try_unrar_spent`] falls straight through the fallback to whatever
/// rung sits below it, and TODO 211's split-container tests read that
/// fall-through as the thing they are asserting. On a box that does have
/// one, those same tests hand it the truncated part 1 of a byte split (a
/// RAR head over a fraction of an archive) and then judge the rescue by
/// whatever the failed subprocess left behind.
///
/// Closing it here STATES that assumption instead of inheriting it. It
/// cannot move a result that is green in CI, because CI has no `unrar`
/// to reach in the first place: it makes every other box agree with CI
/// rather than changing what any test asserts. Nothing here is
/// production behaviour - `cfg(test)` is the bin target's unit tests and
/// nothing else.
///
/// It is not routed through `NZBFAST_TEST_FORBID_UNRAR` because a unit
/// test cannot use that variable safely: env vars are process-global,
/// `cargo test -p nzbfast --bin nzbfast` runs every unit test as a
/// thread of ONE process, and edition 2024 makes `set_var` unsafe for
/// exactly that reason. The variable stays what it has always been - the
/// canary the integration suites set per SPAWNED child, where a process
/// really is one test. The two sit at the SAME rung of
/// [`try_unrar_spent`] and mean the same thing - the subprocess, and only
/// the subprocess, is unavailable; only who sets them differs.
///
/// The subprocess itself belongs to those suites for the same reason,
/// and they already say so out loud: the `prefer_external_unrar` route
/// test skips itself with "unrar not installed" when `have("unrar")` is
/// false (tests/daemon_unpackroute). A unit test has no such move.
#[cfg(test)]
fn external_unrar_closed() -> bool {
    true
}

#[cfg(not(test))]
fn external_unrar_closed() -> bool {
    false
}

/// `cfg(test)` for the same reason [`crate::repair::reextract_dir`] is:
/// every production caller now takes a `_why` form and keeps the
/// ladder's reason, and what is left on the boolean is the tests.
#[cfg(test)]
pub(crate) fn try_unrar(dir: &std::path::Path, password: Option<&str>) -> bool {
    try_unrar_spent(dir, password).is_some()
}

/// [`try_unrar`] that also names the volume files a SUCCESSFUL unpack
/// consumed, so the finalize flows can delete exactly those (Part B,
/// research/SPEC-onepass-obfuscated-store-sets-2026-07-29.md: a demoted
/// set left its full volume set beside the extracted payload - observed
/// live at 144 volumes / ~57 GB - and only this function knows which
/// on-disk set the unpack actually read).
///
/// `None` is failure - every volume stays, it is the only recovery.
/// `Some(vec![])` is success with nothing for the caller to remove:
/// either the obfuscated path already swept its own spent volumes (with
/// its refusals - a memberless `.rev` shape survives), or the before/after
/// diff could not prove the unpack published anything new, and no proof
/// means no delete. A file the unpack itself just published is never
/// reported as spent.
///
/// `cfg(test)` on the same terms as [`try_unrar`] above.
#[cfg(test)]
pub(crate) fn try_unrar_spent(
    dir: &std::path::Path,
    password: Option<&str>,
) -> Option<Vec<PathBuf>> {
    try_unrar_spent_why(dir, password).ok()
}

/// The disk unpack ladder's answer in full: what a success spent, or -
/// on a refusal - why, when the refusal has a reason the JOB should
/// fail with rather than the caller's own generic wording.
///
/// `Err(None)` is the ordinary failure and means exactly what
/// [`try_unrar_spent`]'s `None` always meant: nothing here unpacked,
/// every volume stays. Callers that compose a user-facing failure word
/// that one themselves, because the ladder has nothing to add - the set
/// is compressed, or damaged, or the password is wrong, and which of
/// those it was is not knowable from here.
///
/// `Err(Some(why))` is the case this variant exists for: a refusal that
/// is about the DISK and not the archive. Two rungs raise one - the
/// native pass's bomb verdict and the [`preflight`] ahead of the unrar
/// spawn - and both used to arrive at the caller as a bare `None`,
/// which the tail then reported as "the verified volumes could not be
/// unpacked (compressed set, or the password is wrong)". That is the
/// exact wrong blame the 22 Aug 2026 incident was reported as, one
/// layer down from where [`bomb_fallback`] had already fixed it: the
/// console line was right and the job-level message the user and any
/// *arr sees was not.
///
/// A REASON rather than a flag, and returned rather than kept in a
/// thread-local ledger in the style of [`crate::resumeout`] /
/// [`crate::eatvol`]: those two are ledgers because their state has to
/// outlive a call and be consulted from inside a callback several
/// frames down. This is one value, produced at the moment of the
/// refusal and read by the immediate caller, so a return value keeps
/// the whole story on one screen and cannot go stale - and staleness is
/// a real hazard here, because `try_unrar` and the split rescue re-enter
/// this ladder without ever reading a reason.
pub(crate) fn try_unrar_spent_why(
    dir: &std::path::Path,
    password: Option<&str>,
) -> std::result::Result<Vec<PathBuf>, Option<String>> {
    try_unrar_outcome(dir, password).map(|o| o.spent)
}

/// [`try_unrar_spent_why`] that also carries OUT the groups a successful
/// run left packed, each with its volume names (TODO 164). The ladder
/// tolerates a failed group beside one that produced - that is the decoy
/// rule, see [`vouch`] - and only the level above, where the job's PAR2
/// set is in scope, can tell a decoy from the vouched release. It needs
/// the names to do it, and a display stem is not a name.
/// Instrument-first: one `[mem-floor]` line at the instant the DISK
/// unpack opens, naming what the chase that just gave up is still
/// holding.
///
/// Audit round 14 residue 2 asked whether the materialised copy and the
/// disk pass's working set are alive at the same time as the holds that
/// fed them - worth ~700 MB on a 2 GB budget if they are. The job
/// summary could not answer it: it prints once, at the end, and the
/// sampled high-water lands wherever a 2 Hz tick happened to fall. This
/// prints at the transition itself, so the overlap is a reading rather
/// than an inference.
///
/// Round 35's measurement with it (`bigv4`, `--mem-limit 2G`): the
/// holds BYTES are back to ~0 by this point - the forfeit releases them
/// - but the buffers' reserved slack is not, which is what
/// `holds_reserve` says here and what makes the peak land after the
/// forfeit rather than during the chase.
///
/// Nothing reads this to make a decision; it is a log line.
fn note_disk_pass_opening() {
    use nzbkit::memgauge::Sub;
    let g = nzbkit::memgauge::snapshot();
    let mb = |v: u64| v as f64 / 1e6;
    let footprint = nzbkit::mem::dashboard_rss().unwrap_or(0);
    tracing::info!(
        target: "mem-floor",
        "disk unpack opening · footprint {:.0} MB · holds {:.0} MB (+{:.0} MB reserved slack) · rars decode {:.0} MB · raw bodies {:.0} MB",
        mb(footprint),
        mb(g.cur_of(Sub::Holds)),
        mb(g.cur_of(Sub::HoldsReserve)),
        mb(g.cur_of(Sub::RarsWork)),
        mb(g.cur_of(Sub::RawFree) + g.cur_of(Sub::RawOut)),
    );
}

pub fn try_unrar_outcome(
    dir: &std::path::Path,
    password: Option<&str>,
) -> std::result::Result<UnpackOutcome, Option<String>> {
    note_disk_pass_opening();
    // Sibling binary, else PATH (see tools.rs). There is no third rung:
    // `tools.rs` opens with "nzbfast ships as ONE executable with NO
    // embedded tools" and implements exactly those two steps. This
    // comment promised "the copy embedded in this executable" until
    // 2 Sep 2026 - appendix A item 3 of
    // research/SANDBOX-SCOPING-2026-08.md, which found it by reading
    // both. Nothing in CI can catch this class: ref-gate checks that a
    // referenced symbol or path EXISTS, not that a claim about
    // behaviour is true. The sibling comment in repair/extpar2.rs was
    // always right, which is the version copied here.
    let unrar = tools::resolve("unrar");
    let mut first: Option<PathBuf> = None;
    if let Ok(entries) = std::fs::read_dir(dir) {
        let paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
        let rars: Vec<PathBuf> = paths
            .iter()
            .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("rar")))
            // A `.rar` whose NAME carries no set (hash stem, no .part
            // ordinal, no .rNN sibling) cannot lead the named path:
            // each hash name is its own release_stem, so the group walk
            // below would feed the extractor one volume of a split set
            // per group and fail all of them (issue #47's shape, which
            // extract_one_level's routing already refuses - this is the
            // same rule for the demote/resume callers that land here
            // directly). Dropping them from the lead pick makes `first`
            // None for an all-hash directory, which is precisely the
            // obfuscated hand-off below.
            .filter(|p| !(unpack::rar_name_carries_no_set(p) && rar_magic(p)))
            .cloned()
            .collect();
        first = first_rar_volume(&rars);
        if first.is_none() {
            // Numeric-only RAR sets (Name.001, .002 …) have no `.rar` to
            // start from, so this fallback used to silently no-op. The
            // lowest-numbered volume carrying the Rar! magic is the first
            // volume - unrar handles the .001 naming itself from there.
            first = paths
                .iter()
                .filter_map(|p| {
                    let ext = p.extension()?.to_string_lossy();
                    let n: u64 = ext.parse().ok()?;
                    (ext.len() >= 2).then_some((n, p))
                })
                .filter(|(_, p)| rar_magic(p))
                .min_by_key(|(n, _)| *n)
                .map(|(_, p)| p.clone());
        }
    }
    let Some(first) = first else {
        // Obfuscated posts strip extensions and rename volumes to hex, so
        // NEITHER lookup above can see one: `extension()` is None, which
        // empties the `.rar` filter and makes the numeric-extension
        // fallback's `filter_map` drop every candidate. This used to answer
        // false, and the ladder above turns that into a FAILED job - for a
        // set the obfuscated disk path unpacks perfectly.
        //
        // Sniffing happens only here, once both name-based lookups have
        // come up empty, so a set that carries names never reaches it and
        // its behaviour is untouched.
        //
        // The set cannot be pushed down the named path even with a first
        // volume in hand, which is why this hands off rather than falling
        // through: `try_rars_native` gathers siblings by `release_stem`,
        // and each hash name is its own stem, so it would feed the
        // extractor ONE volume of a split set; and the unrar subprocess
        // derives later volume names from the first one's, which for a hash
        // name names nothing on disk. Grouping by RAR header - what
        // `extract_obfuscated_rar` does - is the only thing that works on
        // this shape. For the same reason this sits AHEAD of the
        // `prefer_external_unrar` escape hatch (the setting, or its
        // `NZBFAST_NO_NATIVE_UNRAR` env override) and ignores it: that
        // switch exists to hand a set to the unrar subprocess instead, and
        // there is no version of that which unpacks this one. It still
        // governs every named set, which is all it was ever about.
        let obf = collect_obfuscated_rar_volumes(dir).unwrap_or_default();
        if obf.is_empty() {
            return Err(None);
        }
        // Depth 1, deliberately, where a named set here keeps its volumes:
        // every caller hands this SAME directory to the depth-1 nested pass
        // immediately afterwards, and there a named set is fenced off by
        // `outer_vol_stems` while a hash name - having no stem - is not. So
        // spent volumes left lying here are extracted a second time and
        // published beside the real payload as `extracted-1-<name>`.
        // Sweeping them reaches exactly the end state that pass produces
        // today, and it is `sweep_spent_obfuscated` doing it, so its three
        // refusals (a memberless `.rev`-shaped set, no before-snapshot,
        // nothing published) still decide each set on their own.
        return extract_obfuscated_rar(dir, &obf, password, 1)
            .ok()
            .then(|| UnpackOutcome {
                spent: Vec::new(),
                packed: Vec::new(),
            })
            .ok_or(None);
    };
    // Taken before anything unpacks: the after-diff is the proof-of-output
    // a spent-volume deletion needs, and the filter that keeps a file the
    // unpack itself just published from ever counting as spent.
    let before = snapshot_recursive(dir).ok();
    let spent = |consumed: Vec<PathBuf>| -> Vec<PathBuf> {
        let Some(before) = before.as_ref() else {
            return Vec::new();
        };
        let Ok(after) = snapshot_recursive(dir) else {
            return Vec::new();
        };
        let published: std::collections::HashSet<&PathBuf> = after.difference(before).collect();
        // A RESUMED member is proof too, and the diff cannot see it: its
        // path was already in `before`, because the chase put the file
        // there before this pass appended the rest. See
        // [`crate::resumeout::finished_any`].
        if published.is_empty() && !crate::resumeout::finished_any() {
            return Vec::new();
        }
        consumed
            .into_iter()
            .filter(|p| !published.contains(p))
            .collect()
    };
    let groups = packed_groups(dir, &first);
    // Said ONCE, at the end, naming every set still packed - and only when
    // something else did unpack, which is the case that finishes the job
    // Completed. Per-group warnings scroll past mid-extraction and read
    // like routine noise ("a decoy failed, as decoys do"); the whole point
    // here is that a legitimate second set may be sitting in the output
    // directory, still packed, on a job that reported success.
    let report_leftovers = |failed: &[PackedGroup]| {
        if failed.is_empty() {
            return;
        }
        warn!(
            target: "extract",
            "{} of {} archive set(s) in this directory did not unpack and are still \
             packed: {}. If one of those is the release (rather than a decoy or a \
             sample), it needs a password, a repair, or a newer unpacker.",
            failed.len(),
            groups.len(),
            vouch::packed_names(failed)
        );
    };
    // Native in-process extraction first (vendored rars fork - measured
    // faster than unrar on every compressed-RAR bench leg); the unrar
    // subprocess stays as the escape hatch, chosen by the daemon's
    // `prefer_external_unrar` setting or its `NZBFAST_NO_NATIVE_UNRAR`
    // env override.
    if !nzbkit::extract::prefer_external_unrar() {
        info!(target: "extract", "unpacking archive natively…");
        // §101: a directory holding more than one archive set must not
        // eat. The loop below calls the whole run successful if ANY
        // group produced, so a second group failing halfway has already
        // destroyed its own volumes while `report_leftovers` still calls
        // them "still packed" - and the job finishes Completed with that
        // release missing and no way back to it. Eating exists for the
        // single large set that will not otherwise fit; it has nothing
        // to offer a decoy-plus-release directory, and this is the one
        // shape where losing the bet is invisible to the user.
        //
        // Held for the whole native pass, restored on drop.
        let _single_set_only = (groups.len() > 1).then(|| crate::eatvol::EatArm::new(false));
        let mut consumed_all: Vec<PathBuf> = Vec::new();
        let mut produced = false;
        let mut failed: Vec<PackedGroup> = Vec::new();
        let mut bombed = false;
        for (stem, group) in &groups {
            let Some(group_first) = first_rar_volume(group) else {
                continue;
            };
            let what = if stem.is_empty() {
                group_first.display().to_string()
            } else {
                stem.clone()
            };
            // Per GROUP, like the zip and 7z arms (Codex sweep G): two
            // encrypted sets in one directory need not share a password,
            // and handing every group the level's single resolved value
            // left the second set packed on a run that reported success
            // (Codex sweep 13 Aug U1). The caller's password leads the
            // candidate order, so it is never shadowed by a harvest (U2).
            let group_pw = passwords::resolve_rar_group_password(dir, group, password);
            let pw = group_pw.as_deref().or(password);
            match try_rars_native(dir, &group_first, pw) {
                Ok(consumed) => {
                    info!(target: "extract", "native unpack complete ✔ ({})", group_first.display());
                    consumed_all.extend(consumed);
                    produced = true;
                }
                Err(e) => {
                    warn!(target: "extract", "native unpack failed for '{what}' ({e})");
                    let bomb = nzbkit::disk::bomb_verdict(&e.to_string());
                    bombed |= bomb;
                    let reason = bomb.then(bomb_failure);
                    failed.push(PackedGroup::record(what, group, pw.is_some(), reason));
                }
            }
        }
        if produced {
            report_leftovers(&failed);
            return Ok(UnpackOutcome {
                spent: spent(consumed_all),
                packed: failed,
            });
        }
        // A bomb verdict is the floor of this ladder, not a rung to pass.
        // The native pass refused because finishing the set would not fit
        // on the disk; the unrar subprocess below carries no budget of
        // any kind, so handing it the same set writes until the device
        // says ENOSPC - which is precisely the outcome both guards exist
        // to prevent, and it arrives wearing unrar's exit 5 ("encrypted
        // or damaged?"), blaming the archive for the disk. Measured
        // 22 Aug 2026: a 2 GB-of-zeros RAR5 (88 KB posted) on a 730 MB
        // volume was refused in-stream, refused again here, and then
        // filled the volume anyway on the third rung.
        //
        // Refusing keeps the volumes, which is the whole point - freeing
        // space and retrying unpacks them, where a filled disk leaves the
        // user nothing to retry WITH.
        if bombed {
            warn!(
                target: "extract",
                "unpacking this archive needs more space than the disk has \
                 (possible decompression bomb) - not retrying with unrar, volumes kept"
            );
            // …and the same thing to the CALLER, which is what turns a
            // job failure that blamed the archive into one that names
            // the disk. See [`try_unrar_spent_why`].
            return Err(Some(bomb_failure()));
        }
        // §101: nothing produced, and under the eating mode the failed
        // pass may have consumed volumes on its way down - in which case
        // the unrar escape hatch below would be handed a directory with
        // no volumes in it and fail for a reason that has nothing to do
        // with unrar. Say what actually happened; the caller turns a
        // None into a job failure either way, but the log is the only
        // place this is explicable.
        if groups.iter().any(|(_, g)| g.iter().any(|p| !p.exists())) {
            warn!(
                target: "extract",
                "volumes were consumed as they were read (the volume-eating unpack), \
                 so there is nothing left for unrar to retry - a retry re-downloads the set"
            );
            return Err(None);
        }
        info!(target: "extract", "falling back to unrar…");
    }
    info!(target: "extract", "unpacking archive with unrar…");
    // One subprocess per stem group, on the same list and the same success
    // rule as the native pass above. The password resolves per GROUP here
    // too (U1/U2, same reasoning as the native loop above).
    // The refusal carries whether the group was handed a password at all
    // (the caller's or a harvested one): the level above reads a vouched
    // encrypted leftover that never had one as LOCKED, not failed.
    let unrar_group = |group_first: &PathBuf,
                       group: &[PathBuf]|
     -> std::result::Result<Vec<PathBuf>, (Option<String>, bool)> {
        // Asked HERE, not at the top of this function, so that closing the
        // hatch closes only the hatch: the native pass above still runs and
        // still fails on the shapes it fails on, and every caller's ladder
        // sees exactly the None a box with no `unrar` installed produces.
        // See [`external_unrar_closed`].
        if external_unrar_closed() {
            warn!(target: "extract", "the external unrar fallback is closed for this build - volumes kept");
            return Err((None, password.is_some()));
        }
        // The integration suites' canary, at the SAME rung and for the same
        // reason. It sat at the top of this function until 22 Aug 2026,
        // where it closed the native engine too - which is neither what
        // its name says nor what twelve of its thirteen users want, and
        // it made TODO 211's rescue rung untestable, because the rescue
        // extracts the container it joined by calling straight back in
        // here. Down here it lets a test say "this job used no external
        // unpacker" without also saying "and no unpacker at all".
        // The thirteenth wanted the whole ladder shut, and now says so:
        // `NZBFAST_NO_NATIVE_UNRAR=1` beside the canary skips the native
        // pass above by the documented route (daemon_retry).
        if std::env::var_os("NZBFAST_TEST_FORBID_UNRAR").is_some() {
            warn!(target: "extract", "unrar invocation forbidden by NZBFAST_TEST_FORBID_UNRAR");
            return Err((None, password.is_some()));
        }
        let group_pw = passwords::resolve_rar_group_password(dir, group, password);
        let pw = group_pw.as_deref().or(password);
        let refused = |why: Option<String>| Err((why, pw.is_some()));
        // `-p<pw>` must be a single argument; bare `-p` would prompt and hang.
        let parg = match pw {
            Some(p) if !p.is_empty() => format!("-p{p}"),
            _ => "-p-".to_string(),
        };
        // The volume set the subprocess is about to read, listed BEFORE it
        // runs - the unpack can publish rar-named members of its own, and
        // those must never be mistaken for input volumes.
        let consumed = stem_volume_set(dir, group_first).unwrap_or_default();
        // The bomb guard's floor, asked ahead of the spawn because this
        // rung has no other way to have one. Under `prefer_external_unrar`
        // the budgeted native pass above never ran, so nothing has yet
        // measured this set against the disk - and the subprocess below
        // will not, at any point, for any archive. See [`preflight`].
        //
        // The verdict travels OUT with the refusal, exactly as the
        // native pass's does above: this rung is the only guard the
        // `prefer_external_unrar` route has, so with a bare refusal the
        // job's own message blames an archive that is fine. See
        // [`try_unrar_spent_why`].
        if preflight::unrar_would_bomb(dir, &consumed, pw) {
            return refused(Some(bomb_failure()));
        }
        // Same staging discipline as the native path: `-o+` overwrites without
        // asking, and unrar reads the volume set by path as it goes, so a member
        // named after a volume would destroy the set mid-extraction. The
        // trailing positional argument is unrar's destination directory; it is
        // relative because cwd is `dir`, and it must end in a separator.
        let staging = match ExtractStaging::new(dir) {
            Ok(s) => s,
            Err(e) => {
                warn!(target: "extract", "could not create a staging directory ({e})");
                return refused(None);
            }
        };
        let dest_arg = {
            let mut a = std::ffi::OsString::from(staging.path().file_name().unwrap_or_default());
            a.push(std::path::MAIN_SEPARATOR_STR);
            a
        };
        // TODO 314 stage 1: the poster's bytes go to a closed-source C++
        // parser with a traversal and RCE history, and they go to it with
        // cwd set to the directory holding them. Everything it may touch
        // is under `dir`, and it has no business on the network at all -
        // see nzbfast_core::sandbox for what the confinement is and how it
        // degrades where none is available.
        match nzbfast_core::sandbox::command(
            &unrar,
            &nzbfast_core::sandbox::Policy::tool("unrar", dir),
        )
        .args(["x", "-y", "-o+", &parg, "-idq"])
        // The volume is dir-prefixed but cwd is already `dir`; passing it
        // verbatim makes unrar resolve `dir/dir/name` and report the archive
        // missing (a spurious "wrong password / damaged" failure). Pass
        // `./name` instead.
        .arg(std::path::Path::new(".").join(group_first.file_name().unwrap_or_default()))
        .arg(&dest_arg)
        .stdin(std::process::Stdio::null())
        .current_dir(dir)
        .status()
        {
            Ok(st) if st.success() && !staging.produced_anything() => {
                warn!(target: "extract", "unrar exited 0 but extracted nothing - treating as a failure");
                refused(None)
            }
            Ok(st) if st.success() => match staging.publish_into(dir) {
                Ok(()) => {
                    info!(target: "extract", "unrar complete ✔ ({})", group_first.display());
                    Ok(consumed)
                }
                Err(e) => {
                    warn!(target: "extract", "{e}");
                    refused(None)
                }
            },
            Ok(st) if pw.is_some() => {
                warn!(target: "extract", "unrar exited with {st} - wrong password, or damaged volumes");
                refused(None)
            }
            Ok(st) => {
                warn!(target: "extract", "unrar exited with {st} (encrypted or damaged?)");
                refused(None)
            }
            // "not runnable (No such file or directory (os error 2))" is what
            // a container user saw after the native path failed, and it names
            // neither the cause nor the cure. The release image ships no unrar
            // on purpose (extraction is native), so ENOENT here is the common
            // case, not the exotic one, and it deserves its own sentence.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                warn!(
                    target: "extract",
                    "unrar is not installed, so there was nothing to fall back to \
                     - volumes left on disk"
                );
                warn!(target: "extract", "install unrar to enable this fallback, or unpack them by hand");
                refused(None)
            }
            Err(e) => {
                warn!(target: "extract", "unrar not runnable ({e}) - volumes left on disk");
                refused(None)
            }
        }
    };
    let mut consumed_all: Vec<PathBuf> = Vec::new();
    let mut produced = false;
    let mut failed: Vec<PackedGroup> = Vec::new();
    // Per GROUP, like the refusal itself: a directory holding a decoy
    // bomb beside a real release still unpacks the release, and only a
    // run where NOTHING produced can be reported as a disk refusal.
    let mut bombed = false;
    for (stem, group) in &groups {
        let Some(group_first) = first_rar_volume(group) else {
            continue;
        };
        match unrar_group(&group_first, group) {
            Ok(consumed) => {
                consumed_all.extend(consumed);
                produced = true;
            }
            Err((why, had_pw)) => {
                bombed |= why.is_some();
                let what = if stem.is_empty() {
                    group_first.display().to_string()
                } else {
                    stem.clone()
                };
                failed.push(PackedGroup::record(what, group, had_pw, why));
            }
        }
    }
    if produced {
        report_leftovers(&failed);
        return Ok(UnpackOutcome {
            spent: spent(consumed_all),
            packed: failed,
        });
    }
    Err(bombed.then(bomb_failure))
}

/// Every packed stem GROUP in `dir`, the caller's chosen first volume
/// leading.
///
/// EVERY stem group in the directory, the caller's chosen first volume
/// leading - not just that one group. `first_rar_volume` picks a single
/// volume across the whole directory and `try_rars_native` then scopes
/// itself to that volume's stem, so returning on its success reported
/// "the directory is unpacked" having unpacked ONE set. A demoted post
/// with two top-level sets (`extras.rar/.r00…` beside
/// `s01e01.rar/.r00…`, no `.part`, so the lexically first wins) then
/// finished Completed with the whole episode still packed: the nested
/// pass skips it too, because its stem IS an outer stem and no foreign
/// archive sits beside it.
///
/// This also subsumes the decoy retry it replaces (a same-size random
/// `.rar`, or SABnzbd's `par2test.part1.11.rar` shadowing
/// `par2test.part1.rar`): a decoy is simply a group that produces
/// nothing. Success is unchanged - at least one group produced - so a
/// decoy that fails cannot now fail a job that used to pass.
///
/// The group list is built from ONE directory read taken before any
/// extraction, so a set published by an earlier group (RAR-in-RAR)
/// never enters it; the nested pass owns that layer as it always did.
///
/// BOTH engines walk this list. Scoping only the native pass to it left
/// the unrar fallback - the path a compressed set takes when the native
/// extractor declines - unpacking the lead group and reporting the whole
/// directory done, which is the same bug one layer down.
fn packed_groups(dir: &std::path::Path, first: &std::path::Path) -> Vec<(String, Vec<PathBuf>)> {
    let mut groups: Vec<(String, Vec<PathBuf>)> = Vec::new();
    use nzbkit::extract::release_stem;
    // Lowercase both sides - `release_stem` returns a slice of what it
    // was handed, so a mixed-case stem groups against itself only when
    // every input had the same case treatment (78a5640f).
    let key = |p: &std::path::Path| {
        release_stem(
            &p.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_lowercase(),
        )
    };
    // A numeric-only set (`Movie.001`, `Movie.002`) shares no
    // release_stem - release_stem keeps a generic numeric tail on
    // purpose, so `.001` and `.002` are different stems - and the
    // walk below only admits files named `.rar`. Both together meant
    // a second numeric set in the same directory was invisible here,
    // even though `stem_volume_set` groups it correctly once it is
    // handed the lead volume (Fable sweep 15 Aug). Key those by
    // numeric base, in a namespace no release_stem can collide with,
    // and require the magic on both sides so a `.7z.001` or
    // `.zip.001` part owned by another arm can never form a group.
    let num_key = |p: &std::path::Path| -> Option<String> {
        let name = p.file_name()?.to_string_lossy().to_lowercase();
        Some(format!("\u{0}num:{}", numeric_vol_base(&name)?))
    };
    let group_key = |p: &std::path::Path| -> String {
        match num_key(p) {
            Some(k) if rar_magic(p) => k,
            _ => key(p).to_string(),
        }
    };
    let mut by_stem: std::collections::BTreeMap<String, Vec<PathBuf>> = Default::default();
    by_stem
        .entry(group_key(first))
        .or_default()
        .push(first.to_path_buf());
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            let named_rar = p.extension().is_some_and(|x| x.eq_ignore_ascii_case("rar"));
            let numeric = num_key(&p).is_some();
            if p != first && (named_rar || numeric) && rar_magic(&p) {
                by_stem.entry(group_key(&p)).or_default().push(p);
            }
        }
    }
    let lead = group_key(first);
    if let Some(g) = by_stem.remove(&lead) {
        groups.push((lead, g));
    }
    groups.extend(by_stem);
    groups
}

/// Part B of the 2026-07-29 one-pass spec: a set that just unpacked has
/// spent its volumes - they are our own working files, removed in place
/// (`fs::remove_file`, never the trash path). Callers hand this exactly
/// what [`try_unrar_spent`] reported, so every deliberate keep (a failed
/// or partial unpack, an encrypted set still waiting for its password,
/// the obfuscated sweep's refusals) never reaches here.
pub fn remove_spent_volumes(vols: &[PathBuf]) {
    let mut removed = 0usize;
    for p in vols {
        match std::fs::remove_file(p) {
            Ok(()) => removed += 1,
            // Already gone is not a failure to report. §101's eating mode
            // deletes each volume mid-extraction, so this sweep - which
            // runs afterwards over the same list - would otherwise print
            // one "could not remove" warning per volume for a job that
            // did exactly what it was told.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                warn!(target: "extract", "could not remove spent volume {}: {e}", p.display())
            }
        }
    }
    if removed > 0 {
        info!(target: "extract", "removed {removed} volume file(s) after extraction");
    }
}

/// Last resort after PAR2 is exhausted: repair damaged volumes using the
/// RAR recovery records embedded in the volumes themselves (RAR5 RR and
/// RAR2/3 old-style protect records, per volume, via the vendored rars),
/// then re-attempt extraction. Extraction is the post-repair verification:
/// RAR5 RR repair does not re-checksum rebuilt shards on its own, but the
/// native extraction path CRC-verifies every entry.
///
/// Groups by stem and resolves the password PER GROUP, as both try_unrar
/// rungs do. This rung took the caller's raw value straight into
/// rr_repair_volume, so a set whose password lives in a harvested
/// sidecar (the nested password-chain shape) failed every
/// header-encrypted volume parse and the repair reported "could not
/// save the set" on a set it could have saved (14 Aug sweep; the
/// per-group resolve moved out of extract_one_level in U2/b1c20eea and
/// this rung never got one).
///
/// The blind form: every volume gets the full pass. Where PAR2 has
/// already verified the set, [`try_rar_rr_repair_hinted`] skips what it
/// proved intact (TODO §11 (b), `rarfix/rrhint.rs`).
///
/// Returns true only when extraction afterwards succeeds. The bool form,
/// kept for the tests; a caller that composes a job failure takes
/// [`try_rar_rr_repair_why`] instead so the ladder's own reason survives,
/// which since TODO §249 item 1 is all of them - hence `cfg(test)`, the
/// same shape [`crate::repair::reextract_dir`] settled into.
#[cfg(test)]
pub(crate) fn try_rar_rr_repair(dir: &std::path::Path, password: Option<&str>) -> bool {
    try_rar_rr_repair_hinted(dir, password, None)
}

/// [`try_rar_rr_repair`] that also names WHY it refused, on the one
/// class of refusal that is about the DISK rather than the archive.
///
/// Same contract as [`try_unrar_spent_why`], which this rung's
/// extraction delegates to: `Err(None)` is the ordinary failure the
/// caller words itself, `Err(Some(why))` is a bomb verdict that must be
/// quoted rather than paraphrased. This closed the third and last rung
/// of the named-RAR arm (TODO §249 item 1); see
/// [`try_rar_rr_repair_hinted_why`] for what each attempt inside can
/// raise.
pub fn try_rar_rr_repair_why(
    dir: &std::path::Path,
    password: Option<&str>,
) -> std::result::Result<(), Option<String>> {
    try_rar_rr_repair_hinted_why(dir, password, None)
}

/// Rebuild missing or destroyed RAR5 volumes from `.rev` recovery volumes
/// (WinRAR `rar rv`). Present volumes map onto the REV metadata's slots by
/// (size, crc32); every unmatched slot is reconstructed via Reed-Solomon
/// and written under the set's `partNN` naming. Returns true when at least
/// one volume was rebuilt (caller retries extraction afterwards).
pub(crate) fn try_rev_reconstruct(dir: &std::path::Path) -> bool {
    use rars::recovery::stream::FileSource;

    let budget = nzbkit::mem::process_budget().repair_cap();
    sweep_stale_rev_temps(dir);

    // Gather .rev files: metadata from a bounded header read, payload
    // CRC-verified by streaming. The old shape read every .rev whole, which
    // for a 60x1 GB set is 1 GB of payload per recovery volume before a
    // single byte was repaired.
    let mut rev_sources: Vec<FileSource> = Vec::new();
    let mut rev_meta: Vec<rars::rar50::Rev5VolumeRef> = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    let mut rev_paths: Vec<std::path::PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("rev")))
        .collect();
    rev_paths.sort();
    for path in &rev_paths {
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let source = match FileSource::open(path) {
            Ok(source) => source,
            Err(e) => {
                warn!(target: "repair", "{name}: unreadable .rev ({e})");
                continue;
            }
        };
        let meta = match rars::rar50::read_rev5_meta(&source) {
            Ok(meta) => meta,
            Err(e) => {
                warn!(target: "repair", "{name}: unusable .rev ({e})");
                continue;
            }
        };
        match rars::rar50::verify_rev5_payload(&source, &meta) {
            Ok(true) => {}
            Ok(false) => {
                warn!(target: "repair", "{name}: .rev payload fails its own checksum");
                continue;
            }
            Err(e) => {
                warn!(target: "repair", "{name}: unreadable .rev payload ({e})");
                continue;
            }
        }
        rev_sources.push(source);
        rev_meta.push(meta);
    }
    // Group the verified .rev files by the SET each describes, and try every
    // group.
    //
    // A directory can hold two unrelated releases' recovery volumes - usenet
    // posts land side by side, and nothing separates them by name. This used
    // to take whichever .rev enumerated first, keep the ones matching it, and
    // discard the rest, so the second set was never attempted even when it
    // was perfectly recoverable on its own. (Before that it failed the whole
    // vector on any mismatch, making NEITHER set recoverable.) Normal RAR
    // extraction already groups by release stem; this path now groups too -
    // by the metadata signature rather than the name, because REV metadata
    // carries no filenames.
    let same_set = |a: &rars::rar50::Rev5VolumeRef, b: &rars::rar50::Rev5VolumeRef| {
        a.meta.data_count == b.meta.data_count
            && a.meta.recovery_count == b.meta.recovery_count
            && a.meta.data_volumes == b.meta.data_volumes
            && a.payload.end - a.payload.start == b.payload.end - b.payload.start
    };
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for index in 0..rev_meta.len() {
        match groups
            .iter_mut()
            .find(|g| same_set(&rev_meta[g[0]], &rev_meta[index]))
        {
            Some(g) => g.push(index),
            None => groups.push(vec![index]),
        }
    }
    if groups.is_empty() {
        return false;
    }
    if groups.len() > 1 {
        info!(
            target: "repair",
            "{} independent .rev sets in this folder; trying each",
            groups.len()
        );
    }
    // rev_paths is sorted, so the grouping and the order they are tried are
    // both deterministic - a rerun reports the same thing.
    //
    // EVERY group is tried, not just up to the first that rebuilds something.
    // Stopping at the first success is the same fault this grouping exists to
    // fix, moved one level up: two damaged releases side by side would leave
    // the second unrepaired, extraction would fail on it anyway, and the .rev
    // volumes that could have saved it are never consulted again. The groups
    // are independent, so there is nothing to gain by stopping early.
    let mut rebuilt_any = false;
    for keep in &groups {
        rebuilt_any |= try_rev_group(dir, budget, keep, &rev_sources, &rev_meta);
    }
    rebuilt_any
}

/// Remove `.rev` staging temps abandoned by an earlier run.
///
/// Rebuilds are staged beside the set and renamed into place only once every
/// one of them verifies, so a crash between those renames leaves temps behind.
/// Nothing mistakes them for volumes - `collect_rar_volumes` wants a
/// `.rar`/`.rNN` name and the obfuscated path is unreachable from here - so
/// they are litter rather than a hazard, but they accumulate across crashes.
///
/// Age, not the embedded pid, decides: pids are reused, and a live repair in
/// this directory belongs to a process we must not interfere with. A repair
/// finishes in minutes even for a very large set on slow storage, so anything
/// this old is abandoned by definition.
pub(crate) fn sweep_stale_rev_temps(dir: &std::path::Path) {
    const ABANDONED_AFTER: std::time::Duration = std::time::Duration::from_secs(6 * 60 * 60);
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if !is_owned_rev_temp(&name.to_string_lossy()) {
            continue;
        }
        let stale = entry
            .metadata()
            .and_then(|m| m.modified())
            .and_then(|t| t.elapsed().map_err(std::io::Error::other))
            .is_ok_and(|age| age > ABANDONED_AFTER);
        if stale {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Exactly the staging shape written below: `revtmp<pid>-<slot>-<n>`, all
/// three fields decimal digits.
///
/// The sweep used to accept the bare `revtmp` prefix, and its delete is
/// unconditional, so any pre-existing file whose name merely started with
/// those six letters and whose mtime was over six hours old was destroyed.
/// That reaches the user's own files: `nzbfast extract <dir>` points this at
/// a directory of arbitrary content, and every restored file carries the
/// archive's recorded mtime, which is routinely years old. Matching the whole
/// grammar keeps the sweep to names this code wrote. Leading zeros and
/// oversized pid fields still match, so no live temp is orphaned.
fn is_owned_rev_temp(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("revtmp") else {
        return false;
    };
    let mut fields = rest.split('-');
    let (Some(pid), Some(slot), Some(n), None) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return false;
    };
    [pid, slot, n]
        .iter()
        .all(|f| !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit()))
}

/// Last case-insensitive occurrence of an ASCII `needle`, as a byte offset
/// that is valid in `hay` itself. Searching a `to_lowercase()` copy instead
/// would shift every offset past a character whose lowercase form has a
/// different byte length (U+0130 lowercases to two chars), which then either
/// panics on a non-boundary slice or cuts the name in the wrong place.
pub(crate) fn rfind_ascii_ci(hay: &str, needle: &str) -> Option<usize> {
    let (hay, needle) = (hay.as_bytes(), needle.as_bytes());
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    // An ASCII byte never appears inside a multi-byte UTF-8 sequence, so a
    // match of an all-ASCII needle always starts on a char boundary.
    (0..=hay.len() - needle.len())
        .rev()
        .find(|&i| hay[i..i + needle.len()].eq_ignore_ascii_case(needle))
}

/// Name for `slot` (0-based) derived from `known`, the on-disk name of the
/// volume filling slot `known_slot`: same `.partNN` pattern, same
/// zero-padding, same casing. `None` when `known` does not carry a `.part`
/// number matching its own slot, in which case we cannot infer the series.
pub(crate) fn derive_part_name(known: &str, known_slot: usize, slot: usize) -> Option<String> {
    let p = rfind_ascii_ci(known, ".part")?;
    let tail = &known[p + 5..];
    let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() || digits.parse::<usize>().ok()? != known_slot + 1 {
        return None;
    }
    Some(format!(
        "{}{}{:0width$}{}",
        &known[..p],
        &known[p..p + 5],
        slot + 1,
        &tail[digits.len()..],
        width = digits.len()
    ))
}

/// Rebuild what one coherent .rev set can. `keep` indexes the members of a
/// single set within `rev_sources`/`rev_meta`; returns true when at least one
/// volume was rebuilt.
pub(crate) fn try_rev_group(
    dir: &std::path::Path,
    budget: u64,
    keep: &[usize],
    rev_sources: &[rars::recovery::stream::FileSource],
    rev_meta: &[rars::rar50::Rev5VolumeRef],
) -> bool {
    use rars::recovery::stream::{FileSource, RangeSource};

    let first = &rev_meta[keep[0]];
    let slots = first.meta.data_volumes.clone();
    info!(
        target: "repair",
        "trying .rev recovery volumes ({} rev file(s), {} data volume slot(s))…",
        keep.len(),
        slots.len()
    );

    // Match on-disk volumes to slots by size + crc32, streamed (REV metadata
    // carries no filenames; a damaged volume simply fails to match and its
    // slot is rebuilt).
    let volumes = collect_rar_volumes(dir).unwrap_or_default();
    let mut slot_path: Vec<Option<std::path::PathBuf>> = vec![None; slots.len()];
    let mut slot_name: Vec<Option<String>> = vec![None; slots.len()];
    for path in &volumes {
        let Ok((crc, len)) = rars::recovery::stream::crc32_of(path) else {
            continue;
        };
        for (i, meta) in slots.iter().enumerate() {
            if slot_path[i].is_none() && meta.file_size == len && meta.crc32 == crc {
                slot_name[i] = path.file_name().map(|n| n.to_string_lossy().into_owned());
                slot_path[i] = Some(path.clone());
                break;
            }
        }
    }
    let missing: Vec<usize> = (0..slots.len())
        .filter(|&i| slot_path[i].is_none())
        .collect();
    if missing.is_empty() {
        info!(target: "repair", "all data volumes verify; .rev not needed");
        return false;
    }
    if missing.len() > keep.len() {
        warn!(
            target: "repair",
            "✘ {} volume(s) missing but only {} usable .rev file(s) - unrepairable",
            missing.len(),
            keep.len()
        );
        return false;
    }

    // Derive names for the rebuilt slots from a matched neighbour's
    // `partNN` pattern (same zero-padding, slot index + 1).
    let derive_name = |slot: usize| -> Option<String> {
        let (i, known) = slot_name
            .iter()
            .enumerate()
            .find_map(|(i, n)| n.as_ref().map(|n| (i, n.as_str())))?;
        derive_part_name(known, i, slot)
    };

    // Intact volumes stay on disk and are read by range; only the missing
    // ones are reconstructed, each into its own temp beside the set.
    let mut intact_sources: Vec<Option<FileSource>> = Vec::with_capacity(slots.len());
    for path in &slot_path {
        intact_sources.push(match path {
            Some(path) => match FileSource::open(path) {
                Ok(source) => Some(source),
                Err(e) => {
                    warn!(target: "repair", "✘ {} became unreadable ({e})", path.display());
                    return false;
                }
            },
            None => None,
        });
    }
    let intact: Vec<Option<&dyn RangeSource>> = intact_sources
        .iter()
        .map(|source| source.as_ref().map(|source| source as &dyn RangeSource))
        .collect();
    let recovery: Vec<rars::rar50::Rev5RecoverySource<'_>> = keep
        .iter()
        .filter_map(|&index| {
            Some(rars::rar50::Rev5RecoverySource {
                row: rev_meta[index].row().ok()?,
                source: &rev_sources[index],
                payload: rev_meta[index].payload.clone(),
            })
        })
        .collect();

    // One temp per missing slot, created exclusively so nothing beside the
    // set is truncated and two concurrent repairs cannot share a name.
    let mut temps: Vec<(std::path::PathBuf, std::fs::File)> = Vec::new();
    let cleanup_temps = |temps: &[(std::path::PathBuf, std::fs::File)]| {
        for (path, _) in temps {
            let _ = std::fs::remove_file(path);
        }
    };
    for (slot, &index) in missing.iter().enumerate() {
        let mut made = None;
        for n in 0..1024 {
            let candidate = dir.join(format!("revtmp{}-{}-{n}", std::process::id(), slot));
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&candidate)
            {
                Ok(file) => {
                    made = Some((candidate, file));
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    warn!(target: "repair", "✘ cannot stage a rebuild for slot {} ({e})", index + 1);
                    cleanup_temps(&temps);
                    return false;
                }
            }
        }
        let Some(made) = made else {
            warn!(target: "repair", "✘ no free temp name for slot {}", index + 1);
            cleanup_temps(&temps);
            return false;
        };
        temps.push(made);
    }

    let mut write_error: Option<std::io::Error> = None;
    let result = rars::rar50::repair_rev5_volumes_streaming(
        &slots,
        &intact,
        &recovery,
        first.meta.recovery_count as usize,
        budget,
        &mut |slot, offset, bytes| {
            use std::io::{Seek, Write};
            let file = &mut temps[slot].1;
            let outcome = file
                .seek(std::io::SeekFrom::Start(offset))
                .and_then(|_| file.write_all(bytes));
            if let Err(e) = outcome {
                let message = e.to_string();
                write_error = Some(e);
                return Err(rars::Error::from(std::io::Error::other(message)));
            }
            Ok(())
        },
    );
    if let Err(e) = result {
        warn!(target: "repair", "✘ .rev reconstruction failed ({e})");
        cleanup_temps(&temps);
        return false;
    }
    if let Some(e) = write_error {
        warn!(target: "repair", "✘ .rev reconstruction could not be written ({e})");
        cleanup_temps(&temps);
        return false;
    }

    // Verify every rebuild against the metadata's own checksum BEFORE any of
    // them is published. A rebuild that does not match is not a volume, and
    // publishing one would replace a known-bad file with an unknown-bad one.
    for (slot, &index) in missing.iter().enumerate() {
        let (path, file) = &mut temps[slot];
        if let Err(e) = file.sync_all() {
            warn!(
                target: "repair",
                "✘ could not flush the rebuild for slot {} ({e})",
                index + 1
            );
            cleanup_temps(&temps);
            return false;
        }
        match rars::recovery::stream::crc32_of(path) {
            Ok((crc, len)) if crc == slots[index].crc32 && len == slots[index].file_size => {}
            Ok(_) => {
                warn!(
                    target: "repair",
                    "✘ rebuilt slot {} fails its checksum - discarded",
                    index + 1
                );
                cleanup_temps(&temps);
                return false;
            }
            Err(e) => {
                warn!(target: "repair", "✘ cannot verify the rebuild for slot {} ({e})", index + 1);
                cleanup_temps(&temps);
                return false;
            }
        }
    }

    // Every rebuild verified: publish them by rename, which is atomic per
    // file. Until this point nothing in the set has been touched.
    let mut rebuilt = 0usize;
    for (slot, &index) in missing.iter().enumerate() {
        let name =
            derive_name(index).unwrap_or_else(|| format!("rebuilt.part{:02}.rar", index + 1));
        let target = dir.join(&name);
        match std::fs::rename(&temps[slot].0, &target) {
            Ok(()) => {
                info!(target: "repair", "✔ {name} - rebuilt from .rev");
                rebuilt += 1;
            }
            Err(e) => warn!(target: "repair", "✘ {name} - could not be published ({e})"),
        }
    }
    cleanup_temps(&temps);
    rebuilt > 0
}

/// What one recovery-record repair of one volume actually did - split so
/// the caller's "rewritten" log and stats count only real rewrites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RrRepair {
    /// Shards were rebuilt and the repaired copy was published by rename.
    Rebuilt,
    /// The record proved the protected prefix already intact - the
    /// original is untouched and nothing was published.
    PrefixIntact,
    /// No RR / unsupported family (clean skip).
    NoRecord,
}

/// Repair one volume in place from its own recovery record.
/// Ok(Rebuilt) = rewritten (atomic rename), Ok(PrefixIntact) = record says
/// the prefix is already intact (original kept), Ok(NoRecord) = no RR /
/// unsupported family (clean skip), Err = volume has RR but repair failed.
///
/// The one-volume form, kept for the tests: production loops go through
/// [`rr_repair_volume_in`] with a session shared across the set.
#[cfg(test)]
pub(crate) fn rr_repair_volume(path: &std::path::Path, password: Option<&str>) -> Result<RrRepair> {
    let mut session = rars::ReadSession::new(rars::ArchiveReadOptions::with_optional_password(
        password.map(str::as_bytes),
    ));
    rr_repair_volume_in(&mut session, path, password)
}

/// [`rr_repair_volume`] over a caller-owned parse session. A loop over
/// the volumes of ONE set (`rrhint::rr_repair_volumes`) hands the same
/// session to every volume, so an encrypted set derives its RAR 5 key
/// once for the pass: `ArchiveReader::read_path_with_options` minted a
/// fresh key cache per call and paid one 2^15-round PBKDF2-HMAC-SHA256
/// per volume, ~15 ms each on a CPU without SHA extensions (the same
/// per-volume derivation the audit found in the bench contestant -
/// research/RAR-PERF-AUDIT-2026-09-02.md, round 2; the disk unpack path
/// in `rarfix/native.rs` never paid it). The keys parsed here are the
/// ones the repair reuses, so nothing below re-derives. `password` is
/// the session's password, spelled again only for the raw-scan fallback,
/// which takes options of its own.
pub(crate) fn rr_repair_volume_in(
    session: &mut rars::ReadSession<'_>,
    path: &std::path::Path,
    password: Option<&str>,
) -> Result<RrRepair> {
    // A UNIQUE temp we provably created, not `path.with_extension("rrtmp")`.
    //
    // The deterministic name was opened with `File::create` - truncating, and
    // symlink-following - before this code had established the archive even
    // carries a recovery record. So a legitimate `release.rrtmp` sitting
    // beside `release.rar` was destroyed and then unlinked by the cleanup
    // path, and if it was a symlink the truncation landed on whatever it
    // pointed at, outside the job entirely. Two concurrent repairs in one
    // directory also shared the name and clobbered each other.
    //
    // `create_new` means we hold a name nobody else has, and refuses to
    // follow an existing symlink; the cleanup below can then only ever
    // delete a file this invocation made.
    //
    // And the STEM is held back rather than the composed name capped.
    // `path` is a volume this job downloaded, so its leaf is a
    // `sanitize_out_name` result and is routinely AT the 255-byte
    // component cap - capping is what produced it. `with_extension`
    // REPLACES, so it only grows when the new extension is longer than
    // the old, which `.rar` -> `.rrtmp0` always is: 255 becomes 258 and
    // no filesystem creates it, so a volume at the cap could not be
    // repaired from its own recovery record at all. This name is nobody's
    // identity key (created with `create_new`, renamed away, removed by
    // `cleanup`), so what matters is that it stays RECOGNISABLE as an RR
    // temp - the tests find one by `contains("rrtmp")` - which capping
    // the composed name would truncate away.
    //
    // ONE closure spells the decoration and the reserve is that same
    // closure over an empty stem, so the two cannot drift; the reserve
    // takes the WIDEST counter this loop can reach, since
    // `cap_shared_stem` reserves its longest tail rather than a sum.
    // Spelled as `{stem}.rrtmp{n}` on the file NAME and not as
    // `with_extension`, which is the same string - `with_extension`
    // replaces everything after `file_stem` with `.` plus its argument -
    // but with the stem in hand to shorten.
    // `to_string_lossy` where `with_extension` was lossless, and the
    // same stated limit as `smart::deferred_trash::stage`: a volume whose
    // name is not valid UTF-8 gets a temp carrying U+FFFD. It costs
    // nothing - the temp is renamed OVER `path`, which is untouched, and
    // a volume this job downloaded is named through a sanitiser that
    // takes `&str`.
    let decorate = |stem: &str, n: usize| format!("{stem}.rrtmp{n}");
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "volume".into());
    let stem = nzbkit::disk::cap_shared_stem(&stem, [decorate("", 1023).as_str()]);
    let (tmp, tmp_file) = {
        let mut made = None;
        for n in 0..1024 {
            let candidate = path.with_file_name(decorate(&stem, n));
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&candidate)
            {
                Ok(f) => {
                    made = Some((candidate, f));
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
        made.ok_or_else(|| anyhow::anyhow!("no free repair temp name beside {}", path.display()))?
    };
    let cleanup = |tmp: &std::path::Path| {
        let _ = std::fs::remove_file(tmp);
    };
    let options = rars::ArchiveReadOptions::with_optional_password(password.map(str::as_bytes));
    // Both branches below stream: the volume is read by range and the
    // repaired copy is built in the temp, so peak memory is this budget
    // rather than the volume. The old shape read the whole volume, cloned
    // it to repair into, and returned a third copy for the caller to write
    // - over 2x an 8-20 GB volume resident, none of it inside the budget.
    let budget = nzbkit::mem::process_budget().repair_cap();
    let repair_result = match session.read_path(path) {
        Ok(archive) => {
            // The path form, not the file form: with the destination PATH in
            // hand the library can clone the volume (APFS/btrfs reflink)
            // instead of copying it, which is most of an undamaged-tail
            // repair. The create_new claim above still owns the name.
            drop(tmp_file);
            archive.repair_recovery_to_path(&tmp, password.map(str::as_bytes), budget)
        }
        Err(_) => {
            // Headers too damaged to parse: raw RAR5 recovery-chunk scan,
            // over the FILE rather than a resident copy of it.
            //
            // Pass the password through: this fallback validates its own
            // reconstruction by re-parsing it, and a passwordless parse
            // reports a header-encrypted archive as NeedPassword - throwing
            // away a repair that had actually worked.
            drop(tmp_file);
            match rars::rar50::repair_inline_recovery_path(path, &tmp, options, budget) {
                Ok(rebuilt) => Ok(rebuilt),
                Err(rars::Error::UnsupportedSignature) => {
                    cleanup(&tmp);
                    anyhow::bail!("unparseable and not a RAR5 volume");
                }
                Err(e) => Err(e),
            }
        }
    };
    match repair_result {
        Ok(rebuilt) => {
            // KEEP the shard list rather than `map(|_| ())`. An empty one
            // is the library saying the protected prefix was already
            // intact - the destination is then a byte-for-byte copy, so
            // the ORIGINAL stays the published file and the copy is
            // deleted: renaming it over the original would replace a
            // known-good inode with a fresh copy for nothing. That used
            // to be indistinguishable in the log from a volume genuinely
            // rebuilt from its record, which is how a repair that did not
            // happen read as one that did. It is now only ever the intact
            // case: a damaged group with no usable record is an error
            // inside the walk rather than a silently skipped group (see
            // `recovery::stream::repair_prefix_streaming`).
            if rebuilt.is_empty() {
                info!(
                    target: "repair",
                    "{} - its recovery record reports the protected prefix already intact; \
                     any damage is outside it",
                    path.display()
                );
                cleanup(&tmp);
                return Ok(RrRepair::PrefixIntact);
            }
            // Flush the rebuild before the rename publishes it - the
            // rename replaces the original, so a torn temp published
            // over it would leave the copy as the only one. Same order
            // as the .rev path above.
            if let Err(e) = std::fs::OpenOptions::new()
                .write(true)
                .open(&tmp)
                .and_then(|f| f.sync_all())
            {
                cleanup(&tmp);
                return Err(e.into());
            }
            std::fs::rename(&tmp, path)?;
            Ok(RrRepair::Rebuilt)
        }
        Err(e) => {
            cleanup(&tmp);
            // Clean skips: family has no RR support, or the volume simply
            // carries no recovery record (RAR5 "inline recovery record",
            // RAR2 "PROTECT_HEAD", RAR3 old-style all phrase it as
            // "does not contain … recovery record").
            let text = e.to_string();
            let no_record = text.contains("does not contain") && text.contains("recovery record");
            if no_record || matches!(e, rars::Error::UnsupportedFamilyFeature { .. }) {
                return Ok(RrRepair::NoRecord);
            }
            // Too large is the one failure the operator can actually act on:
            // the repair is arithmetically possible, it just needs a wider
            // working set than the configured budget allows.
            if matches!(
                e,
                rars::Error::Rar5Recovery(rars::recovery::rar5::Error::RepairTooLarge)
                    | rars::Error::LegacyRepairTooLarge
            ) {
                return Err(anyhow::anyhow!(
                    "{text} - raise --mem-limit (or the mem_limit setting) to repair this volume"
                ));
            }
            Err(anyhow::anyhow!("{text}"))
        }
    }
}

/// All RAR volume files in `dir`, natural volume order - same name grammar
/// as reextract_dir (.rar/.rNN by name; rollover and numeric extensions
/// only with the Rar! magic).
pub fn collect_rar_volumes(dir: &std::path::Path) -> Result<Vec<PathBuf>> {
    use nzbkit::extract::{release_stem, vol_sort_key};
    let mut volumes = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();
        let by_name = name.ends_with(".rar")
            || (name.rfind('.').is_some_and(|p| {
                let t = &name[p + 1..];
                t.len() >= 3 && t.starts_with('r') && t[1..].bytes().all(|c| c.is_ascii_digit())
            }));
        let rollover_or_numeric = name.rfind('.').is_some_and(|p| {
            let t = &name[p + 1..];
            (t.len() >= 3
                && (b's'..=b'z').contains(&t.as_bytes()[0])
                && t[1..].bytes().all(|c| c.is_ascii_digit()))
                || ((2..=4).contains(&t.len()) && t.bytes().all(|c| c.is_ascii_digit()))
        });
        if by_name || (rollover_or_numeric && rar_magic(&path)) {
            volumes.push(path);
        }
    }
    volumes.sort_by_cached_key(|p| {
        let name = p.file_name().unwrap_or_default().to_string_lossy();
        (release_stem(&name), vol_sort_key(&name))
    });
    Ok(volumes)
}

/// The base of a WinRAR numeric volume name: `film.001` -> `film`. `None`
/// for anything whose extension is not a 2-4 digit ordinal, which is the
/// same tail width `stem_volume_set`'s name grammar already accepts.
///
/// Deliberately narrow, and never a substitute for `release_stem`: this
/// only answers "are these two names the same numeric series", and every
/// caller pairs it with the Rar! magic before believing it.
pub(crate) fn numeric_vol_base(name: &str) -> Option<&str> {
    let p = name.rfind('.')?;
    let tail = &name[p + 1..];
    ((2..=4).contains(&tail.len()) && tail.bytes().all(|c| c.is_ascii_digit())).then(|| &name[..p])
}

/// The named RAR volumes in `dir` belonging to `first`'s set, natural
/// volume order - the on-disk set an unpack starting at `first` reads.
/// Same volume-name grammar as reextract_dir: .rar/.rNN by name, rollover
/// (.sNN..) and numeric (.001) only with the Rar! magic. Membership is the
/// shared release stem, except for a numeric-only set, which has no stem
/// to share - see the note on `numeric_base` below.
pub(crate) fn stem_volume_set(
    dir: &std::path::Path,
    first: &std::path::Path,
) -> Result<Vec<PathBuf>> {
    use nzbkit::extract::{release_stem, vol_sort_key};
    let first_name = first
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    // `release_stem` matches suffixes case-insensitively but returns a slice
    // of the name it was GIVEN, so two stems only compare equal when both
    // sides went in with the same case. Every `name` below is lowercased for
    // the extension grammar, so this side must be too. Taken from the
    // original case, the comparison failed for EVERY file whose stem had a
    // capital in it: a live 144-volume `raRjHaZZ…partNNN.rar` remux matched
    // zero volumes, which failed the native unpack (a wasted external-unrar
    // pass, and an outright failure on a box with no unrar) and left all
    // 55 GB of spent volumes on disk, because the caller deletes exactly
    // what this reports.
    let lower_first = first_name.to_lowercase();
    let stem = release_stem(&lower_first);
    // A numeric-only set (`film.001`, `film.002` …) has no stem to group by:
    // `release_stem` deliberately keeps a bare numeric tail, so that
    // `Backup.2019.001` stays one release in the index. Applied here it made
    // every volume its own stem, and the set arrived at the extractor as ONE
    // volume of a split archive: "RAR 5 split entry is incomplete", then a
    // fallback to an unrar that a default install does not ship, so the job
    // failed with both volumes sitting on disk. Where the FIRST volume is
    // itself a magic-carrying numeric volume, group by the numeric base
    // instead. The magic is required on both sides so a byte-split
    // `.zip.001`/`.7z.001` part - owned by other arms of the ladder - can
    // never be swept in, because the caller DELETES what this reports.
    let numeric_base = numeric_vol_base(&lower_first)
        .filter(|_| rar_magic(first))
        .map(str::to_string);
    let mut volumes: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();
        let by_name = name.ends_with(".rar")
            || (name.rfind('.').is_some_and(|p| {
                let t = &name[p + 1..];
                t.len() >= 3 && t.starts_with('r') && t[1..].bytes().all(|c| c.is_ascii_digit())
            }));
        let rollover_or_numeric = name.rfind('.').is_some_and(|p| {
            let t = &name[p + 1..];
            (t.len() >= 3
                && (b's'..=b'z').contains(&t.as_bytes()[0])
                && t[1..].bytes().all(|c| c.is_ascii_digit()))
                || ((2..=4).contains(&t.len()) && t.bytes().all(|c| c.is_ascii_digit()))
        });
        let same_set = match numeric_base.as_deref() {
            Some(base) => numeric_vol_base(&name).is_some_and(|b| b == base) && rar_magic(&path),
            None => release_stem(&name) == stem,
        };
        if (by_name || (rollover_or_numeric && rar_magic(&path))) && same_set {
            volumes.push(path);
        }
    }
    volumes
        .sort_by_cached_key(|p| vol_sort_key(&p.file_name().unwrap_or_default().to_string_lossy()));
    Ok(volumes)
}

mod native;
mod rrhint;
pub(crate) use native::{try_rars_native, write_archives_to, write_archives_to_spending};
#[cfg(test)]
pub(crate) use rrhint::try_rar_rr_repair_hinted;
pub use rrhint::{DamageHint, try_rar_rr_repair_hinted_why};

/// TODO 164: the leftovers a successful ladder run names, and the
/// PAR2-vouching verdict the level above reaches on them.
pub mod vouch;
pub use vouch::{PackedGroup, UnpackOutcome};

/// `pub(crate)` for its predicate alone: `repair::repair_tests` pins the
/// whole floor of the unpack ladder in one place, and this is the rung
/// that has no verdict to read.
pub(crate) mod preflight;

/// TODO 163 item 6's disk half: the tar arm of the post-pass.
mod tar;
pub(crate) use tar::{collect_tar_containers, extract_tar, first_tar_container, is_tar_container};

mod sevenz;
pub use sevenz::{
    collect_sevenz_archives, concat_files, extract_sevenz, open_sevenz, sevenz_set_is_encrypted,
    split_7z_part,
};

/// Extract every zip container in `dir`. Returns true only if every one
/// produced its payload.
///
/// Mirrors [`extract_sevenz`]: `nzbkit::zip::Archive` reads a multi-part
/// set through one logical byte-space, so a split zip never needs a
/// second copy on disk - which also means no scratch container can
/// collide with a member of the archive it came from. The 7z arm joined
/// its parts into a scratch copy until TODO 212 (22 Aug 2026) gave it the
/// same shape.
pub(crate) fn extract_zip(
    dir: &std::path::Path,
    jobs: &[nzbkit::zip::Finding],
    password: Option<&str>,
) -> bool {
    let mut all_ok = true;
    for job in jobs {
        // Per CONTAINER, not per level: two encrypted zips in one post
        // need not share a password, and resolving once for the level
        // handed the second one the first one's value and left it
        // packed while reporting success (Codex sweep G, 13 Aug 2026).
        // The list is also a shortlist rather than a pick - a ZipCrypto
        // check byte accepts a wrong value once in 256 tries, so the
        // extraction below is what settles it (sweep F).
        let cands = passwords::zip_password_candidates(dir, &job.parts, password);
        info!(target: "extract", "unpacking {} natively…", job.shape.label());
        // TODO 205: one SET on the queue row's unpack lane, however many
        // candidates this container takes - `extract_one_zip` reports
        // each ATTEMPT, and only this call banks what the last one
        // produced. Three tries at one zip must publish one total.
        crate::unpackprog::begin_set();
        let mut last: Option<String> = None;
        let mut done = false;
        for (pw, source) in &cands {
            let out = match ExtractStaging::new(dir) {
                Ok(v) => v,
                Err(e) => {
                    last = Some(e.to_string());
                    break;
                }
            };
            match extract_one_zip(out.path(), dir, &job.parts, pw.as_deref())
                .and_then(|resumed| {
                    // Resumed members count as produced: their bytes are
                    // in the output directory rather than in staging, so
                    // an archive whose every entry resumed leaves this
                    // dir empty having delivered the whole payload.
                    if out.produced_anything() || resumed > 0 {
                        Ok(())
                    } else {
                        // "Succeeded" having written nothing is the silent
                        // success this codebase refuses everywhere else: the
                        // user would get a green job and an empty folder.
                        anyhow::bail!("the archive produced no files")
                    }
                })
                .and_then(|()| out.publish_into(dir))
            {
                Ok(()) => {
                    if pw.is_some()
                        && source != "job password"
                        && let Some(first) = job.parts.first()
                    {
                        passwords::log_auto_unlocked(first, source);
                    }
                    info!(target: "extract", "zip unpack complete ✔");
                    done = true;
                    break;
                }
                Err(e) => last = Some(e.to_string()),
            }
        }
        if !done {
            warn!(
                target: "extract",
                "zip unpack failed ({})",
                last.unwrap_or_else(|| "no candidate password opened it".into())
            );
            all_ok = false;
        }
    }
    all_ok
}

/// Extract one zip container (given its parts in read order) into `out`,
/// an `ExtractStaging` dir - never the directory holding the container.
///
/// Every entry goes through the same guards as the 7z path:
/// `sanitized_entry_path` for zip-slip, and `BombGuardWriter` against a
/// decompression bomb, with one budget shared across the whole archive.
/// Symlink entries are refused outright - their payload is a path, and
/// materializing one plants a link pointing wherever the archive likes.
///
/// `publish` and the returned count are the resume ledger, exactly as in
/// [`sevenz::extract_one_sevenz`]: a member a forfeited chase already
/// wrote a good prefix of is appended to in place and never staged.
pub(crate) fn extract_one_zip(
    out: &std::path::Path,
    publish: &std::path::Path,
    parts: &[PathBuf],
    password: Option<&str>,
) -> Result<usize> {
    // TODO 217's rewind, same shape as the RAR arm's: a resumed prefix
    // that fails its verification aborts the pass from inside the entry
    // writer; the ledger is then cleared and the pass runs once more
    // from byte zero. This arm never eats its sources.
    crate::resumeout::with_mismatch_retry(
        || true,
        |mismatch| zip_pass(out, publish, parts, password, mismatch),
    )
}

/// One attempt of [`extract_one_zip`], split out for the rewind.
fn zip_pass(
    out: &std::path::Path,
    publish: &std::path::Path,
    parts: &[PathBuf],
    password: Option<&str>,
    mismatch: &crate::resumeout::MismatchFlag,
) -> Result<usize> {
    let archive =
        nzbkit::zip::Archive::open(parts).map_err(|e| anyhow::anyhow!("opening zip: {e}"))?;
    // Budget and preallocation ceiling together, from the one helper the
    // 7z arm uses - see `extract_budget_and_prealloc_cap` for why they
    // cannot be derived from one flattened `u64`.
    let (bomb_budget, free_for_output) =
        crate::rarfix::extract_budget_and_prealloc_cap(crate::diskfree::free_bytes(out));
    let budget = BombBudget::fixed(bomb_budget);
    let written = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    // Refusals and directory shape first, before any payload byte: a
    // hostile entry anywhere in the directory aborts with nothing
    // written, and the file pass below is left with independent,
    // pre-vetted (entry, target) pairs.
    let mut files: Vec<(&nzbkit::zip::Entry, PathBuf)> = Vec::new();
    for e in archive.entries() {
        let target = sanitized_entry_path(out, &e.name)
            .ok_or_else(|| anyhow::anyhow!("entry {:?} escapes the output directory", e.name))?;
        if e.is_symlink() {
            anyhow::bail!("entry {:?} is a symlink, which is not extracted", e.name);
        }
        if e.is_dir {
            std::fs::create_dir_all(&target)?;
            continue;
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        files.push((e, target));
    }
    // No entry joins or leaves the list past this point: the guard below
    // GROUPS it and the pool writes every member of every group. It used
    // to shrink here, which is what a collision cost before bucketing.
    // Two entries can resolve to ONE output object: an exact duplicate
    // name (legal in the format), an alias that only collides after
    // normalization - `a\b` and `a/b` become the same path because
    // `sanitized_entry_path` maps RAR4-era backslashes to '/', and
    // sanitization folds more shapes together on Windows - or two
    // spellings that a case- and normalization-insensitive volume files
    // as ONE inode. That was harmless while entries extracted one at a
    // time, where the last writer simply won. It is not harmless on the
    // pool below: both workers `File::create` the same path, truncating
    // each other's inode, and each then verifies only ITS OWN entry's
    // CRC and length - so both report success over a file holding
    // interleaved bytes from two members.
    //
    // So colliding entries are BUCKETED rather than dropped, and a
    // bucket - not an entry - is the pool's unit of work: one worker
    // writes a whole bucket, in archive order, so the last entry wins
    // exactly as a one-at-a-time unpack would, and every member is still
    // decoded and CRC-checked on the way rather than silently skipped. A
    // singleton bucket is one entry, so nothing that does not collide
    // loses any parallelism.
    //
    // THE HISTORY IS LOAD-BEARING, because the obvious one-line fix is
    // still wrong and this is where somebody will reach for it.
    //
    //   The key WAS `to_string_lossy().to_lowercase()` on a
    //   case-insensitive volume, DELIBERATELY not
    //   `nzbkit::disk::case_fold_key`, the stronger fold M4-44 put at
    //   every other identity-key site in the tree on 31 Aug 2026. This
    //   was the one site where the two directions did not price the
    //   same, and the difference was the DROP: every other site resolves
    //   a collision by RENAMING, so an over-fold there costs a `001-`
    //   prefix and both files still land. Here it cost a FILE, because
    //   `seen` kept the last index per key and `files.retain` threw the
    //   rest away.
    //
    //   MEASURED 31 Aug 2026 on both filesystems, which is what settled
    //   it. On APFS `case_fold_key` over-folds NOTHING - zero over-folds
    //   across all 62,084 BMP codepoints legal in a filename, scored
    //   against the volume's OWN partition. On real NTFS it is not safe,
    //   and the gap is total rather than marginal: every pair APFS files
    //   as one object and lowercasing misses is TWO files on NTFS.
    //   Probed on the fleet's Windows box by creating both names and
    //   counting what landed - `STRASSE` beside `strasse`'s eszett form,
    //   `ssx` beside its eszett spelling, the ligature `file` beside
    //   `file`, long-s `sample` beside `sample`, final-sigma `odos`
    //   beside medial-sigma `odos`: two files every time. NTFS folds
    //   simple 1:1 case mappings (ASCII, sigma) and nothing else - not
    //   even the Kelvin sign, which IS a 1:1 mapping in Unicode. So the
    //   stronger fold would have merged names Windows keeps apart, and
    //   merging DROPPED one: a measured loss traded for a rarer bug,
    //   which is the wrong direction whatever the fold.
    //
    //   And lowercasing left the other half open, also knowingly: two
    //   spellings the volume files as ONE object - NFC vs NFD accented
    //   names on APFS, which is normalization-insensitive and
    //   preserving, plus the 925 codepoints in 438 classes that
    //   `to_lowercase` under-folds - were two keys here and one inode
    //   there, so the guard saw no collision at all and handed both to
    //   the pool. That was the race, and no fold swap closes it: closing
    //   it needed this guard to stop dropping first.
    //
    // Both halves are answered by asking the VOLUME instead of reasoning
    // about a spelling. On a case-insensitive volume each target is
    // pre-created empty and keyed by `nzbkit::disk::file_object_id` -
    // the filesystem's own answer to "are these one object", the same
    // door `unpack::PublishedNames` already asks through. It therefore
    // covers case, NFC/NFD, the under-folded codepoints and anything
    // else a volume merges, on APFS, HFS+ and NTFS alike, and it cannot
    // over-fold, because it never merges what the volume keeps apart.
    //
    // The probe files are removed again as soon as every id has been
    // read - they must all exist AT ONCE or two spellings of one object
    // get two different inodes in turn - so nothing downstream ever sees
    // a zero-byte target this pass did not write: not the resume ledger,
    // not the bomb budget, and not the kept-files accounting that
    // decides what survives a failed member.
    //
    // `case_fold_key` is the fallback for a target whose id will not
    // read, and taking it here is now safe for exactly the reason the
    // old comment named: once a collision serializes, an over-fold costs
    // wasted parallelism rather than a file that vanishes. On a
    // case-sensitive volume the raw path is the key, as before.
    let fold = nzbkit::disk::case_insensitive_dir(out);
    #[derive(PartialEq, Eq, Hash)]
    enum TargetKey {
        /// The volume's own answer: `(device, inode, 0)` on unix,
        /// `(volume serial, index hi, index lo)` on Windows. Machine-
        /// and run-local, compared and never persisted.
        Object((u64, u64, u64)),
        /// What the path SPELLS, for a target whose id would not read.
        Spelling(PathBuf),
    }
    let mut probed: Vec<&std::path::Path> = Vec::new();
    let mut keys: Vec<TargetKey> = Vec::with_capacity(files.len());
    for (_, target) in &files {
        if fold {
            if !target.exists() && std::fs::File::create(target).is_ok() {
                probed.push(target.as_path());
            }
            if let Some(id) = nzbkit::disk::file_object_id(target) {
                keys.push(TargetKey::Object(id));
                continue;
            }
        }
        keys.push(TargetKey::Spelling(if fold {
            PathBuf::from(nzbkit::disk::case_fold_key(&target.to_string_lossy()))
        } else {
            target.clone()
        }));
    }
    for p in &probed {
        let _ = std::fs::remove_file(p);
    }
    drop(probed);
    // Buckets in ARCHIVE ORDER, both across buckets and inside one, so
    // "the last entry wins" means the same thing it means to a
    // one-at-a-time unpack.
    let mut first_of: std::collections::HashMap<TargetKey, usize> =
        std::collections::HashMap::new();
    let mut buckets: Vec<Vec<usize>> = Vec::with_capacity(files.len());
    for (i, k) in keys.into_iter().enumerate() {
        match first_of.entry(k) {
            std::collections::hash_map::Entry::Occupied(at) => buckets[*at.get()].push(i),
            std::collections::hash_map::Entry::Vacant(v) => {
                v.insert(buckets.len());
                buckets.push(vec![i]);
            }
        }
    }
    drop(first_of);
    if buckets.len() != files.len() {
        let extra = files.len() - buckets.len();
        warn!(
            target: "extract",
            "{extra} zip entr{} resolve to an output file another entry already \
             claims - writing each group in archive order on one worker, so the \
             last of each wins, as a one-at-a-time unpack would",
            if extra == 1 { "y" } else { "ies" }
        );
    }
    // The resume ledger, read on THIS thread - the pool below opens its
    // entry writers on others, and the ledger is a thread-local.
    //
    // SINGLETON buckets only, which is narrower than the old list and
    // deliberately so. A member that shares its output file with another
    // entry either gets overwritten by the last of its bucket or does
    // the overwriting over bytes this same pass just wrote, so a
    // forfeited chase's published prefix is not a prefix of what lands
    // there and appending to it would splice two payloads. Such an
    // archive re-extracts those members from byte zero - the
    // pathological case, paying the one cost nobody meets in practice.
    let members: Vec<String> = buckets
        .iter()
        .filter(|b| b.len() == 1)
        .map(|b| files[b[0]].0.name.clone())
        .collect();
    let resume = crate::resumeout::plan_pass(publish, &members);
    // TODO 205: the queue row's unpack lane over the nested pass, from
    // the same counter the bomb guard already keeps. The total is taken
    // from `files` rather than from the central directory, so it is the
    // set of entries that will actually be written, which since the
    // bucketing above is simply all of them: a colliding entry is written
    // and then overwritten rather than skipped. A resumed member's prefix
    // is credited up front because this pass will not rewrite it.
    crate::unpackprog::attempt(
        &written,
        files
            .iter()
            .fold(0u64, |acc, (e, _)| acc.saturating_add(e.size())),
        resume
            .values()
            .fold(0u64, |acc, (_, len, _)| acc.saturating_add(*len)),
    );
    let resumed: std::sync::Mutex<Vec<PathBuf>> = std::sync::Mutex::new(Vec::new());
    // Entries are independent (each its own byte range, own output file,
    // positional reads through shared handles), so a multi-entry archive
    // decodes on a small pool - the same shape and bound as the encrypted
    // finish-decrypt's file fan-out. The bomb budget is shared across the
    // pool through the same atomic it always used.
    let one_entry =
        |e: &nzbkit::zip::Entry, target: &std::path::Path, resumable: bool| -> Result<()> {
            // Same seam as the 7z arm: a resumed member appends to its
            // published file at the mark, everything else creates a fresh
            // file in staging, and the two differ in nothing but the handle.
            let (file, skip, crc) = match resume.get(e.name.as_str()).filter(|_| resumable) {
                Some((path, len, crc)) => {
                    let f = crate::resumeout::open_at_mark(path, *len)?;
                    resumed.lock_ok().push(path.clone());
                    (f, *len, *crc)
                }
                None => {
                    let f = std::fs::File::create(target)?;
                    // Reservation bounded by the free space this pass may
                    // use, exactly as the 7z arm does it (round 9 measured
                    // 7z Copy 0.68 -> 0.45 s on NTFS from this alone).
                    let _ = nzbkit::disk::preallocate_output(&f, e.size(), free_for_output);
                    (f, 0, 0)
                }
            };
            // The disk write runs on its own thread; the bomb guard and the
            // resume accounting stay here, on the decode side, where they
            // cost nothing. `with_write_thread` owns the buffering, so there
            // is no `BufWriter` under this any more - its capacity WAS the
            // syscall size, and the hand-off buffers are that now.
            with_write_thread(file, |sink| {
                let mut w = crate::resumeout::ResumeWriter::verified(
                    skip,
                    crc,
                    mismatch.clone(),
                    BombGuardWriter {
                        inner: sink,
                        written: written.clone(),
                        budget: budget.clone(),
                    },
                );
                archive
                    .read_entry_to_with(e, &mut w, password)
                    .map_err(|err| anyhow::anyhow!("{err}"))?;
                use std::io::Write as _;
                w.flush()?;
                Ok(())
            })
        };
    // One bucket is one unit of work, so two entries that resolve to one
    // file never run at once - and two that do not are as parallel as
    // they were before this guard existed.
    let one_bucket = |b: &[usize]| -> Result<()> {
        let resumable = b.len() == 1;
        for &i in b {
            let (e, target) = &files[i];
            one_entry(e, target, resumable)?;
        }
        Ok(())
    };
    let workers = buckets
        .len()
        .min(nzbkit::mem::cpu_workers() / 2)
        .clamp(1, 4);
    if workers <= 1 {
        // Not `?` in the loop: the resumed files have to be handed back
        // to the ledger on the failure path too, and an early return
        // would leave an appended-to partial armed with a length that no
        // longer matches its mark - which the arm reads as somebody
        // else's published payload and leaves on disk.
        let mut res = Ok(());
        for b in &buckets {
            res = one_bucket(b);
            if res.is_err() {
                break;
            }
        }
        let resumed = resumed.into_inner().unwrap_or_else(|p| p.into_inner());
        crate::resumeout::finish(&resumed, res.is_ok());
        res?;
        return Ok(resumed.len());
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    let first_err: std::sync::Mutex<Option<anyhow::Error>> = std::sync::Mutex::new(None);
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(b) = buckets.get(i) else {
                        break;
                    };
                    // One failure condemns the archive (the staging dir is
                    // discarded whole), so don't decode the rest of it.
                    if first_err.lock_ok().is_some() {
                        break;
                    }
                    if let Err(err) = one_bucket(b) {
                        let mut g = first_err.lock_ok();
                        if g.is_none() {
                            *g = Some(err);
                        }
                    }
                }
            });
        }
    });
    let err = first_err.into_inner().unwrap_or_else(|p| p.into_inner());
    let resumed = resumed.into_inner().unwrap_or_else(|p| p.into_inner());
    crate::resumeout::finish(&resumed, err.is_none());
    if let Some(e) = err {
        return Err(e);
    }
    Ok(resumed.len())
}

/// Headroom the decompression-bomb guard leaves free on the target
/// volume: extraction may use everything but this. Shared by the disk
/// sink, the 7z sink and the in-stream extractor so all three read the
/// same line.
pub const EXTRACT_RESERVE: u64 = 256 * 1024 * 1024;

/// One free-space reading, turned into the two numbers an extraction
/// pass needs: the decompression-bomb budget, and the ceiling on how
/// much any single output file may be preallocated to.
///
/// ONE FUNCTION BECAUSE THE TWO ANSWERS DISAGREE ABOUT `None`, and a
/// caller that flattens the reading to a `u64` first cannot tell the
/// difference any more. An unreadable volume must not be guarded
/// (nothing measured it, so any budget is a guess that would kill
/// honest extractions) but also must not be preallocated against;
/// a volume with LESS than [`EXTRACT_RESERVE`] free is measured, is
/// the shape the guard exists for, and gets a budget of zero.
///
/// 9e73cf048 collapsed those two into the sentinel `0` and mapped it
/// back to `u64::MAX`, which handed the bomb an unlimited budget on
/// exactly the near-full volume it is there to protect - main's daemon
/// suite went red on five `daemon_bomb` rows the same hour. The zip and
/// tar sinks were never written that way and keep their one-liner; this
/// is for the two sinks that need the ceiling as well.
pub(crate) fn extract_budget_and_prealloc_cap(free: Option<u64>) -> (u64, u64) {
    match free.map(|f| f.saturating_sub(EXTRACT_RESERVE)) {
        Some(usable) => (usable, usable),
        None => (u64::MAX, 0),
    }
}

/// A `Write` whose bytes reach the file on ANOTHER thread, so the
/// caller's decode/decrypt/CRC work overlaps the disk write.
///
/// The zip arm's counterpart to the 7z arm's `piped_copy`, and it exists
/// for the same measured reason: with the buffer and AES fixes in,
/// `sample` put 45% of an AES-256 zip entry's samples in `write` and
/// nearly all the rest in the crypto chain feeding it, in series
/// (research/RAR-PERF-AUDIT-2026-09-02.md, round 13). It is a separate
/// type rather than a reuse of `piped_copy` because the zip entry reader
/// owns its own read loop (it CRCs every byte on the way past) and hands
/// down a `&mut dyn Write`, so the hand-off has to look like a writer
/// rather than like a copy.
///
/// Errors: a write failure stops the thread, and the next `write` here
/// sees the closed channel. It reports a placeholder so the caller
/// unwinds promptly; [`with_write_thread`] then REPLACES that with the
/// thread's real error, because the caller's own "entry shorter than its
/// declared size" would otherwise be the only thing reported for what is
/// really an ENOSPC.
struct ChannelWriter {
    full: Option<std::sync::mpsc::SyncSender<(Vec<u8>, usize)>>,
    empty: std::sync::mpsc::Receiver<Vec<u8>>,
    cur: Option<(Vec<u8>, usize)>,
}

impl ChannelWriter {
    /// Hand the current buffer over and take a fresh one.
    fn hand_off(&mut self) -> std::io::Result<()> {
        let Some((buf, len)) = self.cur.take() else {
            return Ok(());
        };
        if len == 0 {
            self.cur = Some((buf, 0));
            return Ok(());
        }
        let Some(full) = self.full.as_ref() else {
            return Err(std::io::Error::other(WRITE_THREAD_GONE));
        };
        full.send((buf, len))
            .map_err(|_| std::io::Error::other(WRITE_THREAD_GONE))?;
        Ok(())
    }
}

/// The stand-in a `ChannelWriter` reports when its thread has stopped;
/// [`with_write_thread`] swaps the thread's real error in for it.
const WRITE_THREAD_GONE: &str = "the output writer stopped";

impl std::io::Write for ChannelWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if data.is_empty() {
            // An explicit empty write is how a zero-byte entry creates
            // its file; the file already exists, so there is nothing to
            // send, and reporting 0 written is correct for `write_all`.
            return Ok(0);
        }
        if self.cur.is_none() {
            let buf = self
                .empty
                .recv()
                .map_err(|_| std::io::Error::other(WRITE_THREAD_GONE))?;
            self.cur = Some((buf, 0));
        }
        let (buf, len) = self.cur.as_mut().expect("buffer taken above");
        let n = (buf.len() - *len).min(data.len());
        buf[*len..*len + n].copy_from_slice(&data[..n]);
        *len += n;
        if *len == buf.len() {
            self.hand_off()?;
        }
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.hand_off()
    }
}

/// Run `f` with a writer whose `write` calls land on a second thread.
///
/// The thread's error wins over the closure's: see [`ChannelWriter`].
fn with_write_thread<T>(
    mut file: std::fs::File,
    f: impl FnOnce(&mut dyn std::io::Write) -> Result<T>,
) -> Result<T> {
    use std::io::Write as _;
    // Four buffers in flight, the same width and depth round 8 measured
    // for the 7z arm.
    const BUF: usize = 1 << 20;
    const POOL: usize = 4;
    let (full_tx, full_rx) = std::sync::mpsc::sync_channel::<(Vec<u8>, usize)>(POOL);
    let (empty_tx, empty_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(POOL);
    for _ in 0..POOL {
        let _ = empty_tx.send(vec![0u8; BUF]);
    }
    std::thread::scope(|scope| {
        let writer = scope.spawn(move || -> std::io::Result<()> {
            for (buf, len) in full_rx {
                file.write_all(&buf[..len])?;
                // The reader is gone; nothing left to hand back.
                if empty_tx.send(buf).is_err() {
                    break;
                }
            }
            file.flush()
        });
        let mut cw = ChannelWriter {
            full: Some(full_tx),
            empty: empty_rx,
            cur: None,
        };
        let called = f(&mut cw);
        // Flush the partial buffer, THEN drop the sender so the thread's
        // loop ends and the join below can report its verdict.
        let flushed = cw.flush();
        cw.full = None;
        let written = match writer.join() {
            Ok(r) => r,
            Err(_) => Err(std::io::Error::other("the output writer panicked")),
        };
        // The thread's error is the real one whenever it has one.
        written?;
        flushed?;
        called
    })
}

/// A writer that aborts once cumulative extracted bytes cross `budget`
/// (shared across all entries of an archive set) - the decompression-bomb
/// backstop for native RAR extraction.
pub(crate) struct BombGuardWriter<W: std::io::Write> {
    pub(crate) inner: W,
    pub(crate) written: std::sync::Arc<std::sync::atomic::AtomicU64>,
    pub(crate) budget: BombBudget,
}

/// The bomb guard's ceiling.
///
/// `base` is what the target filesystem had free (less the reserve) when
/// the extraction started. `credit` is space that has actually come BACK
/// during it - TODO 101's volume-eating unpack deleting a spent volume -
/// and it moves only after a `remove_file` has returned Ok.
///
/// That "actually" is the whole point. The eating path used to add
/// `volume_bytes(sources)` to the budget UP FRONT, on the grounds that
/// the volumes were about to be handed back one at a time. At the time
/// that was not true for the dominant movie shape - ONE member split
/// across every volume - because the RAR engine held every consumption
/// callback while a split member was pending and released the backlog
/// only after the finish fragment had written the WHOLE payload. A
/// 13.85 GB film with 1.75 GB free sailed past a guard that believed it
/// had 15.6 GB, and met the real disk instead: ENOSPC, a half-written
/// payload, and a filesystem with nothing left on it - the exact
/// outcome the guard exists to prevent, caused by the guard.
///
/// rars has since closed that gap (the H1 residual): a split member now
/// releases each volume as its chain reads it out, wherever a re-read
/// is provably impossible - stored members always, compressed ones
/// above the buffered-retry ceiling - so the single-split-member film
/// extracts in a couple of volumes' headroom. The delivery-only credit
/// stays exactly as it is: it is what makes that claim safe to act on
/// (a volume that failed to delete credits nothing), and it still
/// refuses cleanly on the residue of shapes that hold their volumes
/// (small compressed splits, which by definition fit the buffer).
#[derive(Clone)]
pub(crate) struct BombBudget {
    base: u64,
    credit: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl BombBudget {
    /// A budget nothing gives back to: every extraction except the
    /// volume-eating one.
    pub(crate) fn fixed(base: u64) -> Self {
        Self {
            base,
            credit: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }
    /// A handle on the credit side, for the consumption callback.
    fn credit_handle(&self) -> std::sync::Arc<std::sync::atomic::AtomicU64> {
        self.credit.clone()
    }
    fn limit(&self) -> u64 {
        self.base
            .saturating_add(self.credit.load(std::sync::atomic::Ordering::Relaxed))
    }
}

/// Catches the flush error BufWriter's Drop swallows. The vendored RAR
/// extractor verifies the DECODED bytes, then drops the entry writer and
/// returns success - so a failed write-back of the final buffered tail
/// (ENOSPC, quota, EIO) would otherwise publish a short file as a
/// verified extraction. Any error caught here (or in an explicit flush)
/// is recorded once in `failed`; the extraction caller turns it into a
/// failure before publishing.
struct DeferredFlushWriter<W: std::io::Write> {
    inner: W,
    failed: std::sync::Arc<std::sync::Mutex<Option<String>>>,
}

impl<W: std::io::Write> std::io::Write for DeferredFlushWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl<W: std::io::Write> Drop for DeferredFlushWriter<W> {
    fn drop(&mut self) {
        if let Err(e) = self.inner.flush() {
            self.failed
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get_or_insert_with(|| e.to_string());
        }
    }
}

impl<W: std::io::Write> std::io::Write for BombGuardWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        use std::sync::atomic::Ordering;
        let n = self.inner.write(buf)?;
        let total = self.written.fetch_add(n as u64, Ordering::Relaxed) + n as u64;
        if total > self.budget.limit() {
            // Plain `other`, and deliberately NOT the `StorageFull` that
            // `nzbkit::disk::WriteBudget::charge` raises for the identical
            // message on the in-stream path. That kind exists purely so
            // `storage_exhausted` classifies it and the fetch pool halts on
            // the first trip; this is the disk path, run after the download,
            // so there is no live fetch to halt. The error propagates
            // straight up through anyhow and aborts the extraction on its
            // own. Do not "fix" the two to match.
            //
            // The MESSAGE is shared, and deliberately so: the ladder in
            // `try_unrar_spent` reads it back off the anyhow error to
            // know that the next rung must not run (see
            // [`nzbkit::disk::bomb_verdict`]).
            return Err(std::io::Error::other(nzbkit::disk::BOMB_VERDICT));
        }
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

// The password ladder every arm above spends its candidates from. A
// child module here since the crate-split prep: each of its probes
// opens a container through this module, so it belongs beside them.
pub mod passwords;

/// Join an archive-entry name onto `dir`, rejecting traversal.
///
/// Defined in [`crate::resumeout`] since the crate-split prep and
/// re-exported here, because the extract paths reach it under both
/// names. It moved DOWN rather than the other way about: `resumeout`
/// resolves the same key to ask whether a forfeited chase already
/// published exactly there, so it was the one caller that had to reach
/// UP into the extractor for a path join.
pub(crate) use crate::resumeout::sanitized_entry_path;
#[cfg(test)]
pub(crate) use crate::resumeout::sanitized_entry_path_for;

/// Does the file start with the RAR marker (`Rar!`, v4 or v5)? Defined
/// in [`crate::archname`] since the crate-split prep and re-exported
/// here, because the callers reach it under both names.
pub(crate) use crate::archname::rar_magic;

#[cfg(test)]
#[path = "rarfix_rev_recovery_tests.rs"]
mod rarfix_rev_recovery_tests;

#[cfg(test)]
#[path = "rarfix_numeric_volume_tests.rs"]
mod rarfix_numeric_volume_tests;

#[cfg(test)]
mod native_unrar_tests;
#[cfg(test)]
mod rrhint_tests;

#[cfg(test)]
mod zip_extract_tests;

#[cfg(test)]
mod extract_budget_tests {
    use super::{EXTRACT_RESERVE, extract_budget_and_prealloc_cap as split};

    /// The near-full volume is the whole point, and the case 9e73cf048
    /// inverted: less free space than the reserve means a budget of
    /// ZERO - the guard at its strictest - and never `u64::MAX`.
    ///
    /// This lived only in the daemon suite until 3 Sep 2026, which is
    /// why a defect in it reached main: `daemon_bomb` is behind the
    /// `heavy-tests` feature and a whole daemon start-up, so nothing a
    /// lane runs while iterating covers it. The arithmetic is four
    /// lines and needs neither.
    #[test]
    fn a_volume_under_the_reserve_gets_a_zero_budget_not_an_unlimited_one() {
        for free in [
            0,
            1,
            1 << 20,
            200_000_000,
            EXTRACT_RESERVE - 1,
            EXTRACT_RESERVE,
        ] {
            assert_eq!(
                split(Some(free)),
                (0, 0),
                "{free} bytes free is at or under the {EXTRACT_RESERVE}-byte reserve, \
                 so nothing may be extracted and nothing may be reserved"
            );
        }
    }

    /// A measured volume with room spends what is over the reserve, and
    /// the preallocation ceiling is the same number - a reservation may
    /// never promise more than the guard would allow to be written.
    #[test]
    fn a_volume_with_room_spends_what_is_over_the_reserve() {
        assert_eq!(split(Some(EXTRACT_RESERVE + 4096)), (4096, 4096));
        assert_eq!(
            split(Some(u64::MAX)),
            (u64::MAX - EXTRACT_RESERVE, u64::MAX - EXTRACT_RESERVE)
        );
    }

    /// AND THE TWO ANSWERS DIVERGE for a volume nothing could measure:
    /// unguarded, because any budget would be a guess that kills honest
    /// extractions, but reserving nothing, because a reservation cannot
    /// be sized against an unknown. Collapsing these two to one `u64`
    /// is the shape of the defect this function exists to prevent.
    #[test]
    fn an_unreadable_volume_is_unguarded_and_unreserved() {
        assert_eq!(split(None), (u64::MAX, 0));
    }
}
