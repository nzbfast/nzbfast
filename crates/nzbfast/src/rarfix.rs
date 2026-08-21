//! Disk-side archive extraction and RAR repair: the native unrar path, .rev reconstruction, RAR5 recovery-record repair, and the 7z/zip disk extraction twins.
//!
//! Split out of main.rs verbatim; behaviour unchanged.

use crate::*;

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
pub(crate) fn try_unrar_spent(
    dir: &std::path::Path,
    password: Option<&str>,
) -> Option<Vec<PathBuf>> {
    // Test canary: encrypted-store e2e jobs must complete WITHOUT unrar
    // (native decryption); reaching here with the canary set fails the
    // job loudly instead of quietly proving nothing.
    if std::env::var_os("NZBFAST_TEST_FORBID_UNRAR").is_some() {
        println!("⚠ unrar invocation forbidden by NZBFAST_TEST_FORBID_UNRAR");
        return None;
    }
    // Sibling binary, else the copy embedded in this executable, else
    // PATH (see tools.rs).
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
            return None;
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
        return extract_obfuscated_rar(dir, &obf, password, 1).then(Vec::new);
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
        if published.is_empty() {
            return Vec::new();
        }
        consumed
            .into_iter()
            .filter(|p| !published.contains(p))
            .collect()
    };
    // EVERY stem group in the directory, the caller's chosen first volume
    // leading - not just that one group. `first_rar_volume` picks a single
    // volume across the whole directory and `try_rars_native` then scopes
    // itself to that volume's stem, so returning on its success reported
    // "the directory is unpacked" having unpacked ONE set. A demoted post
    // with two top-level sets (`extras.rar/.r00…` beside
    // `s01e01.rar/.r00…`, no `.part`, so the lexically first wins) then
    // finished Completed with the whole episode still packed: the nested
    // pass skips it too, because its stem IS an outer stem and no foreign
    // archive sits beside it.
    //
    // This also subsumes the decoy retry it replaces (a same-size random
    // `.rar`, or SABnzbd's `par2test.part1.11.rar` shadowing
    // `par2test.part1.rar`): a decoy is simply a group that produces
    // nothing. Success is unchanged - at least one group produced - so a
    // decoy that fails cannot now fail a job that used to pass.
    //
    // The group list is built from ONE directory read taken before any
    // extraction, so a set published by an earlier group (RAR-in-RAR)
    // never enters it; the nested pass owns that layer as it always did.
    //
    // BOTH engines walk this list. Scoping only the native pass to it left
    // the unrar fallback - the path a compressed set takes when the native
    // extractor declines - unpacking the lead group and reporting the whole
    // directory done, which is the same bug one layer down.
    let mut groups: Vec<(String, Vec<PathBuf>)> = Vec::new();
    {
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
            .entry(group_key(&first))
            .or_default()
            .push(first.clone());
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
        let lead = group_key(&first);
        if let Some(g) = by_stem.remove(&lead) {
            groups.push((lead, g));
        }
        groups.extend(by_stem);
    }
    // Said ONCE, at the end, naming every set still packed - and only when
    // something else did unpack, which is the case that finishes the job
    // Completed. Per-group warnings scroll past mid-extraction and read
    // like routine noise ("a decoy failed, as decoys do"); the whole point
    // here is that a legitimate second set may be sitting in the output
    // directory, still packed, on a job that reported success.
    let report_leftovers = |failed: &[String]| {
        if failed.is_empty() {
            return;
        }
        println!(
            "⚠ {} of {} archive set(s) in this directory did not unpack and are still \
             packed: {}. If one of those is the release (rather than a decoy or a \
             sample), it needs a password, a repair, or a newer unpacker.",
            failed.len(),
            groups.len(),
            failed.join(", ")
        );
    };
    // Native in-process extraction first (vendored rars fork - measured
    // faster than unrar on every compressed-RAR bench leg); the unrar
    // subprocess stays as the escape hatch, chosen by the daemon's
    // `prefer_external_unrar` setting or its `NZBFAST_NO_NATIVE_UNRAR`
    // env override.
    if !nzbkit::extract::prefer_external_unrar() {
        println!("unpacking archive natively…");
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
        let mut failed: Vec<String> = Vec::new();
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
            let group_pw = crate::unpack::resolve_rar_group_password(dir, group, password);
            let pw = group_pw.as_deref().or(password);
            match try_rars_native(dir, &group_first, pw) {
                Ok(consumed) => {
                    println!("native unpack complete ✔ ({})", group_first.display());
                    consumed_all.extend(consumed);
                    produced = true;
                }
                Err(e) => {
                    println!("⚠ native unpack failed for '{what}' ({e})");
                    failed.push(what);
                }
            }
        }
        if produced {
            report_leftovers(&failed);
            return Some(spent(consumed_all));
        }
        // §101: nothing produced, and under the eating mode the failed
        // pass may have consumed volumes on its way down - in which case
        // the unrar escape hatch below would be handed a directory with
        // no volumes in it and fail for a reason that has nothing to do
        // with unrar. Say what actually happened; the caller turns a
        // None into a job failure either way, but the log is the only
        // place this is explicable.
        if groups.iter().any(|(_, g)| g.iter().any(|p| !p.exists())) {
            println!(
                "⚠ volumes were consumed as they were read (the volume-eating unpack), \
                 so there is nothing left for unrar to retry - a retry re-downloads the set"
            );
            return None;
        }
        println!("falling back to unrar…");
    }
    println!("unpacking archive with unrar…");
    // One subprocess per stem group, on the same list and the same success
    // rule as the native pass above. The password resolves per GROUP here
    // too (U1/U2, same reasoning as the native loop above).
    let unrar_group = |group_first: &PathBuf, group: &[PathBuf]| -> Option<Vec<PathBuf>> {
        let group_pw = crate::unpack::resolve_rar_group_password(dir, group, password);
        let pw = group_pw.as_deref().or(password);
        // `-p<pw>` must be a single argument; bare `-p` would prompt and hang.
        let parg = match pw {
            Some(p) if !p.is_empty() => format!("-p{p}"),
            _ => "-p-".to_string(),
        };
        // The volume set the subprocess is about to read, listed BEFORE it
        // runs - the unpack can publish rar-named members of its own, and
        // those must never be mistaken for input volumes.
        let consumed = stem_volume_set(dir, group_first).unwrap_or_default();
        // Same staging discipline as the native path: `-o+` overwrites without
        // asking, and unrar reads the volume set by path as it goes, so a member
        // named after a volume would destroy the set mid-extraction. The
        // trailing positional argument is unrar's destination directory; it is
        // relative because cwd is `dir`, and it must end in a separator.
        let staging = match ExtractStaging::new(dir) {
            Ok(s) => s,
            Err(e) => {
                println!("⚠ could not create a staging directory ({e})");
                return None;
            }
        };
        let dest_arg = {
            let mut a = std::ffi::OsString::from(staging.path().file_name().unwrap_or_default());
            a.push(std::path::MAIN_SEPARATOR_STR);
            a
        };
        match std::process::Command::new(&unrar)
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
                println!("⚠ unrar exited 0 but extracted nothing - treating as a failure");
                None
            }
            Ok(st) if st.success() => match staging.publish_into(dir) {
                Ok(()) => {
                    println!("unrar complete ✔ ({})", group_first.display());
                    Some(consumed)
                }
                Err(e) => {
                    println!("⚠ {e}");
                    None
                }
            },
            Ok(st) if pw.is_some() => {
                println!("⚠ unrar exited with {st} - wrong password, or damaged volumes");
                None
            }
            Ok(st) => {
                println!("⚠ unrar exited with {st} (encrypted or damaged?)");
                None
            }
            // "not runnable (No such file or directory (os error 2))" is what
            // a container user saw after the native path failed, and it names
            // neither the cause nor the cure. The release image ships no unrar
            // on purpose (extraction is native), so ENOENT here is the common
            // case, not the exotic one, and it deserves its own sentence.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                println!(
                    "⚠ unrar is not installed, so there was nothing to fall back to \
                     - volumes left on disk"
                );
                println!("  install unrar to enable this fallback, or unpack them by hand");
                None
            }
            Err(e) => {
                println!("⚠ unrar not runnable ({e}) - volumes left on disk");
                None
            }
        }
    };
    let mut consumed_all: Vec<PathBuf> = Vec::new();
    let mut produced = false;
    let mut failed: Vec<String> = Vec::new();
    for (stem, group) in &groups {
        let Some(group_first) = first_rar_volume(group) else {
            continue;
        };
        match unrar_group(&group_first, group) {
            Some(consumed) => {
                consumed_all.extend(consumed);
                produced = true;
            }
            None => failed.push(if stem.is_empty() {
                group_first.display().to_string()
            } else {
                stem.clone()
            }),
        }
    }
    if produced {
        report_leftovers(&failed);
    }
    produced.then(|| spent(consumed_all))
}

/// Part B of the 2026-07-29 one-pass spec: a set that just unpacked has
/// spent its volumes - they are our own working files, removed in place
/// (`fs::remove_file`, never the trash path). Callers hand this exactly
/// what [`try_unrar_spent`] reported, so every deliberate keep (a failed
/// or partial unpack, an encrypted set still waiting for its password,
/// the obfuscated sweep's refusals) never reaches here.
pub(crate) fn remove_spent_volumes(vols: &[PathBuf]) {
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
            Err(e) => println!("⚠ could not remove spent volume {}: {e}", p.display()),
        }
    }
    if removed > 0 {
        println!("  removed {removed} volume file(s) after extraction");
    }
}

/// Last resort after PAR2 is exhausted: repair damaged volumes using the
/// RAR recovery records embedded in the volumes themselves (RAR5 RR and
/// RAR2/3 old-style protect records, per volume, via the vendored rars),
/// then re-attempt extraction. Extraction is the post-repair verification:
/// RAR5 RR repair does not re-checksum rebuilt shards on its own, but the
/// native extraction path CRC-verifies every entry.
///
/// Returns true only when extraction afterwards succeeds.
pub(crate) fn try_rar_rr_repair(dir: &std::path::Path, password: Option<&str>) -> bool {
    let volumes = match collect_rar_volumes(dir) {
        Ok(volumes) if !volumes.is_empty() => volumes,
        _ => return false,
    };
    println!(
        "PAR2 exhausted - trying embedded RAR recovery records on {} volume(s)…",
        volumes.len()
    );
    // Group by stem and resolve the password PER GROUP, as both try_unrar
    // rungs do. This rung took the caller's raw value straight into
    // rr_repair_volume, so a set whose password lives in a harvested
    // sidecar (the nested password-chain shape) failed every
    // header-encrypted volume parse and the repair reported "could not
    // save the set" on a set it could have saved (14 Aug sweep; the
    // per-group resolve moved out of extract_one_level in U2/b1c20eea and
    // this rung never got one).
    let mut by_stem: std::collections::BTreeMap<String, Vec<&PathBuf>> = Default::default();
    {
        use nzbkit::extract::release_stem;
        for p in &volumes {
            let stem = release_stem(
                &p.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_lowercase(),
            )
            .to_string();
            by_stem.entry(stem).or_default().push(p);
        }
    }
    let mut rewritten = 0usize;
    let mut hard_failures = 0usize;
    for group in by_stem.values() {
        let owned: Vec<PathBuf> = group.iter().map(|p| (*p).clone()).collect();
        let group_pw = crate::unpack::resolve_rar_group_password(dir, &owned, password);
        let pw = group_pw.as_deref().or(password);
        for path in group {
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            match rr_repair_volume(path, pw) {
                Ok(true) => {
                    println!("  ✔ {name} - rewritten from recovery record");
                    rewritten += 1;
                }
                Ok(false) => println!("  – {name} - no recovery record"),
                Err(e) => {
                    println!("  ✘ {name} - {e}");
                    hard_failures += 1;
                }
            }
        }
    }
    if rewritten == 0 || hard_failures > 0 {
        println!("⚠ recovery-record repair could not save the set");
        return false;
    }
    try_unrar(dir, password)
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
                println!("  – {name}: unreadable .rev ({e})");
                continue;
            }
        };
        let meta = match rars::rar50::read_rev5_meta(&source) {
            Ok(meta) => meta,
            Err(e) => {
                println!("  – {name}: unusable .rev ({e})");
                continue;
            }
        };
        match rars::rar50::verify_rev5_payload(&source, &meta) {
            Ok(true) => {}
            Ok(false) => {
                println!("  – {name}: .rev payload fails its own checksum");
                continue;
            }
            Err(e) => {
                println!("  – {name}: unreadable .rev payload ({e})");
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
        println!(
            "  – {} independent .rev sets in this folder; trying each",
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
    println!(
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
        println!("  – all data volumes verify; .rev not needed");
        return false;
    }
    if missing.len() > keep.len() {
        println!(
            "  ✘ {} volume(s) missing but only {} usable .rev file(s) - unrepairable",
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
                    println!("  ✘ {} became unreadable ({e})", path.display());
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
                    println!("  ✘ cannot stage a rebuild for slot {} ({e})", index + 1);
                    cleanup_temps(&temps);
                    return false;
                }
            }
        }
        let Some(made) = made else {
            println!("  ✘ no free temp name for slot {}", index + 1);
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
        println!("  ✘ .rev reconstruction failed ({e})");
        cleanup_temps(&temps);
        return false;
    }
    if let Some(e) = write_error {
        println!("  ✘ .rev reconstruction could not be written ({e})");
        cleanup_temps(&temps);
        return false;
    }

    // Verify every rebuild against the metadata's own checksum BEFORE any of
    // them is published. A rebuild that does not match is not a volume, and
    // publishing one would replace a known-bad file with an unknown-bad one.
    for (slot, &index) in missing.iter().enumerate() {
        let (path, file) = &mut temps[slot];
        if let Err(e) = file.sync_all() {
            println!(
                "  ✘ could not flush the rebuild for slot {} ({e})",
                index + 1
            );
            cleanup_temps(&temps);
            return false;
        }
        match rars::recovery::stream::crc32_of(path) {
            Ok((crc, len)) if crc == slots[index].crc32 && len == slots[index].file_size => {}
            Ok(_) => {
                println!(
                    "  ✘ rebuilt slot {} fails its checksum - discarded",
                    index + 1
                );
                cleanup_temps(&temps);
                return false;
            }
            Err(e) => {
                println!("  ✘ cannot verify the rebuild for slot {} ({e})", index + 1);
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
                println!("  ✔ {name} - rebuilt from .rev");
                rebuilt += 1;
            }
            Err(e) => println!("  ✘ {name} - could not be published ({e})"),
        }
    }
    cleanup_temps(&temps);
    rebuilt > 0
}

/// Repair one volume in place from its own recovery record.
/// Ok(true) = rewritten (atomic rename), Ok(false) = no RR / unsupported
/// family (clean skip), Err = volume has RR but repair failed.
pub(crate) fn rr_repair_volume(path: &std::path::Path, password: Option<&str>) -> Result<bool> {
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
    let (tmp, tmp_file) = {
        let mut made = None;
        for n in 0..1024 {
            let candidate = path.with_extension(format!("rrtmp{n}"));
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
    let repair_result = match rars::ArchiveReader::read_path_with_options(path, options) {
        Ok(archive) => {
            // The path form, not the file form: with the destination PATH in
            // hand the library can clone the volume (APFS/btrfs reflink)
            // instead of copying it, which is most of an undamaged-tail
            // repair. The create_new claim above still owns the name.
            drop(tmp_file);
            archive
                .repair_recovery_to_path(&tmp, password.map(str::as_bytes), budget)
                .map(|_| ())
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
                Ok(_) => Ok(()),
                Err(rars::Error::UnsupportedSignature) => {
                    cleanup(&tmp);
                    anyhow::bail!("unparseable and not a RAR5 volume");
                }
                Err(e) => Err(e),
            }
        }
    };
    match repair_result {
        Ok(()) => {
            std::fs::rename(&tmp, path)?;
            Ok(true)
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
                return Ok(false);
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
pub(crate) fn collect_rar_volumes(dir: &std::path::Path) -> Result<Vec<PathBuf>> {
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

/// Post-repair: run the store-mode extraction over repaired volume files
/// on disk (a straight remap copy - repair already verified the bytes).
/// A success also returns the volume files it read, so a finalize caller
/// can delete exactly the spent set.
pub(crate) fn try_rars_native(
    dir: &std::path::Path,
    first: &std::path::Path,
    password: Option<&str>,
) -> Result<Vec<PathBuf>> {
    let volumes = stem_volume_set(dir, first)?;
    if volumes.is_empty() {
        anyhow::bail!(
            "no volumes found for {}",
            first.file_name().unwrap_or_default().to_string_lossy()
        );
    }
    // Parse WITH the password: header-encrypted (-hp) volumes need it just
    // to read their headers - without it every -hp set silently fell back
    // to the unrar subprocess (and failed outright where unrar is absent).
    let options = nzbkit::mem::rar_read_options(password.map(str::as_bytes));
    // One parse session for the whole set: repeated (salt, kdf count)
    // derivations run once instead of once per volume.
    let mut parse = rars::ReadSession::new(options);
    let archives = volumes
        .iter()
        .map(|path| parse.read_path(path))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("parsing volumes: {e}"))?;
    // `volumes` and `archives` are the same set in the same order, which
    // is what lets §101's eating mode delete each volume as the extractor
    // finishes with it.
    write_archives_to_spending(dir, &archives, password, &volumes)?;
    Ok(volumes)
}

/// Stream a parsed RAR volume set out to `dir` under each entry's real
/// name, path-sanitized and bounded by the decompression-bomb guard.
/// Shared by the named-set path and the obfuscated-set path.
///
/// Output lands in an `ExtractStaging` dir and is published into `dir`
/// only once the whole set has decoded - the volumes being read are
/// reopened by path for every range, so nothing may be created beside
/// them while extraction runs.
pub(crate) fn write_archives_to(
    dir: &std::path::Path,
    archives: &[rars::Archive],
    password: Option<&str>,
) -> Result<()> {
    write_archives_to_spending(dir, archives, password, &[])
}

/// [`write_archives_to`] that also knows which FILE each archive was
/// parsed from, so a job running under TODO 101's volume-eating mode can
/// delete each one the moment the extractor is finished with it.
///
/// `sources[i]` must be the path `archives[i]` was read from; hand `&[]`
/// when the mapping is not known and the eating path is skipped entirely.
/// Eating additionally requires [`crate::eatvol::armed`] - the per-job
/// arming the daemon does once all of §101's gates have passed - so this
/// is inert for every ordinary unpack.
pub(crate) fn write_archives_to_spending(
    dir: &std::path::Path,
    archives: &[rars::Archive],
    password: Option<&str>,
    sources: &[PathBuf],
) -> Result<()> {
    // Eating needs a source path for EVERY archive: a partial mapping
    // would delete some volumes and keep others, which is the worst of
    // both (space not really freed, retry-without-refetch already lost).
    let eating = crate::eatvol::armed() && !sources.is_empty() && sources.len() == archives.len();
    // Decompression-bomb guard: bound total extracted bytes at the target
    // filesystem's free space minus a reserve, so a crafted archive that
    // unpacks to far more than it downloaded (a store-mode "zip bomb")
    // can't fill the disk. It never trips on a legitimate large extract
    // that actually fits. Active wherever disk_stat answers, which is now
    // every platform we ship - windows included, since GetDiskFreeSpaceExW
    // landed; before that free_bytes was None there and this guard silently
    // did nothing.
    //
    // Under eating the volume bytes come back one file at a time, and
    // that is the entire point of the mode - so the guard has to grow as
    // they do, or it reads the disk as it stands at the FIRST byte
    // (which on a job that armed `low_disk` is nearly full by
    // definition) and kills the extraction the mode exists to rescue.
    //
    // It grows on DELIVERY, never on promise: see [`BombBudget`] for the
    // shape that pre-crediting `volume_bytes(sources)` broke, and why it
    // broke it on the commonest set of all.
    let budget = BombBudget::fixed(
        crate::serve::free_bytes(dir)
            .map(|free| free.saturating_sub(EXTRACT_RESERVE))
            .unwrap_or(u64::MAX),
    );
    let credit = budget.credit_handle();
    let written = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

    let staging = ExtractStaging::new(dir)?;
    let stage_dir = staging.path().to_path_buf();
    // The vendored extractor drops each entry writer AFTER deciding
    // success on the decoded bytes, and BufWriter's Drop swallows its
    // flush error - so an ENOSPC/EIO on the final buffered tail would
    // publish a short file as a verified extraction (with the source
    // volumes possibly already eaten). DeferredFlushWriter records the
    // swallowed error here; checked below before publish.
    let flush_err: std::sync::Arc<std::sync::Mutex<Option<String>>> =
        std::sync::Arc::new(std::sync::Mutex::new(None));
    let entry_flush_err = flush_err.clone();
    let open = move |meta: &rars::ExtractedEntryMeta| {
        let target = sanitized_entry_path(&stage_dir, &meta.name_lossy()).ok_or_else(|| {
            rars::Error::from(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "archive entry escapes output directory",
            ))
        })?;
        if meta.is_directory {
            std::fs::create_dir_all(&target)?;
            return Ok(Box::new(std::io::sink()) as Box<dyn std::io::Write>);
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::io::BufWriter::new(std::fs::File::create(target)?);
        Ok(Box::new(DeferredFlushWriter {
            inner: BombGuardWriter {
                inner: file,
                written: written.clone(),
                budget: budget.clone(),
            },
            failed: entry_flush_err.clone(),
        }) as Box<dyn std::io::Write>)
    };
    if eating {
        println!(
            "unpacking {} volume(s), deleting each as it is used up…",
            sources.len()
        );
        let mut eaten = 0usize;
        let mut bytes = 0u64;
        // A HARD delete, deliberately not the trash-aware helper: the
        // whole promise of the mode is that the space comes back this
        // instant, and a Trash on the same filesystem gives back nothing.
        // The callback is only ever reached for a volume rars has
        // finished reading - see the guarantees on
        // `extract_volumes_to_with_progress`.
        let consumed = |i: usize| {
            let Some(path) = sources.get(i) else { return };
            // symlink_metadata, and only single-link regular files
            // count: unlinking a symlink or one name of a hardlinked
            // file releases no data blocks, so crediting the target's
            // length would let the guard spend space the disk never
            // gave back - and meet real ENOSPC mid-extraction after
            // the source names are gone.
            let meta = std::fs::symlink_metadata(path).ok();
            let size = match &meta {
                Some(m) if m.is_file() && sole_link(m) => m.len(),
                _ => 0,
            };
            match std::fs::remove_file(path) {
                Ok(()) => {
                    eaten += 1;
                    bytes = bytes.saturating_add(size);
                    // The space is back NOW, so the guard may spend it
                    // now - and not one byte before. A volume we could
                    // not remove credits nothing, which is exactly what
                    // the warning below is about.
                    credit.fetch_add(size, std::sync::atomic::Ordering::Relaxed);
                }
                // Not fatal: extraction has already read this volume, so
                // a file we cannot remove costs space, not correctness.
                Err(e) => println!("⚠ could not remove spent volume {}: {e}", path.display()),
            }
        };
        let result = rars::extract_volumes_to_with_progress(
            archives,
            rars::ArchiveReadOptions::with_optional_password(password.map(str::as_bytes)),
            open,
            consumed,
        );
        if eaten > 0 {
            println!(
                "  freed {eaten} spent volume(s) during extraction ({:.1} GB)",
                bytes as f64 / 1e9
            );
        }
        result.map_err(|e| anyhow::anyhow!("{e}"))?;
    } else {
        rars::extract_volumes_to(archives, password.map(str::as_bytes), open)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    if let Some(e) = flush_err.lock().unwrap_or_else(|p| p.into_inner()).take() {
        anyhow::bail!("extracted file could not be fully written to disk: {e}");
    }
    staging.publish_into(dir)
}

/// True when the file has exactly one directory entry, so unlinking it
/// actually releases its blocks. Non-unix hosts cannot cheaply ask, and
/// hardlinked volume sets are a unix habit - treat single-link as true
/// there.
fn sole_link(m: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::fs::MetadataExt::nlink(m) == 1
    }
    #[cfg(not(unix))]
    {
        let _ = m;
        true
    }
}

/// If `name` is a split 7-Zip part (`<base>.7z.<NNN>`), return the shared
/// base and the numeric part index.
pub(crate) fn split_7z_part(name: &str) -> Option<(String, u32)> {
    let (head, tail) = name.rsplit_once('.')?;
    if tail.is_empty() || !tail.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    head.to_lowercase()
        .ends_with(".7z")
        .then(|| (head.to_string(), tail.parse().ok().unwrap_or(u32::MAX)))
}

/// Every 7-Zip job in `dir`: single `.7z` (or 7z-magic) containers, plus
/// `.7z.NNN` split sets grouped and ordered by part index. Each job is
/// the ordered list of on-disk parts that form one container.
///
/// The magic sniff accepts any extension except a named payload one
/// (`nzbkit::extract::is_final_name` - a `.cb7` comic is the
/// deliverable). It used to require an EMPTY extension, so an
/// obfuscated container posted as `hash.bin` was invisible here: the
/// disk post-pass walked past it, nothing extracted, and the job
/// reported Completed holding one unopened archive. Obfuscation strips
/// the meaning from an extension, not the extension itself.
pub(crate) fn collect_sevenz_archives(dir: &std::path::Path) -> Result<Vec<Vec<PathBuf>>> {
    use std::collections::BTreeMap;
    let mut singles: Vec<PathBuf> = Vec::new();
    let mut splits: BTreeMap<String, BTreeMap<u32, PathBuf>> = BTreeMap::new();
    for e in std::fs::read_dir(dir)?.flatten() {
        if !e.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        let path = e.path();
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();
        if let Some((base, num)) = split_7z_part(&name) {
            splits.entry(base).or_default().insert(num, path);
        } else if name.ends_with(".7z")
            || (!nzbkit::extract::is_final_name(&name) && sevenz_magic(&path))
        {
            // Named, or obfuscated under any name at all - except a
            // named payload file (`.cb7`), whose 7z bytes ARE the
            // deliverable and must never be unpacked.
            singles.push(path);
        }
    }
    let mut jobs: Vec<Vec<PathBuf>> = singles.into_iter().map(|p| vec![p]).collect();
    for (_base, parts) in splits {
        jobs.push(parts.into_values().collect());
    }
    Ok(jobs)
}

/// Extract every 7-Zip job in `dir`. Split sets are concatenated into a
/// scratch container first (7z multipart is a raw byte split). Returns
/// true only if every job extracted.
///
/// Two separate scratch dirs per job, both outside the output namespace:
/// one holds the joined container, the other collects members until the
/// whole container has decoded. A `release.7z` carrying a member named
/// `release.7z` would otherwise truncate the inode still backing its own
/// reader - and putting the join temp beside the members would move that
/// same hazard onto the joined copy.
pub(crate) fn extract_sevenz(
    dir: &std::path::Path,
    jobs: &[Vec<PathBuf>],
    password: Option<&str>,
) -> bool {
    let mut all_ok = true;
    for parts in jobs.iter() {
        // `join` stays alive for the whole iteration: dropping it removes
        // the joined container the reader is still using.
        let (out, join, container) = match prepare_sevenz_job(dir, parts) {
            Ok(v) => v,
            Err(e) => {
                println!("⚠ {e}");
                all_ok = false;
                continue;
            }
        };
        println!("unpacking 7z archive natively…");
        // Per CONTAINER, like the zip arm: one resolved value per level
        // handed every 7z job the first job's password (Codex sweep G).
        // A shortlist rather than a pick, because a probe that hit the
        // 64 MB cap never reached the entry's checksum and cannot settle
        // anything (sweep M) - the extraction does.
        let cands = crate::unpack::sevenz_password_candidates(&container, dir, password);
        let mut last: Option<String> = None;
        let mut done = false;
        // `publish_into` consumes its staging dir, so a retry needs a
        // fresh one; the prepared dir is the first attempt's.
        let mut prepared = Some(out);
        for (pw, source) in &cands {
            let out = match prepared
                .take()
                .map(Ok)
                .unwrap_or_else(|| ExtractStaging::new(dir))
            {
                Ok(v) => v,
                Err(e) => {
                    last = Some(e.to_string());
                    break;
                }
            };
            match extract_one_sevenz(out.path(), &container, pw.as_deref())
                .and_then(|()| out.publish_into(dir))
            {
                Ok(()) => {
                    if pw.is_some() && source != "job password" {
                        println!("🔑 auto-unlocked with password from {source}");
                    }
                    println!("7z unpack complete ✔");
                    done = true;
                    break;
                }
                Err(e) => last = Some(e.to_string()),
            }
        }
        if !done {
            println!(
                "⚠ 7z unpack failed ({})",
                last.unwrap_or_else(|| "no candidate password opened it".into())
            );
            all_ok = false;
        }
        drop(join);
    }
    all_ok
}

/// Staging dirs + container path for one 7-Zip job: the output dir, the
/// scratch dir holding the joined container (multipart sets only), and the
/// container to read.
pub(crate) fn prepare_sevenz_job(
    dir: &std::path::Path,
    parts: &[PathBuf],
) -> Result<(ExtractStaging, Option<ExtractStaging>, PathBuf)> {
    let out = ExtractStaging::new(dir)?;
    if parts.len() == 1 {
        return Ok((out, None, parts[0].clone()));
    }
    let scratch = ExtractStaging::new(dir)?;
    let container = scratch.path().join("joined.7z");
    concat_files(parts, &container)
        .map_err(|e| anyhow::anyhow!("joining 7z split parts failed ({e})"))?;
    Ok((out, Some(scratch), container))
}

/// Concatenate `parts` (already in order) into `dest`.
pub(crate) fn concat_files(parts: &[PathBuf], dest: &std::path::Path) -> Result<()> {
    let mut out = std::io::BufWriter::new(std::fs::File::create(dest)?);
    for p in parts {
        let mut f = std::fs::File::open(p)?;
        std::io::copy(&mut f, &mut out)?;
    }
    use std::io::Write as _;
    out.flush()?;
    Ok(())
}

/// Extract one 7-Zip container into `out` (an `ExtractStaging` dir, never
/// the directory holding the container), path-sanitized and bounded by the
/// same decompression-bomb guard as the RAR path.
pub(crate) fn extract_one_sevenz(
    out: &std::path::Path,
    container: &std::path::Path,
    password: Option<&str>,
) -> Result<()> {
    use sevenz_rust2::{ArchiveReader, Password};
    let pw = match password {
        Some(p) if !p.is_empty() => Password::from(p),
        _ => Password::empty(),
    };
    // The shared declared-size gate (nzbkit's nameprobe, TODO 156 item
    // 5): ArchiveReader::open buffers the declared end header whole and
    // decodes a packed one with the declared sizes as its only bounds,
    // and a chased container that refused at the in-stream gate demotes
    // to exactly this path - so the refusal here must be a named error,
    // not an allocation. The declared variant also judges the CONTENT
    // blocks' dictionary and PPMd declarations, which the extraction
    // below would otherwise allocate unbounded. Malformed shapes fall
    // through to the library's own cheap error, same as the probe
    // halves of the gate.
    if let Ok(mut probe) = std::fs::File::open(container)
        && let Some(reason) = nzbkit::nameprobe::sevenz_disk_declared_bomb(&mut probe)
    {
        anyhow::bail!("{reason}");
    }
    let mut reader =
        ArchiveReader::open(container, pw).map_err(|e| anyhow::anyhow!("opening 7z: {e}"))?;
    // Staging sits on the same filesystem as the job directory, so this
    // still measures the volume the payload lands on.
    let budget = BombBudget::fixed(
        crate::serve::free_bytes(out)
            .map(|free| free.saturating_sub(EXTRACT_RESERVE))
            .unwrap_or(u64::MAX),
    );
    let written = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    reader
        .for_each_entries(|entry, rd| {
            let target = sanitized_entry_path(out, &entry.name).ok_or_else(|| {
                sevenz_rust2::Error::Other("archive entry escapes output directory".into())
            })?;
            if entry.is_directory {
                std::fs::create_dir_all(&target)?;
                return Ok(true);
            }
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut w = BombGuardWriter {
                inner: std::io::BufWriter::new(std::fs::File::create(&target)?),
                written: written.clone(),
                budget: budget.clone(),
            };
            std::io::copy(rd, &mut w)?;
            use std::io::Write as _;
            w.flush()?;
            Ok(true)
        })
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}

/// Extract every zip container in `dir`. Returns true only if every one
/// produced its payload.
///
/// Mirrors [`extract_sevenz`] with one deliberate difference: there is no
/// join step. `nzbkit::zip::Archive` reads a multi-part set through one
/// logical byte-space, so a split zip never needs a second copy on disk -
/// which also means no scratch container can collide with a member of the
/// archive it came from.
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
        let cands = crate::unpack::zip_password_candidates(dir, &job.parts, password);
        println!("unpacking {} natively…", job.shape.label());
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
            match extract_one_zip(out.path(), &job.parts, pw.as_deref())
                .and_then(|()| {
                    if out.produced_anything() {
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
                    if pw.is_some() && source != "job password" {
                        println!("🔑 auto-unlocked with password from {source}");
                    }
                    println!("zip unpack complete ✔");
                    done = true;
                    break;
                }
                Err(e) => last = Some(e.to_string()),
            }
        }
        if !done {
            println!(
                "⚠ zip unpack failed ({})",
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
pub(crate) fn extract_one_zip(
    out: &std::path::Path,
    parts: &[PathBuf],
    password: Option<&str>,
) -> Result<()> {
    let archive =
        nzbkit::zip::Archive::open(parts).map_err(|e| anyhow::anyhow!("opening zip: {e}"))?;
    let budget = BombBudget::fixed(
        crate::serve::free_bytes(out)
            .map(|free| free.saturating_sub(EXTRACT_RESERVE))
            .unwrap_or(u64::MAX),
    );
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
    // Two entries can resolve to ONE output path: an exact duplicate
    // name (legal in the format), or an alias that only collides after
    // normalization - `a\b` and `a/b` become the same path because
    // `sanitized_entry_path` maps RAR4-era backslashes to '/', and
    // sanitization folds more shapes together on Windows. That was
    // harmless while entries extracted one at a time, where the last
    // writer simply won. It is not harmless on the pool below: both
    // workers `File::create` the same path, truncating each other's
    // inode, and each then verifies only ITS OWN entry's CRC and
    // length - so both report success over a file holding interleaved
    // bytes from two members.
    //
    // Keep the LAST entry for each path, which is exactly the serial
    // outcome, rather than rejecting: archives that legitimately carry a
    // duplicate name extracted fine before and must keep doing so. The
    // race is what goes away.
    //
    // Keyed by filesystem IDENTITY, not spelling. `sanitize_filename_for`
    // is case-preserving by construction and the zip central directory is
    // not deduped, so `notes.txt` and `NOTES.TXT` are two distinct keys
    // here and ONE inode on a case-insensitive volume (default APFS,
    // NTFS) - the guard below then sees no collision at all and hands
    // both to the pool, which is precisely the race above. Probe the
    // volume rather than guessing from the build target, the way
    // `par2repair`'s path identity already does.
    let fold = nzbkit::disk::case_insensitive_dir(out);
    let ident = |p: &std::path::Path| -> PathBuf {
        if fold {
            PathBuf::from(p.to_string_lossy().to_lowercase())
        } else {
            p.to_path_buf()
        }
    };
    let mut seen: std::collections::HashMap<PathBuf, usize> = std::collections::HashMap::new();
    for (i, (_, target)) in files.iter().enumerate() {
        seen.insert(ident(target), i);
    }
    if seen.len() != files.len() {
        let dropped = files.len() - seen.len();
        println!(
            "⚠ {dropped} zip entr{} resolve to a path another entry already \
             claims - extracting the last of each, as a one-at-a-time unpack would",
            if dropped == 1 { "y" } else { "ies" }
        );
        let mut keep: Vec<usize> = seen.into_values().collect();
        keep.sort_unstable();
        let mut it = keep.into_iter().peekable();
        let mut i = 0usize;
        files.retain(|_| {
            let hit = it.peek() == Some(&i);
            if hit {
                it.next();
            }
            i += 1;
            hit
        });
    }
    // Entries are independent (each its own byte range, own output file,
    // positional reads through shared handles), so a multi-entry archive
    // decodes on a small pool - the same shape and bound as the encrypted
    // finish-decrypt's file fan-out. The bomb budget is shared across the
    // pool through the same atomic it always used.
    let one_entry = |e: &nzbkit::zip::Entry, target: &std::path::Path| -> Result<()> {
        let mut w = BombGuardWriter {
            inner: std::io::BufWriter::new(std::fs::File::create(target)?),
            written: written.clone(),
            budget: budget.clone(),
        };
        archive
            .read_entry_to_with(e, &mut w, password)
            .map_err(|err| anyhow::anyhow!("{err}"))?;
        use std::io::Write as _;
        w.flush()?;
        Ok(())
    };
    let workers = files
        .len()
        .min(std::thread::available_parallelism().map_or(1, |n| n.get() / 2))
        .clamp(1, 4);
    if workers <= 1 {
        for (e, target) in &files {
            one_entry(e, target)?;
        }
        return Ok(());
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    let first_err: std::sync::Mutex<Option<anyhow::Error>> = std::sync::Mutex::new(None);
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some((e, target)) = files.get(i) else {
                        break;
                    };
                    // One failure condemns the archive (the staging dir is
                    // discarded whole), so don't decode the rest of it.
                    if first_err.lock_ok().is_some() {
                        break;
                    }
                    if let Err(err) = one_entry(e, target) {
                        let mut g = first_err.lock_ok();
                        if g.is_none() {
                            *g = Some(err);
                        }
                    }
                }
            });
        }
    });
    if let Some(e) = first_err.into_inner().unwrap_or_else(|p| p.into_inner()) {
        return Err(e);
    }
    Ok(())
}

/// Headroom the decompression-bomb guard leaves free on the target
/// volume: extraction may use everything but this. Shared by the disk
/// sink, the 7z sink and the in-stream extractor so all three read the
/// same line.
pub(crate) const EXTRACT_RESERVE: u64 = 256 * 1024 * 1024;

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
            return Err(std::io::Error::other(
                "extraction exceeded available disk space (possible decompression bomb)",
            ));
        }
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Join an archive-entry name onto `dir`, rejecting traversal: absolute
/// paths, drive/UNC prefixes, and `..` components all return None.
pub(crate) fn sanitized_entry_path(dir: &std::path::Path, name: &str) -> Option<PathBuf> {
    sanitized_entry_path_for(dir, name, cfg!(windows))
}

/// `sanitized_entry_path` with the host as a parameter, so the Windows-only
/// guarantee is asserted by the suite on the Mac and Linux boxes we develop
/// and run CI on.
pub(crate) fn sanitized_entry_path_for(
    dir: &std::path::Path,
    name: &str,
    windows: bool,
) -> Option<PathBuf> {
    use std::path::Component;
    // RAR4-era archives store Windows-style separators; normalize so the
    // name splits into components on every platform.
    let name = name.replace('\\', "/");
    let entry = std::path::Path::new(name.trim_start_matches('/'));
    let mut target = dir.to_path_buf();
    let mut pushed = false;
    for component in entry.components() {
        match component {
            Component::Normal(part) => {
                // `Components` only parses a drive/UNC prefix at byte 0, so a
                // LATER component can still carry one ("sub/C:evil.dll") - and
                // `PathBuf::push` re-parses what it is given and CLEARS the
                // buffer when the pushed piece has a prefix, dropping the
                // staging dir entirely. Sanitize every component (which maps
                // ':' on Windows) so no entry name can escape.
                let part = nzbkit::disk::sanitize_filename_for(&part.to_string_lossy(), windows);
                target.push(part);
                pushed = true;
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    // Belt and braces: nothing above may leave `dir`.
    (pushed && target.starts_with(dir)).then_some(target)
}

/// Post-repair: run the store-mode extraction over repaired volume files
/// on disk (a straight remap copy - repair already verified the bytes).
///
/// Returns `true` only when the end state is usable output: extraction
/// succeeded (volumes removed), unrar unpacked the verified volumes, or
/// the set is password-protected (verified volumes ARE the deliverable).
/// The extractor runs in protect-sources mode - a fallback must never
/// write a "materialized volume" over the very file it is reading (that
/// truncate destroyed a repaired 62-volume set in the 2026-07 damaged-post
/// bench) - and volumes feed in natural volume order so split-continuation
/// bases resolve as they arrive instead of piling into the holds cap.
/// Does the file start with the RAR marker (`Rar!`, v4 or v5)?
pub(crate) fn rar_magic(path: &std::path::Path) -> bool {
    use std::io::Read;
    let mut b = [0u8; 4];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut b))
        .map(|_| &b == b"Rar!")
        .unwrap_or(false)
}

#[cfg(test)]
#[path = "rarfix_rev_recovery_tests.rs"]
mod rarfix_rev_recovery_tests;

#[cfg(test)]
#[path = "rarfix_numeric_volume_tests.rs"]
mod rarfix_numeric_volume_tests;

#[cfg(test)]
mod native_unrar_tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-native-unrar-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn native_path_extracts_compressed_multivolume_set() {
        use rars::rar50::{CompressedEntry, Rar50VolumeWriter, WriterOptions};
        let dir = temp_dir("multivol");
        let payload: Vec<u8> = (0..200_000u32)
            .flat_map(|i| (i.wrapping_mul(2654435761)).to_le_bytes())
            .collect();
        let entries = [CompressedEntry {
            name: b"inner/data.bin",
            data: &payload,
            mtime: None,
            attributes: 0o100644, // Unix host: attributes are the file mode
            host_os: 1,
        }];
        let volumes = Rar50VolumeWriter::new(WriterOptions::default())
            .compressed_entries(&entries)
            .max_payload_per_volume(64 * 1024)
            .finish()
            .unwrap();
        assert!(volumes.len() > 1, "expected a multivolume set");
        for (index, bytes) in volumes.iter().enumerate() {
            std::fs::write(dir.join(format!("set.part{:02}.rar", index + 1)), bytes).unwrap();
        }

        assert!(try_unrar(&dir, None));
        let extracted = std::fs::read(dir.join("inner").join("data.bin")).unwrap();
        assert_eq!(extracted, payload);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A compressed, split, multivolume RAR5 set on disk - the shape
    /// TODO 101 exists for. Returns the volume paths in set order.
    fn write_multivolume_set(dir: &std::path::Path, payload: &[u8]) -> Vec<PathBuf> {
        use rars::rar50::{CompressedEntry, Rar50VolumeWriter, WriterOptions};
        let entries = [CompressedEntry {
            name: b"inner/data.bin",
            data: payload,
            mtime: None,
            attributes: 0o100644,
            host_os: 1,
        }];
        let volumes = Rar50VolumeWriter::new(WriterOptions::default())
            .compressed_entries(&entries)
            .max_payload_per_volume(64 * 1024)
            .finish()
            .unwrap();
        assert!(volumes.len() > 1, "expected a multivolume set");
        volumes
            .iter()
            .enumerate()
            .map(|(index, bytes)| {
                let p = dir.join(format!("set.part{:02}.rar", index + 1));
                std::fs::write(&p, bytes).unwrap();
                p
            })
            .collect()
    }

    /// TODO 101: with eating armed, a verified set extracts correctly AND
    /// leaves no volume behind - the deletions happen DURING extraction,
    /// which is what makes the peak one volume rather than two whole
    /// copies. The payload check is the half that matters: a mode that
    /// frees space by breaking the extraction would pass a "the volumes
    /// are gone" assertion on its own.
    #[test]
    fn eating_extracts_the_payload_and_leaves_no_volume_behind() {
        let dir = temp_dir("eat-volumes");
        let payload: Vec<u8> = (0..200_000u32)
            .flat_map(|i| (i.wrapping_mul(2654435761)).to_le_bytes())
            .collect();
        let volumes = write_multivolume_set(&dir, &payload);

        let _arm = crate::eatvol::EatArm::new(
            crate::eatvol::decide(
                crate::eatvol::EatMode::Always,
                true,
                false,
                crate::eatvol::forecast(&dir, crate::eatvol::volume_bytes(&volumes), false),
            )
            .eats(),
        );
        assert!(try_unrar(&dir, None));

        let extracted = std::fs::read(dir.join("inner").join("data.bin")).unwrap();
        assert_eq!(extracted, payload, "the payload must survive the eating");
        for v in &volumes {
            assert!(!v.exists(), "{} outlived the extraction", v.display());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Bug sweep 2026-08-06 (H1): the vendored extractor decides
    /// success on the DECODED bytes and drops the entry writer
    /// afterwards, and BufWriter's Drop swallows its flush error - so
    /// an ENOSPC/EIO on the final buffered tail used to publish a
    /// short file as a verified extraction. The deferred-flush wrapper
    /// must catch what Drop would have swallowed.
    #[test]
    fn a_swallowed_flush_failure_is_recorded_not_lost() {
        use std::io::Write as _;
        struct FailingFlush;
        impl std::io::Write for FailingFlush {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::other("no space left on device"))
            }
        }
        let failed: std::sync::Arc<std::sync::Mutex<Option<String>>> =
            std::sync::Arc::new(std::sync::Mutex::new(None));
        {
            let mut w = DeferredFlushWriter {
                inner: std::io::BufWriter::new(FailingFlush),
                failed: failed.clone(),
            };
            assert!(w.write_all(b"the final sub-8k tail").is_ok());
            // Dropped without an explicit flush - exactly what the
            // extractor does once the member's checksum has verified.
        }
        assert!(
            failed.lock().unwrap().is_some(),
            "the flush error vanished in Drop"
        );
    }

    /// The bomb guard may only spend space that has actually come back.
    ///
    /// The eating path used to add the WHOLE volume set to the budget
    /// before a byte was written, on the reasoning that the volumes were
    /// about to be handed back. The engine does hand them back - but for
    /// the commonest set of all (one member split across every volume)
    /// it hands back NOTHING until the whole payload is written, because
    /// a pending split holds every consumption callback. So the guard
    /// waved through an extraction that could not fit and the real
    /// filesystem stopped it instead: ENOSPC on a disk with nothing left.
    ///
    /// This is the accounting rule underneath that, tested directly -
    /// a free-space seam is not reachable from a unit test, but the
    /// arithmetic that made the seam wrong is.
    #[test]
    fn the_bomb_guard_credits_only_space_that_came_back() {
        use std::io::Write as _;
        let budget = BombBudget::fixed(1_000);
        let credit = budget.credit_handle();
        assert_eq!(budget.limit(), 1_000, "a promise is not space");

        let written = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut w = BombGuardWriter {
            inner: Vec::new(),
            written: written.clone(),
            budget: budget.clone(),
        };
        assert!(w.write_all(&[0u8; 900]).is_ok());
        // Still over the line, because nothing has been freed yet: this
        // is exactly the write that used to be allowed on the strength
        // of volumes that were still sitting on the disk.
        assert!(
            w.write_all(&[0u8; 200]).is_err(),
            "the guard spent space the disk did not have"
        );

        // A volume actually removed credits its bytes, and only then.
        credit.fetch_add(500, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(budget.limit(), 1_500);
        let mut w2 = BombGuardWriter {
            inner: Vec::new(),
            written,
            budget,
        };
        assert!(
            w2.write_all(&[0u8; 300]).is_ok(),
            "space that came back must be spendable"
        );
    }

    /// The gate that matters most: an UNVERIFIED set is never eaten,
    /// whatever the mode says - so a retry still has the volumes and
    /// re-downloads nothing. Driven through `decide` rather than by
    /// hand-setting the arm, because the composition of the two is the
    /// thing that could regress.
    #[test]
    fn an_unverified_set_keeps_every_volume() {
        let dir = temp_dir("eat-unverified");
        let payload: Vec<u8> = (0..120_000u32)
            .flat_map(|i| (i.wrapping_mul(2246822519)).to_le_bytes())
            .collect();
        let volumes = write_multivolume_set(&dir, &payload);

        let _arm = crate::eatvol::EatArm::new(
            crate::eatvol::decide(
                // `always` plus a disk with nothing on it - every reason
                // to eat except the one that counts.
                crate::eatvol::EatMode::Always,
                false,
                true,
                crate::eatvol::Forecast {
                    free: 0,
                    volumes: crate::eatvol::volume_bytes(&volumes),
                    encrypted: true,
                },
            )
            .eats(),
        );
        assert!(try_unrar(&dir, None));

        assert_eq!(
            std::fs::read(dir.join("inner").join("data.bin")).unwrap(),
            payload
        );
        for v in &volumes {
            assert!(v.exists(), "{} was eaten unverified", v.display());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Off is off. The same set, the same tight disk, consent given -
    /// and nothing is touched during extraction, because the mode was
    /// never turned on.
    #[test]
    fn the_off_mode_never_eats_however_tight_the_disk() {
        let dir = temp_dir("eat-off");
        let payload: Vec<u8> = (0..120_000u32)
            .flat_map(|i| (i.wrapping_mul(2654435761)).to_le_bytes())
            .collect();
        let volumes = write_multivolume_set(&dir, &payload);

        let _arm = crate::eatvol::EatArm::new(
            crate::eatvol::decide(
                crate::eatvol::EatMode::Off,
                true,
                true,
                crate::eatvol::Forecast {
                    free: 0,
                    volumes: crate::eatvol::volume_bytes(&volumes),
                    encrypted: true,
                },
            )
            .eats(),
        );
        assert!(try_unrar(&dir, None));
        for v in &volumes {
            assert!(v.exists(), "{} was eaten with the mode off", v.display());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rr_repair_rescues_corrupted_volume_and_extracts() {
        use rars::rar50::{CompressedEntry, Rar50Writer, WriterOptions};
        let dir = temp_dir("rr-repair");
        let payload: Vec<u8> = (0..150_000u32)
            .flat_map(|i| (i.wrapping_mul(2246822519)).to_le_bytes())
            .collect();
        let entries = [CompressedEntry {
            name: b"video.bin",
            data: &payload,
            mtime: None,
            attributes: 0o100644,
            host_os: 1,
        }];
        let mut archive = Rar50Writer::new(WriterOptions::default())
            .compressed_entries(&entries)
            .recovery_percent(Some(20))
            .finish()
            .unwrap();
        // Corrupt a run of payload bytes well inside the archive.
        let start = archive.len() / 3;
        for byte in &mut archive[start..start + 2048] {
            *byte ^= 0x5a;
        }
        let path = dir.join("set.rar");
        std::fs::write(&path, &archive).unwrap();

        assert!(try_rar_rr_repair(&dir, None));
        let extracted = std::fs::read(dir.join("video.bin")).unwrap();
        assert_eq!(extracted, payload);
        assert!(!dir.join("set.rrtmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rr_repair_raw_scan_rescues_a_volume_whose_headers_are_destroyed() {
        use rars::rar50::{CompressedEntry, Rar50Writer, WriterOptions};
        let dir = temp_dir("rr-raw-scan");
        let payload: Vec<u8> = (0..80_000u32)
            .flat_map(|i| (i.wrapping_mul(2246822519)).to_le_bytes())
            .collect();
        let entries = [CompressedEntry {
            name: b"video.bin",
            data: &payload,
            mtime: None,
            attributes: 0o100644,
            host_os: 1,
        }];
        let archive = Rar50Writer::new(WriterOptions::default())
            .compressed_entries(&entries)
            .recovery_percent(Some(20))
            .finish()
            .unwrap();

        // Wreck the headers so the archive cannot be parsed at all: this is
        // the last-chance path that used to read the whole volume, clone it,
        // and hand back a third copy.
        let mut damaged = archive.clone();
        for byte in &mut damaged[8..400] {
            *byte ^= 0xa5;
        }
        let path = dir.join("set.rar");
        std::fs::write(&path, &damaged).unwrap();
        assert!(
            rars::ArchiveReader::read_path_with_options(&path, rars::ArchiveReadOptions::default())
                .is_err(),
            "the test must actually exercise the raw-scan fallback"
        );

        assert!(try_rar_rr_repair(&dir, None));
        assert_eq!(
            std::fs::read(&path).unwrap(),
            archive,
            "the raw scan must restore the volume byte for byte"
        );
        assert!(
            !std::fs::read_dir(&dir)
                .unwrap()
                .flatten()
                .any(|e| e.file_name().to_string_lossy().contains("rrtmp")),
            "no repair temp may survive"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rr_repair_raw_scan_leaves_the_original_alone_when_it_cannot_repair() {
        use rars::rar50::{CompressedEntry, Rar50Writer, WriterOptions};
        let dir = temp_dir("rr-raw-fail");
        let payload: Vec<u8> = (0..80_000u32)
            .flat_map(|i| (i.wrapping_mul(2246822519)).to_le_bytes())
            .collect();
        let entries = [CompressedEntry {
            name: b"video.bin",
            data: &payload,
            mtime: None,
            attributes: 0o100644,
            host_os: 1,
        }];
        let archive = Rar50Writer::new(WriterOptions::default())
            .compressed_entries(&entries)
            .recovery_percent(Some(1))
            .finish()
            .unwrap();

        // Headers destroyed AND far more damage than 1% can cover.
        let mut damaged = archive.clone();
        let end = damaged.len() * 3 / 4;
        for byte in &mut damaged[8..end] {
            *byte ^= 0xa5;
        }
        let path = dir.join("set.rar");
        std::fs::write(&path, &damaged).unwrap();

        assert!(!try_rar_rr_repair(&dir, None));
        assert_eq!(
            std::fs::read(&path).unwrap(),
            damaged,
            "a failed repair must leave the volume exactly as it found it"
        );
        assert!(
            !std::fs::read_dir(&dir)
                .unwrap()
                .flatten()
                .any(|e| e.file_name().to_string_lossy().contains("rrtmp")),
            "no repair temp may survive a failure"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rr_repair_leaves_unrepairable_volume_untouched() {
        use rars::rar50::{CompressedEntry, Rar50Writer, WriterOptions};
        let dir = temp_dir("rr-unrepairable");
        let payload: Vec<u8> = (0..100_000u32)
            .flat_map(|i| (i.wrapping_mul(374761393)).to_le_bytes())
            .collect();
        let entries = [CompressedEntry {
            name: b"video.bin",
            data: &payload,
            mtime: None,
            attributes: 0o100644,
            host_os: 1,
        }];
        let mut archive = Rar50Writer::new(WriterOptions::default())
            .compressed_entries(&entries)
            .recovery_percent(Some(1))
            .finish()
            .unwrap();
        // Corrupt far more than 1% RR can cover.
        let end = archive.len() * 3 / 4;
        for byte in &mut archive[64..end] {
            *byte ^= 0xa5;
        }
        let corrupted = archive.clone();
        let path = dir.join("set.rar");
        std::fs::write(&path, &archive).unwrap();

        assert!(!try_rar_rr_repair(&dir, None));
        assert_eq!(
            std::fs::read(&path).unwrap(),
            corrupted,
            "original untouched"
        );
        assert!(!dir.join("set.rrtmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rr_repair_skips_volumes_without_recovery_records() {
        use rars::rar50::{CompressedEntry, Rar50Writer, WriterOptions};
        let dir = temp_dir("rr-none");
        let entries = [CompressedEntry {
            name: b"data.bin",
            data: b"hello recovery-less world",
            mtime: None,
            attributes: 0o100644,
            host_os: 1,
        }];
        let archive = Rar50Writer::new(WriterOptions::default())
            .compressed_entries(&entries)
            .finish()
            .unwrap();
        std::fs::write(dir.join("set.rar"), &archive).unwrap();

        assert!(!try_rar_rr_repair(&dir, None));
        assert!(!dir.join("set.rrtmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn entry_paths_cannot_escape_output_dir() {
        let dir = std::path::Path::new("/tmp/out");
        assert!(sanitized_entry_path(dir, "../evil").is_none());
        assert!(sanitized_entry_path(dir, "a/../../evil").is_none());
        assert!(sanitized_entry_path(dir, "/abs/path").map(|p| p.starts_with(dir)) == Some(true));
        // Windows rejects the drive prefix outright; Unix keeps it as a
        // benign "C:" subdirectory. Either way it must stay under dir.
        let drive = sanitized_entry_path(dir, "C:\\evil");
        assert!(drive.is_none() || drive.is_some_and(|p| p.starts_with(dir)));
        assert_eq!(
            sanitized_entry_path(dir, "sub\\file.bin"),
            Some(dir.join("sub").join("file.bin"))
        );
        assert!(sanitized_entry_path(dir, "").is_none());
    }

    #[test]
    fn drive_relative_component_cannot_escape_on_windows() {
        let dir = std::path::Path::new("/tmp/out");
        // A drive prefix only parses at byte 0, so these forms reach `push`
        // as ordinary components and used to wipe the staging dir.
        for name in ["sub/C:evil.dll", "x/D:payload.exe", "a\\b\\C:evil.dll"] {
            let p = sanitized_entry_path_for(dir, name, true).expect("kept, not escaped");
            assert!(p.starts_with(dir), "{name} escaped to {p:?}");
            assert!(
                !p.to_string_lossy().contains(':'),
                "{name} kept a drive-relative colon"
            );
        }
        // Unix keeps ':' (legal and common in release names) but still may
        // not escape, and the ordinary success path is untouched.
        let p = sanitized_entry_path_for(dir, "Movie: The Sequel/a.mkv", false).unwrap();
        assert_eq!(p, dir.join("Movie: The Sequel").join("a.mkv"));
    }
}

/// Zip disk extraction (the 7z path's twin). The reader itself is tested
/// in `nzbkit::zip`; these cover the WIRING - what lands in the output
/// directory, and the refusals that keep a hostile archive out of it.
#[cfg(test)]
mod sevenz_extract_tests {
    use std::path::PathBuf;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("nzbfast-7zx-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The disk half of TODO 156 item 5's extract gate: a container
    /// whose packed end header declares 512 MiB of decoded header (the
    /// checked-in nzbkit bomb seed) is refused by name BEFORE
    /// ArchiveReader::open decodes on the declaration's say-so. The
    /// message assertion is what discriminates: with the gate neutered
    /// the library errors on the garbage pack bytes as "opening 7z: …"
    /// instead - after requesting the allocations the gate exists to
    /// prevent. It matters here because a chased container that refused
    /// at the in-stream gate demotes to exactly this path.
    #[test]
    fn a_bomb_declaring_sevenz_is_refused_by_name() {
        let dir = tmp("bomb");
        let container = dir.join("bomb.7z");
        std::fs::copy(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../nzbkit/tests/fixtures/sevenz/bomb-container.7z"
            ),
            &container,
        )
        .unwrap();
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let err = super::extract_one_sevenz(&out, &container, None).unwrap_err();
        assert!(
            err.to_string().contains("oversized decode"),
            "must die at the gate, not in the decoder: {err}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The content half of the same gate (bug-sweep H1, 14 Aug): a
    /// container whose CONTENT block declares a 384 MiB LZMA2
    /// dictionary out of 16 packed bytes is refused by name before the
    /// entry decode allocates it, and the zeroed-start shape (H2) is
    /// refused before the library's end-header recovery scan can
    /// decode an unverified packed header with no limit. Both messages
    /// land verbatim in the job's failure detail.
    #[test]
    fn content_and_recovery_bombs_are_refused_by_name() {
        let fixtures = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../nzbkit/tests/fixtures/sevenz"
        );
        let dir = tmp("content-bomb");
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let container = dir.join("content.7z");
        std::fs::copy(format!("{fixtures}/bomb-content-dict.7z"), &container).unwrap();
        let err = super::extract_one_sevenz(&out, &container, None).unwrap_err();
        assert!(
            err.to_string().contains("content declares decoder memory"),
            "content bomb must die at the gate, not in the decoder: {err}"
        );
        let container = dir.join("zeroed.7z");
        std::fs::copy(format!("{fixtures}/recovered-zero-start.bin"), &container).unwrap();
        let err = super::extract_one_sevenz(&out, &container, None).unwrap_err();
        assert!(
            err.to_string().contains("start header geometry is zeroed"),
            "zeroed start must refuse before the recovery scan: {err}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

#[cfg(test)]
mod zip_extract_tests {
    use nzbkit::zip::fixtures::Spec;
    use std::path::PathBuf;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("nzbfast-zipx-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn payload(n: usize, seed: u8) -> Vec<u8> {
        (0..n)
            .map(|i| (i as u8).wrapping_mul(23).wrapping_add(seed))
            .collect()
    }

    /// The headline change: a zip payload used to FAIL the job with
    /// "zip extraction is not built in". It now unpacks, and the
    /// container is gone from the output because its payload replaced it.
    #[test]
    fn a_zip_payload_unpacks_into_the_output_directory() {
        let dir = tmp("payload");
        let movie = payload(120_000, 3);
        let nfo = b"release info".to_vec();
        let z = nzbkit::zip::fixtures::zip_of(&[
            Spec::deflated("Some.Movie/movie.mkv", &movie),
            Spec::stored("Some.Movie/info.nfo", &nfo),
        ]);
        std::fs::write(dir.join("payload.zip"), &z).unwrap();

        let found = nzbkit::zip::scan(&dir);
        assert_eq!(found.len(), 1);
        assert!(super::extract_zip(&dir, &found, None), "zip should unpack");
        assert_eq!(
            std::fs::read(dir.join("Some.Movie/movie.mkv")).unwrap(),
            movie
        );
        assert_eq!(std::fs::read(dir.join("Some.Movie/info.nfo")).unwrap(), nfo);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A self-extracting zip - a stub concatenated in front of a
    /// container - reaches the disk pass by NAME (`zip::scan` never
    /// magic-sniffs a named file), and the reader now follows the
    /// archive's own offsets from where the archive actually starts.
    /// The whole path has to hold, not just the parser: this is the
    /// shape `unzip` reports as "extra bytes at beginning" and 7-Zip as
    /// "the archive is open with offset". TODO 159 item 2.
    #[test]
    fn a_zip_behind_a_prepended_stub_unpacks_from_disk() {
        let dir = tmp("stubzip");
        let data = payload(80_000, 17);
        let mut z = b"MZ stub bytes, not a zip".to_vec();
        z.resize(511, 0);
        z.extend_from_slice(&nzbkit::zip::fixtures::zip_of(&[Spec::deflated(
            "Some.Movie/movie.mkv",
            &data,
        )]));
        std::fs::write(dir.join("selfextract.zip"), &z).unwrap();

        let found = nzbkit::zip::scan(&dir);
        assert_eq!(found.len(), 1, "a named .zip is found whatever its head");
        assert!(super::extract_zip(&dir, &found, None), "zip should unpack");
        assert_eq!(
            std::fs::read(dir.join("Some.Movie/movie.mkv")).unwrap(),
            data
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Two entries that resolve to ONE output path must not be handed to
    /// two workers at once.
    ///
    /// `a\b.bin` and `a/b.bin` are different names in the archive and the
    /// same path here, because backslashes normalize to '/'. While
    /// entries extracted one at a time the last writer simply won; on the
    /// pool both called `File::create` on the same inode and wrote
    /// concurrently, each checking only its own CRC and length, so both
    /// reported success over a file holding a mixture of the two. The
    /// surviving bytes must be exactly one entry's - the last, matching
    /// the serial outcome - and never a blend.
    #[test]
    fn colliding_zip_entry_paths_do_not_race_one_output_file() {
        let dir = tmp("collide");
        // Big enough that a genuine race would interleave visibly rather
        // than finishing inside one buffered write.
        let first = payload(400_000, 1);
        let last = payload(400_000, 200);
        let z = nzbkit::zip::fixtures::zip_of(&[
            Spec::stored("dup/a\\b.bin", &first),
            Spec::stored("dup/a/b.bin", &last),
        ]);
        std::fs::write(dir.join("collide.zip"), &z).unwrap();

        let found = nzbkit::zip::scan(&dir);
        assert_eq!(found.len(), 1);
        assert!(super::extract_zip(&dir, &found, None), "zip should unpack");
        let got = std::fs::read(dir.join("dup/a/b.bin")).unwrap();
        assert_eq!(
            got.len(),
            last.len(),
            "the output is not one whole entry - two writers truncated each other"
        );
        assert_eq!(
            got, last,
            "expected the LAST entry, as a serial unpack gives"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Phase 3: an encrypted zip unpacks when the job carries the
    /// password, in both schemes; without it (or with the wrong one)
    /// the unpack fails and the container stays put for the user.
    #[test]
    fn an_encrypted_zip_unpacks_with_the_job_password() {
        use nzbkit::zip::fixtures::Encrypt;
        let movie = payload(80_000, 9);
        for (tag, enc) in [
            ("zc", Encrypt::ZipCrypto { password: "pw123" }),
            (
                "ae",
                Encrypt::Ae {
                    password: "pw123",
                    strength: 3,
                    vendor_version: 2,
                },
            ),
        ] {
            let dir = tmp(&format!("enc-{tag}"));
            let z = nzbkit::zip::fixtures::zip_of(&[Spec {
                encrypt: Some(enc),
                ..Spec::deflated("movie.mkv", &movie)
            }]);
            std::fs::write(dir.join("payload.zip"), &z).unwrap();
            let found = nzbkit::zip::scan(&dir);
            assert!(
                !super::extract_zip(&dir, &found, None),
                "{tag}: no password must not unpack"
            );
            assert!(
                !super::extract_zip(&dir, &found, Some("wrong")),
                "{tag}: a wrong password must not unpack"
            );
            assert!(
                !dir.join("movie.mkv").exists(),
                "{tag}: nothing published on failure"
            );
            assert!(
                super::extract_zip(&dir, &found, Some("pw123")),
                "{tag}: the right password must unpack"
            );
            assert_eq!(
                std::fs::read(dir.join("movie.mkv")).unwrap(),
                movie,
                "{tag}"
            );
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// Zip-slip: an entry naming its way out of the output directory must
    /// be refused, and nothing may be written outside it.
    #[test]
    fn an_entry_escaping_the_output_directory_is_refused() {
        let dir = tmp("slip");
        let inner = dir.join("inner");
        std::fs::create_dir_all(&inner).unwrap();
        let z = nzbkit::zip::fixtures::zip_of(&[Spec::stored(
            "../../escaped.txt",
            b"should never land",
        )]);
        std::fs::write(inner.join("evil.zip"), &z).unwrap();

        let found = nzbkit::zip::scan(&inner);
        assert!(
            !super::extract_zip(&inner, &found, None),
            "zip-slip must not succeed"
        );
        assert!(
            !dir.join("escaped.txt").exists(),
            "wrote outside the output dir"
        );
        assert!(!inner.join("escaped.txt").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A symlink entry's payload is a PATH. Materializing one plants a
    /// link pointing wherever the archive likes, so it is refused.
    #[test]
    fn a_symlink_entry_is_refused() {
        let dir = tmp("link");
        let z = nzbkit::zip::fixtures::zip_of(&[Spec {
            external: 0xA1FF_0000,
            ..Spec::stored("link", b"/etc/passwd")
        }]);
        std::fs::write(dir.join("l.zip"), &z).unwrap();
        let found = nzbkit::zip::scan(&dir);
        assert!(
            !super::extract_zip(&dir, &found, None),
            "symlink entry must not extract"
        );
        assert!(!dir.join("link").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Damaged bytes must not be published: a wrong CRC fails the job
    /// rather than landing a corrupt file that looks like success.
    #[test]
    fn a_damaged_entry_fails_instead_of_publishing() {
        let dir = tmp("crc");
        let data = payload(40_000, 7);
        let z = nzbkit::zip::fixtures::zip_of(&[Spec {
            crc_override: Some(0x1234_5678),
            ..Spec::stored("movie.mkv", &data)
        }]);
        std::fs::write(dir.join("d.zip"), &z).unwrap();
        let found = nzbkit::zip::scan(&dir);
        assert!(
            !super::extract_zip(&dir, &found, None),
            "a bad CRC must fail the unpack"
        );
        assert!(
            !dir.join("movie.mkv").exists(),
            "corrupt output was published"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A method we decline still reports honestly rather than opening
    /// and producing nothing - and it names the codec.
    #[test]
    fn a_declined_method_fails_with_the_codec_named() {
        let dir = tmp("zstd");
        // zstd (93): bzip2 and then lzma stood here and are now decoded.
        let z = nzbkit::zip::fixtures::zip_of(&[Spec {
            method: 93,
            ..Spec::stored("movie.mkv", &payload(2_000, 9))
        }]);
        std::fs::write(dir.join("b.zip"), &z).unwrap();
        let found = nzbkit::zip::scan(&dir);
        assert!(!super::extract_zip(&dir, &found, None));
        // The container survives for the user to unpack by hand.
        assert!(dir.join("b.zip").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// `.cbz` and friends ARE zip containers but are the deliverable.
    /// The collector must never hand one to the extractor.
    #[test]
    fn a_cbz_payload_is_never_unpacked() {
        let dir = tmp("cbz");
        let z = nzbkit::zip::fixtures::zip_of(&[Spec::stored("page01.jpg", b"jpegbytes")]);
        std::fs::write(dir.join("comic.cbz"), &z).unwrap();
        assert!(
            nzbkit::zip::scan(&dir).is_empty(),
            "a .cbz must not be collected"
        );
        assert!(dir.join("comic.cbz").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The entry pass fans out on a small pool, so a many-entry archive
    /// must land every payload byte-exact under its own name - distinct
    /// content and sizes per entry so any cross-wiring of readers,
    /// writers or CRCs fails loudly. Mixed store and deflate on purpose:
    /// both methods ride the same pool.
    #[test]
    fn a_many_entry_zip_lands_every_payload_byte_exact() {
        let dir = tmp("many");
        let payloads: Vec<(String, Vec<u8>)> = (0..12u8)
            .map(|i| {
                (
                    format!("d{}/file{i:02}.bin", i % 3),
                    payload(
                        30_000 + 1_733 * i as usize,
                        i.wrapping_mul(37).wrapping_add(11),
                    ),
                )
            })
            .collect();
        let specs: Vec<Spec> = payloads
            .iter()
            .enumerate()
            .map(|(i, (n, p))| {
                if i % 2 == 0 {
                    Spec::stored(n, p)
                } else {
                    Spec::deflated(n, p)
                }
            })
            .collect();
        let z = nzbkit::zip::fixtures::zip_of(&specs);
        std::fs::write(dir.join("payload.zip"), &z).unwrap();
        let found = nzbkit::zip::scan(&dir);
        assert_eq!(found.len(), 1);
        assert!(super::extract_zip(&dir, &found, None), "zip should unpack");
        for (n, p) in &payloads {
            assert_eq!(&std::fs::read(dir.join(n)).unwrap(), p, "{n}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// One damaged entry among many condemns the whole archive: nothing
    /// is published, however many siblings decoded cleanly on the pool.
    #[test]
    fn one_damaged_entry_among_many_publishes_nothing() {
        let dir = tmp("many-crc");
        let payloads: Vec<(String, Vec<u8>)> = (0..10u8)
            .map(|i| {
                (
                    format!("file{i:02}.bin"),
                    payload(25_000 + 900 * i as usize, i.wrapping_add(51)),
                )
            })
            .collect();
        let specs: Vec<Spec> = payloads
            .iter()
            .enumerate()
            .map(|(i, (n, p))| Spec {
                // Damage one entry in the middle of the set.
                crc_override: (i == 6).then_some(0xDEAD_BEEF),
                ..Spec::stored(n, p)
            })
            .collect();
        let z = nzbkit::zip::fixtures::zip_of(&specs);
        std::fs::write(dir.join("payload.zip"), &z).unwrap();
        let found = nzbkit::zip::scan(&dir);
        assert!(
            !super::extract_zip(&dir, &found, None),
            "a bad CRC anywhere must fail the unpack"
        );
        for (n, _) in &payloads {
            assert!(!dir.join(n).exists(), "{n} was published from a failed set");
        }
        assert!(dir.join("payload.zip").exists(), "container must survive");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Hand-run timing rig for the multi-entry disk extraction, ignored
    /// in normal runs (it writes gigabytes to the temp volume). Run
    /// around perf changes with:
    /// `cargo test -p nzbfast --bin nzbfast zip_multi_entry_bench -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn zip_multi_entry_bench() {
        for (tag, entries, mib, deflate) in
            [("store", 8usize, 192usize, false), ("deflate", 8, 64, true)]
        {
            let dir = tmp(&format!("bench-{tag}"));
            let payloads: Vec<Vec<u8>> = (0..entries)
                .map(|s| payload(mib << 20, (s as u8).wrapping_mul(31).wrapping_add(5)))
                .collect();
            let names: Vec<String> = (0..entries).map(|i| format!("part{i:02}.bin")).collect();
            let specs: Vec<Spec> = payloads
                .iter()
                .zip(&names)
                .map(|(p, n)| {
                    if deflate {
                        Spec::deflated(n, p)
                    } else {
                        Spec::stored(n, p)
                    }
                })
                .collect();
            let z = nzbkit::zip::fixtures::zip_of(&specs);
            std::fs::write(dir.join("payload.zip"), &z).unwrap();
            drop(z);
            let found = nzbkit::zip::scan(&dir);
            let t0 = std::time::Instant::now();
            assert!(super::extract_zip(&dir, &found, None));
            let dt = t0.elapsed();
            println!(
                "zip bench [{tag}]: {entries} x {mib} MiB unpacked in {:.2}s",
                dt.as_secs_f64()
            );
            for (p, n) in payloads.iter().zip(&names) {
                assert_eq!(&std::fs::read(dir.join(n)).unwrap(), p, "{n}");
            }
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// A byte-split set extracts without a join step - and without ever
    /// writing a second copy of the container to disk.
    #[test]
    fn a_split_zip_set_unpacks_without_a_scratch_copy() {
        let dir = tmp("split");
        let data = payload(90_000, 11);
        let z = nzbkit::zip::fixtures::zip_of(&[Spec::deflated("movie.mkv", &data)]);
        let cut = z.len() / 2;
        std::fs::write(dir.join("m.zip.001"), &z[..cut]).unwrap();
        std::fs::write(dir.join("m.zip.002"), &z[cut..]).unwrap();
        let found = nzbkit::zip::scan(&dir);
        assert_eq!(found.len(), 1);
        assert!(super::extract_zip(&dir, &found, None));
        assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), data);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
