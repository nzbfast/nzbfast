//! Post-download repair: reextract_dir, recovery-volume fetch over the side pool, mapped PAR2 repair, external par2 invocation and fetch_and_repair.
//!
//! Split out of main.rs verbatim; behaviour unchanged.

use crate::*;
use std::path::Path;

pub(crate) fn reextract_dir(dir: &std::path::Path, password: Option<&str>) -> Result<bool> {
    use nzbkit::extract::{Extractor, release_stem, vol_sort_key};
    let mut rars: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();
        // .rar / .rNN by name alone (as before). Letter-rollover
        // continuations past .r99 (.sNN/.tNN…) and WinRAR numeric volumes
        // (.001) additionally require the Rar! magic - those extensions
        // collide with subtitles/hjsplit/zip splits, and a wrongly
        // included file would flip the whole set to the unrar fallback.
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
        // The one exception to `by_name`: a `.rar` whose name carries
        // no set (hash stem, no ordinal, no `.rNN` sibling) belongs to
        // the obfuscated branch below - by name it is its own
        // single-volume stem group, which fails on the split entry
        // (issue #47's shape, same rule as `try_unrar_spent`).
        if name.ends_with(".rar") && unpack::rar_name_carries_no_set(&path) && rar_magic(&path) {
            continue;
        }
        if by_name || (rollover_or_numeric && rar_magic(&path)) {
            rars.push(path);
        }
    }
    if rars.is_empty() {
        // An obfuscated set has no extension at all, so the grammar above
        // sees nothing and this used to answer Ok(true) - "extracted
        // successfully" for a pass that did no work, on a set that unpacks
        // perfectly. A later nested pass happens to rescue the daemon's own
        // callers; `smart::unlock` has no pass behind it and reports the
        // job unlocked with the payload still packed.
        //
        // Recognising the shape (rather than inventing a third outcome) is
        // both the smaller change and the honest one: the only remaining
        // empty case really has nothing to do. It also keeps the signature,
        // so no caller can read a new state wrongly.
        let obf = collect_obfuscated_rar_volumes(dir)?;
        if !obf.is_empty() {
            println!(
                "re-extracting {} obfuscated volume(s) by header order…",
                obf.len()
            );
            // Depth 1 = sweep the volumes this consumed, which is already
            // this function's contract for a set it extracted (the named
            // branch below removes its own on the same terms) and what the
            // nested pass does with them today.
            return Ok(extract_obfuscated_rar(dir, &obf, password, 1));
        }
        // Genuinely nothing packed: a bare recreated payload, an already
        // extracted directory. That IS a legitimate no-op and stays a
        // success - but it is said out loud, so no log or reader can take
        // it for "extracted".
        println!("no archive volumes on disk - nothing to re-extract");
        return Ok(true);
    }
    rars.sort_by_cached_key(|p| {
        let name = p.file_name().unwrap_or_default().to_string_lossy();
        (release_stem(&name), vol_sort_key(&name))
    });
    // A header-encrypted set the in-stream parser cannot read with the
    // password we hold: every volume below would be read off disk in full
    // only to demote, printing one "not re-extractable (encrypted headers
    // (password required))" line per group with a VALID password in hand -
    // 135 of them in the v1.0.11 report this came from - before the unrar
    // fallback did the work. The rars fork reads those headers
    // (`try_rars_native` passes the password into the parse session), so
    // hand the set straight there. Both RAR5 `-hp` and (since RAR4 header
    // decryption landed) RAR4 `-hp` now parse in-stream, so this shortcut
    // only fires for shapes the mapper still cannot open at all.
    // Gated on a single-set directory because
    // `try_rars_native` extracts one stem group: with a second set beside
    // it, the streaming path below is still the one that sees everything.
    // A native failure just falls through to it, having published nothing
    // (`write_archives_to` stages and publishes only on full success).
    let one_set = {
        // Lowercase both sides - `release_stem` returns a slice of what it
        // was handed, so a mixed-case stem compares unequal otherwise
        // (78a5640f).
        let lower_stem = |p: &Path| {
            release_stem(
                &p.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_lowercase(),
            )
        };
        let stem0 = lower_stem(&rars[0]);
        rars.iter().all(|p| lower_stem(p) == stem0)
    };
    let header_encrypted =
        password.is_some() && nzbkit::rar::headers_encrypted_to(&rars[0], password);
    // TODO 101: the disk-feed ladder below reads every volume in full and
    // only removes them after `finish()`, so a job that ARMED the
    // volume-eating unpack got none of it here - it budgeted against the
    // free space as it stood and could refuse the very extraction the
    // arming exists to rescue. A resumed run takes exactly this path
    // (get.rs arms the mode and then calls `reextract_dir`), which is the
    // one shape where the disk is tightest by definition. The native
    // whole-set path IS the one that eats, so an armed job goes there
    // first; a failure still falls through, and the guard below catches
    // the case where falling through is impossible because the volumes
    // have been spent.
    if one_set && (header_encrypted || crate::eatvol::armed()) {
        println!(
            "re-extracting {} volume(s) natively{}…",
            rars.len(),
            if header_encrypted {
                " (header-encrypted)"
            } else {
                ""
            }
        );
        match try_rars_native(dir, &rars[0], password) {
            Ok(consumed) => {
                println!("native re-extract complete ✔");
                remove_spent_volumes(&consumed);
                return Ok(true);
            }
            Err(e) => {
                println!("⚠ native re-extract failed ({e})");
                // The comment above ("a native failure just falls through
                // to it, having published nothing") predates §101. Under
                // the eating mode the failed pass may have consumed
                // volumes as it read them, and the loop below re-reads
                // every one by path - so its `File::open(path)?` would
                // not fall through at all, it would `?` a hard error out
                // of `get_with_progress` and fail the whole download task
                // rather than this step. Fail cleanly here instead.
                if rars.iter().any(|p| !p.exists()) {
                    println!(
                        "  ✘ volumes were consumed as they were read (the volume-eating \
                         unpack), so there is nothing left to re-extract from"
                    );
                    return Ok(false);
                }
            }
        }
    }
    println!("re-extracting {} repaired volume(s)…", rars.len());
    let ex = Extractor::new(dir, rars.len(), true);
    ex.set_protect_sources();
    // Same two bounds as the download path, with the on-disk volume set
    // standing in for the NZB's posted bytes: an inner file's declared
    // unpacked_size is still an untrusted header vint after a repair.
    let posted: u64 = rars
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok().map(|m| m.len()))
        .fold(0u64, u64::saturating_add);
    // 0 would mean "reserve nothing", a silent de-optimisation rather
    // than a bound - leave the ceiling off if we could not stat anything.
    if posted > 0 {
        ex.set_prealloc_ceiling(posted);
    }
    if let Some(free) = crate::serve::free_bytes(dir) {
        ex.set_extract_budget(free.saturating_sub(EXTRACT_RESERVE));
    }
    if let Some(pw) = password {
        ex.set_password(pw);
    }
    let mut buf = vec![0u8; 4 << 20];
    for (si, path) in rars.iter().enumerate() {
        use std::io::Read;
        let mut f = std::fs::File::open(path)?;
        let size = f.metadata()?.len();
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let mut off = 0u64;
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            ex.write(si, &name, size, off, &buf[..n])?;
            off += n as u64;
        }
    }
    let rep = ex.finish()?;
    for (name, size) in &rep.extracted {
        println!("  ▶ {name} ({:.1} MB)", *size as f64 / 1e6);
    }
    for (group, why) in &rep.fallbacks {
        println!("  ⚠ '{group}': not re-extractable ({why})");
    }
    if rep.fallbacks.is_empty() && !rep.extracted.is_empty() {
        // Extraction verified (repair pass vouched for the volume bytes) -
        // the volumes served their purpose.
        for path in &rars {
            let _ = std::fs::remove_file(path);
        }
        println!("  removed {} volume file(s) after extraction", rars.len());
        return Ok(true);
    }
    if rep.fallbacks.iter().all(|(_, w)| w.contains("password"))
        && !rep.fallbacks.is_empty()
        && password.is_none()
    {
        println!("  volumes are verified on disk - password required to unpack");
        return Ok(true);
    }
    println!("  falling back to unrar on the verified volumes…");
    // A successful disk unpack spends the volumes exactly like the clean
    // path above - leaving them behind doubled a job's disk footprint
    // (Part B, research/SPEC-onepass-obfuscated-store-sets-2026-07-29.md).
    match try_unrar_spent(dir, password) {
        Some(spent) => {
            remove_spent_volumes(&spent);
            Ok(true)
        }
        None => Ok(false),
    }
}

mod sidefetch;
// The side-fetch driver, its consumer and the two small helpers that
// price a volume moved out whole (§129 residue 2). Re-exported rather
// than re-pathed at every call site: nothing about the split is
// interesting to a caller, and `use super::*` importers stay valid.
pub(crate) use sidefetch::{
    SideCancel, fetch_volume_articles, fetch_volumes, side_pool_servers, vol_count_from_name,
    volume_prealloc_cap, volume_reqs,
};

/// Candidate recovery volumes of the NZB: (file idx, declared slices,
/// encoded bytes). Unknown counts get a conservative size-based estimate.
/// `sniffed_vols` are file indexes classified as recovery data by the
/// in-stream magic sniff (issue #14) - subject-line classification cannot
/// see them, but their deferred bytes are just as fetchable.
pub(crate) fn recovery_candidates(
    nzb: &Nzb,
    set: &nzbkit::par2::Par2Set,
    already_fetched: &[usize],
    sniffed_vols: &[usize],
) -> Vec<(usize, usize, u64)> {
    let mut vols: Vec<(usize, usize, u64)> = Vec::new();
    for (fi, f) in nzb.files.iter().enumerate() {
        if (f.kind() != FileKind::Par2Volume && !sniffed_vols.contains(&fi))
            || already_fetched.contains(&fi)
        {
            continue;
        }
        let name = f.filename_hint().unwrap_or(&f.subject);
        // Blocks are block_size + ~100 bytes of packet overhead each,
        // yEnc ~2% inflation. Shared with pre-flight, which needs the
        // identical arithmetic to size a `.vol-NN.par2` budget and must
        // not grow a second answer to it (nzbkit::par2).
        let est = nzbkit::par2::est_recovery_blocks(f.bytes(), set.block_size);
        let count = vol_count_from_name(name).unwrap_or(est.max(1));
        vols.push((fi, count, f.bytes()));
    }
    vols
}

/// The most files a mapped repair will recreate from parity alone. Real
/// par-only posts carry a handful of targets; a par2 set declaring
/// thousands of absent files is an allocation bomb, not a post.
const MAX_RECREATED_FILES: usize = 1000;

/// M2c.1 - repair INTO the extracted output. When every damaged file is
/// a mapped store-mode slot, skip volume materialization entirely: read
/// present blocks through the extractor's volume view (header stash +
/// block→payload mapping over the already-extracted files), reconstruct
/// the bad ones, and patch them straight through the mapping - then the
/// whole-file MD5 self-verify runs over that same view. Success means
/// the output file is already correct: no re-extract, no volume files
/// on disk, ever.
///
/// Parity as a source: a par2 target file that is WHOLLY missing - a
/// par-only post (target never in the NZB), or a posted file whose
/// every article vanished - is rebuilt the same way, except its spans
/// cannot patch through a mapping that never existed. They FEED through
/// [`Extractor::write_repair`], the normal arrival path, in offset
/// order (the solver emits blocks in slice order, which is offset order
/// per file): the mapper, the store path, the chase attach all run
/// exactly as if the articles had downloaded, so the rebuilt volume
/// one-passes through whatever route its shape earns and no volume file
/// ever exists. Reconstructed spans charge the held-bytes budget like
/// arriving articles; a set over the cap demotes exactly like a
/// downloaded one.
///
/// Returns Ok(false) for every declined case (gate miss, verify fail,
/// I/O error) - the caller falls through to the materialize +
/// `repair_dir` path unchanged, which re-fetches at worst one round of
/// recovery volumes we already pulled (rare: only after a post-fetch
/// failure).
/// May an in-place plain patch KEEP the slot's classification?
///
/// A `plain_by_sniff` slot is Plain because offset 0 held no archive
/// magic - and a bad block over the sniff window says those were the
/// wrong bytes. Patching such a slot in place can restore a RAR
/// signature into a file the extractor goes on treating as plain:
/// nothing re-sniffs after repair, so the corrected archive retired as
/// the payload, packed, on a Completed job (Codex sweep 13 Aug R2).
/// False routes the set to the materialize + `repair_dir` +
/// `reextract_dir` path, which re-extracts what it repairs. The sniff
/// window is 8 bytes (the longest magic, RAR5); block b covers bytes
/// `[b*bs, (b+1)*bs)`.
fn plain_patch_keeps_sniff(bad_blocks: &[usize], block_size: usize) -> bool {
    !bad_blocks.iter().any(|&b| b.saturating_mul(block_size) < 8)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn try_mapped_repair(
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    nzb: &Nzb,
    out_dir: &Path,
    set: &nzbkit::par2::Par2Set,
    needed: usize,
    already_fetched: &[usize],
    sniffed_vols: &[usize],
    buf_pool: Arc<nzbkit::pool::BufPool>,
    extractor: &nzbkit::extract::Extractor,
    reports: &[(usize, nzbkit::live::SlotReport)],
    missing_files: &[String],
    // Filled, on success only, with the par2 names this call recreated
    // WHOLE from parity. `repair_mapped` whole-file-MD5s every file it
    // rebuilt a block into, so these names are proved to the same
    // standard the disk path proves its whole set - which is what lets
    // the caller clear them from the "still short" verdict.
    recreated_names: &mut Vec<String>,
    // The operator asked for FULL verification rather than fast: the
    // self-prove re-reads untouched files with MD5 too, not just their
    // per-block CRC32s.
    full_verify: bool,
    // The owner's side-fetch cancel handle - see [`SideCancel`]. The
    // parity this path fetches is network work like any other, and a
    // deleted job must stop asking for it.
    cancel: Option<&SideCancel>,
    // The caller's heavy-CPU permit, handed back for the duration of the
    // recovery fetch below - see [`crate::lanegate::HeavyCpu`].
    cpu: &mut crate::lanegate::HeavyCpu,
) -> Result<bool> {
    use nzbkit::par2repair::{MAX_INPUT_SLICES, MAX_REPAIR_DIM, VolumeIo, repair_mapped_catalog};
    // Gate: every set file must be one of
    //  - verified/damaged with a sane ledger, DAMAGED only if mapped or
    //    plain-patchable (a clean plain file was always fine - read_at
    //    serves it from its writer; a DAMAGED one now patches in place
    //    through the same writer, TODO 160);
    //  - wholly missing (unclaimed, or claimed with every block bad and
    //    not a byte on hand) - rebuilt from parity and FED through the
    //    normal arrival path.
    let bs = set.block_size as usize;
    let mut files: Vec<(nzbkit::par2::Par2File, Vec<bool>)> = Vec::with_capacity(set.files.len());
    // Slot per set file; None = a fresh slot, allocated only after
    // every cheap decline below so a declined call leaves no stray
    // slots in the extractor.
    let mut slot_of: Vec<Option<usize>> = Vec::with_capacity(set.files.len());
    // Some((par2 name, length)) = this file's reconstructed spans FEED
    // through `Extractor::write_repair` instead of `patch_volume_span`.
    let mut feed: Vec<Option<(String, u64)>> = Vec::with_capacity(set.files.len());
    let mut total_slices = 0usize;
    let mut missing_slices = 0usize;
    let mut recreated = 0usize;
    for f in &set.files {
        let n = f.length.div_ceil(set.block_size) as usize;
        total_slices += n;
        match reports
            .iter()
            .find(|(_, r)| r.par2_name.as_deref() == Some(f.name.as_str()))
        {
            Some((sidx, r)) => {
                if r.total_blocks != n || r.bad_blocks.iter().any(|&b| b >= n) {
                    return Ok(false);
                }
                // A claimed slot with every block bad and ZERO bytes on
                // hand (a resume-seeded name whose refetch all failed)
                // is a whole-file loss, not damage: nothing to patch
                // through, everything to feed.
                let wholly_missing = n > 0
                    && r.bad_blocks.len() == n
                    && !extractor.is_mapped(*sidx)
                    && extractor.covered_intervals(*sidx, 0, f.length).is_empty();
                if wholly_missing {
                    recreated += 1;
                    feed.push(Some((f.name.clone(), f.length)));
                } else {
                    // Damage patches in place through the slot's own
                    // byte view: the block→payload mapping for a mapped
                    // volume, the output writer for a plain file. Any
                    // other shape - above all a CHASE, whose frontier
                    // buffer cannot take a rewrite - declines the whole
                    // call to the materialize path. A plain file is the
                    // TODO 160 admission: without it, one bad article
                    // in a plain set member demoted every chased volume
                    // beside it to disk and re-extracted them.
                    //
                    if !r.bad_blocks.is_empty()
                        && !extractor.is_mapped(*sidx)
                        && (!extractor.is_plain_patchable(*sidx)
                            || !plain_patch_keeps_sniff(&r.bad_blocks, bs))
                    {
                        return Ok(false);
                    }
                    feed.push(None);
                }
                missing_slices += r.bad_blocks.len();
                let mut present = vec![true; n];
                for &b in &r.bad_blocks {
                    present[b] = false;
                }
                files.push((f.clone(), present));
                slot_of.push(Some(*sidx));
            }
            None => {
                // No slot claimed this file: a par-only post's target,
                // or a posted file whose every article vanished before
                // a name could be learned. Recreate it from parity -
                // with guard rails, since FileDesc name/length are
                // attacker-influenced input reaching a new consumer:
                //  - only files the census actually declared missing;
                //  - no zero-length targets (the disk path makes empty
                //    files; a fed slot with no writes would "verify"
                //    without ever creating one);
                //  - an internally consistent set (IFSC count must
                //    match the declared length);
                //  - posted wins: never a second slot for a name some
                //    output writer or chased slot already carries.
                if !missing_files.iter().any(|m| m == &f.name) {
                    return Ok(false);
                }
                if f.length == 0 {
                    return Ok(false);
                }
                if !f.blocks.is_empty() && f.blocks.len() != n {
                    return Ok(false);
                }
                if !extractor
                    .map_output_range(&nzbkit::disk::sanitize_filename(&f.name), 0, 1)
                    .is_empty()
                {
                    return Ok(false);
                }
                recreated += 1;
                missing_slices += n;
                // The bomb check below runs AFTER this loop, but the
                // allocation is here: `n` comes from a FileDesc length
                // this set declares, and the IFSC cross-check above is
                // skipped when no IFSC packet survived parsing, so a
                // declared length alone can size this vector. Refuse at
                // the same ceiling before reserving anything.
                if missing_slices > MAX_REPAIR_DIM {
                    return Ok(false);
                }
                feed.push(Some((f.name.clone(), f.length)));
                files.push((f.clone(), vec![false; n]));
                slot_of.push(None);
            }
        }
    }
    // Anti-preallocation-bomb: refuse counts the repair math could
    // never satisfy anyway (a 64 GiB FileDesc over 4 KiB blocks is 16M
    // slices against a 32768-slice format) BEFORE allocating anything.
    if recreated > MAX_RECREATED_FILES
        || total_slices > MAX_INPUT_SLICES
        || missing_slices > MAX_REPAIR_DIM
    {
        return Ok(false);
    }

    // Exact-fit recovery fetch - same knapsack + margin as the disk path.
    let fetched_files: Vec<usize>;
    if needed > 0 {
        let vols = recovery_candidates(nzb, set, already_fetched, sniffed_vols);
        let have: usize = vols.iter().map(|v| v.1).sum();
        if have < needed {
            return Ok(false); // the disk path prints the unrepairable warning
        }
        let target = (needed + (needed / 10).max(2)).min(have);
        let chosen = pick_volumes(&vols, target);
        let dl_bytes: u64 = chosen.iter().map(|&i| vols[i].2).sum();
        let dl_blocks: usize = chosen.iter().map(|&i| vols[i].1).sum();
        println!(
            "repair: need {needed} block(s) → fetching {} volume(s), {} block(s), {:.1} MB",
            chosen.len(),
            dl_blocks,
            dl_bytes as f64 / 1e6
        );
        fetched_files = chosen.iter().map(|&vi| vols[vi].0).collect();
        // The failure count is deliberately unused here: this path's
        // `fetched_files` never feeds an exclusion list (a decline
        // falls through to `fetch_and_repair`, which recomputes its
        // candidates), and the mapped catalog below re-proves every
        // slice it selects against its packet MD5.
        let _partial_failures = cpu
            .without_permit(fetch_volumes(
                servers,
                nzb,
                out_dir,
                &buf_pool,
                &fetched_files,
                cancel,
            ))
            .await?;
    }

    // Catalog every recovery slice on disk (bootstrap + fetched volumes)
    // as validated LOCATORS - by extension AND by packet magic, exactly
    // the file set the old whole-file harvest read (an obfuscated post's
    // volumes land under hash names no extension rule can match, issue
    // #14; the packet-file ceiling binds both kinds alike, Codex sweep
    // 10 Aug M4). The payload bytes stay on disk: `repair_mapped_catalog`
    // preads only the exponents the repair actually selects, re-proving
    // each against its packet MD5, so peak recovery memory is missing x
    // block_size instead of every slice in the directory (B3 stage 2 on
    // the B2 catalog).
    let t0 = Instant::now();
    let mut cat = nzbkit::par2repair::PacketCatalog::build(out_dir)?;

    // Allocate the fresh slots only now, past every cheap decline. A
    // late decline (verify failure, I/O error) can still leave fed
    // slots behind for the disk fallback to overrule - `repair_dir`
    // recreates the files on disk authoritatively either way.
    let slot_of: Vec<usize> = slot_of
        .into_iter()
        .map(|s| s.unwrap_or_else(|| extractor.alloc_slot()))
        .collect();

    struct Io<'a> {
        ex: &'a nzbkit::extract::Extractor,
        slot_of: &'a [usize],
        feed: &'a [Option<(String, u64)>],
    }
    impl VolumeIo for Io<'_> {
        fn read(&self, file: usize, off: u64, buf: &mut [u8]) -> std::io::Result<()> {
            self.ex.read_at(self.slot_of[file], off, buf)
        }
        fn write(&self, file: usize, off: u64, data: &[u8]) -> std::io::Result<()> {
            match &self.feed[file] {
                // Wholly-missing file: reconstructed spans are just
                // late-arriving article data - route, classify, extract.
                Some((name, size)) => self
                    .ex
                    .write_repair(self.slot_of[file], name, *size, off, data)
                    .map(|_| ()),
                None => self.ex.patch_volume_span(self.slot_of[file], off, data),
            }
        }
    }
    let io = Io {
        ex: extractor,
        slot_of: &slot_of,
        feed: &feed,
    };
    match repair_mapped_catalog(&files, bs, &mut cat, &set.recovery_set_id, &io, full_verify) {
        Ok(n) => {
            recreated_names.extend(feed.iter().flatten().map(|(name, _)| name.clone()));
            let parity = if recreated > 0 {
                format!(", {recreated} file(s) recreated from parity")
            } else {
                String::new()
            };
            println!(
                "repair complete in {:.2?} ✔ (native, mapped: {n} block(s) rebuilt directly into the output{parity})",
                t0.elapsed(),
            );
            Ok(true)
        }
        Err(e) => {
            println!("⚠ mapped repair declined ({e}) - falling back to volume materialization");
            Ok(false)
        }
    }
}

/// Run the external par2 binary over `out_dir` with OUR handles released.
///
/// par2cmdline opens every target and every extra file with no sharing, so a
/// handle we still hold makes its open fail - and it does not treat that as an
/// error to report, it treats the file as ABSENT. Measured on Windows before
/// this parked anything, on a set with one corrupt article:
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
    extractor: &nzbkit::extract::Extractor,
) -> Result<std::io::Result<std::process::ExitStatus>> {
    let parked = extractor.park_outputs();
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
    Ok(status.expect("status is Some whenever the park succeeded"))
}

/// Damaged path: fetch the cheapest set of recovery volumes covering
/// `needed` blocks (exact-fit by declared slice counts), then hand the
/// directory to par2cmdline for Reed-Solomon repair.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn fetch_and_repair(
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    nzb: &Nzb,
    out_dir: &Path,
    set: &nzbkit::par2::Par2Set,
    needed: usize,
    main_par2: Option<PathBuf>,
    already_fetched: &[usize],
    sniffed_vols: &[usize],
    buf_pool: Arc<nzbkit::pool::BufPool>,
    // Parked around every EXTERNAL par2 invocation - par2cmdline cannot open
    // a file we hold (see `run_external_par2`). Native repair never needs
    // this: it is in-process and reads through our own handles.
    extractor: &nzbkit::extract::Extractor,
    // Set to (needed, have) when the NZB simply does not carry enough
    // recovery blocks - the one repair failure whose arithmetic belongs
    // in the job's fail message, not just the console.
    shortfall: &mut Option<(usize, usize)>,
    // The owner's side-fetch cancel handle - see [`SideCancel`].
    cancel: Option<&SideCancel>,
    // The caller's heavy-CPU permit, handed back for the duration of
    // both recovery fetches below - see [`crate::lanegate::HeavyCpu`].
    cpu: &mut crate::lanegate::HeavyCpu,
) -> Result<bool> {
    let mut fetched_files: Vec<usize> = Vec::new();
    if needed > 0 {
        let vols = recovery_candidates(nzb, set, already_fetched, sniffed_vols);
        let have: usize = vols.iter().map(|v| v.1).sum();
        if have < needed {
            println!(
                "⚠ unrepairable: {needed} blocks needed, only {have} recovery blocks in the NZB"
            );
            *shortfall = Some((needed, have));
            return Ok(false);
        }

        // Min-bytes subset with slice sum ≥ needed - plus ~10% margin:
        // par2's own damage count can exceed the block ledger's (a hole
        // invalidates boundary blocks under its scan), and coming up
        // short costs a whole second round-trip.
        let target = (needed + (needed / 10).max(2)).min(have);
        let chosen = pick_volumes(&vols, target);
        let dl_bytes: u64 = chosen.iter().map(|&i| vols[i].2).sum();
        let dl_blocks: usize = chosen.iter().map(|&i| vols[i].1).sum();
        println!(
            "repair: need {needed} block(s) → fetching {} volume(s), {} block(s), {:.1} MB",
            chosen.len(),
            dl_blocks,
            dl_bytes as f64 / 1e6
        );

        fetched_files = chosen.iter().map(|&vi| vols[vi].0).collect();
        let failures = cpu
            .without_permit(fetch_volumes(
                servers,
                nzb,
                out_dir,
                &buf_pool,
                &fetched_files,
                cancel,
            ))
            .await?;
        if failures > 0 {
            // At least one chosen volume landed PARTIAL, and the batch
            // count cannot say which - so none of the batch may enter
            // the escalation's exclusion list below (only a complete
            // volume may ever be excluded: sidefetch contract). The
            // escalation then refetches them in full, rewriting the
            // files in place - the behavior the resume path documents -
            // instead of permanently stranding the partial volume's
            // missing slices and declaring a recoverable job
            // unrepairable.
            fetched_files.clear();
        }
    }

    // Reed-Solomon repair: native in-process GF(2^16) first - verifies the
    // set from disk, reconstructs missing blocks, and patches files IN
    // PLACE (no volume rewrite). Self-proving: success requires every
    // patched file to match its PAR2 whole-file MD5, so a native bug can
    // never ship bad bytes - it falls through to par2cmdline instead.
    let native_repair = || -> bool {
        if std::env::var_os("NZBFAST_NO_NATIVE_REPAIR").is_some() {
            return false;
        }
        let t0 = Instant::now();
        use nzbkit::par2repair::{RepairStatus, repair_dir};
        match repair_dir(out_dir) {
            Ok(RepairStatus::NoDamage) => {
                println!(
                    "repair complete in {:.2?} ✔ (native - set already verifies on disk)",
                    t0.elapsed()
                );
                true
            }
            Ok(RepairStatus::Repaired(r)) => {
                println!(
                    "repair complete in {:.2?} ✔ (native, in place: {} block(s) rebuilt across {} file(s){}{})",
                    t0.elapsed(),
                    r.blocks_rebuilt,
                    r.files_patched.len(),
                    if r.files_created.is_empty() {
                        String::new()
                    } else {
                        format!(", {} recreated", r.files_created.len())
                    },
                    if r.blocks_adopted == 0 {
                        String::new()
                    } else {
                        format!(
                            ", {} block(s) adopted from {}",
                            r.blocks_adopted,
                            r.adopted_from.join(", ")
                        )
                    },
                );
                true
            }
            Ok(RepairStatus::Unrepairable { needed, have }) => {
                println!(
                    "⚠ native repair: {needed} block(s) damaged, only {have} recovery block(s) on disk"
                );
                false
            }
            Err(e) => {
                println!("⚠ native repair failed ({e}) - falling back to par2cmdline");
                false
            }
        }
    };
    if native_repair() {
        return Ok(true);
    }

    // par2cmdline fallback - the escape hatch for anything the native
    // path declines (see par2repair.rs module docs).
    //
    // It is OPTIONAL, and neither of its two absences may return from
    // here: the escalation below is the NATIVE path's second chance
    // (every remaining recovery volume on disk, then `repair_dir`
    // again), and it is reached by falling through this block. Bailing
    // out because an unrelated external tool is missing failed sets a
    // native-only install could repair (Codex sweep 10 Aug, M3).
    let t0 = Instant::now();
    // `external` is Some only while par2cmdline is still worth trying:
    // taken for each attempt, put back only when it actually ran.
    let mut external = main_par2.as_ref().map(|main_par2| {
        // Sibling binary, else PATH (see tools.rs).
        let par2_bin = tools::resolve("par2");
        // par2cmdline 1.2.0 rejects absolute par2 paths ("failed to set the
        // main par file") - pass the bare name and set cwd.
        let par2_name = main_par2
            .file_name()
            .map(|n| n.to_owned())
            .unwrap_or_else(|| main_par2.clone().into_os_string());
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
        let extra_args: Vec<std::path::PathBuf> = extra_files.iter().map(|f| dot.join(f)).collect();
        (par2_bin, par2_arg, extra_args)
    });
    if external.is_none() {
        println!("⚠ no main .par2 on disk - cannot invoke par2cmdline");
    }
    if let Some((bin, arg, extras)) = external.take() {
        match run_external_par2(&bin, &arg, &extras, out_dir, extractor)? {
            Ok(st) if st.success() => {
                println!("repair complete in {:.2?} ✔", t0.elapsed());
                return Ok(true);
            }
            Ok(st) => {
                println!("⚠ par2 repair exited with {st}");
                external = Some((bin, arg, extras));
            }
            Err(e) => {
                // par2 is no longer embedded - native repair covers real
                // sets, so reaching this needs both an exotic failure AND
                // no external par2 on PATH or next to the executable.
                // Left as None: a binary that could not be spawned will
                // not spawn on the second pass either.
                println!(
                    "⚠ no external par2 was runnable ({e}) - install par2cmdline \
                     (e.g. brew install par2) or place a par2 binary next to nzbfast; \
                     continuing with native repair alone"
                );
            }
        }
    }

    // Escalation: par2's own damage accounting can exceed the ledger's -
    // fetch every remaining recovery volume and try once more.
    let remaining: Vec<usize> = recovery_candidates(nzb, set, already_fetched, sniffed_vols)
        .iter()
        .map(|v| v.0)
        .filter(|fi| !fetched_files.contains(fi))
        .collect();
    if remaining.is_empty() {
        return Ok(false);
    }
    println!(
        "repair short - fetching all {} remaining volume(s)",
        remaining.len()
    );
    cpu.without_permit(fetch_volumes(
        servers, nzb, out_dir, &buf_pool, &remaining, cancel,
    ))
    .await?;
    if native_repair() {
        return Ok(true);
    }
    if let Some((bin, arg, extras)) = external
        && let Ok(st) = run_external_par2(&bin, &arg, &extras, out_dir, extractor)?
        && st.success()
    {
        println!("repair complete (second pass) ✔");
        return Ok(true);
    }
    println!("⚠ repair failed even with every recovery volume");
    Ok(false)
}

/// Indexes into `vols` = (file, slices, bytes) minimizing downloaded bytes
/// subject to Σ slices ≥ needed. Exact 0/1 knapsack with an explicit
/// chosen-set bitmask (recovery sets virtually never exceed 64 volumes);
/// beyond 64, greedy by cost-per-slice.
pub(crate) fn pick_volumes(vols: &[(usize, usize, u64)], needed: usize) -> Vec<usize> {
    if vols.len() > 64 {
        let mut order: Vec<usize> = (0..vols.len()).collect();
        order.sort_by(|&a, &b| (vols[a].2 * vols[b].1 as u64).cmp(&(vols[b].2 * vols[a].1 as u64)));
        let mut chosen = Vec::new();
        let mut got = 0usize;
        for vi in order {
            if got >= needed {
                break;
            }
            chosen.push(vi);
            got += vols[vi].1;
        }
        return chosen;
    }
    // dp[d] = (bytes, mask) - cheapest way to cover a deficit of ≥ d blocks.
    let n = needed;
    const INF: u64 = u64::MAX;
    let mut dp: Vec<(u64, u64)> = vec![(INF, 0); n + 1];
    dp[0] = (0, 0);
    for (vi, &(_, slices, bytes)) in vols.iter().enumerate() {
        for d in (0..=n).rev() {
            let (cost, mask) = dp[d];
            if cost == INF {
                continue;
            }
            let nd = (d + slices).min(n);
            let ncost = cost + bytes;
            if ncost < dp[nd].0 {
                dp[nd] = (ncost, mask | (1u64 << vi));
            }
        }
    }
    let mask = dp[n].1;
    (0..vols.len())
        .filter(|vi| mask & (1u64 << vi) != 0)
        .collect()
}

// Child module file, not inline: repair.rs sits under the size-gate
// ceiling (TODO 106) and test growth belongs beside it, same pattern
// as side_fetch_tests below.
#[cfg(test)]
mod repair_tests;

// Child module file, not inline: repair.rs sits under a size-gate
// baseline (TODO 106) and test growth belongs beside it, same pattern
// as pool/unit_tests.rs.
#[cfg(test)]
mod side_fetch_tests;
