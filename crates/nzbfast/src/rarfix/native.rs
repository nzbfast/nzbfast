//! The native in-process RAR extraction path: the vendored `rars`
//! engine driving a parsed volume set out to disk, with TODO 101's
//! volume-eating mode and the chase's resume ledger hanging off it.
//!
//! Split out of `rarfix.rs` verbatim under the TODO 106 recipe (the file
//! was at its size ceiling and the resume hook could not land in it) -
//! a move of the functions, not a redesign. The bomb-guard and
//! deferred-flush writers stay in the parent: the 7z and zip disk arms
//! use them too.

use super::*;
use tracing::{info, warn};

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
    // TODO 217's rewind lives HERE, not in the pass: a resumed prefix
    // that fails its verification against the re-decode aborts the
    // whole extraction from inside the entry writer, and the only
    // correct answer is to clear the ledger and run the pass once more
    // from byte zero - which is the old behaviour and always correct.
    // `with_mismatch_retry` carries the loop-proof. The one shape that
    // may not retry is a pass that has already eaten source volumes:
    // the retry would read files the first attempt deleted.
    let eaten_any = std::sync::atomic::AtomicBool::new(false);
    crate::resumeout::with_mismatch_retry(
        || !eaten_any.load(std::sync::atomic::Ordering::Relaxed),
        |mismatch| unpack_pass(dir, archives, password, sources, mismatch, &eaten_any),
    )
}

/// One attempt of [`write_archives_to_spending`]'s extraction: plan the
/// resume, stage, extract, publish. Split from the wrapper so the
/// mismatch rewind can run it twice without duplicating a line of it.
fn unpack_pass(
    dir: &std::path::Path,
    archives: &[rars::Archive],
    password: Option<&str>,
    sources: &[PathBuf],
    mismatch: &crate::resumeout::MismatchFlag,
    eaten_any: &std::sync::atomic::AtomicBool,
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
        crate::diskfree::free_bytes(dir)
            .map(|free| free.saturating_sub(EXTRACT_RESERVE))
            .unwrap_or(u64::MAX),
    );
    let credit = budget.credit_handle();
    let written = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    // Members a forfeited chase already wrote a good prefix of, so this
    // pass appends instead of re-extracting from byte zero. Read ONCE,
    // here, on the calling thread: the ledger is a thread-local (see
    // [`crate::resumeout::plan_pass`], which also carries the
    // duplicate-name refusal and clears the partials this pass declines).
    let member_names: Vec<String> = archives
        .iter()
        .flat_map(|a| a.members())
        .filter(|m| !m.meta.is_directory)
        .map(|m| m.meta.name_lossy())
        .collect();
    let resume = crate::resumeout::plan_pass(dir, &member_names);
    let resumed_bytes: u64 = resume.values().map(|(_, len, _)| *len).sum();
    // TODO 205: the queue row's unpack line reads this very counter.
    // Resumed bytes count as work already done, or the row would stall
    // short of its total by exactly the prefix this pass never writes.
    crate::unpackprog::watch(&written, archives, resumed_bytes);

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
    // Which resumed files this pass actually opened. Success hands them
    // to the ledger as finished; a failure takes them away, because an
    // appended-to partial is no longer the clean prefix the ledger's own
    // cleanup can recognise.
    let resumed_opened: std::sync::Arc<std::sync::Mutex<Vec<PathBuf>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let resumed_paths = resumed_opened.clone();
    let verify_flag = mismatch.clone();
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
        // A resumed member is the one entry that does NOT stage: its
        // bytes are already in the output directory and there is no way
        // to append to them from a staging copy (a hardlink would share
        // the inode, so the writes would land in the published file
        // anyway - with none of the atomicity a staged copy implies).
        // Opened for WRITE without truncation, positioned at the mark.
        if let Some((path, len, crc)) = resume.get(meta.name_lossy().as_str()) {
            let f = crate::resumeout::open_at_mark(path, *len)?;
            resumed_paths.lock_ok().push(path.clone());
            return Ok(Box::new(DeferredFlushWriter {
                inner: crate::resumeout::ResumeWriter::verified(
                    *len,
                    *crc,
                    verify_flag.clone(),
                    BombGuardWriter {
                        inner: std::io::BufWriter::new(f),
                        written: written.clone(),
                        budget: budget.clone(),
                    },
                ),
                failed: entry_flush_err.clone(),
            }) as Box<dyn std::io::Write>);
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
        info!(
            target: "extract",
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
                    eaten_any.store(true, std::sync::atomic::Ordering::Relaxed);
                    bytes = bytes.saturating_add(size);
                    // The space is back NOW, so the guard may spend it
                    // now - and not one byte before. A volume we could
                    // not remove credits nothing, which is exactly what
                    // the warning below is about.
                    credit.fetch_add(size, std::sync::atomic::Ordering::Relaxed);
                }
                // Not fatal: extraction has already read this volume, so
                // a file we cannot remove costs space, not correctness.
                Err(e) => {
                    warn!(target: "extract", "could not remove spent volume {}: {e}", path.display())
                }
            }
        };
        let result = rars::extract_volumes_to_with_progress(
            archives,
            rars::ArchiveReadOptions::with_optional_password(password.map(str::as_bytes)),
            open,
            consumed,
        );
        if eaten > 0 {
            info!(
                target: "extract",
                "freed {eaten} spent volume(s) during extraction ({:.1} GB)",
                bytes as f64 / 1e9
            );
        }
        finish_resumed(&resumed_opened, result.is_ok());
        result.map_err(|e| anyhow::anyhow!("{e}"))?;
    } else {
        let result = rars::extract_volumes_to(archives, password.map(str::as_bytes), open);
        finish_resumed(&resumed_opened, result.is_ok());
        result.map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    if let Some(e) = flush_err.lock().unwrap_or_else(|p| p.into_inner()).take() {
        // The decode said yes and the device said no, on a file we were
        // APPENDING to - so it is short by an unknown amount with no
        // record of where. `finish_resumed` has already handed it to the
        // ledger as finished, which is wrong for this one path: take it
        // back and remove it, exactly as an extraction failure would.
        crate::resumeout::discard(&resumed_opened.lock_ok());
        anyhow::bail!("extracted file could not be fully written to disk: {e}");
    }
    staging.publish_into(dir)
}

/// Hand the resumed files to the ledger through their mutex - the
/// entry callback runs on the extractor's own threads, so the list this
/// unlocks is the only settled view of what was opened.
fn finish_resumed(opened: &std::sync::Mutex<Vec<PathBuf>>, ok: bool) {
    crate::resumeout::finish(&opened.lock_ok(), ok);
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
