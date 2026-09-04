//! Post-download repair: reextract_dir, recovery-volume fetch over the side pool, mapped PAR2 repair, external par2 invocation and fetch_and_repair.
//!
//! Split out of main.rs verbatim; behaviour unchanged.

use crate::*;
use std::path::Path;
use tracing::{info, warn};

/// Extract the archive volumes sitting in `dir`, whether they arrived
/// there by a repair, a resume, or a demote - "did the payload come
/// out?" and nothing more.
///
/// Nothing in production reads the ladder that way any longer. The last
/// one was `smart::unlock`, whose callers walk a LIST of passwords and
/// so had the most to lose by dropping the reason - a single bomb
/// verdict refused every candidate in the operator's file in turn and
/// was then reported as "no password worked" (22 Aug 2026). It took
/// [`reextract_dir_why`] with the rest, and what is left here is the
/// tests, which assert "did the payload come out" and nothing more.
// `test-support` as well as `test`: `serve`'s own reextract tests are a
// CRATE away since the step 3 cut, and a `cfg(test)` item is invisible
// from another crate whatever its visibility.
#[cfg(any(test, feature = "test-support"))]
pub fn reextract_dir(dir: &std::path::Path, password: Option<&str>) -> Result<bool> {
    Ok(reextract_dir_why(dir, password)?.is_ok())
}

/// [`reextract_dir`] that also names WHY it failed, on the one class of
/// failure that is about the DISK rather than the archive.
///
/// Same contract and same reasoning as [`crate::rarfix::try_unrar_spent_why`],
/// which this delegates to for its own last rung: `Err(None)` is the
/// ordinary failure the caller words itself, `Err(Some(why))` is a bomb
/// verdict that must be quoted rather than paraphrased. Both of this
/// function's callers compose a job failure from a bare `false` -
/// "resumed job: the verified volumes on disk could not be extracted"
/// and "PAR2 repair succeeded but re-extraction failed" - and both of
/// those blame the archive for a full disk.
///
/// The third caller - `smart`'s password unlock - read the plain
/// [`reextract_dir`] until 22 Aug 2026, on the reasoning that "did this
/// password open anything" has no job message to compose. It has: its
/// own callers walk a LIST of candidates, so one bomb verdict refused
/// every password in the operator's file in turn and the job was then
/// reported as having none that worked. It takes this function now, and
/// what is left on the boolean is the tests.
pub fn reextract_dir_why(
    dir: &std::path::Path,
    password: Option<&str>,
) -> Result<std::result::Result<(), Option<String>>> {
    Ok(reextract_dir_outcome(dir, password)?.map(|_| ()))
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
/// bases resolve as they arrive instead of piling into the holds cap. This
/// paragraph predates the split into [`reextract_dir_why`]/this function;
/// "true" was the return type before that split, and the mechanism it
/// describes now lives here.
///
/// [`reextract_dir_why`] that also carries out what the unrar rung left
/// PACKED beside a sibling that produced (TODO 164): the resumed-run arm
/// of the tail runs this ladder with the job's PAR2 set in scope, and
/// judges the leftovers against it exactly as the fresh-run arms do -
/// see [`crate::rarfix::vouch`]. Every success path that never reaches
/// the unrar rung left nothing packed, and says so with an empty list.
pub fn reextract_dir_outcome(
    dir: &std::path::Path,
    password: Option<&str>,
) -> Result<std::result::Result<Vec<crate::rarfix::PackedGroup>, Option<String>>> {
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
            info!(
                target: "extract",
                "re-extracting {} obfuscated volume(s) by header order…",
                obf.len()
            );
            // Depth 1 = sweep the volumes this consumed, which is already
            // this function's contract for a set it extracted (the named
            // branch below removes its own on the same terms) and what the
            // nested pass does with them today.
            return Ok(extract_obfuscated_rar(dir, &obf, password, 1)
                .ok()
                .then(Vec::new)
                .ok_or(None));
        }
        // Genuinely nothing packed: a bare recreated payload, an already
        // extracted directory. That IS a legitimate no-op and stays a
        // success - but it is said out loud, so no log or reader can take
        // it for "extracted".
        info!(target: "extract", "no archive volumes on disk - nothing to re-extract");
        return Ok(Ok(Vec::new()));
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
    // (get/tail.rs arms the mode and then calls `reextract_dir_outcome`),
    // which is the one shape where the disk is tightest by definition. The
    // native whole-set path IS the one that eats, so an armed job goes
    // there first; a failure still falls through, and the guard below
    // catches the case where falling through is impossible because the
    // volumes have been spent.
    //
    // TODO 205 follow-up: the native shortcut below and the plain feed
    // under it are two ways at ONE set, and a native failure falls
    // through from the first to the second - so without a rewind the
    // failed shortcut's totals were banked into the queue row's unpack
    // lane as a set of their own, and every header-encrypted set that
    // fell through reported twice the bytes it produces. See
    // [`crate::unpackprog::mark`].
    let mark = crate::unpackprog::mark();
    if one_set && (header_encrypted || crate::eatvol::armed()) {
        info!(
            target: "extract",
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
                info!(target: "extract", "native re-extract complete ✔");
                remove_spent_volumes(&consumed);
                return Ok(Ok(Vec::new()));
            }
            Err(e) => {
                warn!(target: "extract", "native re-extract failed ({e})");
                // The comment above ("a native failure just falls through
                // to it, having published nothing") predates §101. Under
                // the eating mode the failed pass may have consumed
                // volumes as it read them, and the loop below re-reads
                // every one by path - so its `File::open(path)?` would
                // not fall through at all, it would `?` a hard error out
                // of `get_with_progress` and fail the whole download task
                // rather than this step. Fail cleanly here instead.
                if rars.iter().any(|p| !p.exists()) {
                    warn!(
                        target: "extract",
                        "✘ volumes were consumed as they were read (the volume-eating \
                         unpack), so there is nothing left to re-extract from"
                    );
                    return Ok(Err(None));
                }
            }
        }
    }
    info!(target: "extract", "re-extracting {} repaired volume(s)…", rars.len());
    // No `set_holds_cap` here, deliberately: since TODO 260 the ctor
    // takes its default from the PUBLISHED process budget, and all three
    // nzbfast entry points (`serve`, the CLI's `run`, `embedded_init`)
    // publish one before anything can reach this path - so this pass gets
    // the operator's 45% slice without a second copy of the arithmetic.
    // Audited the same day: no FrontierBuffer can fill here for two
    // independent reasons - `set_protect_sources` below gates off all four
    // container attaches (extract/chase.rs, sevenz.rs, zip.rs, tar.rs),
    // and this extractor is not in an `Arc`, so `self_weak` never
    // upgrades and every attach declines regardless. Ordinary holds CAN
    // still accumulate, though: the volumes below are fed whole and in
    // `vol_sort_key` order, which an obfuscated set has no ordering for,
    // so a continuation volume fed first holds its bytes until the head
    // arrives. That is safe (a breach discards the slot and falls through
    // to the unrar rung) but it is exactly the RAM the operator sized.
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
    if let Some(free) = crate::diskfree::free_bytes(dir) {
        ex.set_extract_budget(free.saturating_sub(EXTRACT_RESERVE));
    }
    if let Some(pw) = password {
        ex.set_password(pw);
    }
    // TODO 205: the queue row's unpack lane, on the one arm of the disk
    // ladder that does not go through `rarfix::write_archives_to_spending`.
    //
    // There is no `written` accumulator to publish here and no header
    // total either: this branch hands the volumes to nzbkit's own
    // extractor, which parses each member as the feed reaches its header
    // rather than up front. Its OWN output writers are both figures, and
    // they are the very ones the IN-STREAM lane reads
    // (`writers_snapshot`, `api/queue.rs`), so the sample below
    // counts nothing twice and the total climbs as members appear -
    // which is what [`crate::unpackprog::raise_total`] is monotonic for.
    //
    // Nothing resumes on this route (`set_protect_sources` discards a
    // demote rather than materializing it, so no slot writer can join
    // the snapshot either), so the credit is 0.
    let unpacked = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    mark.rewind();
    crate::unpackprog::watch(&unpacked, &[], 0);
    let sample = |ex: &Extractor| {
        let (done, total) = ex
            .writers_snapshot()
            .iter()
            .fold((0u64, 0u64), |(d, t), (_, w)| {
                (d.saturating_add(w.written()), t.saturating_add(w.size))
            });
        unpacked.store(done, std::sync::atomic::Ordering::Relaxed);
        crate::unpackprog::raise_total(total);
    };
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
            // Once per 4 MB chunk: a snapshot clones a handful of `Arc`s
            // under a read lock, which is nothing beside the decode that
            // just ran, and the row would otherwise sit still for a
            // whole volume at a time.
            sample(&ex);
        }
    }
    let rep = ex.finish()?;
    // The last writers close inside `finish`, so the figure the row ends
    // on comes from here rather than from the loop above.
    sample(&ex);
    for (name, size) in &rep.extracted {
        info!(target: "extract", "{name} ({:.1} MB)", *size as f64 / 1e6);
    }
    for (group, why) in &rep.fallbacks {
        warn!(target: "extract", "'{group}': not re-extractable ({why})");
    }
    if rep.fallbacks.is_empty() && !rep.extracted.is_empty() {
        // Extraction verified (repair pass vouched for the volume bytes) -
        // the volumes served their purpose.
        for path in &rars {
            let _ = std::fs::remove_file(path);
        }
        info!(target: "extract", "removed {} volume file(s) after extraction", rars.len());
        return Ok(Ok(Vec::new()));
    }
    if rep.fallbacks.iter().all(|(_, w)| w.contains("password"))
        && !rep.fallbacks.is_empty()
        && password.is_none()
    {
        warn!(target: "extract", "volumes are verified on disk - password required to unpack");
        return Ok(Ok(Vec::new()));
    }
    // Same floor as the ladder in `try_unrar_spent_why`, one level up:
    // this pass demoted because the extraction would not fit on the disk,
    // and the unrar rung below carries no budget to stop it filling. The
    // caller turns a failure into a job failure and every volume stays -
    // and it says the VERDICT, because `bomb_fallback` has one right here
    // and the caller's own wording ("PAR2 repair succeeded but
    // re-extraction failed") blames the archive for the disk.
    if let Some(why) = bomb_fallback(rep.fallbacks.iter().map(|(_, w)| w.as_str())) {
        return Ok(Err(Some(why)));
    }
    info!(target: "extract", "falling back to unrar on the verified volumes…");
    // A successful disk unpack spends the volumes exactly like the clean
    // path above - leaving them behind doubled a job's disk footprint
    // (Part B, research/SPEC-onepass-obfuscated-store-sets-2026-07-29.md).
    match try_unrar_outcome(dir, password) {
        Ok(outcome) => {
            remove_spent_volumes(&outcome.spent);
            Ok(Ok(outcome.packed))
        }
        // TODO 211's third and last call site. A repaired set can be a byte
        // SPLIT of one container (`stage.rar.001`..`.062`) exactly as often
        // as an undamaged one can, and the collector above pulls only part 1
        // out of it - the sole part carrying the `Rar!` magic that
        // `rollover_or_numeric` demands - so the feed loop hands the mapper
        // 1/62nd of an archive, every arm demotes, and unrar finds nothing
        // it can open. Without this rung the shape TODO 211 fixed still
        // failed whenever it ALSO needed a repair.
        //
        // The sweep is right here despite `set_protect_sources` above:
        // that flag is a within-pass invariant (no fallback slot may
        // materialize a writer over a file the feed is still reading), and
        // `ex.finish()` has already returned. Consuming the parts is the
        // same trade the two arms above make - the payload beside them IS
        // their content - and it is what stops a repaired split job
        // finishing holding both the movie and all 62 parts of it. A
        // sibling PAR2 set is not stranded by it: recovery files are swept
        // (or kept) downstream by `par_cleanup` on the job's own verdict,
        // never by what the volumes did, and `collect_container_split_sets`
        // will not join a `.par2`/`.par`/`.rev`/`.sfv` base in the first
        // place. A refusal anywhere leaves every part exactly where it was.
        Err(_) if rescue_split_after_failed_unpack(dir, password) => Ok(Ok(Vec::new())),
        // Whatever the ladder refused with, verbatim: `Some` only for a
        // bomb verdict, which is the one refusal that must not be
        // reworded by the caller.
        Err(why) => Ok(Err(why)),
    }
}

mod volbase;
// TODO 311's index-name rule, out of the way of a file at its ceiling.
// One function and its two bounds; `recovery_candidates` is its only
// caller and there is nothing about the split for anyone else to know.
use volbase::index_bases_on_disk;

mod volcount;
// L2 of the wave-4 matrix read: how far a recovery volume's NAME may be
// believed about its own block count, out of the way of the same
// ceiling. One function and the same single caller.
use volcount::credited_blocks;

mod mappedplan;
// The mapped route's gate, moved out on 31 Aug 2026 to keep the split
// that bought `try_mapped_repair` its margin from spending this file's.
// One subject and one caller ([`try_mapped_repair`]); there is nothing
// about the split for anyone else to know.
use mappedplan::{MappedPlan, plan_mapped_repair};

mod nativepass;
// The native Reed-Solomon pass, out here for the same reason. One caller
// ([`fetch_and_repair`]), which binds it as a closure so its own three
// call sites read as they did when the body lived there.
use nativepass::native_repair_pass;

mod volpayload;
// L1 / M4-28's P1: the payload posted under a recovery VOLUME's name,
// which no slot-indexed rescue in `get/settle.rs` can reach. Its own
// file because the subject is self-contained (a screen, a fetch and a
// content proof) and because this one is at its ceiling; one caller,
// [`fetch_and_repair`], at the one moment the module header argues for.
use volpayload::rescue_payload_posted_as_volume;

mod sidefetch;
// The side-fetch driver, its consumer and the two small helpers that
// price a volume moved out whole (§129 residue 2). Re-exported rather
// than re-pathed at every call site: nothing about the split is
// interesting to a caller, and `use super::*` importers stay valid.
// `VolumeFailures` is deliberately NOT re-exported: no caller outside
// sidefetch.rs names the type, they only call `total()` / `for_file()`
// on what the driver hands back, and an unused re-export is a warning.
pub use sidefetch::{
    SideCancel, VolumeOpen, VolumeYield, fetch_volume_articles, fetch_volume_articles_with,
    fetch_volumes, side_pool_servers, vol_count_from_name, volume_prealloc_cap, volume_reqs,
};

mod gridrefute;
// The fourth arm of [`shortfall_is_final`], and the only one that is not
// about finding more parity: it asks whether the arithmetic was ever
// true, by taking the FileDesc whole-file MD5 of the members the live
// grid names damaged. Out here because this file was the NARROWEST in
// the repo when it landed; one caller, the chain in
// [`shortfall_is_final`], and its pins stay beside the other three arms'
// in `shortfall_gate_tests` because what they pin is the CHAIN.
use gridrefute::whole_file_md5_refutes_the_grid;

mod shortfall;
// The shortfall verdict and the two helpers that shape one: the type is
// the whole of what `get::tail` turns into a user's fail message, and it
// carries its own reasoning at length (why `have` is a PER-SET figure and
// has to keep saying so). Out of line for the size gate, re-exported
// rather than re-pathed so `use super::*` importers and every existing
// call site stay valid.
pub use shortfall::{RepairShortfall, blocks_over_set, scope_to_post, skipped_samples_clause};

mod extpar2;
// The external par2cmdline rung moved out whole: the decision to take
// it, the invocation it builds, the run itself and the clear-up after.
// Out here because this file was the NARROWEST in the repo when it
// landed - 10 of the flat 3,000-line ceiling, with no `BASELINE_FILES`
// entry to absorb it - and because the subject's call graph is closed:
// its only ties back to this file are prose. Re-exported rather than
// re-pathed so every existing call site and every `use super::*`
// importer (`nativepass`, `repair_tests`, `shortfall_gate_tests`) reads
// exactly as it did. `donor_extra_args` is deliberately NOT re-exported:
// its one caller is `par2cmdline_invocation` beside it, and an unused
// re-export is a warning.
pub(crate) use crate::diag::adopted_clause;
pub(crate) use extpar2::run_external_par2;
use extpar2::{
    NarrowedNeed, NativeVerdict, adoption_narrowed_need, native_shortfall, par2cmdline_invocation,
    publish_external_coverage,
};
// `repair_tests` is the only thing outside `extpar2` that names these
// two, so they are imported under the same cfg it is: an import no
// production build reads is a warning, and this crate is built at
// `-D warnings`.
#[cfg(test)]
use extpar2::{dir_entry_names, purge_par2_backups};

/// Delete source files a repair report PROVED spent (byte-identical to
/// a verified target, or its damaged twin - the spent_donors rules in
/// par2repair.rs). The disk-fallback path has always swept these; the
/// in-stream path left them lingering in finished jobs (finding F9's
/// residue).
pub fn sweep_spent_sources(spent: &[PathBuf]) {
    // Sorted and deduped first, since X5-10 (31 Aug 2026): the callers
    // that DEFER this - `fetch_and_repair` through `settle_with_set`,
    // and the late-set pass's own fixpoint - accumulate one list across
    // several sets, and two sets can prove the SAME donor spent. Without
    // the dedupe the second unlink fails with ENOENT and warns "could
    // not remove spent source" about a file this pass had just removed
    // correctly. `settle`'s own disk-fallback sweep has always done
    // exactly this, for exactly this reason.
    let mut spent: Vec<&Path> = spent.iter().map(PathBuf::as_path).collect();
    spent.sort_unstable();
    spent.dedup();
    // Through the SAME parked delete every other sweep on this tail uses
    // (§64): `remove_swept_file` honours `cleanup_recoverable`, so a file
    // this pass judged spent goes to the Trash when the user asked for
    // recoverable cleanup and is only hard-unlinked when they did not.
    // This path shipped as a bare `remove_file` (30 Aug 2026 sweep) while
    // its own sibling - the disk-fallback sweep in `get/tail.rs` - was
    // already recoverable, so which of the two ran decided whether the
    // user could get the file back. `proven_spent` is a per-byte proof
    // and not an infallible one; the recoverable path is what makes a
    // wrong verdict survivable.
    let recoverable = crate::smart::cleanup_recoverable();
    let staging = spent
        .first()
        .and_then(|p| p.parent())
        .and_then(crate::smart::trash_staging_dir);
    let mut swept = 0usize;
    for p in spent {
        match crate::smart::remove_swept_file(p, recoverable, staging.as_deref()) {
            Ok(_) => swept += 1,
            Err(e) => warn!(
                target: "repair",
                "could not remove spent source {}: {e}",
                p.display()
            ),
        }
    }
    if swept > 0 {
        info!(
            target: "repair",
            "removed {swept} spent source file(s) the repair adopted from{}",
            if recoverable { " (to the Trash)" } else { "" }
        );
    }
}

/// Is a recovery-block shortfall FINAL, or is there something for the
/// adoption scan to read first? §293: with a donor directory the
/// arithmetic is never final - the scan can stand in for recovery
/// blocks the NZB never declared, and only `repair_dir` can say how
/// many it finds. The SAME reasoning covers the job's own directory
/// (findings F7/F9, capability corpus 30 Aug 2026): an obfuscated post
/// whose damaged-head or split-posted file never got claimed leaves
/// the bytes sitting in out_dir under a hash name - measured 1984/1986
/// blocks adoptable on the damaged-head leg and 993/994 on the
/// split-join leg. Bailing on the declared-parity arithmetic alone
/// failed posts that were byte-complete on disk. So the arithmetic is
/// final only when there is nothing anywhere for adoption to read; a
/// fall-through that still comes up short reports the (post-adoption)
/// shortfall from the native verdict exactly as before.
///
/// THE THIRD ARM ([`repeated_block_donor_possible`]) IS ABOUT CLAIMED
/// FILES, and it exists because sweep item 13 took a shape OUT of the
/// two above. Before the twin tier (30 Aug 2026) a damaged
/// identical-head twin stayed unclaimed and sat in out_dir under its
/// posted hash, so it was an adoption candidate and this fell through;
/// the tier now claims it on per-block evidence and the extractor
/// renames it to the set's own name - and that file lands at the length
/// its descriptor declares (damage from this pipeline is a HOLE, never a
/// shift), so it is held out by the length screen
/// [`adoption_candidates_present`] applies to a declared name. The engine
/// has an arm for exactly that file - `repair_dir_set_inner`'s
/// last-resort escalation appends every IDENTIFIED DAMAGED target as a
/// scan candidate once damage exceeds the recovery on disk - and this
/// gate is the only thing standing between the get path and it.
///
/// THE FOURTH ARM ([`whole_file_md5_refutes_the_grid`]) IS NOT A SCAN AT
/// ALL, and it is here because `needed` is somebody's WORD. Every arm
/// above asks whether more parity can be found; this one asks whether
/// the arithmetic was ever true. `needed` comes from the live block
/// grid, which is the set's own IFSC entries applied to the bytes on
/// disk, and `verify_pass1` - the thing that answers `clean` from a
/// FileDesc whole-file MD5 - runs only AFTER this returns. So a set
/// whose entries lie about blocks of a byte-exact file fails the job on
/// arithmetic the strongest evidence it carries would contradict
/// (M4-69's mirror direction; measured 31 Aug 2026, half the IFSC CRC32
/// entries forged over byte-exact bytes reports `1000/2000 blocks bad`
/// against 400 carried and the job ENDS, with the payload byte-exact in
/// the output directory).
fn shortfall_is_final(
    needed: usize,
    have: usize,
    donor_dirs: &[PathBuf],
    out_dir: &Path,
    set: &nzbkit::par2::Par2Set,
    // The live grid's own damage claim, by FileDesc name - sanitized and
    // lowercased, the key every coverage test on this path uses. The
    // fourth arm's population, and the ONLY thing that keeps its cost
    // proportional to the damage rather than to the download.
    damaged: &[String],
) -> bool {
    // ONE chain, in cost order and evaluated lazily, so each arm both
    // decides and names itself. Written as a chain rather than as bools
    // ANDed into a guard because that shape put the cheap tests in front
    // of the dear ones TWICE - once to decide and once to phrase - and a
    // clause that only ever short-circuits another is a clause no
    // mutation can kill (measured: dropping it changed no verdict and no
    // log line).
    //
    // THE LAST TWO ARMS ARE COMPLEMENTS, not rivals, and landed within
    // hours of each other from two lanes. `in_set_harvest_possible`
    // (M4-01) is about a file that did NOT land - the split-and-join
    // shape, where the join's every block is already on disk next door -
    // and its own header names its stated limit: a beneficiary that
    // landed at its declared length and is merely DAMAGED is counted as
    // a source rather than as something to rescue.
    // `repeated_block_donor_possible` (follow-up 13a) is exactly that
    // limit, which is why it runs after: the twin tier now CLAIMS a
    // damaged identical-head twin and renames it, so every member is
    // landed, the M4-01 arm correctly declines on `landed.all()`, and
    // the blocks the two share are still there to lift across. Both
    // count against the SHORTFALL rather than merely detecting, and both
    // lanes were driven to that by the same fixture.
    let scanning = if !donor_dirs.is_empty() {
        "the failed predecessor's files as donors"
    } else if adoption_candidates_present(out_dir, set) {
        "the job's own unclaimed files for their blocks"
    } else if in_set_harvest_possible(out_dir, set, needed.saturating_sub(have)) {
        "the set's own landed files for blocks the missing ones share"
    } else if repeated_block_donor_possible(out_dir, set, needed.saturating_sub(have)) {
        "the set's own files for the blocks it declares twice"
    } else if whole_file_md5_refutes_the_grid(out_dir, set, damaged) {
        "the set's own files against the whole-file MD5s their descriptors carry"
    } else {
        warn!(
            target: "repair",
            "unrepairable: {needed} blocks needed, only {have} recovery blocks in the NZB"
        );
        return true;
    };
    info!(
        target: "repair",
        "recovery short ({needed} blocks needed, {have} in the NZB) - \
         scanning {scanning} before giving up"
    );
    false
}

/// Could the IN-SET harvest stand in for recovery blocks the NZB never
/// declared? The other half of the question [`adoption_candidates_present`]
/// asks, for bytes that gate cannot see by construction (M4-01, 30 Aug
/// 2026).
///
/// One set may name a file AND the pieces it was split into -
/// `Rawsplit.mkv.001`, `Rawsplit.mkv.002` AND `Rawsplit.mkv`. The halves
/// land under their own FileDescs, so they are DECLARED names and the
/// sibling gate skips them on purpose; the join is then a wholly missing
/// file whose every block is already on disk next door. `par2repair`'s
/// in-set harvest reads exactly those blocks, but only if the repair is
/// allowed to run at all - and the declared-parity arithmetic on its own
/// failed a post that was byte-complete on disk.
///
/// The signature comes out of packets already parsed plus one `stat` per
/// declared name: slices of a file that did NOT land at its declared
/// length whose block checksums a landed file also declares. `shortfall`
/// is what the harvest would have to cover, and COUNTING rather than
/// merely detecting is what keeps this honest: measured 30 Aug 2026, an
/// ordinary three-volume RAR set with one volume lost already shares a
/// handful of blocks between the lost volume and a landed one (padding,
/// repeated headers), so a bare does-any-duplicate-exist test falls
/// through on posts no harvest could ever save and turns every one of
/// them into a wasted repair pass.
///
/// Permissive within that bound, on the same terms as its sibling: the
/// count is an upper bound (some of those blocks are already present
/// where they belong), so a false yes costs one repair pass that ends in
/// the same honest post-adoption shortfall verdict with better numbers.
/// A file that is ABSENT and byte-identical to a landed one is left out
/// of the count: the harvest declines to materialize a duplicate
/// descriptor, which is `land_duplicate_filedescs`' capped job (W4-14),
/// so counting it would buy a repair pass that finds nothing.
///
/// One STATED limit: a beneficiary that landed at the right length and is
/// merely DAMAGED is counted as a source rather than as something to
/// rescue, so this gate does not open for it. `repair_dir`'s own
/// escalation already scans identified damaged targets, and widening the
/// rule here would put every set with a shared padding block back through
/// a pointless repair.
fn in_set_harvest_possible(out_dir: &Path, set: &nzbkit::par2::Par2Set, shortfall: usize) -> bool {
    if shortfall == 0 {
        return false;
    }
    let landed: Vec<bool> = set
        .files
        .iter()
        .map(|f| {
            std::fs::metadata(out_dir.join(nzbkit::disk::sanitize_out_name(&f.name)))
                .is_ok_and(|m| m.is_file() && m.len() == f.length)
        })
        .collect();
    if !landed.iter().any(|&l| l) || landed.iter().all(|&l| l) {
        return false;
    }
    // Counted over SLICES of the unlanded files, not over distinct
    // checksums: what the harvest can stand in for is one missing slice
    // per slice it finds a source for, and a payload with repeated block
    // content (the e2e fixtures' own generator makes 1000 slices out of
    // 631 distinct blocks) would otherwise price its own rescue short.
    let sources: std::collections::HashSet<(u32, [u8; 16])> = set
        .files
        .iter()
        .zip(&landed)
        .filter(|&(_, &l)| l)
        .flat_map(|(f, _)| f.blocks.iter().map(|b| (b.crc32, b.md5)))
        .collect();
    // A file that is ABSENT and is a byte-for-byte clone of a landed one
    // is a duplicate descriptor, whose materialization is capped by
    // `land_duplicate_filedescs` (W4-14). The harvest declines those, so
    // counting them here would open a repair pass that finds nothing.
    let clones: std::collections::HashSet<(u64, [u8; 16])> = set
        .files
        .iter()
        .zip(&landed)
        .filter(|&(_, &l)| l)
        .map(|(f, _)| (f.length, f.md5))
        .collect();
    let reachable = set
        .files
        .iter()
        .zip(&landed)
        .filter(|&(f, &l)| !l && !clones.contains(&(f.length, f.md5)))
        .flat_map(|(f, _)| f.blocks.iter())
        .filter(|b| sources.contains(&(b.crc32, b.md5)))
        .count();
    reachable >= shortfall
}

/// Could the sliding scan donate a block between files the repair has
/// already IDENTIFIED - the case [`in_set_harvest_possible`] above names
/// as its own stated limit, and the shape sweep item 13 created?
/// Answered off the set's OWN block checksums, with no disk read at all:
/// two blocks that declare the same (MD5, CRC32) are the same bytes, so
/// a missing one can be served by whichever copy survived.
///
/// THE TWO ARE COMPLEMENTS and the chain in [`shortfall_is_final`] says
/// why at length. The short version: that one is about a file that did
/// NOT land, and declines outright once every member has
/// (`landed.iter().all()`), which is exactly what the twin tier now
/// produces - it CLAIMS a damaged identical-head twin and the extractor
/// renames it, so every member is landed at its declared length and the
/// blocks the twins share are still there to lift across.
///
/// MEASURED, both directions, 30 Aug 2026 (follow-up 13a; the probe is
/// `research/TWIN-INPLACE-ADOPTION-2026-08-30.md`). Three two-file sets
/// built from INDEPENDENT xorshift payloads - never `e2e.rs::payload`,
/// whose seeds correlate at 84% of offsets and are what made a fixture
/// look repairable on parity it never had (follow-up 13c) - sharing a
/// head of 40000 / 16384 / 262144 bytes at block sizes 2000 / 65536 /
/// 65536, each damaged in both members and posted short of parity. The
/// blocks the repair actually adopted were 20 / 0 / 4; the count this
/// predicate reports is 20 / 0 / 4. The identity is not luck - donation
/// between identified targets IS "a missing block whose content the set
/// declares somewhere else", and the middle row is the one to read: a
/// 16 KiB shared head is what the twin tier GUARANTEES, and at any
/// block size above it that guarantee is worth exactly nothing.
///
/// THE COUNT IS AN UPPER BOUND AND IS COMPARED AGAINST THE GAP, which
/// is the second half of the narrowing and was not in the first cut.
/// Aligned donation can supply at most one block per repeat, so a set
/// that repeats 38 blocks can never close a 376-block shortfall - and
/// asking it to try buys the whole recovery fetch for an answer that is
/// arithmetically settled. Measured on
/// `e2e::wholly_missing_volume_with_insufficient_recovery_fails_unchanged`,
/// which is exactly that set (775 needed, 399 declared, 38 repeats) and
/// which the countless first cut sent to a pointless fetch. The bound is
/// the honest one to state: it is an upper bound on the ALIGNED
/// donation this predicate is about, never a promise that the scan will
/// find that many.
///
/// WHAT IT COSTS WHEN IT SAYS YES: one adoption scan of the files this
/// job has just written - and it was one FULL recovery-volume fetch, of
/// everything the NZB declares, until follow-up 13a-1 put the scan in
/// front of the fetch hours after this predicate landed (repriced
/// 31 Aug 2026 alongside the length screen in
/// [`adoption_candidates_present`]; the scan is 0.4-3.4 s per GB of
/// payload against 50-150 MB per GB of metered parity). That is still a
/// cost worth a predicate rather than a plain permissive arm, and it is
/// no longer the reason this one is narrow. WHAT IT COSTS WHEN IT SAYS
/// NO: nothing, and that is the measurement that makes it affordable.
/// Duplicate-block census over real data at real block sizes, same day:
/// a compressed 12.5 MB three-volume set reports 0 duplicated blocks at
/// every one of 4096 / 16384 / 384000 / 768000, and 196 MB of
/// uncompressed real binaries reports 0 at 384000, 1 in 11967 at 16384,
/// and 169 in 47862 (0.35%, of which 166 are all-zero blocks) at 4096.
/// So on the ordinary post this arm is silent and the verdict is the
/// one it always was.
///
/// A SECOND LIMIT, on the other side: this asks whether donation is
/// POSSIBLE, never whether it will pay. A set that repeats a block but
/// whose only damage is a member missing outright buys a fetch that
/// finds nothing - the escalation scans identified DAMAGED targets, and
/// an intact one is not a candidate at any tier. Which member is
/// damaged is not a question this frame can answer (`needed` is a
/// total), and the census that would make it sharp is the read this
/// predicate exists to avoid. It is bounded twice over by what is
/// already here: the gap comparison holds the guess to a shortfall the
/// repeats could actually close, and the census above measures zero on
/// every real corpus at every real block size, so the case does not
/// arise on an ordinary post at all.
///
/// STATED LIMIT: aligned donation only. The scan SLIDES, so it can also
/// lift a block out of a candidate at an offset no block grid names,
/// and no census of declared checksums can see that. It is out of scope
/// here rather than overlooked: the get path writes every article at
/// its declared yEnc offset (`get/workers.rs` - `off` is `begin - 1`),
/// so a missing article leaves a HOLE where its bytes belong and never
/// shifts what follows - so DAMAGE cannot produce a file shifted inside
/// itself, and this arm may ignore that shape.
///
/// A POSTING CAN, and this paragraph said it could not until follow-up
/// 13a-4 measured it (31 Aug 2026). Both halves of the old sentence
/// were wrong, and they were wrong in the direction that made the
/// blind spot look empty: a poster who splices bytes into the MIDDLE of
/// a payload the recovery set was built over lands a file that verifies
/// its head - IDENTIFIED, not unidentified - with the rest of its
/// content shifted inside itself, which is exactly what
/// `par2repair::repair_dir_set_inner`'s last-resort escalation is for.
/// Driven end to end in `e2e_norar::shiftname`. It is still not THIS
/// arm's business, which is the only part that survives unchanged: the
/// blocks are the member's OWN, so no declared repeat is involved and
/// this census would report nothing whatever it looked at.
/// [`adoption_candidates_present`] is what answers it, and until
/// 13a-4 it did not - it excluded the file on the verified head.
fn repeated_block_donor_possible(out_dir: &Path, set: &nzbkit::par2::Par2Set, gap: usize) -> bool {
    if gap == 0 {
        return false;
    }
    // Nothing to scan: the escalation reads FILES, so a set whose
    // members never reached disk has no donor whatever it declares.
    //
    // ASKED THE WAY THE ENGINE ASKS IT, `join_out_name` onto `out_dir` -
    // par2repair's own present-set gate and its `Target` paths are both
    // built that way, on the rule that a FileDesc name is relative to
    // the JOB. This compared `read_dir` BASENAMES until the 31 Aug 2026
    // sweep's finding 3, and `sanitize_out_name` preserves a tree, so a
    // disc post naming `VIDEO_TS/VTS_01_1.VOB` showed the walk one
    // DIRECTORY entry, matched nothing, and answered a false no with
    // every member one level down. The escalation never ran.
    let any_member = set.files.iter().any(|f| {
        let p = nzbkit::disk::join_out_name(out_dir, &nzbkit::disk::sanitize_out_name(&f.name));
        std::fs::metadata(&p).is_ok_and(|m| m.is_file() && m.len() > 0)
    });
    if !any_member {
        return false;
    }
    // The census itself. Already-parsed data, so this is a hash-set walk
    // over the blocks and never a read - a 30 GB set at 384 KB blocks is
    // ~78,000 sixteen-byte keys. A file with no IFSC packet contributes
    // nothing and correctly cannot argue for a fetch.
    let mut seen: std::collections::HashSet<([u8; 16], u32)> = std::collections::HashSet::new();
    let mut repeated = 0usize;
    for f in &set.files {
        for b in &f.blocks {
            if !seen.insert((b.md5, b.crc32)) {
                repeated += 1;
                if repeated >= gap {
                    return true;
                }
            }
        }
    }
    false
}

/// Does the output directory hold at least one file the adoption scan
/// could read blocks out of - a regular file that is neither recovery
/// data nor one of this set's own files? The gate that decides
/// whether a recovery-block shortfall is FINAL (findings F7/F9): an
/// obfuscated post's unclaimed hash-named files carry the missing
/// bytes, and `repair_dir`'s sliding scan is what ties them to the
/// damage - but only if the repair is allowed to run at all. Permissive
/// on purpose: a false yes costs one repair pass that ends in the same
/// honest (post-adoption) shortfall verdict with better numbers; a
/// false no is the F7/F9 class back again.
///
/// A DECLARED NAME IS NOT ONE OF THIS SET'S FILES, and until follow-up
/// 13a-3 (31 Aug 2026) this gate treated the two as the same thing. The
/// engine's own exclusion - `par2repair::adopt::adoption_candidates` -
/// skips a target only when it is IDENTIFIED: it exists AND at least
/// one of its blocks verified. `repair_dir_set_inner` names the gap in
/// its own words ("missing, renamed, SHIFTED - nothing on disk
/// verifies"). So a file wearing a name the set declares whose content
/// answers to none of it is an ordinary adoption candidate TO THE
/// ENGINE, and this gate excluding it by name alone was the only thing
/// between the get path and a repair that works. It is not a corner:
/// `nzbkit::live::nametier` already prints "arrived under the name
/// {:?} but carries none of that file's bytes" and leaves the slot out
/// of the set, so the product had ALREADY established the file is not
/// the set's - and this gate then asked its name.
///
/// MEASURED (`e2e_norar::shiftname`, 31 Aug 2026): a 200,000-byte
/// member posted with 3,000 bytes of furniture in front of it lands
/// under its own honest name, verifies not one of its 100 blocks, and
/// against the 10 recovery blocks the NZB carries this gate called
/// 100-over-10 FINAL - with all 100 of those blocks sitting in that
/// same file. Let through, the scan lifts every one of them and the
/// file comes back byte-exact.
///
/// THE PRICE OF ASKING, which is why the question is asked in this
/// order and no other. The cheap walk runs FIRST and unchanged, so the
/// F7/F9 hash-named case costs exactly what it always did. Only when
/// nothing cheaper has answered is a declared name asked at all, and
/// only one whose ON-DISK LENGTH is not the descriptor's: a full-length
/// file is not a shifted one, and probing every heavily damaged member
/// of an unrepairable post is the read this exclusion existed to avoid.
/// The probe itself is [`nzbkit::live::declared_block_evidence`] - the
/// live name tier's own strong-evidence test, one copy of the rule,
/// strided and bounded by both probe count and bytes. What it is asked
/// for is `read > 0`: were there BYTES HERE TO READ. A member whose
/// every article failed answers `(0, 0)`, which is silence and not
/// evidence of anything, and it stays excluded - `settle_binding`'s
/// rule, and the reason that door returns a pair rather than a boolean.
///
/// IT IS NOT ASKED WHETHER A BLOCK MATCHED, and it was until follow-up
/// 13a-4 (31 Aug 2026). That rule - `read > 0 && hit == 0`, let through
/// only on a POSITIVE DENIAL - reads a matched block as "this file is
/// the set's own file, so the scan has nothing to find here". PAST THE
/// LENGTH SCREEN THAT INFERENCE CANNOT HOLD: a file whose on-disk
/// length is not its descriptor's can never be INTACT, whatever
/// verifies inside it, so a hit there does not say "leave it alone", it
/// says IDENTIFIED AND DAMAGED - which is the exact state
/// `repair_dir_set_inner`'s last-resort escalation puts BACK into the
/// scan ("a mid-file insertion leaves a file half-verified with the
/// rest of its content byte-shifted inside itself; only a scan of that
/// file can find it"). So `hit` carried no information at this seam and
/// was excluding, by itself, the one shape the escalation exists for.
/// 13a-3 fixed "excluded by NAME"; this is "excluded by ANY HIT", which
/// was still narrower than the engine's own test.
///
/// MEASURED (`e2e_norar::shiftname`, 31 Aug 2026), and the shape is
/// REACHABLE ON THIS PIPELINE rather than argued for: a 200,000-byte
/// member posted with 3,000 bytes of furniture inserted at its
/// MIDPOINT lands 203,000 bytes long, verify prices it `50/100 blocks
/// bad`, and 50-over-10 was called FINAL with all 50 of those blocks
/// sitting whole at +3,000 in that same file. Let through, the
/// escalation lifts every one of them and the file comes back
/// byte-exact - `0 block(s) rebuilt across 1 file(s), 50 block(s)
/// adopted from Half.vob`.
///
/// IT COSTS NO I/O THAT THE OLD RULE DID NOT ALSO PAY. The probe walk
/// is identical either way: a file with a hit stops at that block under
/// both rules, and a file with none walks its 32-probe / 64 MB bound
/// under both. What changed is only the verdict, and only for a
/// declared name AT A WRONG LENGTH - so the ordinary failing job, whose
/// every member lands at the length its descriptor declares (damage
/// from this pipeline is a HOLE, never a shift), is excluded on the
/// length screen at zero reads exactly as before. There is a cheaper
/// form available and it is deliberately NOT taken here: asked only for
/// `read > 0`, the probe could stop at the first block it SUCCEEDS in
/// reading rather than at the first that matches, which would save the
/// walk on a wrong-length file that matches nothing. That means a
/// second `stop_early` shape in `twintier::probe_blocks`, which the
/// twin tier shares, for a saving on a file that is already anomalous.
///
/// WHAT IS NOT ESTABLISHED, stated rather than left to be found: HOW
/// OFTEN a real poster does this. The get path writes every article at
/// its declared yEnc offset (`get/workers.rs` - `off` is `begin - 1`),
/// so a shift cannot come from damage and has to be POSTED, and nothing
/// in `research/`, in the capability corpus list or in the wave-4
/// matrix describes a posted mid-file insertion - F7 and F9 measured
/// shifted bytes in UNCLAIMED hash-named files, not in a declared name.
/// What carries it instead is that the engine's escalation is PARITY
/// code: par2cmdline has its own target scan for this shape, and
/// `nzbkit`'s
/// `integration::par2repair_parity::mid_file_insertion_escalates_to_target_scan`
/// pins the two engines agreeing on it. The reference implementation
/// having carried a scan for it for twenty years is the evidence that
/// it happens; this gate was the only thing keeping our own copy of
/// that scan off the get path.
///
/// STATED LIMIT: a shifted file at EXACTLY the declared length is not
/// reached, because the length screen holds it out before the probe. It
/// needs a poster to have both prefixed and truncated to the byte.
///
/// THE SCREEN WAS PRICED AGAINST A COST THAT NO LONGER EXISTS, and was
/// REPRICED on 31 Aug 2026 rather than left standing on the old
/// arithmetic (`research/ADOPTION-GATE-NAME-VS-IDENTIFIED-2026-08-31.md`,
/// R-1). When it was written, a false yes here bought every recovery
/// volume the NZB declares; follow-up 13a-1 (`e5e5faaef`) landed hours
/// later and put the adoption scan in FRONT of the fetch, so a false
/// yes now costs one scan of files this job has just written - 0.4-3.4 s
/// per GB of payload against the 50-150 MB per GB of metered recovery
/// data it used to spend. [`adoption_narrowed_need`]'s header says so
/// from the other side and names this gate as one of three kept
/// deliberately: they "are now asked only to be cheap, because the
/// engine gets the last word". Measured on that lane's own rig (512 MB
/// in four 128 MB members, real `par2 create -s786432`, 768 KB blocks,
/// this dev Mac under other lanes' load):
///
/// * DROPPING THE SCREEN IS CHEAP ON THE ORDINARY FAILING JOB, so that
///   is NOT why it stays. Four full-length truthful members cost 4
///   probes, 3.15 MB, 5.8-6.5 ms - block 0 of each hits and it is
///   excluded. Head-clustered damage costs more, because the probe
///   walks until a block survives: per member, 40% -> 13 probes /
///   10.2 MB, 90% -> 27 probes / 21.2 MB.
/// * WHAT IT STAYS FOR IS A FALSE-YES SHAPE THIS PIPELINE PRODUCES. A
///   member landing full length with every one of the 32 strided probe
///   positions a hole reads blocks, matches none, and is a POSITIVE
///   DENIAL. Measured threshold: between 98.0% and 98.5% head damage,
///   which the ordinary "only the last article survived" post reaches.
///   Without the screen the rig's four such members cost 116 probes /
///   91.2 MB / 0.16 s AND then an engine scan of 0.72-1.71 s, for the
///   verdict the arithmetic had already given. The screen holds that
///   out for nothing.
/// * A WHOLLY FAILED MEMBER IS NOT THAT SHAPE, checked rather than
///   assumed: it is ABSENT from `out_dir`, never full length and
///   zeroed. Verified end to end on `e2e_norar` - corrupt all 50
///   articles of a member and no file is written at all; corrupt 49 of
///   50 and it lands at its declared 200,000 bytes.
/// * NOTHING IN THIS TREE EVIDENCES THE SHAPE THE LIMIT COSTS. The
///   engine's OWN account of a shifted set is a MID-FILE INSERTION
///   (`nzbkit::par2repair`'s module note), which leaves the file LONGER
///   than its descriptor - so the screen lets that one through. It was
///   the HIT RULE that then held it out, which is the defect follow-up
///   13a-4 fixed above; the screen never touched it, and this bullet
///   said the screen's limit was cheap because the hit rule was
///   catching that shape. It was catching it and dropping it.
///
/// A THIRD OPTION WAS DERIVED AND NOT TAKEN, written down so the next
/// lane does not re-derive it: read an all-zero NON-MATCHING block as
/// SILENCE rather than as denial - `settle_binding`'s rule at BLOCK
/// granularity, where the `(read, hit)` pair above applies it at FILE
/// granularity.
/// That kills the false-yes shape above (every probed block is a hole,
/// so there was nothing to deny with) and would let the screen go. It
/// costs the block reads above on every failing job, it changes
/// `twintier::probe_blocks`, which the twin tier shares, and it buys a
/// shape nothing has evidenced. `md5_16k` was the other candidate and
/// is WORSE on its own: a head-damaged truthful member fails it, which
/// is far commoner than either shape here.
///
/// The other stated cost is a real one and is the permissive trade this
/// gate has always made: a foreign payload posted under a set member's
/// name (W4-18) is indistinguishable from a shifted one to any ALIGNED
/// probe - only the sliding scan can tell them apart, and that is the
/// scan being reached for - so such a job pays one adoption scan before
/// reporting the same honest shortfall. Follow-up 13a-1 is what took
/// that from every declared recovery volume down to the scan.
/// THE WALK REACHES A TREE, and it is the ENGINE's own walk it borrows
/// to do it (`par2repair::source_candidate_files`). This block argued
/// the top-level walk was DELIBERATE, and it was right to: this gate
/// predicts what `par2repair::adopt::adoption_candidates` finds, and
/// THAT walk had no recursion, so answering true on a tree bought a
/// whole adoption scan for a verdict the arithmetic had already given.
/// Wave-4 row X6-02 ended that on 31 Aug 2026 and the two halves landed
/// HOURS APART, so for those hours this answered NO where the engine
/// would have found a candidate - and that NO is not a wasted scan, it
/// is one arm of [`shortfall_is_final`]: when every arm declines,
/// `fetch_and_repair` takes the give-up branch and can `return
/// Ok(false)` WITHOUT reaching [`adoption_narrowed_need`], whose native
/// probe is the thing that would now find the bytes.
///
/// It is not the one-line symmetry it looks like, which is why the
/// engine lane left it: the name test compared a BASENAME against
/// `sanitize_out_name`, and that carries a DIRECTORY under the relpath
/// ruling - so a tree candidate would read as undeclared and return
/// true for the wrong reason, on a file the set declares. It asks
/// `disk::out_name_of` now, exactly as `adopt::is_somebodys_payload`
/// does, and the dot screen stays on the LEAF so it goes on meaning
/// "a hidden file". A predicate that walks a different set from the
/// walk it predicts is worse than no predicate; the two share one
/// function so they cannot part again. Its sibling
/// [`repeated_block_donor_possible`] resolves a set MEMBER through
/// `join_out_name` and has seen a tree since the same day; all three
/// now ask the directory one question.
///
/// AND THE RECOVERY SCREEN IS THE ENGINE'S OWN PREDICATE, not a second
/// spelling of it (31 Aug 2026). This screened a `.par2` name on the
/// EXTENSION ALONE, which is a NAME deciding what a file IS - exactly
/// the rule wave-4 row M4-52 ended at the engine, where
/// `par2repair::is_recovery_by_name_and_content` opens the file and
/// lets the packet magic decide. The row's own composition is what the
/// divergence costs: an obfuscated post whose payload carries a yEnc
/// `name=` of `<hash>.par2`, so the in-stream set never claims it and
/// the inner set naming `movie.mkv` never activated. If the only
/// undeclared files in the directory are that payload and the real
/// recovery volumes, EVERY entry hit the extension screen, this
/// answered NO, and that NO is an arm of [`shortfall_is_final`] -
/// `fetch_and_repair` then takes the give-up branch and can `return
/// Ok(false)` without ever reaching [`adoption_narrowed_need`], whose
/// native probe is the thing that would have found the bytes sitting in
/// the same directory. Same defect as the walk above, one screen over,
/// and the same fix: the predicate is SHARED, so the two cannot part
/// again. Writing a second copy here is what M4-52 cost in the first
/// place - it was live at two seams and fixable at one.
///
/// WHAT THE READ COSTS, measured rather than asserted, because this
/// gate exists to avoid buying a scan for a verdict the arithmetic
/// already gave and a screen that opens files is not free by
/// inspection. One `open` plus an 8-byte `read`, asked only of names
/// carrying the extension and only after the free dot test: 8.1-10.7 us
/// per file on this box's APFS volume, so 0.24-0.32 ms for a set with
/// 30 recovery volumes. That is 4-6x the `read_dir` + `metadata` walk
/// this rides on (41-73 us for the same 30) and about 0.02-0.04% of the
/// 0.72-1.71 s adoption scan a wrong YES buys - and the engine pays the
/// identical reads moments later on the same warm inodes. The shape is
/// metadata plus one cache line, never file DATA, so a cold spinning
/// disk or a network share scales it by seek latency and not by set
/// size.
///
/// THE DOT HALF IS DELIBERATELY LEFT NARROWER THAN THE ENGINE, which
/// has no dot screen at all. It is not the same divergence: this gate
/// predicts the engine's OUTCOME, not its candidate list, and the
/// dotted files a download directory really holds are the ones we did
/// NOT write - the daemon's own `.nzbfast.journal` and `.nzbfast-*`
/// scratch (`nzbkit::disk::hide_from_user` makes the leading dot the
/// internal-name convention) and the OS's `.DS_Store` furniture. The
/// engine would take those as candidates and slide-scan them to no
/// effect, so skipping them predicts the right answer cheaply, where
/// skipping a `.par2` payload predicted the wrong one. What makes it
/// SOUND is a property of a different function, and it is pinned rather
/// than assumed: `nzbkit::disk::sanitize_out_name` maps a leading dot
/// to `_` (row M4-66), so no name this job can publish reaches disk
/// wearing one. `get::latesets`'
/// `the_dot_skip_is_sound_only_while_nothing_we_publish_can_be_dotted`
/// is the interlock that goes red if that ever stops holding, and its
/// note carries the fix for this seam too: skip the names WE write,
/// never every dotted name.
pub(crate) fn adoption_candidates_present(out_dir: &Path, set: &nzbkit::par2::Par2Set) -> bool {
    let declared: std::collections::HashMap<String, &nzbkit::par2::Par2File> = set
        .files
        .iter()
        .map(|f| (nzbkit::disk::sanitize_out_name(&f.name).to_lowercase(), f))
        .collect();
    let Ok(files) = nzbkit::par2repair::source_candidate_files(out_dir) else {
        return false;
    };
    // Deferred, never decided in the walk: the expensive question is
    // asked only of the files nothing cheaper spoke for, and only once
    // the whole directory has failed to produce an ordinary candidate.
    let mut wearing_a_declared_name: Vec<(PathBuf, u64, &nzbkit::par2::Par2File)> = Vec::new();
    for (p, len) in files {
        // The declared name is the JOB-relative one, the way the engine
        // resolves a target; the dot screen is about a hidden FILE, so
        // it stays on the leaf and means what it always meant.
        let name = nzbkit::disk::out_name_of(out_dir, &p);
        let leaf = p.file_name().unwrap_or_default().to_string_lossy();
        // The dot test is free and runs first; the recovery test opens
        // the file, so it is asked only of what survives. Both are
        // argued in the header - the second is the engine's own.
        if leaf.starts_with('.') || nzbkit::par2repair::is_recovery_by_name_and_content(&p) {
            continue;
        }
        match declared.get(&name.to_lowercase()) {
            Some(f) => wearing_a_declared_name.push((p, len, f)),
            None => return true,
        }
    }
    let bs = set.block_size as usize;
    wearing_a_declared_name.into_iter().any(|(p, len, f)| {
        if len == f.length {
            return false;
        }
        // `hit` is deliberately unread - see the header. Past the
        // length screen a match cannot mean intact, only identified
        // and damaged, which is what the engine's escalation scans.
        let (read, _) = nzbkit::live::declared_block_evidence(&p, f, bs);
        read > 0
    })
}

/// Candidate recovery volumes of the NZB: (file idx, declared slices,
/// encoded bytes). Unknown counts get a conservative size-based estimate.
/// `sniffed_vols` are file indexes classified as recovery data by the
/// in-stream magic sniff (issue #14) - subject-line classification cannot
/// see them, but their deferred bytes are just as fetchable.
///
/// `out_dir` is read for this set's own PAR2 indexes and nothing else -
/// see [`index_bases_on_disk`]. A directory that does not exist, or
/// holds no index of this set, leaves every verdict below exactly where
/// it was.
pub(crate) fn recovery_candidates(
    nzb: &Nzb,
    out_dir: &Path,
    set: &nzbkit::par2::Par2Set,
    already_fetched: &[usize],
    sniffed_vols: &[usize],
) -> Vec<(usize, usize, u64)> {
    // TODO 311: which volumes belong to THIS set, as far as a name can
    // say. A post with one recovery set per file has one set's volumes
    // interleaved with every other set's, and this list is what
    // `pick_volumes` chooses the next batch from - so without an
    // ordering the batch is bought for the wrong set, lands 0 usable
    // slices (they carry another set id) and the repair declines with
    // parity for the damage sitting undownloaded. Measured on
    // `e2e_multiset`: 145 usable of 250 needed, and 0 for one set.
    //
    // It has to FILTER and not merely reorder, which was measured:
    // `pick_volumes` is a byte-minimizing knapsack over the whole list
    // and pays no attention to order at all, so a reordered list
    // changed nothing. Filtering is sound on its own terms - a volume
    // belonging to another set carries another set id, so not one of
    // its slices can ever be usable here, and buying it is pure wire.
    //
    // The fallback is what keeps a name a HINT: when NOTHING is affine
    // the full list comes back, so an obfuscated post - where no name
    // identifies anything - behaves exactly as it did, escalation
    // included. A post with one set is all-affine or none-affine, so it
    // is untouched either way. The residual trade is stated rather than
    // hidden: on a multi-set post whose volumes are named after some
    // OTHER set's payload, this set's own volumes become unreachable
    // where before they were merely improbable. That takes deliberately
    // crossed naming, and the alternative - measured on
    // `e2e_multiset` - is that a per-file-set post cannot repair at all.
    let mut vols: Vec<(usize, usize, u64)> = Vec::new();
    let mut affine: Vec<bool> = Vec::new();
    // Kept whatever the affine filter decides - see the sniff paragraph
    // in the loop below. Parallel to `vols` and `affine`.
    let mut sniffed: Vec<bool> = Vec::new();
    // `track01.bin` -> `track01`, and the full name too: par2cmdline
    // writes `track01.bin.vol00+01.par2` by default and
    // `track01.vol00+01.par2` when given an explicit base.
    let stems: Vec<String> = set
        .files
        .iter()
        .flat_map(|f| {
            let full = f.name.to_ascii_lowercase();
            let stem = full
                .rsplit_once('.')
                .map_or(full.clone(), |(a, _)| a.to_string());
            [full, stem]
        })
        // Too short to distinguish one release from another.
        .filter(|st| st.len() >= 3)
        .collect();
    // The affinity test is on the volume's BASE NAME and is an EQUALITY.
    // It was a `starts_with` over the whole volume name until 28 Aug
    // 2026, and a prefix cannot tell one member of a numbered series
    // from another: with an eighteen-track post, stem `track1` (from
    // `track1.bin`) prefix-matches `track18.bin.vol00+01.par2`, so
    // track 1's set read seventeen siblings' volumes as its own. Once
    // ANY volume is affine the list is filtered to the affine ones, so
    // the knapsack then bought another set's volumes, got zero usable
    // slices (they carry another set id) and declined the repair with
    // this set's own parity still sitting on the server. Cost is a
    // wasted round trip and roughly double the recovery bytes rather
    // than an unrepaired job, because the escalation re-asks - which is
    // why this fix is a tightening and not a rewrite.
    //
    // A DELIMITER rule (stem, then a `.` or `-`) was the obvious
    // alternative and does not close the commonest case: a stem that
    // ends in an extension is followed by a dot in a SIBLING's volume
    // name too, so `track01` would still take `track01.cue`'s volumes
    // when `track01.bin` is this set's file. Base equality takes
    // neither - `track01.cue` is not `track01.bin` and not `track01`.
    //
    // `par2_vol_suffix` is the repo's one answer to "where does the
    // volume suffix start", shared with classification and with
    // `extract::release_stem`; the text before it is the base. It
    // returns an offset into the LOWERCASED name, which `lower` below
    // is, and ASCII lowercasing never changes a byte's length so the
    // offset is good for either spelling.
    //
    // ONE CORNER, decided deliberately rather than left to be found.
    // Base equality is strictly NARROWER than the old prefix test -
    // every base-equal name was prefix-affine too - so this can never
    // make a volume affine that was not, and therefore can never turn
    // the none-affine FALLBACK off for a set that used to enjoy it.
    // Where the tightening empties the affine list the fallback re-arms
    // and hands back the whole list, which includes this set's own
    // volumes: strictly better than today, where a prefix-colliding
    // sibling's volumes could arm the filter and exclude them. What is
    // left is the narrower shape: a set whose OWN volume's base is a
    // delimiter-free extension of one of its own stems (`abcd` off
    // `abc`) at the same time as some other volume's base equals that
    // stem exactly. That volume is then filtered out where the prefix
    // rule kept it. It is UNGUARDED on purpose: no par2 tool writes a
    // volume base that is not either a payload name or that name minus
    // its last extension - both of which are in `stems` - and the only
    // guard available at this altitude is a second prefix tier, which
    // would restore the very collision above.
    //
    // The offset comes off the file's OWN classification rather than
    // from a second call to the public `par2_vol_suffix`, which is the
    // raw-subject rule whatever the kind was decided under (T2, 31 Aug
    // 2026). At THIS site the two cannot currently disagree - the
    // isolated rule accepts a strict subset of the raw one, and the
    // loop below only ever asks about a file `kind()` already called a
    // volume, so an isolated `Some` implies the same raw `Some` - but
    // it is the same rule written a second time, which is what put
    // N6-04 and N6-05 live in two places apiece. `SubjectClass` is
    // where it lives now.
    // THE INDEX BASES JOIN THE STEMS AS A UNION, 31 Aug 2026, and both
    // halves of that are the decision rather than the default. They are
    // a union because the two answer the same question from opposite
    // ends and neither subsumes the other: a base read off an index of
    // THIS set is proof (the bytes carry the set id), where a stem is a
    // guess about what a poster called the volume, and a post whose
    // index never reached disk still has nothing but the stem. And they
    // are a union rather than a replacement because the index rule can
    // only ever ADD - so no volume this function reached yesterday
    // becomes unreachable by a name it still matches.
    //
    // WHAT IT COLLECTS is the shape the stems provably cannot see, and
    // it is the shape the pin
    // `e2e_multiset::a_release_named_multi_set_post_never_greens_over_a_holed_file`
    // exists for: `par2 create cd1.par2 track01.bin` names the volumes
    // after the RELEASE and the FileDesc after the PAYLOAD, so every
    // stem here is `track01.bin` and every volume base is `cd1` - no
    // stem matches anything, the none-affine fallback fires by design,
    // and each of the three sets is handed all three sets' parity.
    // Re-measured on this tree 31 Aug 2026 through this very function:
    // six candidates in, all six back. With `cd1.par2` on disk, `cd1`
    // is affine by proof, the filter arms, and the other two sets'
    // volumes are not bought.
    //
    // WHAT IT DOES NOT COVER, stated rather than left to be found: a
    // volume renamed away from BOTH its own index base and this set's
    // payload names. Nothing on disk or in the NZB ties such a name to
    // a set, and the only thing that could is the per-candidate article
    // probe - priced at 2.7x to 5.3x the purchase it guards and refused
    // (`research/VOLUME-ATTRIBUTION-PRICE-2026-08-31.md`). Where this
    // set's index IS resolvable and such a volume exists it is now
    // filtered out where the fallback used to hand it back; that is the
    // same residual trade the stems arm already states two paragraphs
    // up, and it is bounded the same way - the escalation re-asks, so
    // the cost is wire and not an unrepaired job.
    let index_bases = index_bases_on_disk(out_dir, set);
    let base_is_affine = |class: &nzbkit::nzb::SubjectClass<'_>| {
        class.vol_suffix().is_some_and(|at| {
            let base = class.name()[..at].to_ascii_lowercase();
            index_bases.iter().any(|b| b.as_str() == base)
                || stems.iter().any(|st| st.as_str() == base)
        })
    };
    for (fi, f) in nzb.files.iter().enumerate() {
        let class = f.classify();
        if (class.kind() != FileKind::Par2Volume && !sniffed_vols.contains(&fi))
            || already_fetched.contains(&fi)
        {
            continue;
        }
        // A SNIFFED volume is recovery data identified by packet magic,
        // not by name - an obfuscated post's volume is a hash - so it
        // can never be affine to anything and must never be filtered
        // out by a decision made about names.
        //
        // KEPT SEPARATELY rather than counted affine, since the 31 Aug
        // 2026 sweep's finding 8. Counting it affine did leave the
        // sniffed volume as reachable as it was - and ARMED the filter
        // for the whole set, the half the old comment missed. Where no
        // NAME is affine the fallback hands a set every candidate there
        // is (`cd1.vol...` against a FileDesc `track01.bin`,
        // `e2e_multiset`'s own shape); one sniffed volume anywhere in
        // the NZB took the filter branch instead and dropped every named
        // volume with it.
        sniffed.push(sniffed_vols.contains(&fi));
        affine.push(base_is_affine(&class));
        // Blocks are block_size + ~100 bytes of packet overhead each,
        // yEnc ~2% inflation. Shared with pre-flight, which needs the
        // identical arithmetic to size a `.vol-NN.par2` budget and must
        // not grow a second answer to it (nzbkit::par2).
        //
        // The ESTIMATE is only reached when the name declares nothing.
        // Where it declares a count, [`credited_blocks`] holds that
        // count down to what the volume's bytes could carry - see its
        // module header for why a name alone is not evidence, and why
        // the ceiling can never bite an honest volume of this set.
        let est = nzbkit::par2::est_recovery_blocks(f.bytes(), set.block_size);
        let count = credited_blocks(class.name(), f.bytes(), set.block_size).unwrap_or(est.max(1));
        vols.push((fi, count, f.bytes()));
    }
    if affine.iter().any(|&a| a) {
        return vols
            .into_iter()
            .zip(affine.into_iter().zip(sniffed))
            .filter(|(_, (a, s))| *a || *s)
            .map(|(v, _)| v)
            .collect();
    }
    vols
}

/// The most files a mapped repair will recreate from parity alone. Real
/// par-only posts carry a handful of targets; a par2 set declaring
/// thousands of absent files is an allocation bomb, not a post.
const MAX_RECREATED_FILES: usize = 1000;

/// Is the row-26 in-place chase repair armed? DEFAULT ON since 22 Aug
/// 2026, with `NZBFAST_NO_CHASE_REPAIR=1` as the escape hatch - the
/// same sequencing §94 A's resume replay and §94 B's verify gate took:
/// ship dark, soak, measure, flip in its own commit.
///
/// The round that flipped it, 22 Aug 2026 on a 32-core arm64 box with
/// the out-dir on its own APFS image: on a damaged compressed RAR5 set
/// device I/O falls from 3.06x of payload to 2.03x and wall by 10%,
/// byte-correct on 6/6 legs, with the row-27 nested shape unchanged to
/// the tenth of a GiB. It buys disk and wall and NOT cpu (flat at
/// ~84.5 s), and it costs peak RSS: 784 -> 1213 MB, holds peak 73 ->
/// 290 MB, because the rebuilt blocks are charged to the holds budget.
/// That memory price is the reason to reach for the switch; the disk
/// figure is the reason not to.
///
/// `NZBFAST_CHASE_REPAIR=1` is no longer read. It is left documented as
/// an accepted no-op for one release (`docs/ENVIRONMENT.md`) so a
/// soak-era shell profile or bench arm that still exports it is inert
/// rather than surprising - it never disarmed anything, and after the
/// flip it asks for what already happens.
fn chase_repair_on() -> bool {
    chase_repair_on_value(std::env::var("NZBFAST_NO_CHASE_REPAIR").ok().as_deref())
}

/// Pure parse of the escape-hatch value (unit-testable without mutating
/// the process environment under the parallel test runner), the
/// `nzbkit::extract::config` house pattern. Only the exact `1` disarms:
/// an empty or misspelt value leaves the measured default in place
/// rather than silently taking a job back to the 3x route.
fn chase_repair_on_value(v: Option<&str>) -> bool {
    v != Some("1")
}

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

/// Test-only (`NZBFAST_TEST_WAIT_CHASE_CONSUMED_MS`): hold a mapped
/// repair until every chased slot it is about to patch has DECODED past
/// its damage, so the row-26 conflict tripwire is exercised by
/// construction instead of by winning a race.
///
/// The tripwire only fires when a rewrite lands below the buffer's
/// `served` line - the decode has to have consumed the stale bytes for
/// correcting them to be a conflict at all. Which side of that line the
/// repair lands on is pure timing: the download and the decode run
/// concurrently, so on a box where the decode keeps up it has read the
/// last volume by settle, and on one where it lags the repair patches
/// bytes nothing has read and takes the in-place route, correctly.
/// **Both endings are correct and the extracted bytes are byte-exact in
/// each** - only the ROUTE differs. But the two `e2e_chaserepair` legs
/// that pin the DECLINE need the first ending, and from 24 Aug 2026 the
/// ubuntu CI runner produced the second one deterministically (six
/// leg-attempts over three nights, every one the same way) while every
/// box on this fleet produced the first one just as deterministically,
/// starved to `--cpus 0.5` included. That is TODO 278, and it kept
/// nightly red for three nights over a race nobody could reproduce.
///
/// A CONDITION-WAIT and deliberately not a sleep: a sleep is the same
/// race with better odds, and better odds are what this was already
/// running on. The timeout is a floor under a hung decode, not the
/// mechanism - it expires into the OLD behaviour (patch anyway), so the
/// leg then fails with the message it would have failed with before,
/// naming which route it saw.
///
/// Nothing production reads the variable, and an unparseable value is
/// the same no-op as an absent one: a debug knob must not be able to
/// change what a real repair does.
async fn wait_for_the_decode_to_reach_the_damage(
    extractor: &nzbkit::extract::Extractor,
    chased_damage: &[(usize, u64)],
) {
    let Some(ms) = std::env::var("NZBFAST_TEST_WAIT_CHASE_CONSUMED_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    else {
        return;
    };
    if chased_damage.is_empty() {
        return;
    }
    let deadline = Instant::now() + std::time::Duration::from_millis(ms);
    for &(slot, end) in chased_damage {
        // The `while let` is the loop condition doing real work rather
        // than a shape clippy asked for: a slot whose chase is GONE has
        // forfeited, which is the conflict in its strongest form
        // (`chase_repair_conflicted` reads an absent chase as true), so
        // there is nothing left to wait for and the loop is over.
        while let Some(served) = extractor.chase_served(slot) {
            if served >= end {
                break;
            }
            if Instant::now() >= deadline {
                info!(
                    target: "repair",
                    "test hook: slot {slot} decode reached {served} of {end} before the \
                     wait expired - this repair will patch bytes the decode has not read",
                );
                return;
            }
            // `tokio::time::sleep` and not `thread::sleep`: this runs
            // on a runtime worker, and the wait is the one place in
            // this function that is not instantaneous. Parking the
            // worker for up to the whole timeout would hold every other
            // task on it - and a hook that can wedge a job is worse
            // than the race it replaces.
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }
    info!(target: "repair", "test hook: the chase decode is past every damaged block");
}

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
/// `repair_dir` path unchanged, handing it whatever recovery this call
/// had already pulled (`fetched_out`), so a decline that happens AFTER
/// the fetch does not buy the same volumes twice.
#[expect(clippy::too_many_arguments)]
pub async fn try_mapped_repair(
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
    // Which slot belongs to which adopted set (`LiveVerifier::slot_sets`)
    // and WHICH of them this call repairs - the scope
    // `plan_mapped_repair` needs before it resolves a report by NAME.
    // `None` where no verifier stands behind the call (the unit rigs, a
    // single-set world by construction); the guard at that function's
    // report lookup says what a shared list costs without it.
    set_scope: Option<(&[Option<usize>], usize)>,
    missing_files: &[String],
    // Filled, on success only, with the par2 names this call recreated
    // WHOLE from parity. `repair_mapped` whole-file-MD5s every file it
    // rebuilt a block into, so these names are proved to the same
    // standard the disk path proves its whole set - which is what lets
    // the caller clear them from the "still short" verdict.
    recreated_names: &mut Vec<String>,
    // Filled with the NZB file indexes of the recovery volumes this
    // call pulled off the wire, and only when every article of them
    // landed. A DECLINE hands this to [`fetch_and_repair`] as
    // `banked`: the bytes are on disk, whole, and nothing about the
    // decline invalidates them - see the reuse test there.
    //
    // Zero-failure only, because a partial volume may never enter an
    // exclusion list (the sidefetch contract `fetch_and_repair`
    // spells out): the batch count cannot say WHICH of the chosen
    // volumes came back short, so banking any of them would strand
    // its missing slices behind a refetch that never happens.
    fetched_out: &mut Vec<usize>,
    // §282 item 4: filled with what this call's recovery fetch asked
    // for and what came back, whether it landed whole or not. A
    // DECLINE hands it to [`fetch_and_repair`] as `mapped_yield`,
    // which is the only way that function can know the source has
    // already been asked for exactly these volumes and refused them -
    // its own plan is the same `pick_volumes` over the same
    // candidates, so without this it buys the identical failure a
    // second time before the escalation buys it a third.
    yield_out: &mut Option<VolumeYield>,
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
    use nzbkit::par2repair::{VolumeIo, repair_mapped_catalog_resumed};
    let bs = set.block_size as usize;
    // Every set file classified, or a decline - see [`plan_mapped_repair`],
    // which went out of line on 31 Aug 2026, when this function sat at 469
    // of the size gate's 500-line ceiling.
    let MappedPlan {
        files,
        slot_of,
        feed,
        recreated,
        chased,
        chased_damage,
        in_place,
        prefixes,
    } = match plan_mapped_repair(set, bs, extractor, reports, missing_files, set_scope) {
        Some(p) => p,
        None => return Ok(false),
    };

    // Exact-fit recovery fetch - same knapsack + margin as the disk path.
    // Article failures from that fetch, kept for the decline message
    // below: a shortfall verdict on its own cannot say whether the
    // recovery data is absent from the POST or merely absent from what
    // the provider served us, and on the §282 incident that was the
    // whole question (1206 of ~1290 articles lost, so not one 5.25 MB
    // slice landed whole).
    let mut fetch_failures = 0usize;
    let fetched_files: Vec<usize>;
    if needed > 0 {
        let vols = recovery_candidates(nzb, out_dir, set, already_fetched, sniffed_vols);
        // Saturating folds, not `sum()`: every figure summed here comes
        // off the wire and `sum()` is a plain `+` that panics under
        // overflow-checks and wraps in a release build (X5-16, whose
        // seam is `pick_volumes` below - these are the same values one
        // frame out). `have` gates a refusal and a wrapped one lets an
        // unrepairable post through; the two totals below only reach a
        // log line, where a wrapped figure is merely a lie.
        let have: usize = vols.iter().fold(0usize, |a, v| a.saturating_add(v.1));
        if have < needed {
            return Ok(false); // the disk path prints the unrepairable warning
        }
        let target = needed.saturating_add((needed / 10).max(2)).min(have);
        let chosen = pick_volumes(&vols, target);
        let dl_bytes: u64 = chosen
            .iter()
            .fold(0u64, |a, &i| a.saturating_add(vols[i].2));
        let dl_blocks: usize = chosen
            .iter()
            .fold(0usize, |a, &i| a.saturating_add(vols[i].1));
        info!(
            target: "repair",
            "need {needed} block(s) → fetching {} volume(s), {} block(s), {:.1} MB",
            chosen.len(),
            dl_blocks,
            dl_bytes as f64 / 1e6
        );
        fetched_files = chosen.iter().map(|&vi| vols[vi].0).collect();
        // The mapped catalog below re-proves every slice it selects
        // against its packet MD5, so a partial volume cannot make this
        // path repair from bad bytes. The count still matters for what
        // it BANKS: a decline falls through to `fetch_and_repair`,
        // which re-plans over these same candidates and would buy the
        // same volumes a second time (measured 23 Aug 2026 on the
        // costB2 `loop-comp-silent` arm: 134.6 MB pulled where 67.3 MB
        // was needed, and on a metered line the second copy is bought
        // and discarded). Handing the selection over instead costs
        // nothing and is only sound for a COMPLETE pull - see
        // `fetched_out`.
        let pulled = cpu
            .without_permit(fetch_volumes(
                servers,
                nzb,
                out_dir,
                &buf_pool,
                &fetched_files,
                cancel,
            ))
            .await?;
        *yield_out = Some(pulled);
        fetch_failures = pulled.failed as usize;
        if pulled.failed == 0 {
            fetched_out.extend_from_slice(&fetched_files);
        }
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
    // Hold every chased decode still for the duration of the patch. The
    // guard resumes on drop, so a decline, an error or a panic below all
    // release the engines; taken unconditionally because it is a no-op
    // when nothing is chased, and taking it inside the `!chased.is_empty()`
    // branch would put a second exit path on the guard's lifetime.
    //
    // THIS IS ALSO WHAT LETS A RECREATED FILE SIT BESIDE A LIVE CHASE
    // (TODO 287.1, 24 Aug 2026). A wholly-missing file's spans feed
    // through the normal arrival path, so routing can attach the rebuilt
    // volume to the very chase group this call is patching, and that
    // registration happens INSIDE this guard. The pair used to decline
    // outright, just above the bomb check below, because the guard held a
    // SNAPSHOT of the volumes registered when it was taken: a volume
    // joining under it was not held, which made the interaction safe by
    // ARGUMENT (the engine is forward-only, so it reaches that volume
    // only having finished every earlier one) rather than by
    // construction, and §287 called that not good enough for a route
    // whose whole purpose is to skip a second extraction.
    //
    // §287 made it safe by construction, which is what retired the
    // decline: `pause_chase_reads` latches `Inner::chase_reads_paused`
    // under the routing lock, `try_attach_chase` reads it at buffer
    // construction (before the seeding loop, so its failure return is
    // covered too), and this guard's `Drop` clears the latch and resumes
    // the registry as it stands THEN rather than the snapshot it took.
    // The engine cannot read a byte of the rebuilt volume, or of
    // anything after it, until every block of this repair has landed.
    //
    // MEASURED, and worth knowing before reading that latch as the only
    // thing standing here: with it disabled, the ghost-beside-a-chase
    // e2e leg still passes, 3 runs of 3. A mid-pause registration is the
    // ONLY unpaused buffer in the set - every volume ahead of it arrived
    // during the download, so the snapshot holds all of them - which
    // means a forward-only engine can walk the rebuilt volume and then
    // blocks on the next one it wants, and the rebuilt volume's own
    // bytes are written once, in offset order, and never rewritten. This
    // pair sat inside the old gap's stated shape without being able to
    // reach its consequence. That is one more argument about
    // interleavings, which is precisely what the latch replaces.
    //
    // What a decline AFTER the attach leaves behind is the ordinary
    // ending, not a new one: the fed volume's buffer has holes, the
    // resume lets the engine read up to the first of them, and
    // `chase_finish` aborts it, demotes the group and materializes every
    // volume - after which `repair_dir` recreates the missing file on
    // disk authoritatively, exactly as it does for the fed slots a late
    // decline leaves behind today. A demote that happens DURING the
    // patch is caught by the `demoted_to_disk` sweep below, which reads
    // every in-place slot and so covers the chased ones this feed shares
    // a group with.
    // TODO 278's ordering hook, and it must run BEFORE the pause below -
    // the pause is what stops the decode, so a wait taken under it can
    // never be satisfied. Unset (the only production state) is a no-op.
    wait_for_the_decode_to_reach_the_damage(extractor, &chased_damage).await;
    let pause = extractor.pause_chase_reads();
    match repair_mapped_catalog_resumed(
        &files,
        bs,
        &mut cat,
        &set.recovery_set_id,
        &io,
        full_verify,
        &prefixes,
    ) {
        Ok(n) => {
            // Did any rewrite land on bytes a chase had already decoded?
            // Read once, here, still under the pause: the buffer holds
            // the CORRECTED copy either way, so declining now leaves the
            // caller's materialize exactly as byte-exact as it was
            // before this path existed - and, since `fetched_out` hands
            // the recovery over, no longer at the price of buying it
            // again. Structurally unreachable for damage that is
            // MISSING articles (the decode parks at a hole and cannot
            // pass it), so this is the poster-side-corruption arm: bytes
            // that arrived under a valid article CRC and failed PAR2.
            if let Some(&s) = chased
                .iter()
                .find(|&&s| extractor.chase_repair_conflicted(s))
            {
                println!(
                    "⚠ mapped repair declined (slot {s}: the rebuilt bytes differ from \
                     what the archive decode already consumed) - falling back to volume \
                     materialization"
                );
                return Ok(false);
            }
            // ...and the same question one step wider, for the slots the
            // check above does not cover. A MAPPED slot has no chase to
            // conflict, but it can still demote mid-patch on a budget
            // breach or a mapping error - and a demote deletes the
            // group's partially-extracted inner files, so a repair that
            // finished onto the materialized volumes and self-proved
            // clean has no extracted output left to claim. Declining
            // hands the set to the materialize path, which re-extracts
            // it; claiming success would ship the job with its payload
            // deleted.
            //
            // Read under the same pause and AFTER the conflict check,
            // which reads true for a forfeited chase as well and names
            // the sharper reason when it is the one that fired.
            if let Some(&s) = in_place.iter().find(|&&s| extractor.demoted_to_disk(s)) {
                println!(
                    "⚠ mapped repair declined (slot {s}: the volume demoted to disk while \
                     the rebuilt blocks were landing, so its extracted output is gone) - \
                     falling back to volume materialization"
                );
                return Ok(false);
            }
            drop(pause);
            recreated_names.extend(feed.iter().flatten().map(|(name, _)| name.clone()));
            let parity = if recreated > 0 {
                format!(", {recreated} file(s) recreated from parity")
            } else {
                String::new()
            };
            // `n` is the count the LIVE ledger handed this route: the
            // `present` vectors above are `r.bad_blocks` inverted, so
            // every block settle called bad was rebuilt here. The disk
            // route's "in place: N block(s)" sentence counts something
            // else entirely - a fresh on-disk PAR2 verify taken at
            // repair time - so the two do NOT have to agree on the same
            // damage. Read the note at that report site (the
            // `RepairStatus::Repaired` arm in `fetch_and_repair`)
            // before reconciling two leg logs by hand.
            info!(
                target: "repair",
                "repair complete in {:.2?} ✔ (native, mapped: {n} block(s) rebuilt directly into the output{parity})",
                t0.elapsed(),
            );
            Ok(true)
        }
        Err(e) => {
            let lost = if fetch_failures > 0 {
                format!("; the recovery fetch lost {fetch_failures} article(s)")
            } else {
                String::new()
            };
            warn!(
                target: "repair",
                "mapped repair declined ({e}{lost}) - falling back to volume materialization"
            );
            Ok(false)
        }
    }
}

/// Damaged path: fetch the cheapest set of recovery volumes covering
/// `needed` blocks (exact-fit by declared slice counts), then hand the
/// directory to par2cmdline for Reed-Solomon repair.
#[expect(clippy::too_many_arguments)]
pub async fn fetch_and_repair(
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    nzb: &Nzb,
    out_dir: &Path,
    set: &nzbkit::par2::Par2Set,
    // Narrowed in place by the scan-before-buying probe below: the
    // ledger's damage count on the way in, the POST-ADOPTION shortfall
    // once the engine has looked. Everything downstream - `pick_volumes`
    // and its margin, the "need N block(s)" line - is about what still
    // has to be BOUGHT, so it wants the narrowed figure.
    mut needed: usize,
    main_par2: Option<PathBuf>,
    already_fetched: &[usize],
    sniffed_vols: &[usize],
    // Recovery volumes a declined [`try_mapped_repair`] already pulled
    // COMPLETE, in this same tail, against this same `needed` and this
    // same `already_fetched` - its `fetched_out`. Empty when nothing
    // was banked (no mapped attempt, a decline before its fetch, or a
    // pull with failures), which is the whole of this function's
    // behaviour before 23 Aug 2026.
    banked: &[usize],
    // §282 item 4: what a declined [`try_mapped_repair`] measured about
    // this provider's willingness to serve this recovery set - its
    // `yield_out`. `None` when nothing was fetched there (no mapped
    // attempt, or a decline before its fetch).
    mapped_yield: Option<VolumeYield>,
    buf_pool: Arc<nzbkit::pool::BufPool>,
    // Parked around every EXTERNAL par2 invocation - par2cmdline cannot open
    // a file we hold (see `run_external_par2`). Native repair never needs
    // this: it is in-process and reads through our own handles.
    extractor: &nzbkit::extract::Extractor,
    // Set when the repair died on the RECOVERY SET rather than on a bad
    // byte - too little parity declared, or a provider that will not
    // serve the parity that is. The arithmetic belongs in the job's
    // fail message, not just the console. See [`RepairShortfall`].
    shortfall: &mut Option<RepairShortfall>,
    // The owner's side-fetch cancel handle - see [`SideCancel`].
    cancel: Option<&SideCancel>,
    // The caller's heavy-CPU permit, handed back for the duration of
    // both recovery fetches below - see [`crate::lanegate::HeavyCpu`].
    cpu: &mut crate::lanegate::HeavyCpu,
    // §293 donor directories - see [`extpar2::donor_extra_args`] for the
    // whole story; both repair engines below read them.
    donor_dirs: &[PathBuf],
    // X5-10 (31 Aug 2026): where a proven-spent adoption source is
    // RECORDED rather than deleted. See the push site below.
    spent: &mut Vec<PathBuf>,
    // The live block grid's own damage claim, by FileDesc name -
    // sanitized and lowercased. Read by `shortfall_is_final`'s fourth
    // arm and by nothing else: `needed` is a SUM, and refuting a sum
    // means knowing which files it was summed over.
    damaged: &[String],
    // 31 Aug 2026: where [`volpayload::rescue_payload_posted_as_volume`]
    // records the candidates it bought and did NOT publish. Threaded
    // exactly as `spent` above is, and accumulating across the sets of a
    // multi-set post for the same reason - this function is per set. The
    // failing job's quarantine renames these aside; nothing here deletes
    // them. See that module's stated limits.
    rescue_left: &mut Vec<PathBuf>,
    // FileDesc names [`volpayload::rescue_payload_posted_as_volume`]
    // PUBLISHED into `out_dir` on this call, extended rather than
    // replaced, and the complement of `rescue_left` above: that vector
    // carries the candidates the content proof DECLINED, this one the
    // ones it accepted and renamed. Both are invisible to every arm of
    // the failing finish's quarantine for the same reason (no slot,
    // never extracted); they part company because a published file may
    // still be healed in place by the repair below, so its disposition
    // cannot be decided until that has happened. The caller's
    // `unproven_rescues` is what decides it, and feeds the answer back
    // into `rescue_left` so there is still one door.
    published_rescues: &mut Vec<String>,
    // (declared name, landed relative name) for every FileDesc this
    // set's census says landed somewhere other than its own name
    // predicts - accumulated across however many native passes this
    // call runs, deduplicated, and rendered ONCE by the caller after
    // this function returns. See `nativepass::record_declared_name_mismatches`
    // and the claim this closes, `repair-report-name-vs-path-render`.
    mismatches: &mut Vec<(String, String)>,
) -> Result<bool> {
    // §282 item 4: the most recent measurement of whether this source
    // will serve this recovery set at all. Seeded from the declined
    // mapped attempt, overwritten by each of this function's own
    // fetches, and read at every point below that would otherwise ask
    // for MORE - and once more at the very bottom, on the escalation's
    // own yield, where there is nothing left to ask for and the VERDICT
    // is the only thing left to get right.
    let mut wire = mapped_yield.unwrap_or_default();
    if wire.source_will_not_serve() {
        // The mapped attempt already asked this provider for these
        // volumes - its plan is this same `pick_volumes` over this same
        // candidate list for this same `needed` - and got a fraction of
        // them back. Buying the identical failure again is where the
        // §282 incident spent its first 229 seconds; the repair engines
        // below still run against whatever DID reach disk, which costs
        // nothing and is the only thing left that could still work.
        warn!(
            target: "repair",
            "recovery unusable: {} on the volumes this repair needs - not \
             re-asking the same source for them",
            wire.describe()
        );
    }
    // X5-10's recording cell, and it is a `Mutex` rather than a `&mut`
    // capture for a reason the type does not make obvious.
    // `adoption_narrowed_need` below takes the closure as `&dyn Fn`, so
    // a mutable capture makes it `FnMut` and stops compiling; a
    // `RefCell` fixes that and is not `Sync`, which costs this whole
    // future its `Send` and reddens every `tokio::spawn` of a job.
    // There is no contention to speak of - one thread, one statement's
    // worth of borrow, nothing re-entrant.
    let spent = std::sync::Mutex::new(spent);
    let mismatches = std::sync::Mutex::new(mismatches);
    // The native pass, which went out of line on 31 Aug 2026, when this
    // function sat at 475 of the size gate's 500-line ceiling - see
    // [`native_repair_pass`], which carries the whole story. Bound as a
    // closure so the three call sites below
    // (two direct, one through [`adoption_narrowed_need`]) read exactly as
    // they did when the body lived here.
    let native_repair =
        |probe: bool| native_repair_pass(out_dir, set, donor_dirs, probe, &spent, &mismatches);

    let mut fetched_files: Vec<usize> = Vec::new();
    if needed > 0 && !wire.source_will_not_serve() {
        let vols = recovery_candidates(nzb, out_dir, set, already_fetched, sniffed_vols);
        // Saturating folds, not `sum()`: every figure summed here comes
        // off the wire and `sum()` is a plain `+` that panics under
        // overflow-checks and wraps in a release build (X5-16, whose
        // seam is `pick_volumes` below - these are the same values one
        // frame out). `have` gates a refusal and a wrapped one lets an
        // unrepairable post through; the two totals below only reach a
        // log line, where a wrapped figure is merely a lie.
        let have: usize = vols.iter().fold(0usize, |a, v| a.saturating_add(v.1));
        if have < needed && shortfall_is_final(needed, have, donor_dirs, out_dir, set, damaged) {
            // L1 (31 Aug 2026), and the LAST thing tried before the job
            // is lost: a file the NZB called a recovery VOLUME may be
            // the payload itself, in which case nothing has ever
            // fetched it - `build_fetch_plan` skips a non-bootstrap
            // `Par2Volume` before a slot exists, so every rescue in
            // `get/settle.rs` is blind to it by construction. See
            // [`volpayload`] for the screen, the budget and the proof.
            //
            // A rescue does NOT return: it falls through to
            // [`adoption_narrowed_need`] below, whose native probe
            // re-reads the set OFF DISK - so a set the rescue completed
            // comes back `Repaired` and one it only partly closed comes
            // back with a correctly smaller `needed`. Nothing here has
            // to re-derive either figure.
            let rescued = cpu
                .without_permit(rescue_payload_posted_as_volume(
                    servers,
                    nzb,
                    out_dir,
                    set,
                    &buf_pool,
                    already_fetched,
                    cancel,
                    rescue_left,
                ))
                .await;
            if rescued.is_empty() {
                *shortfall = Some(RepairShortfall::Blocks {
                    needed,
                    have,
                    set: Some(set.recovery_set_id),
                });
                return Ok(false);
            }
            // Handed up BEFORE the repair below runs, and deliberately
            // without a verdict attached: whether these bytes are whole
            // is a question about the state the repair LEAVES, not the
            // state it found, and the only frame that can see both is
            // the caller's `unproven_rescues`.
            published_rescues.extend(rescued);
        }
        // Scan before buying - see [`adoption_narrowed_need`], which is
        // out of line only because `fetch_and_repair` was at 498 of the
        // size gate's 500-line ceiling on 28 Aug 2026.
        match adoption_narrowed_need(needed, have, banked, &native_repair) {
            NarrowedNeed::Repaired => return Ok(true),
            NarrowedNeed::Final { needed: after } => {
                *shortfall = Some(RepairShortfall::Blocks {
                    needed: after,
                    have,
                    set: Some(set.recovery_set_id),
                });
                return Ok(false);
            }
            NarrowedNeed::Buy(after) => needed = after,
        }

        // Min-bytes subset with slice sum ≥ needed - plus ~10% margin:
        // par2's own damage count can exceed the block ledger's (a hole
        // invalidates boundary blocks under its scan), and coming up
        // short costs a whole second round-trip.
        let target = needed.saturating_add((needed / 10).max(2)).min(have);
        let chosen = pick_volumes(&vols, target);
        let dl_bytes: u64 = chosen
            .iter()
            .fold(0u64, |a, &i| a.saturating_add(vols[i].2));
        let dl_blocks: usize = chosen
            .iter()
            .fold(0usize, |a, &i| a.saturating_add(vols[i].1));
        fetched_files = chosen.iter().map(|&vi| vols[vi].0).collect();

        // Did a declined mapped repair already buy exactly this?
        //
        // Its plan is this same `pick_volumes` over this same
        // `recovery_candidates` list for this same `needed`, all pure
        // of anything that moves between the two calls, so the
        // selections are equal whenever both ran - and equal means the
        // volumes are on disk, whole (`banked` is zero-failure only),
        // and holding the same slices for the same damage. Nothing
        // about a route decline touches recovery data.
        //
        // Compared rather than assumed. If the two ever disagree this
        // fetches, exactly as it did before, instead of repairing
        // against a directory it only believes is populated - and the
        // comparison is over ~64 volumes at most, against the 67.3 MB
        // the reuse saves (measured 23 Aug 2026, costB2
        // `loop-comp-silent`).
        let reuse = !banked.is_empty()
            && fetched_files.len() == banked.len()
            && fetched_files.iter().all(|fi| banked.contains(fi));
        if reuse {
            info!(
                target: "repair",
                "need {needed} block(s) → reusing {} volume(s), {} block(s), {:.1} MB \
                 already fetched before the in-place repair declined",
                chosen.len(),
                dl_blocks,
                dl_bytes as f64 / 1e6
            );
        } else {
            info!(
                target: "repair",
                "need {needed} block(s) → fetching {} volume(s), {} block(s), {:.1} MB",
                chosen.len(),
                dl_blocks,
                dl_bytes as f64 / 1e6
            );
            let pulled = cpu
                .without_permit(fetch_volumes(
                    servers,
                    nzb,
                    out_dir,
                    &buf_pool,
                    &fetched_files,
                    cancel,
                ))
                .await?;
            wire = pulled;
            if pulled.failed > 0 {
                // At least one chosen volume landed PARTIAL, and the
                // batch count cannot say which - so none of the batch
                // may enter the escalation's exclusion list below (only
                // a complete volume may ever be excluded: sidefetch
                // contract). The escalation then refetches them in
                // full, rewriting the files in place - the behavior the
                // resume path documents - instead of permanently
                // stranding the partial volume's missing slices and
                // declaring a recoverable job unrepairable.
                fetched_files.clear();
            }
        }
    }

    let native = native_repair(false);
    if native == NativeVerdict::Done {
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
    let mut external = main_par2
        .as_ref()
        .map(|m| par2cmdline_invocation(m, out_dir, donor_dirs));
    if external.is_none() {
        warn!(target: "repair", "no main .par2 on disk - cannot invoke par2cmdline");
    }
    // (name, length) of every file the recovery set declares - the
    // targets par2's exit 0 has just verified, and the only writers
    // whose coverage that verdict licenses us to publish (sweep 8, M5).
    let verified: Vec<(String, u64)> = set
        .files
        .iter()
        .map(|f| (f.name.clone(), f.length))
        .collect();
    if let Some((bin, arg, extras)) = external.take() {
        match run_external_par2(&bin, &arg, &extras, out_dir, &verified, extractor)? {
            Ok(st) if st.success() => {
                publish_external_coverage(extractor, &verified);
                info!(target: "repair", "repair complete in {:.2?} ✔", t0.elapsed());
                return Ok(true);
            }
            Ok(st) => {
                warn!(target: "repair", "par2 repair exited with {st}");
                external = Some((bin, arg, extras));
            }
            Err(e) => {
                // par2 is no longer embedded - native repair covers real
                // sets, so reaching this needs both an exotic failure AND
                // no external par2 on PATH or next to the executable.
                // Left as None: a binary that could not be spawned will
                // not spawn on the second pass either.
                //
                // §282 item 16: what to SAY about that depends entirely
                // on why the native pass declined. Advertising
                // par2cmdline to somebody whose set has no parity on
                // disk sends them to install a tool that would have
                // failed on the same arithmetic. On the incident job it
                // sent the reader off to ask why nzbfast needs an
                // external par2 at all, which is the wrong question and
                // one this message caused: see [`NativeVerdict`].
                //
                // "on this process's PATH" and not "on this machine",
                // which is a second wrong claim the old line made and
                // §282 item 4's notes measured: par2cmdline WAS
                // installed on the incident box, at a Homebrew prefix,
                // and `tools::resolve` falls back to the bare name -
                // i.e. $PATH, which under launchd is
                // /usr/bin:/bin:/usr/sbin:/sbin. So the hatch is
                // unreachable on every Homebrew macOS install run as a
                // service, and the old remedy was one the reader had
                // already followed. Widening the search to a Homebrew
                // prefix is a separate judgement (that directory is
                // user-writable and the result is spawned), so this
                // says what is true rather than pretending otherwise.
                match native {
                    NativeVerdict::NoRecovery { needed, have } => warn!(
                        target: "repair",
                        "no external par2 on this process's PATH ({e}), and it could \
                         not have helped: {needed} block(s) are damaged with only \
                         {have} recovery block(s) on disk, and no par2 implementation \
                         can rebuild data it has no parity for. What is missing here \
                         is recovery data, not a tool"
                    ),
                    _ => warn!(
                        target: "repair",
                        "no external par2 was runnable ({e}) - install par2cmdline \
                         (e.g. brew install par2) or place a par2 binary next to nzbfast; \
                         continuing with native repair alone"
                    ),
                }
            }
        }
    }

    // Escalation: par2's own damage accounting can exceed the ledger's -
    // fetch every remaining recovery volume and try once more.
    let remaining: Vec<usize> =
        recovery_candidates(nzb, out_dir, set, already_fetched, sniffed_vols)
            .iter()
            .map(|v| v.0)
            .filter(|fi| !fetched_files.contains(fi))
            .collect();
    if remaining.is_empty() {
        if shortfall.is_none() {
            *shortfall = blocks_shortfall(native, &wire, set.recovery_set_id);
        }
        return Ok(false);
    }
    // §282 item 4: the escalation's premise is that par2's own damage
    // accounting ran a little ahead of the block ledger's, so a little
    // more parity closes the gap. That premise needs a source that
    // SERVES parity. When the fetch above measured otherwise, the
    // remaining volumes come back at the same fraction - the incident
    // asked for 1024 MB, got 6.7% of it, and answered by asking for all
    // seven remaining volumes, which is where 46 minutes of
    // post-processing went against a payload that was 99.8% intact.
    //
    // A yield gate, NOT a timeout: §146 owns "this is taking too long"
    // and prices it against a 2x parity margin. Nothing here switches
    // on throughput, and a slow provider that is actually serving walks
    // straight past this.
    if wire.source_will_not_serve() {
        warn!(
            target: "repair",
            "recovery unusable: {} - not escalating to the {} remaining volume(s). \
             This provider will not serve this post's recovery set",
            wire.describe(),
            remaining.len()
        );
        *shortfall = Some(RepairShortfall::Unservable(wire));
        return Ok(false);
    }
    info!(
        target: "repair",
        "repair short - fetching all {} remaining volume(s)",
        remaining.len()
    );
    // Bound, not discarded: this is the LAST ask this job makes and, on
    // a ladder that got here, usually the largest sample it takes. See
    // the verdict at the bottom of this function.
    wire = cpu
        .without_permit(fetch_volumes(
            servers, nzb, out_dir, &buf_pool, &remaining, cancel,
        ))
        .await?;
    // Shadows the pre-escalation verdict on purpose: this pass ran with
    // every volume on disk, so its needed/have supersede the first
    // pass's for the [`blocks_shortfall`] verdict at the bottom.
    let native = native_repair(false);
    if native == NativeVerdict::Done {
        return Ok(true);
    }
    if let Some((bin, arg, extras)) = external
        && let Ok(st) = run_external_par2(&bin, &arg, &extras, out_dir, &verified, extractor)?
        && st.success()
    {
        publish_external_coverage(extractor, &verified);
        info!(target: "repair", "repair complete (second pass) ✔");
        return Ok(true);
    }
    warn!(target: "repair", "repair failed even with every recovery volume");
    // §282 item 4: the gate above is read at every point that would ask
    // for MORE, and this is the point where there is nothing more to
    // ask for - so until 24 Aug 2026 nothing ever read the escalation's
    // OWN yield, and a job could demonstrate beyond doubt that its
    // provider will not serve this recovery set and still reach the
    // user with the plain missing-articles opening that item 17's rung
    // exists to displace. Measured on a throwaway fixture: 280 recovery
    // articles asked, 0 arrived, verdict `download incomplete: 1
    // file(s) with missing segments`. The route in is the floor working
    // correctly - a FIRST ask under `MIN_RECOVERY_YIELD_SAMPLE`
    // declines to judge, which is right, and the escalation it then
    // runs is far over the floor and was judged by nobody.
    //
    // REPORTING only. Every guard above is pre-ask and stays exactly as
    // it was: this cannot make the ladder buy anything it does not buy
    // today, which is where §282's 229 seconds went.
    //
    // Judged on the escalation's own yield, REPLACING the earlier
    // sample rather than summing with it. Both are asks of one source
    // against one set, so summing is arithmetically defensible - but it
    // lets a smaller, older sample outvote a larger, fresher one, and
    // that has a false positive this verdict must not have. When
    // `pick_volumes`' cheapest subset happens to be volumes a partially
    // retained set no longer holds, the first ask comes back empty
    // while the escalation is served most of the way; summed, that job
    // is told its provider will not serve the parity and sent hunting a
    // different source, when the honest answer is that the parity on
    // offer was not enough. The floor applies either way, so neither
    // form judges a sample too small to mean anything - and the case
    // summing would additionally catch is one where the WHOLE remaining
    // set is under sixteen articles, which is exactly the size the
    // floor exists to refuse.
    if wire.source_will_not_serve() {
        warn!(
            target: "repair",
            "recovery unusable: {} across every remaining volume - this provider \
             will not serve this post's recovery set",
            wire.describe()
        );
        *shortfall = Some(RepairShortfall::Unservable(wire));
    } else if let Some(s) = blocks_shortfall(native, &wire, set.recovery_set_id) {
        *shortfall = Some(s);
    }
    Ok(false)
}

/// Sweep S13: the donor road skips the early `Blocks` shortfall (its
/// arithmetic is not final until the adoption scan has run), so when
/// the native pass has measured the post-adoption shortfall, that
/// arithmetic still belongs in the job's fail message - not only in
/// the console. Guarded off a provider that will not serve, where "the
/// recovery set ... carries only {have}" would blame the poster for the provider's
/// refusal - the `Unservable` arms own that story.
///
/// `set_id` is recorded unconditionally and blanked later by whoever
/// owns the whole set list - see [`RepairShortfall::forget_set`].
fn blocks_shortfall(
    native: NativeVerdict,
    wire: &VolumeYield,
    set_id: [u8; 16],
) -> Option<RepairShortfall> {
    match native {
        NativeVerdict::NoRecovery { needed, have } if !wire.source_will_not_serve() => {
            Some(RepairShortfall::Blocks {
                needed,
                have,
                set: Some(set_id),
            })
        }
        _ => None,
    }
}

/// Indexes into `vols` = (file, slices, bytes) minimizing downloaded bytes
/// subject to Σ slices ≥ needed. Exact 0/1 knapsack with an explicit
/// chosen-set bitmask (recovery sets virtually never exceed 64 volumes);
/// beyond 64, greedy by cost-per-slice.
pub(crate) fn pick_volumes(vols: &[(usize, usize, u64)], needed: usize) -> Vec<usize> {
    if vols.len() > 64 {
        let mut order: Vec<usize> = (0..vols.len()).collect();
        // Cost-per-slice, compared by cross-multiplication so no division
        // and no zero-slice special case is needed. WIDENED TO u128 (X5-16):
        // `bytes` is an NZB's advertised `bytes=`, which parses as a full
        // u64 and is never bounded by what the article actually holds, so
        // `bytes * slices` overflows u64 on a figure a tiny real article
        // can advertise. That panics under overflow-checks and WRAPS in a
        // release build, and a wrapped comparator is not a consistent
        // ordering at all - `sort_by` may then return an arbitrary subset
        // rather than the cheap one. u128 is exactly wide enough: both
        // factors fit in u64, so the product cannot overflow it. The index
        // tiebreak keeps equal-ratio volumes in a deterministic order.
        order.sort_by(|&a, &b| {
            let l = (vols[a].2 as u128) * (vols[b].1 as u128);
            let r = (vols[b].2 as u128) * (vols[a].1 as u128);
            l.cmp(&r).then(a.cmp(&b))
        });
        let mut chosen = Vec::new();
        let mut got = 0usize;
        for vi in order {
            if got >= needed {
                break;
            }
            chosen.push(vi);
            got = got.saturating_add(vols[vi].1);
        }
        return chosen;
    }
    // dp[d] = Some((bytes, mask)) - cheapest way to cover a deficit of ≥ d
    // blocks, None where no subset reaches that deficit at all.
    //
    // `Option` rather than a `u64::MAX` sentinel, and `saturating_add`
    // rather than `+`, are one fix and not two (X5-16). The costs here are
    // attacker-supplied - see the u128 note above - so two of them sum past
    // u64::MAX, which panicked under overflow-checks at the `cost + bytes`
    // this replaces. Saturating alone would not do: it lands on u64::MAX,
    // which the old sentinel spells "unreachable", so the planner would
    // silently return an EMPTY selection for a deficit it can in fact
    // cover. Separating reachability from cost keeps "ruinously expensive"
    // and "impossible" distinct, which is the whole of what the DP decides.
    let n = needed;
    let mut dp: Vec<Option<(u64, u64)>> = vec![None; n + 1];
    dp[0] = Some((0, 0));
    for (vi, &(_, slices, bytes)) in vols.iter().enumerate() {
        for d in (0..=n).rev() {
            let Some((cost, mask)) = dp[d] else {
                continue;
            };
            // Saturating for the same reason the cost below is, and
            // reachable from the same place: `slices` is a per-volume
            // recovery-block COUNT derived from parsed packet data, so a
            // huge one overflows this add before either cost is looked
            // at. `.min(n)` clamps it back immediately - the saturation
            // can never change which bucket this lands in.
            let nd = d.saturating_add(slices).min(n);
            let ncost = cost.saturating_add(bytes);
            if dp[nd].is_none_or(|(best, _)| ncost < best) {
                dp[nd] = Some((ncost, mask | (1u64 << vi)));
            }
        }
    }
    let mask = dp[n].map_or(0, |(_, m)| m);
    (0..vols.len())
        .filter(|vi| mask & (1u64 << vi) != 0)
        .collect()
}

// Child module file, not inline: repair.rs sits under the size-gate
// ceiling (TODO 106) and test growth belongs beside it, same pattern
// as side_fetch_tests below.
#[cfg(test)]
mod repair_tests;

// X5-16's two arithmetic pins for `pick_volumes` above. Out here for the
// reason the four modules below are - repair.rs sits under the size-gate
// ceiling (TODO 106) - and in the CRATE rather than in `tests/` because
// `pick_volumes` is `pub(crate)`.
#[cfg(test)]
mod wave5_probe_tests;

// Its second child, split off in turn: `repair_tests` reached the
// gate's own 3,000-line file ceiling when the bomb-refusal cases landed,
// and the fallback-ROUTING cases were the coherent third of it. Same
// rule as above - the numbers only go down.
#[cfg(test)]
mod ladder_tests;

// Child module file, not inline: repair.rs sits under a size-gate
// baseline (TODO 106) and test growth belongs beside it, same pattern
// as pool/unit_tests.rs.
#[cfg(test)]
mod side_fetch_tests;

// TODO 205's two follow-up routes - the plain feed branch above and the
// nested 7z/zip pass - and the shortlist rule that separates
// `unpackprog::attempt` from `unpackprog::watch`. Out here for the same
// reason as the three above: `repair_tests` is 2,775 of the gate's
// 3,000 lines and this subject is its own.
#[cfg(test)]
mod unpackprog_tests;

// TODO 311's volume-affinity rule - which of a multi-set post's
// recovery volumes `recovery_candidates` lets the knapsack buy for one
// set. Out here for the reason the four above are: `repair_tests` is
// 2,939 of the size gate's 3,000 lines, and this subject is its own.
#[cfg(test)]
mod vol_affinity_tests;

// Follow-up 13a's third arm on `shortfall_is_final` - whether a set
// whose files are all CLAIMED is still worth handing to the repair
// engines. Out here for the reason the five above are: `repair_tests`
// is 2,939 of the size gate's 3,000 lines, and this subject is its own.
#[cfg(test)]
mod shortfall_gate_tests;

// The nested password-chain auto-unlock cases and their harvest/resolve
// pins, moved out whole. Out here for the reason the six above are:
// `repair_tests` sat at 2,909 lines of the size gate's 3,000-line
// ceiling when this subject came out, and it is its own.
#[cfg(test)]
mod password_chain_tests;
