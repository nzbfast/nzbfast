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
#[cfg(test)]
pub(crate) fn reextract_dir(dir: &std::path::Path, password: Option<&str>) -> Result<bool> {
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
pub(crate) fn reextract_dir_why(
    dir: &std::path::Path,
    password: Option<&str>,
) -> Result<std::result::Result<(), Option<String>>> {
    Ok(reextract_dir_outcome(dir, password)?.map(|_| ()))
}

/// [`reextract_dir_why`] that also carries out what the unrar rung left
/// PACKED beside a sibling that produced (TODO 164): the resumed-run arm
/// of the tail runs this ladder with the job's PAR2 set in scope, and
/// judges the leftovers against it exactly as the fresh-run arms do -
/// see [`crate::rarfix::vouch`]. Every success path that never reaches
/// the unrar rung left nothing packed, and says so with an empty list.
pub(crate) fn reextract_dir_outcome(
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
    // (`writers_snapshot`, `serve/api/queue.rs`), so the sample below
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

mod sidefetch;
// The side-fetch driver, its consumer and the two small helpers that
// price a volume moved out whole (§129 residue 2). Re-exported rather
// than re-pathed at every call site: nothing about the split is
// interesting to a caller, and `use super::*` importers stay valid.
// `VolumeFailures` is deliberately NOT re-exported: no caller outside
// sidefetch.rs names the type, they only call `total()` / `for_file()`
// on what the driver hands back, and an unused re-export is a warning.
pub(crate) use sidefetch::{
    SideCancel, VolumeOpen, VolumeYield, fetch_volume_articles, fetch_volume_articles_with,
    fetch_volumes, side_pool_servers, vol_count_from_name, volume_prealloc_cap, volume_reqs,
};

/// Why a PAR2 repair could not complete, when the reason is arithmetic
/// about the RECOVERY SET rather than a bad byte anywhere.
///
/// The one class of repair failure whose numbers belong in the job's
/// own fail message and not just the console: the user is owed which of
/// the two halves of the post let them down, because the answers are
/// opposite. `Blocks` means the poster shipped too little parity for
/// the damage and no provider could have helped. `Unservable` means the
/// parity is declared, is the right size, and this provider will not
/// hand it over - the payload may be all but perfect (99.8% on the
/// §282 incident), and an alternate source is the whole remedy.
///
/// Both spellings carry "repair could not complete", so both classify
/// [`crate::failkind::FailKind::Unrepairable`]: transient enough for
/// the one automatic retry, and hinting `search` rather than `retry`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RepairShortfall {
    /// The NZB does not declare enough recovery blocks to cover the
    /// damage, whatever the provider does.
    Blocks { needed: usize, have: usize },
    /// §282 item 4: the volumes are declared and the source will not
    /// serve them. Carries the measured yield that said so.
    Unservable(VolumeYield),
}

impl RepairShortfall {
    /// The clause the job's fail message states this shortfall in, put
    /// after "verification failed and PAR2 repair could not complete".
    pub(crate) fn clause(&self) -> String {
        match self {
            RepairShortfall::Blocks { needed, have } => {
                format!("{needed} recovery block(s) needed but the NZB only carries {have}")
            }
            RepairShortfall::Unservable(y) => format!(
                "the recovery data for this post could not be fetched from your \
                 provider ({}). The payload is not the problem here, so a different \
                 source for the same release is what would fix it",
                y.describe()
            ),
        }
    }
}

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
    let base_is_affine = |lower: &str| {
        nzbkit::nzb::par2_vol_suffix(lower)
            .is_some_and(|at| stems.iter().any(|st| st.as_str() == &lower[..at]))
    };
    for (fi, f) in nzb.files.iter().enumerate() {
        if (f.kind() != FileKind::Par2Volume && !sniffed_vols.contains(&fi))
            || already_fetched.contains(&fi)
        {
            continue;
        }
        let name = f.filename_hint().unwrap_or(&f.subject);
        // A SNIFFED volume is recovery data identified by packet magic,
        // not by name - an obfuscated post's volume is a hash - so it
        // can never be affine to anything and must never be filtered
        // out by a decision made about names. It counts as affine to
        // every set, which leaves it exactly as reachable as it was.
        let lower = name.to_ascii_lowercase();
        affine.push(sniffed_vols.contains(&fi) || base_is_affine(&lower));
        // Blocks are block_size + ~100 bytes of packet overhead each,
        // yEnc ~2% inflation. Shared with pre-flight, which needs the
        // identical arithmetic to size a `.vol-NN.par2` budget and must
        // not grow a second answer to it (nzbkit::par2).
        let est = nzbkit::par2::est_recovery_blocks(f.bytes(), set.block_size);
        let count = vol_count_from_name(name).unwrap_or(est.max(1));
        vols.push((fi, count, f.bytes()));
    }
    if affine.iter().any(|&a| a) {
        return vols
            .into_iter()
            .zip(affine)
            .filter(|(_, a)| *a)
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
    // Chased slots this call intends to patch in place - re-read for
    // the conflict verdict once every rebuilt block has landed.
    let mut chased: Vec<usize> = Vec::new();
    // The same slots with the END of their damage, for the TODO 278
    // ordering hook below. A repair only trips the conflict when it
    // rewrites a byte the decode has already READ, so the hook needs to
    // know which byte to wait for, and this is the only place that
    // knows: `r.bad_blocks` and the set's block size are both in scope
    // here and neither survives into the patch.
    let mut chased_damage: Vec<(usize, u64)> = Vec::new();
    // EVERY slot this call intends to patch in place, chased or not.
    // Each was Rar / Plain / RarChase when the gate below passed it -
    // `is_mapped`, `is_plain_patchable` and `is_chase_patchable` match
    // nothing else - so any of them reading `demoted_to_disk` after the
    // patch demoted DURING it, which deleted the group's extracted
    // output. Same post-check discipline as `chased`, one question
    // wider; see the verdict block after `repair_mapped_catalog`.
    let mut in_place: Vec<usize> = Vec::new();
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
                    if !r.bad_blocks.is_empty() && !extractor.is_mapped(*sidx) {
                        let plain_ok = extractor.is_plain_patchable(*sidx)
                            && plain_patch_keeps_sniff(&r.bad_blocks, bs);
                        // Shape-coverage row 26: a CHASED volume can
                        // take the rewrite too, straight into its
                        // frontier buffer, which is what keeps a damaged
                        // COMPRESSED set off the three-write disk route
                        // (measured 22 Aug 2026 at 3.05x of payload
                        // in device I/O against 1.03x for the same
                        // damage on a store set, and re-measured the
                        // same day at 2.03x with this route taken).
                        // DEFAULT ON since that round; the escape
                        // hatch is `NZBFAST_NO_CHASE_REPAIR=1` - see
                        // `chase_repair_on`.
                        let chase_ok = chase_repair_on() && extractor.is_chase_patchable(*sidx);
                        if !plain_ok && !chase_ok {
                            return Ok(false);
                        }
                        if chase_ok {
                            chased.push(*sidx);
                            // Past the LAST bad block, clipped to the
                            // file: a decode that has read that far has
                            // read every byte this repair will rewrite,
                            // so the conflict is settled rather than
                            // still in flight.
                            let last = r.bad_blocks.iter().copied().max().unwrap_or(0);
                            let end = ((last as u64 + 1) * set.block_size).min(f.length);
                            chased_damage.push((*sidx, end));
                        }
                    }
                    if !r.bad_blocks.is_empty() {
                        in_place.push(*sidx);
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
    // Article failures from that fetch, kept for the decline message
    // below: a shortfall verdict on its own cannot say whether the
    // recovery data is absent from the POST or merely absent from what
    // the provider served us, and on the §282 incident that was the
    // whole question (1206 of ~1290 articles lost, so not one 5.25 MB
    // slice landed whole).
    let mut fetch_failures = 0usize;
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
    match repair_mapped_catalog(&files, bs, &mut cat, &set.recovery_set_id, &io, full_verify) {
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
fn dir_entry_names(dir: &std::path::Path) -> Option<std::collections::HashSet<std::ffi::OsString>> {
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
fn purge_par2_backups(
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
fn publish_external_coverage(extractor: &nzbkit::extract::Extractor, verified: &[(String, u64)]) {
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
enum NativeVerdict {
    /// The set is whole. Nothing below this runs.
    Done,
    /// The damage outruns the recovery blocks ON DISK. par2cmdline
    /// reads the same directory and would reach the same arithmetic.
    NoRecovery { needed: usize, have: usize },
    /// A native bug, the repair-dimension guard, an I/O error, or the
    /// kill switch: the cases the external backstop exists for.
    Backstop,
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
/// Empty when nothing was adopted, so the everyday line is unchanged.
pub(crate) fn adopted_clause(adopted: usize) -> String {
    if adopted == 0 {
        String::new()
    } else {
        format!(" (adoption already found {adopted} of them in files outside the recovery set)")
    }
}

/// Report the native pass's shortfall and turn it into a verdict.
///
/// Out of line only because [`fetch_and_repair`] is at its size-gate
/// ceiling; the wording is the whole point of it, so keep the two
/// together if that ever changes.
fn native_shortfall(needed: usize, have: usize, adopted: usize) -> NativeVerdict {
    warn!(
        target: "repair",
        "native repair: {needed} block(s) damaged, only {have} recovery block(s) on disk{}",
        adopted_clause(adopted)
    );
    NativeVerdict::NoRecovery { needed, have }
}

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

/// Damaged path: fetch the cheapest set of recovery volumes covering
/// `needed` blocks (exact-fit by declared slice counts), then hand the
/// directory to par2cmdline for Reed-Solomon repair.
#[expect(clippy::too_many_arguments)]
pub(crate) async fn fetch_and_repair(
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    nzb: &Nzb,
    out_dir: &Path,
    set: &nzbkit::par2::Par2Set,
    needed: usize,
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
    // §293 donor directories - see [`donor_extra_args`] for the whole
    // story; both repair engines below read them.
    donor_dirs: &[PathBuf],
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
    let mut fetched_files: Vec<usize> = Vec::new();
    if needed > 0 && !wire.source_will_not_serve() {
        let vols = recovery_candidates(nzb, set, already_fetched, sniffed_vols);
        let have: usize = vols.iter().map(|v| v.1).sum();
        if have < needed {
            // §293: with a donor available this is no longer a
            // foregone conclusion - the adoption scan can stand in for
            // recovery blocks the NZB never declared, and only
            // `repair_dir` can say how many it finds. Fall through to
            // the repair with whatever recovery DOES exist; if the
            // donor comes up short the native verdict below reports
            // the (post-adoption) shortfall exactly as before. Without
            // a donor the arithmetic is final, as it always was.
            if donor_dirs.is_empty() {
                warn!(
                    target: "repair",
                    "unrepairable: {needed} blocks needed, only {have} recovery blocks in the NZB"
                );
                *shortfall = Some(RepairShortfall::Blocks { needed, have });
                return Ok(false);
            }
            info!(
                target: "repair",
                "recovery short ({needed} blocks needed, {have} in the NZB) - \
                 trying the failed predecessor's files as donors before giving up"
            );
        }

        // Min-bytes subset with slice sum ≥ needed - plus ~10% margin:
        // par2's own damage count can exceed the block ledger's (a hole
        // invalidates boundary blocks under its scan), and coming up
        // short costs a whole second round-trip.
        let target = (needed + (needed / 10).max(2)).min(have);
        let chosen = pick_volumes(&vols, target);
        let dl_bytes: u64 = chosen.iter().map(|&i| vols[i].2).sum();
        let dl_blocks: usize = chosen.iter().map(|&i| vols[i].1).sum();
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

    // Reed-Solomon repair: native in-process GF(2^16) first - verifies the
    // set from disk, reconstructs missing blocks, and patches files IN
    // PLACE (no volume rewrite). Self-proving: success requires every
    // patched file to match its PAR2 whole-file MD5, so a native bug can
    // never ship bad bytes - it falls through to par2cmdline instead.
    //
    // SCOPED TO THIS SET BY ID, and load-bearing: this runs once PER
    // declined set (`disk_repair_declined_sets`) and the directory-scoped
    // entry repaired the first set every time, greening over the others'
    // holes - see [`nzbkit::par2repair::repair_dir_set_with_donors`].
    let native_repair = || -> NativeVerdict {
        if std::env::var_os("NZBFAST_NO_NATIVE_REPAIR").is_some() {
            return NativeVerdict::Backstop;
        }
        let t0 = Instant::now();
        use nzbkit::par2repair::{RepairStatus, repair_dir_set_with_donors};
        match repair_dir_set_with_donors(out_dir, &set.recovery_set_id, donor_dirs) {
            Ok(RepairStatus::NoDamage) => {
                info!(
                    target: "repair",
                    "repair complete in {:.2?} ✔ (native - set already verifies on disk)",
                    t0.elapsed()
                );
                NativeVerdict::Done
            }
            Ok(RepairStatus::Repaired(r)) => {
                // `r.blocks_rebuilt` is what `repair_dir`'s own verify
                // found bad ON DISK at this instant. That is NOT the
                // damage count settle printed, and on a chased set that
                // declined the mapped route it is reproducibly LOWER -
                // often zero, in which case this arm does not run at all
                // and the `NoDamage` line above prints instead. Nothing
                // is undercounted here: a declined mapped attempt is not
                // rolled back, so the blocks it already landed are good
                // on disk by the time this pass looks.
                //
                // Measured 23 Aug 2026 (M3 Ultra, costB2
                // `loop-comp-silent`, 3 reps of 3 identical; same shape
                // at test scale in
                // `a_declined_mapped_repair_still_lands_every_rebuilt_block`)
                // at "3/35 blocks bad", the verify-gated twin saying
                // "mapped: 3 block(s)" and this line "in place: 2
                // block(s)". That split was a DEFECT, fixed the same
                // day: the mapped attempt's first patched block landed
                // in the chase's frontier buffer, `chase_span` saw it
                // conflict with bytes the decode had already consumed
                // and forfeited INSIDE that write, and
                // `patch_volume_span` then refused the demoted slot -
                // so the next block's write returned "no backing data"
                // and two blocks already solved in memory were thrown
                // away for this pass to solve again. `patch_volume_span`
                // now admits `RarFallback` and those writes go through
                // to the volume the demote just materialized, so the
                // same fixture reaches here with nothing to rebuild.
                //
                // What did NOT change is the decline itself: the decode
                // consumed stale bytes, so the set still materializes
                // and re-extracts. Only the repair work stopped being
                // discarded.
                //
                // The "need N block(s) →" line just above still names
                // the LEDGER's N, so this route still plans for blocks
                // it no longer needs - it reuses the mapped attempt's
                // volumes rather than buying them twice (see `banked`),
                // and the surplus is inside the exact-fit margin.
                info!(
                    target: "repair",
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
                NativeVerdict::Done
            }
            Ok(RepairStatus::Unrepairable {
                needed,
                have,
                adopted,
            }) => native_shortfall(needed, have, adopted),
            Err(e) => {
                warn!(target: "repair", "native repair failed ({e}) - falling back to par2cmdline");
                NativeVerdict::Backstop
            }
        }
    };
    let native = native_repair();
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
        let mut extra_args: Vec<std::path::PathBuf> =
            extra_files.iter().map(|f| dot.join(f)).collect();
        extra_args.extend(donor_extra_args(donor_dirs));
        (par2_bin, par2_arg, extra_args)
    });
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
    let remaining: Vec<usize> = recovery_candidates(nzb, set, already_fetched, sniffed_vols)
        .iter()
        .map(|v| v.0)
        .filter(|fi| !fetched_files.contains(fi))
        .collect();
    if remaining.is_empty() {
        if shortfall.is_none() {
            *shortfall = blocks_shortfall(native, &wire);
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
    let native = native_repair();
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
    } else if let Some(s) = blocks_shortfall(native, &wire) {
        *shortfall = Some(s);
    }
    Ok(false)
}

/// Sweep S13: the donor road skips the early `Blocks` shortfall (its
/// arithmetic is not final until the adoption scan has run), so when
/// the native pass has measured the post-adoption shortfall, that
/// arithmetic still belongs in the job's fail message - not only in
/// the console. Guarded off a provider that will not serve, where "the
/// NZB only carries {have}" would blame the poster for the provider's
/// refusal - the `Unservable` arms own that story.
fn blocks_shortfall(native: NativeVerdict, wire: &VolumeYield) -> Option<RepairShortfall> {
    match native {
        NativeVerdict::NoRecovery { needed, have } if !wire.source_will_not_serve() => {
            Some(RepairShortfall::Blocks { needed, have })
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
