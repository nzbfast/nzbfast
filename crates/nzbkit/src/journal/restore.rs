//! Restore: how a parsed journal becomes bytes a resume run can use -
//! the half journal.rs's grammar section names when it says "[`restore`]
//! copies those fragments back into the volume files the resume run
//! works with". The plaintext-once re-encryption that has to run first
//! (an encrypted store's output holds PLAINTEXT, so its placements are
//! re-encrypted rather than copied), the partial-quarantine dance that
//! has to run before THAT (a failed job's payload wears
//! `.nzbfast-partial` between attempts, and the restore pass cannot see
//! it under that name), and the placement replay itself. Split out of
//! journal.rs (TODO 106 size gate); every caller reaches these through
//! `journal::` unchanged, via the re-export at the cut.

use super::*;

/// One plaintext-once fragment restore job for [`restore_crypto`]:
/// re-encrypt plaintext `[file_off, file_off+len)` of `file` and write
/// the resulting posted bytes at `vol_off` of the slot's volume file.
struct CryptoRestoreJob {
    article: usize, // index into a per-run article table
    file_off: u64,
    vol_off: u64,
    len: u64,
    dest: PathBuf,
    dest_size: u64,
}

/// Re-encrypt plaintext-once fragments back into volume files. Returns
/// per-article success (indexed like the caller's table). Walks each
/// file once in offset order with a rolling CBC chain, reseeding from
/// the journaled checkpoints across coverage holes and CROSS-VERIFYING
/// the rolling chain against every checkpoint it passes - a mismatch
/// (plaintext holes read as zeros, a truncated file) fails the fragment
/// and reseeds, so at most one checkpoint stride of garbage can ever be
/// written, and the resume run's full-hash verification catches even
/// that (restored bytes are never trusted unhashed).
fn restore_crypto(
    out_dir: &Path,
    resume: &ResumeState,
    password: Option<&str>,
    jobs_by_file: HashMap<&str, Vec<CryptoRestoreJob>>,
    article_ok: &mut [bool],
) {
    let Some(pw) = password else {
        for jobs in jobs_by_file.values() {
            for j in jobs {
                article_ok[j.article] = false;
            }
        }
        return;
    };
    for (fname, mut jobs) in jobs_by_file {
        let Some(meta) = resume.crypto_files.get(fname) else {
            for j in &jobs {
                article_ok[j.article] = false;
            }
            continue;
        };
        let fail_all = |jobs: &[CryptoRestoreJob], article_ok: &mut [bool]| {
            for j in jobs {
                article_ok[j.article] = false;
            }
        };
        let Some(keys) = crate::rarcrypt::derive_keys(pw, &meta.salt, meta.lg2) else {
            fail_all(&jobs, article_ok);
            continue;
        };
        // Prove the password before re-encrypting a single byte: a wrong
        // key would faithfully rebuild GARBAGE posted bytes for every
        // fragment, which the full-hash pass then damages wholesale. No
        // stored check means no proof - refetch instead of guessing.
        match meta.check {
            Some(stored) if crate::rarcrypt::make_check(&keys) == stored => {}
            _ => {
                fail_all(&jobs, article_ok);
                continue;
            }
        }
        let Ok(src) = File::open(out_dir.join(fname)) else {
            fail_all(&jobs, article_ok);
            continue;
        };
        let src_len = src.metadata().map(|m| m.len()).unwrap_or(0);
        let cipher_len = crate::rarcrypt::align16(meta.unp);
        let mut ckpts: Vec<(u64, [u8; 16])> =
            meta.checkpoints.iter().map(|(&o, &b)| (o, b)).collect();
        ckpts.sort_unstable();
        jobs.sort_by_key(|j| j.file_off);
        let mut dests: HashMap<PathBuf, Option<File>> = HashMap::new();
        // Rolling chain state: cipher block [cpos-16, cpos).
        let (mut cpos, mut chain): (u64, [u8; 16]) = (0, meta.iv);
        let mut walk = vec![0u8; 64 << 10];
        // Advance the rolling chain to `target` (16-aligned) by
        // encrypting the plaintext between, reseeding from the best
        // anchor at or below it; verify against every checkpoint passed.
        // Returns false when the stretch cannot be walked faithfully.
        let mut chain_to = |cpos: &mut u64, chain: &mut [u8; 16], target: u64| -> bool {
            if *cpos == target {
                return true;
            }
            // Best anchor at or below the target: the rolling state or
            // the nearest checkpoint, whichever is CLOSER. Every
            // decrypted region begins at a journaled K (the writer emits
            // one per decrypt boundary), so the nearest anchor is always
            // inside the target's own region and the walk can never
            // cross a coverage hole - the shape that used to re-encrypt
            // zero-filled plaintext into garbage posted bytes. The
            // password itself is proven against the stored check before
            // any of this runs.
            let (mut at, mut c) = (0u64, meta.iv);
            if *cpos <= target {
                (at, c) = (*cpos, *chain);
            }
            let below = ckpts.partition_point(|&(ko, _)| ko <= target);
            if let Some(&(ko, kb)) = ckpts[..below].iter().rev().find(|&&(ko, _)| ko > at) {
                (at, c) = (ko, kb);
            }
            let mut next_ck = ckpts.partition_point(|&(ko, _)| ko <= at);
            while at < target {
                let n = crate::disk::chunk_len(target - at, walk.len());
                if at + (n as u64) > src_len
                    || crate::disk::read_exact_at(&src, &mut walk[..n], at).is_err()
                {
                    return false;
                }
                let mut enc = crate::rarcrypt::CbcEncStream::new(&keys.aes(), &c);
                enc.encrypt(&mut walk[..n]);
                c = walk[n - 16..n].try_into().unwrap();
                at += n as u64;
                // Cross-verify each checkpoint the walk passes.
                while next_ck < ckpts.len() && ckpts[next_ck].0 <= at {
                    let (ko, kb) = ckpts[next_ck];
                    if ko > 0 && ko <= at {
                        let s = (n as u64 - (at - ko)) as usize;
                        let got: [u8; 16] = if s >= 16 {
                            walk[s - 16..s].try_into().unwrap()
                        } else {
                            c // ko == at edge: the rolling block
                        };
                        if got != kb {
                            return false;
                        }
                    }
                    next_ck += 1;
                }
            }
            (*cpos, *chain) = (at, c);
            true
        };
        for j in jobs {
            let lo = j.file_off & !15;
            let hi = (j.file_off + j.len).next_multiple_of(16).min(cipher_len);
            if hi <= lo || j.file_off + j.len > cipher_len {
                article_ok[j.article] = false;
                continue;
            }
            if !chain_to(&mut cpos, &mut chain, lo) {
                article_ok[j.article] = false;
                // Reseed for the next job from scratch.
                (cpos, chain) = (0, meta.iv);
                continue;
            }
            // Encrypt [lo, hi): plaintext from disk below unp, the
            // journaled padding beyond it.
            let n = (hi - lo) as usize;
            let mut buf = vec![0u8; n];
            let disk_end = hi.min(meta.unp);
            let mut ok = disk_end <= src_len;
            if ok && disk_end > lo {
                ok = crate::disk::read_exact_at(&src, &mut buf[..(disk_end - lo) as usize], lo)
                    .is_ok();
            }
            if ok && hi > meta.unp {
                match &meta.pad {
                    Some(pad) if pad.len() as u64 >= hi - meta.unp => {
                        let a = (meta.unp - lo) as usize;
                        buf[a..].copy_from_slice(&pad[..(hi - meta.unp) as usize]);
                    }
                    _ => ok = false,
                }
            }
            if !ok {
                article_ok[j.article] = false;
                continue;
            }
            let mut enc = crate::rarcrypt::CbcEncStream::new(&keys.aes(), &chain);
            enc.encrypt(&mut buf);
            let new_chain: [u8; 16] = buf[n - 16..].try_into().unwrap();
            let dest = dests.entry(j.dest.clone()).or_insert_with(|| {
                std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    // Never truncate: the writes below land at offsets
                    // inside a file this may be re-opening, and set_len
                    // only ever grows it.
                    .truncate(false)
                    .open(&j.dest)
                    .ok()
                    .inspect(|d| {
                        let cur = d.metadata().map(|m| m.len()).unwrap_or(0);
                        if j.dest_size > cur {
                            let _ = d.set_len(j.dest_size);
                        }
                    })
            });
            let Some(dest) = dest.as_ref() else {
                article_ok[j.article] = false;
                continue;
            };
            let a = (j.file_off - lo) as usize;
            if crate::disk::write_all_at(dest, &buf[a..a + j.len as usize], j.vol_off).is_err() {
                article_ok[j.article] = false;
                continue;
            }
            (cpos, chain) = (hi, new_chain);
        }
    }
}

/// Suffix worn by a failed job's unverified payload while it waits for a
/// retry. Chosen to be inert everywhere it might be seen: it is not a
/// media, archive or par2 extension, so no *arr import rule, media
/// scanner, unpack ladder or `looks_like_named_rar` scan claims it, and
/// a user reading their download folder can see at a glance that it is
/// not the file they asked for.
pub const PARTIAL_SUFFIX: &str = ".nzbfast-partial";

/// Take a failed job's direct-extracted payload out of circulation
/// WITHOUT throwing its bytes away.
///
/// A one-pass job writes the inner file straight to the output
/// directory, so a job that fails on missing articles leaves a payload
/// of exactly the right name and exactly the right size with a
/// zero-filled hole in the middle of it. That is the same false artifact
/// `drop_spared_metadata` deletes on the success path - "a holed .nfo
/// looks exactly like a real .nfo" - one level up, and it is worse here
/// because it is the deliverable itself: an *arr importing on name and
/// size takes it, a player opens it, and nothing about the directory
/// says otherwise.
///
/// Renamed rather than deleted, because those bytes are also the ONLY
/// resume state a retry has. The journal's placement (`R`) records
/// address fragments by their offsets INSIDE this file - direct-extracted
/// articles never touched a volume file - so deleting it turns a retry
/// that refetches one missing article into a retry that refetches the
/// whole post. [`unquarantine_partials`] puts the name back at the start
/// of the next attempt, before [`restore`] reads it, so the rename costs
/// a resume nothing.
///
/// This function's scope is payload NAMES the extraction reported; the
/// failing finish holds the downloaded volume files the same way
/// through [`quarantine_paths`] (TODO 159 item 1c - a failed job's
/// partial download must not keep wearing real volume names in the
/// output directory either). The discrimination over which downloaded
/// files are held lives with the caller, which can tell a volume from
/// a plain file the job proved whole.
///
/// Returns `(quarantined, failed)` by on-disk name. A failure is
/// reported, never swallowed - the caller is already failing the job,
/// but a payload that could not be renamed is still sitting there
/// looking real.
pub fn quarantine_partials(out_dir: &Path, payload: &[String]) -> (Vec<String>, Vec<String>) {
    let paths: Vec<PathBuf> = payload
        .iter()
        .map(|n| crate::disk::join_out_name(out_dir, &crate::disk::sanitize_out_name(n)))
        .collect();
    quarantine_paths(&paths)
}

/// Path-level half of [`quarantine_partials`]: rename each existing
/// file aside to `<name>.nzbfast-partial`, returning `(renamed,
/// failed)` by file name. Callers hand it the on-disk paths a failing
/// job must take out of circulation - the get tail's downloaded volume
/// files - where [`quarantine_partials`] builds paths from payload
/// names. A path already wearing the suffix is left alone, so a
/// second pass over the same directory cannot stack suffixes.
pub fn quarantine_paths(paths: &[PathBuf]) -> (Vec<String>, Vec<String>) {
    let (mut done, mut failed) = (Vec::new(), Vec::new());
    for from in paths {
        let Some(name) = from.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            continue;
        };
        // DELIBERATELY `exists()`, decided under the 31 Aug 2026
        // rename-occupancy census. This tests the SOURCE, which is a
        // different question from the destination one this file's
        // `unquarantine_partials` asks: "is there a payload here to take
        // out of circulation". A link at a volume's name is not this
        // job's payload, and skipping it is the conservative answer -
        // where quarantining a resolving link renames the LINK aside and
        // is reversible, so neither arm destroys anything. Nothing is
        // gained by sharpening it and the entry question would be the
        // wrong one to ask.
        if name.ends_with(PARTIAL_SUFFIX) || !from.exists() {
            continue;
        }
        let mut to = from.clone().into_os_string();
        to.push(PARTIAL_SUFFIX);
        // NO OCCUPANCY TEST ON THE DESTINATION, DECIDED under the same
        // 31 Aug 2026 rename-occupancy census as the source test above,
        // and unlike `unquarantine_partials` below, which grew one.
        // `rename` REPLACES an existing regular file in silence
        // (measured on APFS that day), so this line does discard an
        // earlier `<name>.nzbfast-partial` when it finds one. Three
        // things make that the right answer rather than a missing guard.
        //
        // 1. THE ENGINE ALONE CANNOT REACH THE STATE. This is the only
        //    writer of the suffix, and it requires the base name to
        //    exist and removes it in the same rename;
        //    `unquarantine_partials` runs unconditionally at the top of
        //    every attempt (`build_intake`, before `Journal::open`) and
        //    removes the suffixed name whenever the base one is free. So
        //    at an attempt boundary the two coexist only if a SECOND
        //    writer put a file at the base name - the case that
        //    function's own header names, a re-add into an occupied
        //    directory or a copy the user made.
        // 2. IN THAT CASE THE LOSER'S BYTES ARE ALREADY DEAD. What kept
        //    it suffixed is the unquarantine DECLINING, and `restore`
        //    addresses payloads by their recorded base name, never the
        //    suffixed one - so it was invisible to the restore that ran
        //    minutes ago and every article whose bytes live in it has
        //    been refetched by the attempt now failing. Keeping it keeps
        //    bytes nothing can address, and hands the next restore a
        //    file the newest records do not describe, which is the
        //    seeded-with-the-wrong-bytes harm `unquarantine_partials`
        //    declines FOR. The narrow cost of newest-wins - an attempt
        //    that died early leaving less than the one before it - is
        //    bandwidth, and it is the cheaper side.
        // 3. EVERY ALTERNATIVE COSTS MORE. Refusing leaves the holed
        //    payload wearing its real name, which is the false artifact
        //    this whole mechanism exists to prevent. A second suffix is
        //    never restored (`strip_suffix` matches one) and never
        //    cleaned, so it is permanent clutter in the download folder,
        //    which is what `PARTIAL_SUFFIX`'s own doc is about.
        //
        // NOR DOES IT WANT the `symlink_metadata` guard the unquarantine
        // side just gained, and the asymmetry is the point: the BASE
        // name is user vocabulary and a link at it is somebody's
        // library, where the suffixed name is ours alone and nothing but
        // this line has ever written one. A directory at the
        // destination is refused by the kernel (`IsADirectory`, measured
        // the same day) and reported in `failed`, never swallowed.
        match std::fs::rename(from, PathBuf::from(to)) {
            Ok(()) => done.push(name),
            Err(_) => failed.push(name),
        }
    }
    (done, failed)
}

/// Undo [`quarantine_partials`] at the start of an attempt, so the
/// journal's placement records find the file they address.
///
/// Must run BEFORE [`restore`]: a `.nzbfast-partial` file is invisible to
/// the restore pass, which would drop every article whose bytes live in
/// it and refetch them.
///
/// A base name that already exists is left alone and its quarantined
/// copy is NOT clobbered. That case means something other than this
/// mechanism put a file there - a re-add into an occupied directory, a
/// user's own copy - and the live file wins; guessing between two
/// candidates is how a resume ends up seeded with the wrong bytes.
/// Returns the names it restored.
pub fn unquarantine_partials(out_dir: &Path) -> Vec<String> {
    let mut back = Vec::new();
    // WALKS SUBDIRECTORIES, because `quarantine_partials` WRITES into
    // them: since the relpath-preserve ruling its paths come from
    // `join_out_name(out_dir, sanitize_out_name(n))`, so a tree-preserved
    // payload is parked at `out_dir/VIDEO_TS/x.vob.nzbfast-partial`. A
    // top-level `read_dir` never saw it, and the consequence is the one
    // this function's own header states: the file stays invisible to
    // `restore`, every article whose bytes live in it is refetched, and
    // the `.nzbfast-partial` is left behind for good (30 Aug 2026 sweep).
    //
    // Depth-capped by `disk::MAX_DEPTH` ITSELF - the same constant that
    // decides how many components `sanitize_out_name` will ever produce
    // - so a symlinked or hostile tree cannot walk forever and the two
    // move together. It was a hand-copied literal until 31 Aug 2026,
    // which meant raising that budget left this walk short of exactly
    // the trees it would then have to find: the partial goes invisible
    // again and every article whose bytes are in it refetches, the
    // defect above. A deepest preserved name is MAX_DEPTH components,
    // of which the last is the leaf, so the deepest directory this must
    // read sits at MAX_DEPTH - 1.
    //
    // `symlink_metadata` keeps the walk off links entirely, the same
    // refusal `create_out_dirs` makes on the way in.
    let mut stack: Vec<(PathBuf, usize)> = vec![(out_dir.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            let Ok(md) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            if md.is_dir() {
                if depth + 1 < crate::disk::MAX_DEPTH {
                    stack.push((p, depth + 1));
                }
                continue;
            }
            if !md.is_file() {
                continue; // a symlink is never ours to restore
            }
            let Some(n) = p.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some(base) = n.strip_suffix(PARTIAL_SUFFIX) else {
                continue;
            };
            if base.is_empty() {
                continue;
            }
            let dest = p.with_file_name(base);
            // `symlink_metadata`, the same question the walk above
            // already asks on the way IN, and this line was the one
            // place in the function that asked the other one. The header
            // promises that a base name something else already holds is
            // left alone and the quarantined copy is not clobbered;
            // `Path::exists` FOLLOWS symlinks and answers false on any
            // error, so a link at the base name read as free and the
            // `fs::rename` below removed it - rename removes whatever
            // ENTRY is at its destination and never resolves it.
            //
            // Declining costs a REFETCH of the articles whose bytes are
            // in the quarantined file, which this function's own header
            // describes as the ordinary consequence of a file staying
            // invisible to `restore`. That is bandwidth. The link's
            // target string is the only record of where it pointed and
            // nothing brings it back, so the harms are not symmetric.
            // Argued in full at `tv_rename` in
            // `nzbfast-unpack/src/smart/filing.rs`.
            //
            // AND IT IS A CLAIM RATHER THAN A LOOK since 31 Aug 2026,
            // under `occupancy-claim-the-rest-of-the-class`. The
            // `lstat` was a check before a use: MEASURED on the sibling
            // guard in `nzbfast`'s `unpack::published_names::publish`,
            // it covered about 1% of its own interval and 96.8% of
            // concurrent arrivals that got the name landed inside the
            // gap. `create_new` answers `AlreadyExists` over a regular
            // file, a dangling link, a link out of the directory and a
            // directory - the same four answers the `lstat` gave - so
            // the claim IS this guard, taken atomically.
            //
            // Plain `create_new` and not `disk::open_out_leaf_under`,
            // per the argument at `tv_rename` in
            // `nzbfast-unpack/src/smart/filing.rs`: the rename below resolves
            // its destination by path, so a bound claim would ask a
            // stricter question than the operation it guards and refuse
            // a job directory reached through a symlink.
            //
            // A claim that fails for any other reason - the directory
            // gone, a read-only volume - takes the same arm as a taken
            // name, which is what the discarded `rename` result already
            // did with it: the partial stays quarantined and its
            // articles refetch.
            if std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&dest)
                .is_err()
            {
                continue;
            }
            if std::fs::rename(&p, &dest).is_ok() {
                // The out_dir-relative name, so the caller's set matches
                // the `S`/`M` records and `Frag.file`, which all carry
                // the tree form.
                back.push(crate::disk::out_name_of(out_dir, &dest));
            } else {
                // Our own placeholder. Left behind it is a zero-byte
                // file at the base name, which `restore` would then
                // trust as the volume file - a length no fragment can
                // sit at - and which every later run reads as the name
                // being taken, so the quarantined bytes could never come
                // back.
                let _ = std::fs::remove_file(&dest);
            }
        }
    }
    back
}

/// Does the article's on-disk payload still hash to the commitment its
/// record carries? (X5-02, 30 Aug 2026.)
///
/// **`None` is a refusal, not a pass.** A record with no commitment
/// cannot be authenticated, so its article refetches - which is the
/// point of the row, and it is what a journal an older binary wrote
/// looks like. The cost of that is one resume, once, after an upgrade;
/// the cost of the other answer is shipping whatever happens to be at
/// the right offsets with the right length.
///
/// `art_src` is parallel to `frags` and says where each fragment's bytes
/// physically are NOW, which is the only thing that makes one function
/// serve all four fragment shapes: an identity fragment and a
/// re-encrypted crypto one are read from the slot's own file, a copy
/// source is read from the source (its bytes are about to be copied
/// verbatim, so hashing either end is the same question), and a
/// materialised copy is read from the destination it was just written
/// to.
///
/// Fragments are hashed in VOLUME ORDER because that is payload order: a
/// yEnc part covers one contiguous range of the posted file, and the
/// fragments partition exactly that range, so concatenating them by
/// ascending `vol_off` reconstructs the bytes the crc was taken over.
/// The record's own fragment order is not that, and must not be assumed
/// to be.
///
/// TWO THINGS IT DELIBERATELY DOES NOT CLAIM, stated rather than left to
/// be found. It is a crc32, so it is a commitment against a CRASH, a
/// half-written file and an accidental external edit - not a MAC: a
/// writer who can rewrite a job's payload can rewrite the journal beside
/// it, and the journal was never a boundary against one (they could
/// equally delete it, or rewrite the finished output). And it costs one
/// extra read of every admitted byte at RESUME time - never on the
/// download path, where the number is one the decode already computed -
/// which is local disk against a network refetch, the trade this whole
/// mechanism exists to keep winning.
///
/// `open` is the caller's per-SLOT handle cache, and it is a parameter
/// rather than a local for one reason: this function is called once per
/// ARTICLE, so a local map opened the same handful of files once per
/// article - 27,981 `open()` calls over the m15b fixture's 24 source
/// files, 3.7% of the pre-pool serial replay profile (Round 21). It is
/// keyed by the `Arc<str>` names `art_src` carries rather than by
/// borrowed `&str`, because `art_src` is rebuilt per article and a
/// borrow from it cannot outlive one. It stays a PARAMETER OWNED BY THE
/// CALLING SLOT - never a shared or static cache - because phase B runs
/// on a pool, one slot per lane. It is a distinct map from
/// [`restore_slot`]'s `srcs`, which is keyed off the journal's `f.file`
/// COPY sources; this one's key domain is where the bytes are NOW, which
/// includes the slot's own volume file and is not the same set.
///
/// Caching a FAILED open across articles does not change any verdict:
/// every name that reaches here names a file that already exists when
/// the first article naming it is checked (an identity fragment needs a
/// pre-existing destination, a crypto fragment's volume file was written
/// by phase A, and a materialised copy's destination is created by the
/// copy branch before this runs), so there is no article whose open
/// would fail while a later one's succeeds. A cached handle reads
/// through the page cache, so writes made through `restore_slot`'s
/// separate `dest` handle - and the `set_len` that may precede them -
/// are visible to it.
fn article_authentic(
    out_dir: &Path,
    frags: &[Frag],
    art_src: &[(std::sync::Arc<str>, u64)],
    crc: Option<u32>,
    buf: &mut [u8],
    open: &mut HashMap<std::sync::Arc<str>, Option<File>>,
) -> bool {
    let Some(want) = crc else {
        return false;
    };
    if art_src.len() != frags.len() {
        // Every fragment shape pushes its source; a mismatch means this
        // function is reading a list it does not understand, and the
        // safe answer to that is the refusal, never the admission.
        return false;
    }
    let mut order: Vec<usize> = (0..frags.len()).collect();
    order.sort_by_key(|&i| frags[i].vol_off);
    let mut hasher = crc32fast::Hasher::new();
    for i in order {
        let (name, off) = &art_src[i];
        if !open.contains_key(&**name) {
            open.insert(name.clone(), File::open(out_dir.join(&**name)).ok());
        }
        let Some(src) = open[&**name].as_ref() else {
            return false;
        };
        let mut done = 0u64;
        while done < frags[i].len {
            let n = crate::disk::chunk_len(frags[i].len - done, buf.len());
            if crate::disk::read_exact_at(src, &mut buf[..n], off + done).is_err() {
                return false;
            }
            hasher.update(&buf[..n]);
            done += n as u64;
        }
    }
    hasher.finalize() == want
}

/// Rebuild the volume files a resume run works with from a placement
/// journal: identity fragments (bytes already at their final offsets in
/// the destination) are trusted in place; translated fragments (bytes in
/// an extracted inner file) are COPIED back into the volume file - a
/// local disk copy instead of a network refetch - and plaintext-once
/// fragments (`D` records) are RE-ENCRYPTED back into posted bytes via
/// [`restore_crypto`]. An article counts as restored only when every
/// fragment succeeds; anything else refetches. Never fails: a missing
/// source file just drops its articles.
pub fn restore(out_dir: &Path, resume: &ResumeState, password: Option<&str>) -> Restored {
    restore_for(out_dir, resume, password, true)
}

/// [`restore`] with the volume-materialisation half made optional.
///
/// `materialize_volumes = true` is the historic behaviour: every
/// placement is COPIED out of the output file it landed in and back into
/// the slot's volume file, so the resume sees volumes exactly as the
/// wire delivered them.
///
/// `false` is what §94 A's replay wants. Those bytes are already on
/// disk, in the output run 1 wrote them to, and the replay is about to
/// read them and feed them straight back through `Extractor::write` -
/// so copying them into a volume file first writes a full extra copy of
/// the resumed fraction and then reads it back. That round trip was the
/// difference between a resumed job costing 2.02x payload of device I/O
/// and the 1.01x a clean run costs. With it off, each restored span is
/// recorded in `SlotSeed::sources` instead and the replay reads from
/// there.
///
/// Two kinds of fragment are unaffected either way and always report
/// their own volume file: an IDENTITY fragment (the bytes never moved -
/// a plain slot, which is also every PAR2 recovery volume, so the
/// issue-#14 resume sniff still finds them on disk), and a crypto
/// fragment, which phase A has already re-encrypted into volume form
/// because plaintext on disk is not what the wire sent.
///
/// The admission check is unchanged: a source that cannot be opened, or
/// is too short to hold the span, still fails its article so it
/// refetches. That has to stay, because a `false` run reads the source
/// LATER (at replay time) rather than here, and an article already in
/// `completed` will not refetch if the read fails then.
pub fn restore_for(
    out_dir: &Path,
    resume: &ResumeState,
    password: Option<&str>,
    materialize_volumes: bool,
) -> Restored {
    let mut out = Restored::default();
    // The wire-domain outputs, before phase A: a crypto fragment naming
    // one of these is the contradiction `Restored::plaintext_outputs`
    // describes, and it must fail admission rather than re-encrypt
    // bytes that are not plaintext.
    for rec in resume.slots.values() {
        if rec.name.is_empty() {
            continue;
        }
        for a in &rec.articles {
            for (i, f) in a.frags.iter().enumerate() {
                if a.crypto && a.crypto_frag.get(i).copied().unwrap_or(true) {
                    continue;
                }
                *out.wire_outputs.entry(f.file.clone()).or_default() += f.len;
            }
        }
    }
    // Phase A: the crypto fragments, per file in offset order.
    let mut article_ids: Vec<(usize, &str)> = Vec::new(); // (slot, id)
    let mut article_refs: Vec<&Article> = Vec::new(); // parallel to article_ids
    let mut jobs_by_file: HashMap<&str, Vec<CryptoRestoreJob>> = HashMap::new();
    let mut meta_missing: Vec<usize> = Vec::new();
    for (&slot, rec) in &resume.slots {
        if rec.name.is_empty() {
            continue;
        }
        for a in &rec.articles {
            if !a.crypto {
                continue;
            }
            let article = article_ids.len();
            article_ids.push((slot, &a.id));
            article_refs.push(a);
            for (i, f) in a.frags.iter().enumerate() {
                if !a.crypto_frag.get(i).copied().unwrap_or(true) {
                    continue; // plain neighbor: phase B copies it
                }
                // A crypto fragment whose E facts are missing can only
                // refetch - falling through to a copy would put
                // PLAINTEXT into a volume file. So can one naming a file
                // a plain placement also claims: those bytes may be
                // either domain, and re-encrypting ciphertext poisons
                // the volume exactly as copying plaintext would.
                if resume.crypto_files.contains_key(f.file.as_str())
                    && !out.wire_outputs.contains_key(f.file.as_str())
                {
                    jobs_by_file
                        .entry(f.file.as_str())
                        .or_default()
                        .push(CryptoRestoreJob {
                            article,
                            file_off: f.file_off,
                            vol_off: f.vol_off,
                            len: f.len,
                            dest: out_dir.join(&rec.name),
                            dest_size: rec.size,
                        });
                } else {
                    meta_missing.push(article);
                }
            }
        }
    }
    let mut article_ok = vec![true; article_ids.len()];
    for a in meta_missing {
        article_ok[a] = false;
    }
    // How long each destination already was, taken BEFORE phase A: phase A
    // opens every crypto slot's destination with `create(true)` + `set_len`,
    // so a file that was deleted between runs (user cleanup, or a spent-
    // volume sweep) is recreated as a hole and a phase-B existence probe
    // would then read true. Its identity fragments - "the bytes are already
    // where the resume expects them" - are zeros, and they would be accepted
    // instead of refetched, so with no PAR2 behind the job those zeros ship.
    //
    // The LENGTH, not just the existence, because a file that survived but
    // was truncated (a partial write, an interrupted move, an external tool)
    // fails the same way one step in: the path is there, so presence alone
    // says yes, but the bytes an identity fragment names are past the end.
    // `seed_slot` grows the file back to the recorded size and marks those
    // spans covered, so the hole ships. An identity fragment is trusted only
    // when the pre-restore file reached past the end of its span.
    // `identity_without_existing_file_refetches` and
    // `identity_against_truncated_file_refetches` are the tests for the intent.
    let pre_len: HashMap<&str, u64> = resume
        .slots
        .values()
        .filter(|r| !r.name.is_empty())
        .filter_map(|r| {
            Some((
                r.name.as_str(),
                std::fs::metadata(out_dir.join(&r.name)).ok()?.len(),
            ))
        })
        .collect();
    restore_crypto(out_dir, resume, password, jobs_by_file, &mut article_ok);
    // Every admitted crypto article pins its output to plaintext-once
    // for the resumed run (see `Restored::plaintext_outputs`).
    for (a, _) in article_refs.iter().zip(&article_ok).filter(|&(_, &ok)| ok) {
        for (fi, f) in a.frags.iter().enumerate() {
            if !a.crypto_frag.get(fi).copied().unwrap_or(true) {
                continue;
            }
            if let Some(m) = resume.crypto_files.get(f.file.as_str()) {
                out.plaintext_outputs
                    .entry(f.file.clone())
                    .or_insert((m.salt, m.iv));
            }
        }
    }
    let crypto_verdict: HashMap<(usize, &str), bool> = article_ids
        .iter()
        .zip(&article_ok)
        .map(|(&(slot, id), &ok)| ((slot, id), ok))
        .collect();
    // Phase B: per-article accounting + the plain copies.
    //
    // ON A POOL, NOT ONE SLOT AFTER ANOTHER (3 Sep 2026, handoff item 9,
    // claim `startup-and-resume`). This pass is what a resume spends its
    // time on and nothing had ever timed it: on the m15b fixture - a
    // 24 GB stored set killed at 85%, resumed on the mapped route - it
    // was 19,986 ms of a 32.6 s run, 61% of the wall, all of it before
    // the first byte went back on the wire. A `sample` over it is 92%
    // `pread` on ONE thread at 1,036 MB/s, which is a latency figure and
    // not a device one: the same 20.7 GB re-read by the PAR2 backfill's
    // four workers, on the same box in the same leg, runs at 2,132 MB/s.
    //
    // The bytes are read because every admitted article is checked
    // against the X5-02 crc32 its record carries (`article_authentic`),
    // and that is true on BOTH routes - the mapped one writes nothing
    // and still reads everything. So the pass is I/O-latency bound and
    // splits the way the backfill's does.
    //
    // SLOTS ARE INDEPENDENT BY CONSTRUCTION: a slot's iteration touches
    // its own destination, its own source handles and its own span
    // lists, and the only shared things it reads - `pre_len`,
    // `crypto_verdict`, `out.wire_outputs` - are all finished before
    // this point and never written here. The five things it produces
    // are collected per slot and merged BELOW in work order, so the
    // result is identical to the serial one rather than merely
    // equivalent: `out.ids` is a set, the three counters are sums, and
    // `out.seeds` is rebuilt in a fixed order. That order is now sorted
    // by slot index, where the serial loop took `HashMap` order - a
    // narrowing, not a change: nothing downstream ever had an order to
    // depend on.
    let work: Vec<(usize, &SlotPlacement)> = {
        let mut w: Vec<(usize, &SlotPlacement)> = resume
            .slots
            .iter()
            .filter(|(_, r)| !r.name.is_empty())
            .map(|(&s, r)| (s, r))
            .collect();
        w.sort_by_key(|&(s, _)| s);
        w
    };
    // TWO SLOTS CAN NAME THE SAME FILE, and that is the one shape this
    // pass may not split. Within a single run the writer disambiguates
    // (`used_names` in journal.rs), but the guard is per journal INSTANCE
    // and `parse_lines` resolves `S` last-wins PER SLOT, so a second
    // generation that re-records slot A under a name generation 1 gave
    // slot B leaves both slots pointing at one destination. Serially that
    // is already a mess; in parallel it is a WORSE one, because the
    // materialising arm opens the destination per slot and calls
    // `set_len` on it - two threads doing that to one file can truncate
    // away bytes the other just wrote. So a duplicate name stands the
    // pool down rather than being handled: it is rare enough that its
    // speed has never mattered, and "run it the way it has always run"
    // is the only answer here that cannot be subtly wrong.
    let unique_dests = {
        let mut n: Vec<&str> = work.iter().map(|(_, r)| r.name.as_str()).collect();
        n.sort_unstable();
        let before = n.len();
        n.dedup();
        n.len() == before
    };
    // `cpu_workers` rather than `available_parallelism` (cpu-workers-gate:
    // this is a worker pool and a phone must be able to cap it). Half the
    // machine, capped, and never more lanes than there is work: unlike the
    // PAR2 backfill - which runs WHILE the download does and takes 4 for
    // that reason - this pass owns the box, nothing else has started yet.
    // The cap is what bounds the transient RSS: `RESTORE_BUF` is per
    // worker, so eight lanes is 32 MiB rather than one buffer per core.
    let workers = if unique_dests {
        (crate::mem::cpu_workers() / 2)
            .clamp(1, RESTORE_MAX_WORKERS)
            .min(work.len())
    } else {
        1
    };
    let mut done: Vec<(usize, SlotOutcome)> = if workers <= 1 {
        let mut buf = vec![0u8; RESTORE_BUF];
        work.iter()
            .enumerate()
            .map(|(i, &(slot, rec))| {
                (
                    i,
                    restore_slot(
                        out_dir,
                        slot,
                        rec,
                        &pre_len,
                        &crypto_verdict,
                        materialize_volumes,
                        &mut buf,
                    ),
                )
            })
            .collect()
    } else {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let next = AtomicUsize::new(0);
        let collected = std::sync::Mutex::new(Vec::with_capacity(work.len()));
        // Bound as SHARED references before the scope: a `move` closure
        // would otherwise take the first worker's capture by value and
        // leave the rest with nothing to claim work from.
        let (work, next, collected) = (&work, &next, &collected);
        let (pre_len, crypto_verdict) = (&pre_len, &crypto_verdict);
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(move || {
                    let mut buf = vec![0u8; RESTORE_BUF];
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some(&(slot, rec)) = work.get(i) else {
                            break;
                        };
                        let o = restore_slot(
                            out_dir,
                            slot,
                            rec,
                            pre_len,
                            crypto_verdict,
                            materialize_volumes,
                            &mut buf,
                        );
                        // Once per slot, so the lock is not on any hot
                        // path - the work inside is tens of thousands of
                        // preads.
                        collected
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push((i, o));
                    }
                });
            }
        });
        std::mem::take(&mut *collected.lock().unwrap_or_else(|e| e.into_inner()))
    };
    // Work order, so the merge below is the serial result exactly.
    done.sort_by_key(|&(i, _)| i);
    for (_, o) in done {
        out.ids.extend(o.ids);
        out.dropped_crypto += o.dropped_crypto;
        out.dropped_source.0 += o.dropped_source.0;
        out.dropped_source.1 += o.dropped_source.1;
        out.dropped_unauthenticated.0 += o.dropped_unauthenticated.0;
        out.dropped_unauthenticated.1 += o.dropped_unauthenticated.1;
        out.seeds.extend(o.seed);
    }
    out
}

/// One slot's worth of [`restore_for`]'s phase B, so the pass can run on
/// a pool. Everything it produces rides home in [`SlotOutcome`] instead
/// of being written into the shared `Restored` as it goes; the body is
/// otherwise the loop that used to be inline, verbatim.
fn restore_slot(
    out_dir: &Path,
    slot: usize,
    rec: &SlotPlacement,
    pre_len: &HashMap<&str, u64>,
    crypto_verdict: &HashMap<(usize, &str), bool>,
    materialize_volumes: bool,
    buf: &mut [u8],
) -> SlotOutcome {
    let mut out = SlotOutcome::default();
    let dest_path = out_dir.join(&rec.name);
    // `None` = no such file before this restore; `Some(n)` = it was n
    // bytes long, the ceiling an identity fragment has to fit under.
    let dest_len = pre_len.get(rec.name.as_str()).copied();
    let mut dest: Option<File> = None; // opened lazily, only for copies
    let mut srcs: HashMap<&str, Option<File>> = HashMap::new();
    // The X5-02 check's own handle cache, hoisted out of
    // `article_authentic` so a slot opens each source ONCE rather than
    // once per article. Separate from `srcs` above: that one is keyed by
    // the journal's copy-source names, this one by where each admitted
    // fragment's bytes physically are now. Local to the slot, so it stays
    // per-worker under the pool.
    let mut auth_open: HashMap<std::sync::Arc<str>, Option<File>> = HashMap::new();
    let mut spans: Vec<(u64, u64)> = Vec::new();
    // Parallel to `spans`, and only when we are NOT materialising:
    // where each span's bytes actually are. `self_name` is the
    // slot's own volume file, shared by every identity and crypto
    // fragment rather than cloned per span (a big resume has
    // thousands).
    let self_name: std::sync::Arc<str> = std::sync::Arc::from(rec.name.as_str());
    let mut sources: Vec<(std::sync::Arc<str>, u64)> = Vec::new();
    let mut span_ids: Vec<std::sync::Arc<str>> = Vec::new();
    let mut src_names: HashMap<&str, std::sync::Arc<str>> = HashMap::new();
    let mut restored_here = false;
    for Article {
        id,
        frags,
        crypto_frag,
        crypto,
        crc,
    } in &rec.articles
    {
        if *crypto && crypto_verdict.get(&(slot, id.as_str())) != Some(&true) {
            // TODO 309(b): counted, not logged here - `nzbkit` is
            // the library and the resume banner lives in the
            // daemon's plan. Its own counter, because "we could not
            // re-encrypt this" and "your partial output moved" are
            // different facts about a user's disk.
            out.dropped_crypto += 1;
            continue;
        }
        let mut all_ok = true;
        // Built per article and only committed with `spans` when the
        // whole article restored, so a half-admitted article leaves
        // neither list holding a span nothing vouches for.
        let mut art_src: Vec<(std::sync::Arc<str>, u64)> = Vec::new();
        for (fi, f) in frags.iter().enumerate() {
            // A crypto article's plaintext-once fragments were
            // written in phase A; only its plain-file fragments (a
            // span straddling into a neighboring unencrypted output)
            // still need the copy below.
            if *crypto && crypto_frag.get(fi).copied().unwrap_or(true) {
                art_src.push((self_name.clone(), f.vol_off));
                continue;
            }
            let identity = f.file == rec.name && f.file_off == f.vol_off;
            if identity {
                // Bytes are already where the resume run expects them -
                // nothing to move, but only if the file predates us AND
                // was long enough to hold the span. A shorter file cannot
                // be holding these bytes, whatever the journal says.
                //
                // LENGTH ALONE admits a FOREIGN file too: when
                // `unquarantine_partials` declined this base name
                // because something else already occupied it, `dest_len`
                // is that stranger's length, not the quarantined
                // payload's. Reachable, and left safe by the crc32
                // check below rather than by anything here - see
                // `identity_against_a_foreign_file_at_the_base_name_still_refuses_on_crc`
                // in journal.rs (claim `restore-for-foreign-identity-fragments`).
                let held = dest_len.is_some_and(|n| f.file_off.saturating_add(f.len) <= n);
                if !held {
                    all_ok = false;
                    break;
                }
                art_src.push((self_name.clone(), f.vol_off));
                continue;
            }
            let src = srcs
                .entry(f.file.as_str())
                .or_insert_with(|| File::open(out_dir.join(&f.file)).ok());
            let Some(src) = src.as_ref() else {
                all_ok = false;
                break;
            };
            if !materialize_volumes {
                // Same admission the copy below performs, without
                // the write: the span has to BE there, or its
                // article must refetch rather than be recorded
                // restored against bytes the replay cannot read.
                let long_enough = src
                    .metadata()
                    .map(|m| f.file_off.saturating_add(f.len) <= m.len())
                    .unwrap_or(false);
                if !long_enough {
                    all_ok = false;
                    break;
                }
                let name = src_names
                    .entry(f.file.as_str())
                    .or_insert_with(|| std::sync::Arc::from(f.file.as_str()));
                art_src.push((name.clone(), f.file_off));
                continue;
            }
            if dest.is_none() {
                dest = std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    // Never truncate - same reason as the encrypt
                    // path above: offset writes into a file that may
                    // already hold earlier records.
                    .truncate(false)
                    .open(&dest_path)
                    .ok()
                    .inspect(|d| {
                        let cur = d.metadata().map(|m| m.len()).unwrap_or(0);
                        if rec.size > cur {
                            let _ = d.set_len(rec.size);
                        }
                    });
            }
            let Some(dest) = dest.as_ref() else {
                all_ok = false;
                break;
            };
            let (mut done, mut ok) = (0u64, true);
            while done < f.len {
                let n = crate::disk::chunk_len(f.len - done, buf.len());
                if crate::disk::read_exact_at(src, &mut buf[..n], f.file_off + done).is_err() {
                    ok = false;
                    break;
                }
                if crate::disk::write_all_at(dest, &buf[..n], f.vol_off + done).is_err() {
                    ok = false;
                    break;
                }
                done += n as u64;
            }
            if !ok {
                all_ok = false;
                break;
            }
            // This is the ONE branch that writes the fragment rather
            // than leaving it where it is, so its bytes are now in
            // the DESTINATION and that is where the X5-02 check must
            // read them. Recorded here so `art_src` stays parallel
            // to `frags` for every fragment shape; `sources` is
            // appended only when `!materialize_volumes`, which is
            // exactly when this branch does not run, so nothing the
            // replay reads changes.
            art_src.push((self_name.clone(), f.vol_off));
        }
        // X5-02: the admission above proves the bytes are REACHABLE
        // - the file opens and is long enough. It does not prove
        // they are the bytes the wire sent, and length was the whole
        // test. Two ways that was wrong, both measured on the tree
        // this fixes: a span whose bytes were replaced at the same
        // length was admitted and shipped, and so was a PREALLOCATED
        // HOLE - full length, no bytes - which needs no adversary at
        // all, being exactly what a crash between the preallocation
        // and the write leaves behind. With no PAR2 behind the job
        // nothing downstream can notice either.
        let mut unauthenticated = false;
        if all_ok && !article_authentic(out_dir, frags, &art_src, *crc, buf, &mut auth_open) {
            all_ok = false;
            unauthenticated = true;
            out.dropped_unauthenticated.0 += 1;
            out.dropped_unauthenticated.1 += frags.iter().map(|f| f.len).sum::<u64>();
        }
        if all_ok {
            out.ids.push(id.clone());
            let id_arc: std::sync::Arc<str> = std::sync::Arc::from(id.as_str());
            for f in frags {
                spans.push((f.vol_off, f.len));
                span_ids.push(id_arc.clone());
            }
            if !materialize_volumes {
                debug_assert_eq!(art_src.len(), frags.len());
                sources.append(&mut art_src);
            }
            restored_here = true;
        } else if !unauthenticated {
            // TODO 309(b): the article had a placement record and
            // this restore refused it, so its bytes go back on the
            // wire. Every `break` above lands here, and all of them
            // are the same fact from the reader's side - the file
            // the bytes were written into does not open, or is no
            // longer long enough to hold the span. Counted whole:
            // an article is admitted only when EVERY fragment is,
            // so a half-readable article refetches entire and the
            // honest figure is all of its fragments.
            //
            // The X5-02 refusal is a DIFFERENT fact - the bytes are
            // there and are not the right bytes - so it has its own
            // counter and is held out here rather than folded in.
            // Same reasoning `dropped_crypto` is kept separate for:
            // the two are answered differently by whoever reads
            // them.
            out.dropped_source.0 += 1;
            out.dropped_source.1 += frags.iter().map(|f| f.len).sum::<u64>();
        }
    }
    if restored_here {
        out.seed = Some(SlotSeed {
            slot,
            name: rec.name.clone(),
            size: rec.size,
            spans,
            sources,
            article_ids: span_ids,
        });
    }
    out
}

/// What one slot's phase B produced, before it is merged into
/// [`Restored`]. Its own type rather than a tuple: five values, three of
/// them pairs of numbers that mean different things, and the merge reads
/// them by name.
#[derive(Default)]
struct SlotOutcome {
    seed: Option<SlotSeed>,
    /// Restored article ids, in the order the slot admitted them.
    ids: Vec<String>,
    dropped_crypto: usize,
    dropped_source: (usize, u64),
    dropped_unauthenticated: (usize, u64),
}

/// Per-worker read buffer for the phase-B re-read. Multiplied by
/// [`RESTORE_MAX_WORKERS`], which is what keeps this pass's transient
/// RSS a fixed 32 MiB rather than one buffer per core.
const RESTORE_BUF: usize = 4 << 20;

/// Lanes for phase B. Eight rather than the backfill's four because this
/// pass has the box to itself - it runs before the pipeline is built, so
/// there are no decoders or connections to take cores from - and because
/// the profile it answers is `pread` latency, which more lanes hide and
/// more cores do not.
const RESTORE_MAX_WORKERS: usize = 8;
