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
        .map(|n| out_dir.join(sanitize_filename(n)))
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
        if name.ends_with(PARTIAL_SUFFIX) || !from.exists() {
            continue;
        }
        let mut to = from.clone().into_os_string();
        to.push(PARTIAL_SUFFIX);
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
    let Ok(rd) = std::fs::read_dir(out_dir) else {
        return back;
    };
    for e in rd.flatten() {
        let p = e.path();
        let Some(n) = p.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(base) = n.strip_suffix(PARTIAL_SUFFIX) else {
            continue;
        };
        if base.is_empty() {
            continue;
        }
        let dest = out_dir.join(base);
        if dest.exists() {
            continue;
        }
        if std::fs::rename(&p, &dest).is_ok() {
            back.push(base.to_string());
        }
    }
    back
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
    let mut buf = vec![0u8; 4 << 20];
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
    for (&slot, rec) in &resume.slots {
        if rec.name.is_empty() {
            continue;
        }
        let dest_path = out_dir.join(&rec.name);
        // `None` = no such file before this restore; `Some(n)` = it was n
        // bytes long, the ceiling an identity fragment has to fit under.
        let dest_len = pre_len.get(rec.name.as_str()).copied();
        let mut dest: Option<File> = None; // opened lazily, only for copies
        let mut srcs: HashMap<&str, Option<File>> = HashMap::new();
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
        } in &rec.articles
        {
            if *crypto && crypto_verdict.get(&(slot, id.as_str())) != Some(&true) {
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
            }
            if all_ok {
                out.ids.insert(id.clone());
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
            }
        }
        if restored_here {
            out.seeds.push(SlotSeed {
                slot,
                name: rec.name.clone(),
                size: rec.size,
                spans,
                sources,
                article_ids: span_ids,
            });
        }
    }
    out
}
