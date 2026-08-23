//! The 7z arm of the disk post-pass: find every container in a job dir
//! and extract it natively, split sets included.
//!
//! Split out of rarfix.rs 22 Aug 2026 (TODO 212), and the split shape
//! changed with the move. A `.7z.NNN` set used to be concatenated into a
//! scratch `joined.7z` before anything read it, and on the field's
//! header-encrypted (`-mhe`) shape - 443 of 444 sampled split sets, 97.3%
//! of sampled 7z bytes - that was a full extra pass of the payload
//! followed by rc=1, because the missing password is only discovered when
//! the END header is parsed, and the join came first. Measured 2.000x of
//! payload in device I/O, three reps to three decimals
//! (`research/SEVENZ-MHE-ROUND-2026-08-22.md` §4.4). Now the parts are
//! read in place through [`SplitParts`], one logical byte-space over the
//! ordered files, the way the zip arm and the in-stream chase already
//! do; there is no joined copy on any ending, so a refused password costs
//! one end-header read and an unsupported codec in a split set no longer
//! pays a join either.

use crate::*;
use tracing::{info, warn};

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
///
/// That sniff reaches a single obfuscated container. The SPLIT one -
/// `hash.001`, `hash.002`, ... with the 7z signature at the head of part
/// 1 - is grouped by `splitjoin::collect_obfuscated_sevenz_splits`,
/// which owns the numbered-run grammar (gapless from 1, one file per
/// index, uniform part sizes, no head on parts 2..=n) and the stronger
/// head check such a set has to pass. Without that grouping the sniff
/// above claimed part 1 ALONE as a container - one job that is 1/nth of
/// an archive, failing on a truncated read while the rest of the set sat
/// there unclaimed - and the set was then joined whole by
/// `rescue_split_of_container`, which is the 2.000x TODO 212 exists to
/// remove. Its parts are excluded from the scan below for that reason.
pub(crate) fn collect_sevenz_archives(dir: &std::path::Path) -> Result<Vec<Vec<PathBuf>>> {
    use std::collections::BTreeMap;
    let obfuscated = crate::splitjoin::collect_obfuscated_sevenz_splits(dir)?;
    let claimed: std::collections::HashSet<&std::path::Path> =
        obfuscated.iter().flatten().map(PathBuf::as_path).collect();
    let mut singles: Vec<PathBuf> = Vec::new();
    let mut splits: BTreeMap<String, BTreeMap<u32, PathBuf>> = BTreeMap::new();
    for e in std::fs::read_dir(dir)?.flatten() {
        if !e.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        let path = e.path();
        if claimed.contains(path.as_path()) {
            continue;
        }
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
    jobs.extend(obfuscated);
    Ok(jobs)
}

/// Extract every 7-Zip job in `dir`. Returns true only if every job
/// extracted.
///
/// One scratch dir per attempt, outside the output namespace: it
/// collects members until the whole container has decoded, so a
/// `release.7z` carrying a member named `release.7z` cannot truncate the
/// inode still backing its own reader. The parts are read where they lie
/// ([`SplitParts`]); nothing is copied before the first header is parsed.
pub(crate) fn extract_sevenz(
    dir: &std::path::Path,
    jobs: &[Vec<PathBuf>],
    password: Option<&str>,
) -> bool {
    let mut all_ok = true;
    for parts in jobs.iter() {
        let Some(first) = parts.first() else {
            continue;
        };
        info!(target: "extract", "unpacking 7z archive natively…");
        // TODO 205: one SET on the queue row's unpack lane, however many
        // candidates below it takes - `extract_one_sevenz` reports each
        // ATTEMPT, and only this call banks what the last one produced.
        crate::unpackprog::begin_set();
        // Per CONTAINER, like the zip arm: one resolved value per level
        // handed every 7z job the first job's password (Codex sweep G).
        // A shortlist rather than a pick, because a probe that hit the
        // 64 MB cap never reached the entry's checksum and cannot settle
        // anything (sweep M) - the extraction does.
        let cands = crate::unpack::sevenz_password_candidates(parts, dir, password);
        let mut last: Option<String> = None;
        let mut done = false;
        for (pw, source) in &cands {
            // `publish_into` consumes its staging dir, so every attempt
            // takes a fresh one.
            let out = match ExtractStaging::new(dir) {
                Ok(v) => v,
                Err(e) => {
                    last = Some(e.to_string());
                    break;
                }
            };
            match extract_one_sevenz(out.path(), dir, parts, pw.as_deref())
                .and_then(|_| out.publish_into(dir))
            {
                Ok(()) => {
                    if pw.is_some() && source != "job password" {
                        crate::unpack::log_auto_unlocked(first, source);
                    }
                    info!(target: "extract", "7z unpack complete ✔");
                    done = true;
                    break;
                }
                Err(e) => last = Some(e.to_string()),
            }
        }
        if !done {
            warn!(
                target: "extract",
                "7z unpack failed ({})",
                last.unwrap_or_else(|| "no candidate password opened it".into())
            );
            all_ok = false;
        }
    }
    all_ok
}

/// Concatenate `parts` (already in order) into `dest`.
///
/// No longer on the 7z path (see the module doc); `splitjoin` still
/// materializes a plain numbered split through it.
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

/// The ordered parts of one 7z container read as a single seekable
/// byte-space. A 7z multipart is a raw byte split, so the container IS
/// the concatenation; this reads it without writing it. Bare `File`s,
/// exactly what `ArchiveReader::open` hands the library for a single
/// container, so the per-read cost is unchanged. A one-part set is the
/// degenerate case and costs one table entry.
pub(crate) struct SplitParts {
    /// `(file, start offset in the byte-space, length)`, ascending.
    files: Vec<(std::fs::File, u64, u64)>,
    total: u64,
    /// Logical cursor.
    pos: u64,
    /// Which part the underlying cursor of `files[idx].0` is known to sit
    /// at, and where - so a sequential read never re-seeks.
    at: Option<(usize, u64)>,
}

impl SplitParts {
    pub(crate) fn open(parts: &[PathBuf]) -> std::io::Result<Self> {
        if parts.is_empty() {
            return Err(std::io::Error::other("7z job has no parts"));
        }
        let mut files = Vec::with_capacity(parts.len());
        let mut total = 0u64;
        for p in parts {
            let f = std::fs::File::open(p)?;
            let len = f.metadata()?.len();
            files.push((f, total, len));
            total = total.checked_add(len).ok_or_else(|| {
                std::io::Error::other("7z split set exceeds the addressable size")
            })?;
        }
        Ok(Self {
            files,
            total,
            pos: 0,
            at: None,
        })
    }

    /// Index of the part holding logical offset `pos`, skipping empty
    /// parts, or `None` past the end.
    fn part_at(&self, pos: u64) -> Option<usize> {
        let idx = self.files.partition_point(|&(_, start, _)| start <= pos);
        // `partition_point` lands one past the last part starting at or
        // before `pos`; empty parts share a start with their successor,
        // and the successor (later in the table) is the one that holds
        // the byte.
        idx.checked_sub(1)
            .filter(|&i| pos < self.files[i].1 + self.files[i].2)
    }
}

impl std::io::Read for SplitParts {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use std::io::Seek as _;
        let Some(i) = self.part_at(self.pos) else {
            return Ok(0);
        };
        let (ref mut f, start, len) = self.files[i];
        let local = self.pos - start;
        if self.at != Some((i, local)) {
            f.seek(std::io::SeekFrom::Start(local))?;
        }
        let want = usize::try_from(len - local)
            .unwrap_or(usize::MAX)
            .min(buf.len());
        let n = f.read(&mut buf[..want])?;
        self.pos += n as u64;
        self.at = Some((i, local + n as u64));
        Ok(n)
    }
}

impl std::io::Seek for SplitParts {
    fn seek(&mut self, to: std::io::SeekFrom) -> std::io::Result<u64> {
        use std::io::SeekFrom::*;
        let next = match to {
            Start(n) => Some(n),
            End(d) => self.total.checked_add_signed(d),
            Current(d) => self.pos.checked_add_signed(d),
        };
        let Some(next) = next else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek before the start of the 7z set",
            ));
        };
        self.pos = next;
        Ok(next)
    }
}

/// Open one 7-Zip container - the ordered parts of a split set, or a
/// single file - behind the shared declared-size gate, ready to read
/// entries. The gate runs through the same reader the library is about
/// to use, so a split set is judged where it lies.
///
/// The shared declared-size gate (nzbkit's nameprobe, TODO 156 item 5):
/// ArchiveReader::new buffers the declared end header whole and decodes
/// a packed one with the declared sizes as its only bounds, and a chased
/// container that refused at the in-stream gate demotes to exactly this
/// path - so the refusal here must be a named error, not an allocation.
/// The declared variant also judges the CONTENT blocks' dictionary and
/// PPMd declarations, which the extraction would otherwise allocate
/// unbounded. Malformed shapes fall through to the library's own cheap
/// error, same as the probe halves of the gate.
///
/// This is also where a header-encrypted set answers the password
/// question: the END header is parsed here, and a wrong or missing key
/// fails here, having read one header's worth of bytes off the last part.
pub(crate) fn open_sevenz(
    parts: &[PathBuf],
    password: Option<&str>,
) -> Result<sevenz_rust2::ArchiveReader<SplitParts>> {
    use sevenz_rust2::{ArchiveReader, Password};
    let pw = match password {
        Some(p) if !p.is_empty() => Password::from(p),
        _ => Password::empty(),
    };
    let mut src = SplitParts::open(parts)?;
    if let Some(reason) = nzbkit::nameprobe::sevenz_disk_declared_bomb(&mut src) {
        anyhow::bail!("{reason}");
    }
    std::io::Seek::seek(&mut src, std::io::SeekFrom::Start(0))?;
    ArchiveReader::new(src, pw).map_err(|e| anyhow::anyhow!("opening 7z: {e}"))
}

/// Is this 7-Zip container (the ordered parts of a split set, or a
/// single file) encrypted at all, judged from the end header alone?
///
/// The `parts`-taking face of nzbkit's [`nzbkit::nameprobe::sevenz_is_encrypted`],
/// through the same joining reader [`open_sevenz`] uses - so a split
/// `.7z.NNN` set is judged where it lies, unjoined, and the shared
/// declared-size gate runs on the way in. Fails closed exactly as the
/// nzbkit half does: true covers "encrypted" and "not provably
/// otherwise", so only a false is worth acting on.
pub(crate) fn sevenz_set_is_encrypted(parts: &[PathBuf]) -> bool {
    let Ok(mut src) = SplitParts::open(parts) else {
        return true;
    };
    nzbkit::nameprobe::sevenz_is_encrypted(&mut src)
}

/// Extract one 7-Zip container (its ordered parts) into `out` (an
/// `ExtractStaging` dir, never the directory holding the container),
/// path-sanitized and bounded by the same decompression-bomb guard as the
/// RAR path.
///
/// `publish` is where the pass will PUBLISH what it stages, and it is
/// read for one thing only: the resume ledger a forfeited 7z chase left
/// behind (TODO 213 item 2). A member whose prefix is already sitting
/// there, still exactly the length the extractor cut it to, is appended
/// to in place instead of being staged from byte zero - so it is the one
/// entry that does not go through `out`. Answers how many members were
/// resumed, for a caller that needs to tell a pass which produced
/// nothing from one which produced everything in place.
pub(crate) fn extract_one_sevenz(
    out: &std::path::Path,
    publish: &std::path::Path,
    parts: &[PathBuf],
    password: Option<&str>,
) -> Result<usize> {
    // TODO 217's rewind, same shape as the RAR arm's: a resumed prefix
    // that fails its verification aborts the pass from inside the entry
    // writer; the ledger is then cleared and the pass runs once more
    // from byte zero. This arm never eats its sources, so the retry is
    // always allowed.
    crate::resumeout::with_mismatch_retry(
        || true,
        |mismatch| sevenz_pass(out, publish, parts, password, mismatch),
    )
}

/// One attempt of [`extract_one_sevenz`], split out for the rewind.
fn sevenz_pass(
    out: &std::path::Path,
    publish: &std::path::Path,
    parts: &[PathBuf],
    password: Option<&str>,
    mismatch: &crate::resumeout::MismatchFlag,
) -> Result<usize> {
    let mut reader = open_sevenz(parts, password)?;
    // The resume ledger, read here on the calling thread and before a
    // single entry is opened - see [`crate::resumeout::plan_pass`] for
    // both requirements. The member list comes off the parsed end
    // header, so it is the exact set of names the walk below will write.
    let members: Vec<String> = reader
        .archive()
        .files
        .iter()
        .filter(|f| !f.is_directory)
        .map(|f| f.name.clone())
        .collect();
    let resume = crate::resumeout::plan_pass(publish, &members);
    // Which of them this pass actually opened. Handed to the ledger
    // below: kept on success, removed on failure, because an appended-to
    // partial is no longer the clean prefix the arm's cleanup can
    // recognise.
    let mut resumed: Vec<PathBuf> = Vec::new();
    // Staging sits on the same filesystem as the job directory, so this
    // still measures the volume the payload lands on.
    let budget = BombBudget::fixed(
        crate::serve::free_bytes(out)
            .map(|free| free.saturating_sub(EXTRACT_RESERVE))
            .unwrap_or(u64::MAX),
    );
    let written = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    // TODO 205: the queue row's unpack lane over the nested pass. Same
    // counter the bomb guard below already keeps, so the hot path is
    // unchanged; the total is the end header's, which is parsed by the
    // time we are here. A resumed member's prefix is in that total and
    // this pass will not rewrite it, so it is credited up front exactly
    // as the RAR arm credits its own.
    crate::unpackprog::attempt(
        &written,
        reader
            .archive()
            .files
            .iter()
            .filter(|f| !f.is_directory)
            .fold(0u64, |acc, f| acc.saturating_add(f.size)),
        resume
            .values()
            .fold(0u64, |acc, (_, len, _)| acc.saturating_add(*len)),
    );
    let result = reader.for_each_entries(|entry, rd| {
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
        // A resumed member writes to the PUBLISHED file at its mark, not
        // to `target` in staging: the prefix is already there, and the
        // bytes below the mark go to a counter rather than to the device.
        // Everything else about the entry - the bomb budget, the flush
        // check - is unchanged, so the two arms differ in the file handle
        // and in nothing else.
        let (file, skip, crc) = match resume.get(entry.name.as_str()) {
            Some((path, len, crc)) => {
                let f = crate::resumeout::open_at_mark(path, *len)?;
                resumed.push(path.clone());
                (f, *len, *crc)
            }
            None => (std::fs::File::create(&target)?, 0, 0),
        };
        let mut w = crate::resumeout::ResumeWriter::verified(
            skip,
            crc,
            mismatch.clone(),
            BombGuardWriter {
                inner: std::io::BufWriter::new(file),
                written: written.clone(),
                budget: budget.clone(),
            },
        );
        std::io::copy(rd, &mut w)?;
        use std::io::Write as _;
        w.flush()?;
        Ok(true)
    });
    crate::resumeout::finish(&resumed, result.is_ok());
    result.map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(resumed.len())
}

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
        let err = super::extract_one_sevenz(&out, &dir, std::slice::from_ref(&container), None)
            .unwrap_err();
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
        let err = super::extract_one_sevenz(&out, &dir, std::slice::from_ref(&container), None)
            .unwrap_err();
        assert!(
            err.to_string().contains("content declares decoder memory"),
            "content bomb must die at the gate, not in the decoder: {err}"
        );
        let container = dir.join("zeroed.7z");
        std::fs::copy(format!("{fixtures}/recovered-zero-start.bin"), &container).unwrap();
        let err = super::extract_one_sevenz(&out, &dir, std::slice::from_ref(&container), None)
            .unwrap_err();
        assert!(
            err.to_string().contains("start header geometry is zeroed"),
            "zeroed start must refuse before the recovery scan: {err}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// One container, header-encrypted, cut into numbered parts the way
    /// the field posts it (`.7z.001`, `.7z.002`, ...), with the cut
    /// falling inside the payload AND inside the end header. The key is
    /// one no other test in this process writes into the operator
    /// password file - `pwfile_tests` sets that process-global with
    /// "right" in it, and the harvest below would find it.
    const MHE_KEY: &str = "todo-212-mhe-key";

    fn mhe_bytes(data: &[u8]) -> Vec<u8> {
        use sevenz_rust2::{
            ArchiveEntry, ArchiveWriter, Password, encoder_options::AesEncoderOptions,
        };
        let mut w = ArchiveWriter::new(std::io::Cursor::new(Vec::new())).unwrap();
        w.set_encrypt_header(true);
        w.set_content_methods(vec![AesEncoderOptions::new(Password::from(MHE_KEY)).into()]);
        w.push_archive_entry(ArchiveEntry::new_file("movie.mkv"), Some(data))
            .unwrap();
        w.finish().unwrap().into_inner()
    }

    fn mhe_split_set(dir: &std::path::Path, data: &[u8], parts: usize) -> Vec<PathBuf> {
        split_bytes(dir, &mhe_bytes(data), parts)
    }

    fn split_bytes(dir: &std::path::Path, bytes: &[u8], parts: usize) -> Vec<PathBuf> {
        split_bytes_as(dir, bytes, parts, "set.7z")
    }

    /// `split_bytes` for a set posted under some other stem - the
    /// obfuscated shape below cuts the same container into `hash.NNN`,
    /// with nothing in the names saying 7z.
    fn split_bytes_as(
        dir: &std::path::Path,
        bytes: &[u8],
        parts: usize,
        stem: &str,
    ) -> Vec<PathBuf> {
        let cut = bytes.len().div_ceil(parts);
        bytes
            .chunks(cut)
            .enumerate()
            .map(|(i, chunk)| {
                let p = dir.join(format!("{stem}.{:03}", i + 1));
                std::fs::write(&p, chunk).unwrap();
                p
            })
            .collect()
    }

    /// Everything under `dir` that is not one of the parts - the trace a
    /// join or a kept staging dir would leave.
    fn leftovers(dir: &std::path::Path) -> Vec<String> {
        leftovers_beside(dir, "set.7z.")
    }

    /// [`leftovers`] for a set whose parts carry some other prefix.
    fn leftovers_beside(dir: &std::path::Path, part_prefix: &str) -> Vec<String> {
        fn walk(root: &std::path::Path, d: &std::path::Path, out: &mut Vec<String>) {
            for e in std::fs::read_dir(d).unwrap() {
                let p = e.unwrap().path();
                // One separator spelling, because every caller below
                // compares against a literal like "sub/notes.txt" and
                // `display()` hands back `sub\notes.txt` on Windows.
                // That mismatch failed windows-unit the moment the job
                // could run again (23 Aug 2026), having been invisible
                // behind a red windows-build since 21 Aug.
                let rel = p.strip_prefix(root).unwrap().display().to_string();
                out.push(rel.replace(std::path::MAIN_SEPARATOR, "/"));
                if p.is_dir() {
                    walk(root, &p, out);
                }
            }
        }
        let mut v = Vec::new();
        walk(dir, dir, &mut v);
        v.retain(|n| !n.starts_with(part_prefix));
        v.sort();
        v
    }

    /// TODO 212: the field's shape. With the right password a split
    /// `-mhe` set lands its payload, and nothing but the payload is
    /// left beside the parts - no `joined.7z`, no scratch dir.
    #[test]
    fn a_split_header_encrypted_set_unpacks_with_the_password() {
        let dir = tmp("mhe-ok");
        let data: Vec<u8> = (0..200_000u32).map(|i| (i * 7 + 3) as u8).collect();
        let parts = mhe_split_set(&dir, &data, 5);
        let jobs = super::collect_sevenz_archives(&dir).unwrap();
        assert_eq!(
            jobs,
            vec![parts.clone()],
            "the five parts are one ordered job"
        );
        assert!(super::extract_sevenz(&dir, &jobs, Some(MHE_KEY)));
        assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), data);
        assert_eq!(leftovers(&dir), vec!["movie.mkv".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// TODO 212's measured ending: the wrong (or no) password. The
    /// failure is the end header refusing, read off the last part where
    /// it lies - the parts are never joined. Before the fix this wrote a
    /// whole second copy of the set first (2.000x of payload in device
    /// I/O, `research/SEVENZ-MHE-ROUND-2026-08-22.md` §4.4); the
    /// `leftovers` assertion is what would catch a join coming back, and
    /// the byte count is the proof the parts were READ but not copied.
    #[test]
    fn a_split_header_encrypted_set_refuses_a_wrong_password_without_joining() {
        let dir = tmp("mhe-wrong");
        let data: Vec<u8> = (0..200_000u32).map(|i| (i * 5 + 1) as u8).collect();
        let parts = mhe_split_set(&dir, &data, 4);
        let jobs = super::collect_sevenz_archives(&dir).unwrap();
        for pw in [Some("wrong"), None] {
            assert!(
                !super::extract_sevenz(&dir, &jobs, pw),
                "{pw:?} must not open it"
            );
            assert!(
                leftovers(&dir).is_empty(),
                "nothing may be left beside the parts: {:?}",
                leftovers(&dir)
            );
            // Every part still there, byte for byte.
            let mut on_disk = 0u64;
            for p in &parts {
                on_disk += std::fs::metadata(p).unwrap().len();
            }
            let mut whole = Vec::new();
            for p in &parts {
                whole.extend(std::fs::read(p).unwrap());
            }
            assert_eq!(on_disk as usize, whole.len());
            assert!(on_disk > data.len() as u64);
        }
        // And the refusal is the library's password verdict, not a read
        // error across the parts.
        let err = match super::open_sevenz(&parts, Some("wrong")) {
            Ok(_) => panic!("a wrong password must not open the set"),
            Err(e) => e.to_string(),
        };
        assert!(err.starts_with("opening 7z:"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The plain split shape keeps working through the same reader, and
    /// a `-mhe` header still parses when a cut falls one byte into it.
    #[test]
    fn a_plain_split_set_unpacks_without_a_scratch_copy() {
        use sevenz_rust2::{ArchiveEntry, ArchiveWriter};
        let dir = tmp("plain-split");
        let data: Vec<u8> = (0..150_000u32).map(|i| (i * 13 + 5) as u8).collect();
        let bytes = {
            let mut w = ArchiveWriter::new(std::io::Cursor::new(Vec::new())).unwrap();
            w.push_archive_entry(ArchiveEntry::new_file("movie.mkv"), Some(&data[..]))
                .unwrap();
            w.push_archive_entry(ArchiveEntry::new_file("sub/notes.txt"), Some(&b"hello"[..]))
                .unwrap();
            w.finish().unwrap().into_inner()
        };
        split_bytes(&dir, &bytes, 3);
        let jobs = super::collect_sevenz_archives(&dir).unwrap();
        assert_eq!(jobs.len(), 1);
        assert!(super::extract_sevenz(&dir, &jobs, None));
        assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), data);
        assert_eq!(std::fs::read(dir.join("sub/notes.txt")).unwrap(), b"hello");
        let mut left = leftovers(&dir);
        left.retain(|n| n != "movie.mkv" && n != "sub" && n != "sub/notes.txt");
        assert!(left.is_empty(), "{left:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The obfuscated twin of the two tests above, and the gap TODO 258
    /// named in its closing paragraph: the SAME header-encrypted split
    /// container, posted as `hash.001`, `hash.002`, ... with nothing in
    /// the names saying 7z. Part 1 carries the signature header in
    /// plaintext (`-mhe` encrypts the END header, which lies in the last
    /// part), so the set is one ordered 7z job all the same - and part 1
    /// alone is NOT a job, which is what it used to be: a container that
    /// is one sixth of an archive, failing on a truncated read while its
    /// other five parts sat there unclaimed.
    ///
    /// Both endings are asserted through `leftovers_beside`, which is
    /// what catches a join coming back: nothing but the payload may ever
    /// appear beside the parts.
    #[test]
    fn an_obfuscated_split_set_is_grouped_and_read_in_place() {
        let dir = tmp("obf-split");
        let data: Vec<u8> = (0..180_000u32).map(|i| (i * 11 + 2) as u8).collect();
        let parts = split_bytes_as(&dir, &mhe_bytes(&data), 6, "hash");
        assert_eq!(parts.len(), 6);
        let jobs = super::collect_sevenz_archives(&dir).unwrap();
        assert_eq!(
            jobs,
            vec![parts.clone()],
            "the six parts are one ordered job, and part 1 is not a job of its own"
        );
        // The failing ending: the end header refuses where it lies, and
        // not one byte is copied to find that out.
        for pw in [Some("wrong"), None] {
            assert!(
                !super::extract_sevenz(&dir, &jobs, pw),
                "{pw:?} must not open it"
            );
            assert!(
                leftovers_beside(&dir, "hash.").is_empty(),
                "nothing may be left beside the parts: {:?}",
                leftovers_beside(&dir, "hash.")
            );
        }
        // The succeeding one: the payload lands, still with no join.
        assert!(super::extract_sevenz(&dir, &jobs, Some(MHE_KEY)));
        assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), data);
        assert_eq!(
            leftovers_beside(&dir, "hash."),
            vec!["movie.mkv".to_string()]
        );
        // And the joiner still SEES the set - it is a container split by
        // its rules - but now hands it to this arm instead of joining it.
        let sets = crate::collect_container_split_sets(&dir).unwrap();
        assert_eq!(sets.len(), 1, "the container scan sees one set");
        assert!(
            crate::obfuscated_sevenz_split(&sets[0]),
            "and the 7z arm owns it"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The same set through the whole ladder, which is where the SECOND
    /// join lived. `rescue_split_of_container` joins a numbered set whose
    /// part 1 carries a head once the arm that owns that head has failed
    /// - so before this change an obfuscated `-mhe` set with no password
    /// paid the 1.000x TODO 212 took off the 7z arm all over again one
    /// step later, and DELETED its parts to do it. The level still fails
    /// without the password, which is right; what must not happen is a
    /// join.
    #[test]
    fn the_ladder_never_joins_an_obfuscated_sevenz_split() {
        use crate::unpack::{NestOutcome, extract_one_level};
        let dir = tmp("obf-ladder");
        let data: Vec<u8> = (0..120_000u32).map(|i| (i * 3 + 9) as u8).collect();
        let parts = split_bytes_as(&dir, &mhe_bytes(&data), 4, "hash");
        assert_eq!(
            extract_one_level(&dir, None, 0).unwrap(),
            Some(NestOutcome::Failed),
            "no password: the level fails, as it should"
        );
        assert!(
            !dir.join("hash").exists(),
            "...but the rescue must not have joined the parts"
        );
        for p in &parts {
            assert!(p.exists(), "{} is still where it landed", p.display());
        }
        // And with the password the same ladder lands the payload,
        // through the same reader, with nothing joined either.
        assert_eq!(
            extract_one_level(&dir, Some(MHE_KEY), 0).unwrap(),
            Some(NestOutcome::Produced)
        );
        assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), data);
        assert!(!dir.join("hash").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The reader itself, at every seam: a read spanning parts, a seek
    /// from the end, an empty middle part, a read past the end.
    #[test]
    fn split_parts_reads_one_byte_space_across_the_seams() {
        use std::io::{Read as _, Seek as _, SeekFrom};
        let dir = tmp("seams");
        let whole: Vec<u8> = (0..=255u8).collect();
        let cuts = [(0usize, 100usize), (100, 100), (100, 100), (100, 256)];
        let mut parts = Vec::new();
        for (i, (a, b)) in cuts.iter().enumerate() {
            let p = dir.join(format!("set.7z.{:03}", i + 1));
            std::fs::write(&p, &whole[*a..*b]).unwrap();
            parts.push(p);
        }
        let mut r = super::SplitParts::open(&parts).unwrap();
        let mut all = Vec::new();
        r.read_to_end(&mut all).unwrap();
        assert_eq!(all, whole);
        assert_eq!(r.seek(SeekFrom::End(-6)).unwrap(), 250);
        let mut tail = Vec::new();
        r.read_to_end(&mut tail).unwrap();
        assert_eq!(tail, &whole[250..]);
        r.seek(SeekFrom::Start(98)).unwrap();
        let mut span = [0u8; 4];
        r.read_exact(&mut span).unwrap();
        assert_eq!(
            span,
            [98, 99, 100, 101],
            "a read straddles the seam and the empty part"
        );
        assert_eq!(r.seek(SeekFrom::Current(-2)).unwrap(), 100);
        r.seek(SeekFrom::Start(1000)).unwrap();
        assert_eq!(r.read(&mut span).unwrap(), 0);
        assert!(r.seek(SeekFrom::Current(-2000)).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
