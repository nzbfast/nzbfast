//! The tar arm of the disk post-pass: find every `.tar` container a job
//! directory is left holding and unpack it where it lies.
//!
//! The disk half of TODO 163 item 6. The in-stream half landed first,
//! in 8d0278615 (`nzbkit::tar` for the format, `nzbkit::extract::tar`
//! for the chase), and left this one explicitly owed: until it was
//! built, a `.tar` that reached the output directory stayed packed and
//! the job reported Completed. Three roads put one there, and none of
//! them is a fault:
//!
//! - a top-level or nested chase that DEMOTED (the bomb guard, a member
//!   the reader refuses, the held-bytes cap),
//! - a resumed run, which disables extraction wholesale and never
//!   chases at all,
//! - `NZBFAST_NO_TAR=1`, which is the chase's kill switch and not this
//!   arm's: turning the chase off routes a tar HERE, which is exactly
//!   what the switch has always claimed to do.
//!
//! # The reader is the one in nzbkit, unchanged
//!
//! `nzbkit::tar::Reader` is a plain `io::Read` consumer with no `Seek`
//! and no random access, so driving it over a `std::fs::File` needs no
//! new code and, more to the point, no second copy of the tar grammar.
//! Every refusal the chase makes is therefore made here by the same
//! lines: symlinks, hard links, devices and FIFOs (a member that is a
//! reference rather than bytes), GNU sparse in both its spellings, a
//! member whose data runs past the container, a member cut short inside
//! its data, and a container that ends between two members rather than
//! on its end-of-archive block. Two more are this side's own, shared
//! with the zip and 7z arms: an entry name that escapes the output
//! directory, and the decompression-bomb budget.
//!
//! A refusal condemns the WHOLE container, never half of it. Staging is
//! discarded, the `.tar` is left exactly as it arrived, and the arm
//! reports the container to `extract_one_level_at` as REFUSED so the
//! spent-intermediate sweep cannot mistake it for a container this level
//! consumed and delete it.
//!
//! # Why a refusal does not fail the job
//!
//! This is the one disk arm that declines rather than fails, and the
//! reason is what the three roads above have in common: before this arm
//! existed, EVERY tar that reached a job directory left it exactly like
//! this, with the job Completed. Turning that into rc=1 would be a
//! regression introduced by adding an extractor, on the commonest real
//! tar shape there is (a source tarball carrying a symlink), and it
//! would hand an *arr a blocklist verdict on a download that arrived
//! whole. What the user is left with is a standard container every
//! operating system ships a tool for, named in a warning that carries
//! the reason. So the arm claims `Produced`, the identity of the ladder's
//! `and` lattice: it cannot mask another arm's failure and it does not
//! invent one of its own. The obfuscated-RAR arm claims the same value
//! for the same reason on its own forgiven casualty.
//!
//! That covers the bomb guard's verdict too, which is the one refusal
//! here that is about the DISK rather than the archive, and it is
//! easier to accept for a tar than it would be for any other container:
//! tar stores its members uncompressed, so the bytes the user is left
//! holding are the SAME bytes either way, and the container costs no
//! more space on the volume that just ran out than the payload would
//! have. Failing the job would send an *arr to re-grab a release that
//! will meet the same full disk on the way back.

use crate::*;
use tracing::{info, warn};

/// Is this file a tar container the disk pass owns?
///
/// The name gate is `nzbkit::tar::chase_eligible_name`, the chase's own:
/// `.tar` or no extension at all (the obfuscated post). It is the
/// narrowest of the four container predicates in this tree, and that is
/// what keeps this out of the trouble widening a magic sniff causes -
/// a named payload file cannot reach the sniff below at all, so there is
/// no `.cbr`/`.cb7`-shaped hazard to guard against separately.
///
/// The sniff itself is over a WHOLE header block, so
/// `looks_like_tar` verifies the header checksum rather than trusting
/// the six magic bytes alone. Nothing else in a job directory can pass
/// it: RAR, 7z, zip and PAR2 all announce themselves at offset 0, and
/// this magic sits 257 bytes in.
pub(crate) fn is_tar_container(path: &std::path::Path) -> bool {
    use std::io::Read as _;
    let Some(name) = path.file_name() else {
        return false;
    };
    if !nzbkit::tar::chase_eligible_name(&name.to_string_lossy()) {
        return false;
    }
    // One header block plus the end-of-archive marker is the smallest
    // thing that can be a tar at all - the chase's own floor.
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() || meta.len() < (nzbkit::tar::BLOCK * 3) as u64 {
        return false;
    }
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut head = [0u8; nzbkit::tar::BLOCK];
    let mut done = 0usize;
    while done < head.len() {
        match f.read(&mut head[done..]) {
            Ok(0) => break,
            Ok(n) => done += n,
            Err(_) => return false,
        }
    }
    nzbkit::tar::looks_like_tar(&head[..done])
}

/// Every tar container sitting directly in `dir`, in name order.
pub(crate) fn collect_tar_containers(dir: &std::path::Path) -> Result<Vec<PathBuf>> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)?
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.path())
        .filter(|p| is_tar_container(p))
        .collect();
    out.sort();
    Ok(out)
}

/// The first tar container in `dir`, for the nested-prevalence line.
pub(crate) fn first_tar_container(dir: &std::path::Path) -> Option<PathBuf> {
    collect_tar_containers(dir).ok()?.into_iter().next()
}

/// Unpack every tar container in `jobs`. Answers the containers it
/// DECLINED, which the caller records as refused so the
/// spent-intermediate sweep leaves them alone.
///
/// No password anywhere on this path: tar carries no encryption, so
/// there is no candidate shortlist to walk and no per-container
/// resolution to get wrong.
pub(crate) fn extract_tar(dir: &std::path::Path, jobs: &[PathBuf]) -> Vec<PathBuf> {
    let mut declined = Vec::new();
    for container in jobs {
        let name = container
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        info!(target: "extract", "unpacking {name} natively…");
        // TODO 205: one SET on the queue row's unpack lane per container.
        crate::unpackprog::begin_set();
        let out = match ExtractStaging::new(dir) {
            Ok(v) => v,
            Err(e) => {
                warn!(target: "extract", "{name} could not be unpacked ({e})");
                declined.push(container.clone());
                continue;
            }
        };
        match extract_one_tar(out.path(), dir, container).and_then(|()| out.publish_into(dir)) {
            Ok(()) => info!(target: "extract", "tar unpack complete ✔"),
            Err(e) => {
                warn!(
                    target: "extract",
                    "{name} could not be unpacked ({e}) - the container is left in the \
                     output directory exactly as it arrived; unpack it with your own tool"
                );
                declined.push(container.clone());
            }
        }
    }
    declined
}

/// Extract one tar container into `out`, an `ExtractStaging` dir and
/// never the directory holding the container itself.
///
/// `publish` is where the pass will PUBLISH what it stages, and it is
/// read for one thing only: the resume ledger a forfeited chase left
/// behind (TODO 213 item 2). A tar chase forfeits through the same
/// `sevenz_teardown_sinks` the 7z and zip chases do, so it can leave a
/// member's contiguous prefix on disk, and this arm has to consume that
/// ledger whether or not it wants the saving - `clear_unresumed` is what
/// removes a partial sitting under a member's own name, and the publish
/// step disambiguates rather than overwrites, so a partial left there
/// would shunt the real member out to a second name beside it.
fn extract_one_tar(
    out: &std::path::Path,
    publish: &std::path::Path,
    container: &std::path::Path,
) -> Result<()> {
    // TODO 217's rewind, same shape as the RAR arm's: a mismatched
    // resumed prefix clears the ledger and the pass runs once more from
    // byte zero. This arm never eats its sources.
    crate::resumeout::with_mismatch_retry(
        || true,
        |mismatch| tar_pass(out, publish, container, mismatch),
    )
}

/// One attempt of [`extract_one_tar`], split out for the rewind.
fn tar_pass(
    out: &std::path::Path,
    publish: &std::path::Path,
    container: &std::path::Path,
    mismatch: &crate::resumeout::MismatchFlag,
) -> Result<()> {
    use std::io::Write as _;
    let file = std::fs::File::open(container)?;
    let total = file.metadata()?.len();
    // The member list `plan_pass` needs costs one extra sequential read
    // of the container, because the reader skips a member's data by
    // READING it - there is no seek on this path by construction. So it
    // is taken only when there is a ledger to plan against, which is the
    // held-bytes-cap forfeit and nothing else: every ordinary unpack
    // (the gate off, a resumed run, a refused member, a tar nobody ever
    // chased) sees an empty arm here and skips the walk entirely. On the
    // forfeit itself the extra read buys back a full write of everything
    // the chase had already decoded, which is the trade TODO 213 exists
    // to make.
    let resume = if crate::resumeout::plan(publish).is_empty() {
        std::collections::HashMap::new()
    } else {
        let members = tar_member_names(container, total)?;
        crate::resumeout::plan_pass(publish, &members)
    };
    let mut resumed: Vec<PathBuf> = Vec::new();
    // Staging sits on the same filesystem as the job directory, so this
    // still measures the volume the payload lands on.
    let budget = BombBudget::fixed(
        crate::serve::free_bytes(out)
            .map(|free| free.saturating_sub(EXTRACT_RESERVE))
            .unwrap_or(u64::MAX),
    );
    let written = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    // TODO 205: the queue row's unpack lane. Tar is the second arm that
    // cannot declare a total up front - the reader learns each member as
    // it reaches that member's header - so the figure is raised as the
    // walk goes, the way `repair::reextract_dir_outcome`'s plain branch
    // already does. A resumed member's prefix is credited here because
    // this pass will not rewrite it.
    crate::unpackprog::attempt(
        &written,
        0,
        resume
            .values()
            .fold(0u64, |acc, (_, len, _)| acc.saturating_add(*len)),
    );
    let result = (|| -> Result<()> {
        let mut rd = nzbkit::tar::Reader::new(std::io::BufReader::new(file), total);
        let mut buf = vec![0u8; 64 * 1024];
        let mut files = 0usize;
        let mut declared = 0u64;
        loop {
            let Some(entry) = rd.next_entry().map_err(|e| anyhow::anyhow!("{e}"))? else {
                break;
            };
            match entry.kind {
                nzbkit::tar::Kind::Dir => {
                    if let Some(target) = sanitized_entry_path(out, &entry.name) {
                        std::fs::create_dir_all(&target)?;
                    }
                    continue;
                }
                // The chase's rule, and the zip arm's before it: a member
                // that is a reference rather than bytes has no honest
                // output, and following one is how an archive writes
                // outside its own directory.
                nzbkit::tar::Kind::Reference(_) => anyhow::bail!(
                    "entry {:?} is a {}, which is not extracted",
                    entry.name,
                    entry.kind_word()
                ),
                nzbkit::tar::Kind::File => {}
            }
            let target = sanitized_entry_path(out, &entry.name).ok_or_else(|| {
                anyhow::anyhow!("entry {:?} escapes the output directory", entry.name)
            })?;
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            declared = declared.saturating_add(entry.size);
            crate::unpackprog::raise_total(declared);
            files += 1;
            // A resumed member writes to the PUBLISHED file at its mark;
            // everything else creates a fresh file in staging. The two
            // differ in the handle and in nothing else.
            let (sink, skip, crc) = match resume.get(entry.name.as_str()) {
                Some((path, len, crc)) => {
                    let f = crate::resumeout::open_at_mark(path, *len)?;
                    resumed.push(path.clone());
                    (f, *len, *crc)
                }
                // Creating the file here is also what makes a zero-byte
                // member land: the copy loop below never runs for one.
                None => (std::fs::File::create(&target)?, 0, 0),
            };
            let mut w = crate::resumeout::ResumeWriter::verified(
                skip,
                crc,
                mismatch.clone(),
                BombGuardWriter {
                    inner: std::io::BufWriter::new(sink),
                    written: written.clone(),
                    budget: budget.clone(),
                },
            );
            let mut got = 0u64;
            loop {
                let n = rd
                    .read_data(&mut buf)
                    .map_err(|e| anyhow::anyhow!("reading {}: {e}", entry.name))?;
                if n == 0 {
                    break;
                }
                got += n as u64;
                w.write_all(&buf[..n])?;
            }
            w.flush()?;
            // The reader bounds each member by its declared size, so a
            // short read means the container ended inside it. Publishing
            // that would call a truncated file a whole one.
            if got != entry.size {
                anyhow::bail!("{} is shorter than its declared size", entry.name);
            }
        }
        if !rd.saw_end_marker() {
            // The container ran out BETWEEN two members rather than on
            // its end-of-archive block. Every member read so far is
            // perfectly well-formed, so nothing else in this loop would
            // have noticed, and publishing them would call a cut archive
            // a complete one.
            anyhow::bail!("the tar archive ends without its end-of-archive marker");
        }
        if files == 0 {
            // "Unpacked successfully" having produced nothing is the
            // silent success this codebase refuses everywhere else.
            anyhow::bail!("the tar archive contains no files");
        }
        Ok(())
    })();
    crate::resumeout::finish(&resumed, result.is_ok());
    result
}

/// Every regular member's name, in archive order: the list `plan_pass`
/// needs before the extraction opens anything. Walks the container once
/// through the same reader, reading past each member's data because that
/// is the only way this format can be skipped.
fn tar_member_names(container: &std::path::Path, total: u64) -> Result<Vec<String>> {
    let f = std::fs::File::open(container)?;
    let mut rd = nzbkit::tar::Reader::new(std::io::BufReader::with_capacity(256 * 1024, f), total);
    let mut names = Vec::new();
    while let Some(e) = rd.next_entry().map_err(|e| anyhow::anyhow!("{e}"))? {
        if matches!(e.kind, nzbkit::tar::Kind::File) {
            names.push(e.name);
        }
    }
    Ok(names)
}

#[cfg(test)]
#[path = "tar_tests.rs"]
mod tar_tests;
