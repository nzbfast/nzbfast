//! The FINAL, on-disk half of the §76 queue-row media prober: read what
//! post-processing actually left in the output directory, and the claim
//! name that answer is judged against.
//!
//! Both were in `tasks/media.rs` beside the prober LANE, and both are
//! called from outside it - `histmigrate`'s re-derivation pass over old
//! history rows, and `stream`'s own tests. Neither touches the lane's
//! state: `probe_disk_facts_checked` resolves a path through
//! `serve::stream`, opens it and hands the bytes to
//! `nzbkit::mediaprobe`. The lane still owns the live pass over the
//! running writer, the latch and the tick.
//!
//! Verbatim from `media.rs`, visibility widened on `media_claim_name`
//! (the lane still calls it, from above).

use super::*;

/// The name a mismatch is judged against: what an identity oracle
/// concluded, when one answered, and the posted name otherwise.
///
/// This matters most on exactly the posts the feature is for. An
/// obfuscated stem claims nothing - `parse_release` finds no resolution
/// and no codec in "a4f9c2e1", so nothing can contradict it - while the
/// canonical name srrdb or xREL handed back claims everything. Judging
/// the bytes against that is free here and impossible anywhere else.
pub fn media_claim_name(j: &Job) -> String {
    if j.identity_name.is_empty() {
        j.name.clone()
    } else {
        j.identity_name.clone()
    }
}

/// Pass 2: the finished payload, whatever post-processing left behind,
/// keeping the difference between "there is nothing to read" and "I
/// could not read it".
///
/// `Ok(None)` is a settled answer: no media file of ours in the output
/// directory, or a file whose bytes are not a container we understand.
/// `Err` is a failure to look, and only ever an I/O one - the volume,
/// the permission, the network mount. Every caller needs that
/// distinction (Codex sweep 7, M6): the re-derivation pass must not
/// record "no payload" for a disk it never managed to read, and the
/// prober says a different thing in the log for each - a lossy wrapper
/// that erased both into `None` is what made a chipless row and an
/// unprobed row look identical.
pub fn probe_disk_facts_checked(
    d: &Daemon,
    job: &Arc<Mutex<Job>>,
) -> std::io::Result<Option<nzbkit::mediaprobe::MediaFacts>> {
    let Some(path) = stream::finished_media_path_checked(d, job)? else {
        return Ok(None);
    };
    let name = media_claim_name(&job.lock_ok());
    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    let mut f = match std::fs::File::open(&path) {
        Ok(f) => f,
        // The walk named it a moment ago, so a NotFound here is a file
        // that has just been moved or deleted - an answer, not a fault.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let info = match nzbkit::mediaprobe::probe(
        &mut f,
        nzbkit::mediaprobe::ProbeHint {
            filename: path.file_name().map(|n| n.to_string_lossy().to_string()),
            known_size: Some(size),
        },
    ) {
        Ok(i) => i,
        // A container we cannot parse is a property of the FILE and will
        // read the same way forever; only the I/O arm is worth retrying.
        Err(nzbkit::mediaprobe::ProbeError::Io(e)) => return Err(e),
        Err(_) => return Ok(None),
    };
    Ok(Some(nzbkit::mediaprobe::facts::check(&info, &name)))
}
