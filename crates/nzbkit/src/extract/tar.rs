//! The TAR chase (top-level and nested): attach, the worker that drives
//! the tar reader over arriving bytes, and the blocking view it reads
//! through.
//!
//! The zip arm's twin (TODO 163 item 6), and the simplest of the three
//! container chases, because tar is the only one with nothing at its
//! tail. A zip's central directory and a 7z's end header both sit behind
//! the payload, so both of those attaches front-load a window through
//! the promote hook before a single entry can be named; a tar is a flat
//! `header, data, padding, …` run, so this worker reads strictly
//! forward from byte 0 and never asks the chain above for anything.
//!
//! Three consequences worth stating, because they are what make this
//! file short:
//!
//! - **No tail promote.** `SevenZCtl::tail` stays `None`, so nothing is
//!   queued at attach and nothing is promoted when a part joins.
//! - **The drop-behind trim arms immediately.** The hazard `arm_trim`
//!   exists for is a reader whose position jumps to the tail during an
//!   open phase and back down afterwards; there is no open phase here
//!   and the read position only ever ascends, so bytes behind it are
//!   provably cold from the first byte.
//! - **The bomb guard is the container's own length.** Tar stores its
//!   members uncompressed, so the extracted total cannot exceed the
//!   container. That is enforced rather than assumed: a member whose
//!   declared size runs past the container is refused at its header
//!   (`tar::Reader`), and the chain-wide [`Limits`] budget the child
//!   sink writes through still bounds every level. The one shape that
//!   could break the identity - a GNU sparse member, whose real size is
//!   unrelated to the bytes behind it - is refused outright in both of
//!   its spellings.
//!
//! A container this chase DECLINES or demotes lands in the output
//! directory, where the disk post-pass's own tar arm picks it up
//! (`nzbfast`'s `rarfix::tar`, TODO 163 item 6's disk half). That arm
//! drives this same `crate::tar::Reader`, so the two halves cannot
//! drift apart on what they refuse.
//!
//! Everything else is the zip arm's machinery unchanged: the same
//! `SevenZSet` byte space, the same `ChaseSink` routing seam into a
//! child slot (so a `.tar` inside a store RAR one-passes, which is the
//! shape this exists for), the same demote ladder, and the same
//! finish/join in `sevenz_finish`.

use super::*;
use crate::sync::MutexExt;

/// Blocking sequential `io::Read` over a chased tar container - the view
/// the tar worker parses through. Reads block until the bytes arrive,
/// and each one publishes the chase's drop-behind watermark: the reader
/// never revisits, so everything below the last read is releasable.
pub(super) struct BlockingTarSource {
    pub(super) set: Arc<SevenZSet>,
    pub(super) low_water: Arc<AtomicU64>,
    pub(super) pos: u64,
}

impl io::Read for BlockingTarSource {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let n = self.set.read_blocking(self.pos, buf)?;
        self.pos += n as u64;
        self.low_water.store(self.pos, Ordering::Relaxed);
        Ok(n)
    }
}

impl Extractor {
    /// Attach a tar container to the chase. Returns false when
    /// ineligible - the slot then classifies Plain and materializes as
    /// an ordinary `.tar` file, which is exactly what happened before
    /// this arm existed, so declining is never a regression. Since TODO
    /// 163 item 6's disk half (23 Aug 2026) the disk post-pass unpacks
    /// that file (`nzbfast`'s `rarfix::tar`), so declining now costs a
    /// second pass over the container rather than the payload.
    ///
    /// Runs at any depth, like the zip and 7z attaches: the depth
    /// ceiling needs no check of its own because a child created AT
    /// `nested_max_depth` is disabled and classifies everything Plain
    /// before any attach runs (see `ensure_child`), and a resumed run is
    /// disabled wholesale the same way.
    ///
    /// One gate (`tar_on`) rather than zip's top/nested pair: those two
    /// exist because zip's nested lift and its top-level chase shipped
    /// as separate phases and each needed its own soak switch. Tar lands
    /// whole, and a top-level tar that declines lands on disk unchanged,
    /// so one kill switch says everything a second one would.
    ///
    /// LAST of the four container arms the offset-0 sniff tries, and it
    /// could not usefully go earlier: RAR, 7z and zip all announce
    /// themselves in the first bytes, while a tar's magic sits 257 bytes
    /// in, so this can only be asked once those three have passed. The
    /// name gate is the narrowest of the four for the same reason.
    ///
    /// `payload_name` is the caller's [`is_final_name`] verdict - a
    /// `.cbr` or `.cb7` whose bytes carry an archive magic is the
    /// deliverable, never packaging - threaded in rather than
    /// re-derived, so all four arms answer it from one read.
    ///
    /// Mints NO shape bit, deliberately. `ArchiveShape::from_bits` has
    /// no tar token, and adding one means a persisted wire value plus
    /// dashboard and i18n copy - the same piece of work nested zip's
    /// badge has been waiting on since phase 2.
    pub(super) fn try_attach_tar(
        &self,
        inner: &mut Inner,
        slot: usize,
        data: &[u8],
        payload_name: bool,
    ) -> io::Result<bool> {
        if payload_name
            || !inner.nested_on
            || !inner.tar_on
            || inner.protect_sources
            || inner.slots[slot].size == 0
            || inner.self_weak.upgrade().is_none()
        {
            return Ok(false);
        }
        let size = inner.slots[slot].size;
        // One header block plus the end-of-archive marker is the
        // smallest thing that can be a tar at all.
        if size < (crate::tar::BLOCK * 3) as u64 {
            return Ok(false);
        }
        if !crate::tar::chase_eligible_name(&inner.slots[slot].name) {
            return Ok(false);
        }
        // The magic lives at offset 257, not 0, so this needs more of
        // the first article than the other sniffs do (see
        // `tar::looks_like_tar` for what a short prefix can and cannot
        // establish). A first span too short to reach it declines, and
        // the container lands on disk.
        if !crate::tar::looks_like_tar(data) {
            return Ok(false);
        }
        let ctl = Arc::new(SevenZCtl {
            set: Arc::new(SevenZSet::new(size, size)),
            key: String::new(),
            archive_base: 0,
            low_water: Arc::new(AtomicU64::new(0)),
            // No tail: nothing in a tar lives behind its payload.
            tail: Mutex::new(None),
            trim_ok: std::sync::atomic::AtomicBool::new(false),
            worker: Mutex::new(None),
            sink_slots: Mutex::new(Vec::new()),
            outcome: Mutex::new(None),
        });
        inner.slots[slot].container_fmt = ChaseFormat::Tar;
        let joined = self.sevenz_join_set(inner, slot, ctl.clone(), 1)?;
        if !joined {
            // Unreachable for a fresh one-part set (nothing to collide
            // with), kept for symmetry with the zip and 7z attaches.
            inner.slots[slot].container_fmt = ChaseFormat::SevenZ;
            return Ok(false);
        }
        let weak = inner.self_weak.clone();
        let ctl2 = ctl.clone();
        let handle = std::thread::Builder::new()
            .name("nzb-tar-chase".into())
            .spawn(move || Self::tar_worker(weak, ctl2))
            .map_err(io::Error::other)?;
        *ctl.worker.lock_ok() = Some(handle);
        Ok(true)
    }

    /// The tar chase worker. The extractor is reached weakly so a
    /// cancelled job can drop; the outcome is recorded for
    /// `sevenz_finish` to act on.
    pub(super) fn tar_worker(me: Weak<Extractor>, ctl: Arc<SevenZCtl>) {
        let result = Self::tar_run(&me, &ctl);
        *ctl.outcome.lock_ok() = Some(result);
    }

    /// The worker's engine drive: walk the container front to back and
    /// stream every regular member into a fresh child slot.
    ///
    /// Declines refuse the WHOLE container rather than skipping a
    /// member, the same rule the zip worker keeps: half an archive
    /// extracted beside a demoted container is two half-answers, and
    /// the demote leaves a `.tar` that is exactly what the user would
    /// have got before this arm existed. Every wording here reaches the
    /// user through the demote reason, marked
    /// [`TAR_DISK_FALLBACK_PREFIX`] at the demote site when this is a
    /// top-level container.
    pub(super) fn tar_run(me: &Weak<Extractor>, ctl: &SevenZCtl) -> Result<(), String> {
        use std::io::Write as _;
        // A one-part container resolves at attach; the wait costs
        // nothing and keeps this the same shape as its two siblings.
        let total = ctl.set.wait_resolved_total().map_err(|e| e.to_string())?;
        let src = BlockingTarSource {
            set: ctl.set.clone(),
            low_water: ctl.low_water.clone(),
            pos: 0,
        };
        // Safe from the first byte: this reader has no open phase to
        // seek around in, so the watermark it publishes only ascends.
        ctl.arm_trim(false);
        let mut rd = crate::tar::Reader::new(src, total);
        let mut buf = vec![0u8; 64 * 1024];
        let mut files = 0usize;
        loop {
            let entry = match rd.next_entry() {
                Ok(Some(e)) => e,
                Ok(None) => break,
                Err(e) => return Err(e.to_string()),
            };
            match entry.kind {
                crate::tar::Kind::Dir => continue,
                crate::tar::Kind::Reference(_) => {
                    return Err(format!(
                        "entry {:?} is a {}, which is not extracted",
                        entry.name,
                        entry.kind_word()
                    ));
                }
                crate::tar::Kind::File => {}
            }
            let Some(ex) = me.upgrade() else {
                return Err("extractor dropped".to_string());
            };
            // Same single-lock-hold discipline as the zip and 7z sinks:
            // the liveness check and the sink-slot registration must be
            // atomic against a demotion draining sink_slots, or the
            // fresh slot leaks a partial output.
            let (child, cslot) = {
                let mut g = ex.inner.lock_ok();
                let inner = &mut *g;
                let members = ctl.set.member_slots();
                if members.is_empty()
                    || !members
                        .iter()
                        .all(|&m| matches!(inner.slots[m].mode, SlotMode::SevenZ))
                {
                    return Err("tar chase demoted".to_string());
                }
                let child = ex.ensure_child(inner);
                let cslot = child.alloc_slot();
                ctl.sink_slots.lock_ok().push(cslot);
                (child, cslot)
            };
            let mut sink = ChaseSink {
                child,
                slot: cslot,
                name: entry.name.clone(),
                size: entry.size,
                pos: 0,
            };
            files += 1;
            if entry.size == 0 {
                // An explicit empty write is what creates the output
                // file - the copy loop never calls the sink for zero
                // bytes, and a tar does carry empty members.
                sink.write(&[])
                    .map_err(|err| format!("writing {}: {err}", entry.name))?;
                continue;
            }
            let mut written = 0u64;
            loop {
                let n = rd
                    .read_data(&mut buf)
                    .map_err(|err| format!("reading {}: {err}", entry.name))?;
                if n == 0 {
                    break;
                }
                written += n as u64;
                sink.write_all(&buf[..n])
                    .map_err(|err| format!("writing {}: {err}", entry.name))?;
            }
            // The reader bounds each member by its declared size, so a
            // short read means the container ended inside it - the same
            // "shorter than its declared size" the zip worker refuses,
            // and the one thing that would publish a truncated file as
            // though it were whole.
            if written != entry.size {
                return Err(format!("{} is shorter than its declared size", entry.name));
            }
        }
        if !rd.saw_end_marker() {
            // The container ran out between two members rather than on
            // its end-of-archive block. Every member read so far is
            // well-formed, so nothing else in this loop would have
            // noticed - and publishing them would call a cut archive a
            // complete one. A member cut mid-data is caught above, by
            // its own declared size.
            return Err("the tar archive ends without its end-of-archive marker".to_string());
        }
        if files == 0 {
            // "Unpacked successfully" having produced nothing is the
            // silent success this codebase refuses everywhere else.
            return Err("the tar archive contains no files".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "tar_tests.rs"]
mod tar_tests;
