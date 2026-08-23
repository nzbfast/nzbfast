//! The post-forfeit resume ledger: what a chase that gave up on the
//! held-bytes cap leaves on disk for the disk pass to pick up from.
//!
//! Split out of `extract/mod.rs` under the TODO 106 recipe - a move of
//! the type and its three methods, not a redesign. The ledger itself
//! lives in `Inner::resume_pending`; `chase_teardown` (RAR) and
//! `sevenz_teardown_sinks` (7z and zip) fill it, `finish` empties it
//! into the report, and a repair rewrite anywhere in the job voids it.

use super::*;

/// Escape hatch for the post-forfeit resume: with it set, a chase that
/// forfeits on the held-bytes cap deletes its in-stream output and the
/// disk pass re-extracts every member from byte zero, which is exactly
/// the behaviour before this existed. The exact analogue of
/// `NZBFAST_NO_RAR_TRIM`.
///
/// Read at the forfeit rather than latched at construction, which is
/// what lets one binary run both arms of an A/B - the 22 Aug round used
/// it for precisely that, so the two arms differ in this flag and in
/// nothing else, not even the build.
pub(super) fn chase_resume_env_off() -> bool {
    chase_resume_env_off_value(std::env::var("NZBFAST_NO_CHASE_RESUME").ok().as_deref())
}

/// Pure parse of the resume escape-hatch value (same rationale as the
/// other gates in `extract::config`: the parse is tested, the read is
/// not).
pub(super) fn chase_resume_env_off_value(v: Option<&str>) -> bool {
    v == Some("1")
}

/// One in-stream output a chase that forfeited on the held-bytes cap
/// left behind, and how far into it the decode had committed.
///
/// The forfeit materializes the volumes and hands them to the disk
/// unpack pass, which re-extracts the same members - and used to do it
/// from byte zero, throwing away output the chase had already written
/// correctly (measured 21 Aug 2026 on a compressed RAR5 set at 250
/// MB/s: 1.96-1.98x payload of device I/O against 1.556x for a set that
/// forfeited without ever trimming, the difference being the trim spill
/// plus ~3.3 GiB of discarded output -
/// `research/MEASURED-HOLDS-LADDER-2026-08-21.md` §3). The disk pass may
/// instead skip re-WRITING the first `len` bytes of `member` and append
/// from there; it still decodes them, because a compressed member has no
/// seekable entry point, but the bytes never reach the device twice.
///
/// Only the held-bytes-cap forfeit produces these. The other forfeit
/// reason - "repair rewrote chased bytes" - means the decode may have
/// run on bytes PAR2 has since corrected, so its prefix is exactly what
/// must not be trusted, and that path deletes its partials as it always
/// did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeOutput {
    /// The archive member name the chase was decoding, as the engine
    /// reported it - the same string the disk pass's own extraction
    /// callback sees.
    pub member: String,
    /// The file the chase wrote it to. Truncated to exactly `len` before
    /// this record was made, so a caller may test the length to prove
    /// nothing has touched the file since.
    pub path: PathBuf,
    /// Contiguous bytes from offset 0 that are on disk and correct.
    ///
    /// The CHECKSUMMED length, which is what `crc32` covers - never the
    /// writer's raw contiguous frontier, which can run past the hashed
    /// end when a write landed out of order and froze the hash (TODO
    /// 217 hard part 2: shipping the larger of the two would hand the
    /// disk pass bytes nothing can verify).
    pub len: u64,
    /// CRC32 of the first `len` bytes, folded in as the chase wrote
    /// them (TODO 217). The disk pass re-decodes the same prefix anyway
    /// - a compressed member has no seekable entry point - so it hashes
    /// the re-decode on the way past and compares at the mark: a match
    /// PROVES the append writes exactly what a from-zero extract would
    /// have, and a mismatch falls back to extracting from byte zero,
    /// which is the old behaviour and always correct.
    pub crc32: u32,
}

impl Extractor {
    /// Does a forfeit carrying `reason` KEEP the in-stream output its
    /// sinks wrote, or delete it the way every demotion used to?
    ///
    /// The one test, shared by the RAR teardown (`chase_teardown`) and
    /// the 7z/zip one (`sevenz_teardown_sinks`) rather than spelled
    /// twice: the two arms reach the forfeit down different paths and
    /// have to agree on this exactly, or a container format quietly gets
    /// a laxer rule than the format the guards were reasoned about on.
    ///
    /// Depth 0 only - a nested chase's partial is a member of a member,
    /// and the pass that would resume it works another directory. And
    /// the reason must be the held-bytes cap WHOLE, never a substring: a
    /// forfeit raised because "repair rewrote chased bytes" means the
    /// decode may have run over bytes PAR2 has since corrected, so its
    /// prefix is precisely what nobody may trust.
    pub(super) fn chase_resume_ok(&self, reason: &str) -> bool {
        self.depth == 0 && reason == HELD_BYTES_CAP_CHASE && !chase_resume_env_off()
    }

    /// The resume half of [`Self::abandon_slot`], for a chase sink whose
    /// container forfeited on the held-bytes cap: stop mapping the slot
    /// but KEEP the bytes it wrote, so the disk pass can append to them
    /// instead of re-extracting the member from byte zero.
    ///
    /// Answers the member name and its writer, or `None` - having
    /// abandoned the slot exactly as before - when the slot is anything
    /// but a settled plain file. That is the only shape whose file
    /// provably holds the MEMBER's own bytes: a slot still holding
    /// pre-sniff spans has bytes in RAM and not on disk, and one that
    /// classified as a nested archive has its own map or chase, so its
    /// file (if it has one) is a volume, not the decoded member.
    ///
    /// Deliberately does NOT release the name: the file stays, so the
    /// name stays taken.
    pub(super) fn retain_slot_output(&self, slot: usize) -> Option<(String, Arc<FileWriter>)> {
        // Takes only our lock, and the caller holds the PARENT's - the
        // same parent-then-child order `abandon_slot` is called in.
        if self.stable_plain_writer(slot).is_none() {
            self.abandon_slot(slot);
            return None;
        }
        let mut g = self.inner.lock_ok();
        let inner = &mut *g;
        // Re-checked under this lock: `stable_plain_writer` dropped it,
        // and Plain is terminal but the writer is not - only holding the
        // lock across take-and-Discard makes the pair atomic.
        let s = &mut inner.slots[slot];
        if s.mode != SlotMode::Plain || !s.holds.is_empty() {
            drop(g);
            self.abandon_slot(slot);
            return None;
        }
        let Some(w) = s.writer.take() else {
            drop(g);
            self.abandon_slot(slot);
            return None;
        };
        let name = s.name.clone();
        s.piece_crcs = HashMap::new();
        s.mapper = None;
        s.pre_bytes = 0;
        // Discard swallows every later span, so the engine's own writes
        // stop here even though a write already queued may still land -
        // which is why the mark is measured at finish and not now.
        s.mode = SlotMode::Discard;
        // `stable_plain_writer` already promised no holds; a header stash
        // is not part of that promise and a slot nobody owns any more
        // must not keep charging the shared budget for one. Empty on a
        // decoded member in practice - only volume slots stash headers -
        // so this is the same belt `abandon_slot` wears.
        let headers = std::mem::take(&mut inner.slots[slot].header_spans);
        for (_, span) in &headers {
            Self::uncharge_span(inner, span);
        }
        Some((name, w))
    }

    /// Measure and truncate the kept partials, and hand the caller the
    /// ledger for its report. Called from `finish` and only there: every
    /// chase worker has been joined by then, so `contiguous_from_start`
    /// is a settled number rather than one a write still in flight can
    /// move under us.
    ///
    /// The truncate is what makes the file honest. Output writers
    /// PREALLOCATE to the member's declared size, so an untruncated
    /// partial is already full-length with a sparse tail - indistinguish-
    /// able by `stat` from a complete extraction, which is precisely the
    /// masquerade the forfeit's delete existed to prevent. Cut to the
    /// contiguous prefix, a partial is short, and both this crate's
    /// caller and any later pass can tell the two apart by length.
    ///
    /// A member with nothing contiguous on disk, or one we cannot cut
    /// down, is dropped from the ledger and its file removed: no entry
    /// is better than an entry a caller might trust.
    ///
    /// The mark is the writer's CHECKSUMMED prefix (TODO 217), not its
    /// raw contiguous frontier: the two are equal on the sequential
    /// writes a chase sink makes, and where they differ - an
    /// out-of-order write froze the hash short - only the hashed length
    /// can ever be verified, so only it may be recorded. A writer whose
    /// hash was never armed or was poisoned records nothing and its
    /// file is removed, exactly like a zero mark.
    pub(super) fn settle_resume_ledger(inner: &mut Inner) -> Vec<ResumeOutput> {
        let pending = std::mem::take(&mut inner.resume_pending);
        let mut out = Vec::with_capacity(pending.len());
        for (member, w) in pending {
            let (len, crc32) = w.prefix_hash().unwrap_or((0, 0));
            let path = w.current_path();
            // Drop our reference before touching the file by path: on
            // Windows an open handle can refuse the unlink below.
            // `retain_slot_output` took the writer out of the slot, so
            // this is normally the last reference - but the streaming
            // server hands out clones (`writers_snapshot`), so a viewer
            // watching this very member can still hold one. Both calls
            // below tolerate that: the `set_len` goes through a fresh
            // handle either way, and a `remove_file` that loses to an
            // open handle leaves a partial the caller's own cleanup will
            // find (`resumeout`'s arm proves ownership by length).
            drop(w);
            if len == 0 {
                let _ = std::fs::remove_file(&path);
                continue;
            }
            let cut = std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .and_then(|f| f.set_len(len));
            if cut.is_err() {
                let _ = std::fs::remove_file(&path);
                continue;
            }
            out.push(ResumeOutput {
                member,
                path,
                len,
                crc32,
            });
        }
        out
    }

    /// Throw the resume ledger away, files and all: a PAR2 repair has
    /// rewritten bytes of this job, and a chase that decoded before the
    /// rewrite may have decoded from the stale copy. Every CRC on that
    /// path still passes, so nothing downstream would catch it - the only
    /// safe reading is that no kept prefix is trustworthy any more.
    ///
    /// Deliberately blunt (one repair span drops the whole ledger, at any
    /// depth, whatever it rewrote): a repair is rare, the ledger is an
    /// I/O optimisation, and a cheap over-approximation here costs one
    /// job's re-extraction where a clever one risks the payload. The
    /// in-chase twin of this guard is the `mark_conflict` forfeit, which
    /// fires while the chase is LIVE and carries its own reason so no
    /// ledger is ever written for it; this catches the repair that lands
    /// after the forfeit, when the chase is already gone.
    pub(super) fn drop_resume_ledger(&self) {
        let pending = {
            let mut g = self.inner.lock_ok();
            if g.resume_pending.is_empty() {
                return;
            }
            std::mem::take(&mut g.resume_pending)
        };
        for (_, w) in pending {
            let path = w.current_path();
            // Same reference caveat as `settle_resume_ledger`: usually
            // the last one, not provably so.
            drop(w);
            let _ = std::fs::remove_file(&path);
        }
    }
}
