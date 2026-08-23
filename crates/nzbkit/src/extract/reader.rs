//! The read side of a mapped slot: coverage queries, byte-exact
//! volume read-back for the live verifier, mapped-repair patches,
//! slot/file introspection, resume seeding, and the /stream open.
//!
//! Split out of the 19,920-line `extract.rs` under the TODO 43
//! recipe: a verbatim move, not a redesign.

use super::*;
use crate::sync::MutexExt;

/// Whether clipped `[start, end)` intervals cover the complete
/// `[0, len)` request. Coverage is normally only a handful of header,
/// hold, and mapped-data spans, so track spans rather than allocating
/// and scanning one boolean per requested byte.
fn intervals_cover_all(mut intervals: Vec<(u64, u64)>, len: u64) -> bool {
    if len == 0 {
        return true;
    }
    intervals.sort_unstable();
    let mut covered_to = 0u64;
    for (start, end) in intervals {
        if start > covered_to {
            return false;
        }
        covered_to = covered_to.max(end);
        if covered_to >= len {
            return true;
        }
    }
    false
}

impl Extractor {
    /// Byte-exact volume read for verifier read-back: headers from the
    /// stash, data areas from the extracted files (or the materialized
    /// volume file after fallback).
    /// True iff `[off, off+len)` of this slot's (volume-view) bytes are
    /// really on disk / in the header stash - a sparse hole would pread
    /// as zeros, so the M15 backfill path must ask first.
    pub fn covered(&self, slot: usize, off: u64, len: usize) -> bool {
        let inner = self.inner_read();
        // TODO 211 (b): a split part's bytes are its head's, at the
        // logical offset (same translation in read_at and
        // covered_intervals).
        let (slot, off) = Self::split_target(&inner, slot, off);
        let s = &inner.slots[slot];
        match s.mode {
            SlotMode::Plain | SlotMode::RarFallback => s
                .writer
                .as_ref()
                .is_some_and(|w| w.covered(off, len as u64)),
            // Chased slot: the frontier buffer is the byte record
            // (frontier + parked out-of-order spans) from the trim point
            // up; below it the slot's own archive file holds the bytes a
            // drop-behind trim spilled, and they count exactly the same.
            SlotMode::RarChase | SlotMode::SevenZ => {
                let Some(ch) = s.chase.as_ref() else {
                    return false;
                };
                if len == 0 {
                    return true;
                }
                let end = off + len as u64;
                let base = ch.buf.base();
                if off < base {
                    let spilled = base.min(end);
                    if !s
                        .writer
                        .as_ref()
                        .is_some_and(|w| w.covered(off, spilled - off))
                    {
                        return false;
                    }
                    if end <= base {
                        return true;
                    }
                    return ch.buf.intervals(base, end - base) == [(base, end)];
                }
                ch.buf.intervals(off, len as u64) == [(off, end)]
            }
            SlotMode::Rar => {
                let Some(m) = s.mapper.as_ref() else {
                    return false;
                };
                let mut covered =
                    Vec::with_capacity(s.header_spans.len().saturating_add(s.holds.len()));
                // Held spans count: bytes that arrived but sit parked
                // behind an unparsed header (a lost mid-file entry
                // header leaves everything after it in holds) are real,
                // exact volume bytes - mapped repair must be able to
                // read them to rebuild the header blocks that free them.
                // Paged spans count identically (read_at preads them).
                for (hs, span) in s.header_spans.iter().chain(&s.holds) {
                    let he = hs + span.len() as u64;
                    let qs = off.max(*hs);
                    let qe = (off + len as u64).min(he);
                    if qs < qe {
                        covered.push((qs - off, qe - off));
                    }
                }
                for (ei, piece_off, span_off, plen) in m.map_span(off, len as u64) {
                    // Soft-skip like read_at: holds may already cover a
                    // range whose base/route is unresolved.
                    let Some(base) = Self::base_for(&inner, slot, ei) else {
                        continue;
                    };
                    let ok = match Self::dest_for(&inner, slot, &m.entries[ei].name) {
                        // Plaintext-once file: coverage is in POSTED-byte
                        // terms (arrived cipher), not the plaintext the
                        // writer holds - seams and tail padding live in
                        // the crypto stashes, not on disk.
                        Some(Dest::Writer(w)) => match Self::crypto_of(&inner, &w) {
                            Some(cs) => cs.covers(base + piece_off, plen),
                            None => w.covered(base + piece_off, plen),
                        },
                        Some(Dest::Child(c, cs)) => c.covered(cs, base + piece_off, plen as usize),
                        None => false,
                    };
                    if !ok {
                        continue;
                    }
                    covered.push((span_off, span_off + plen));
                }
                intervals_cover_all(covered, len as u64)
            }
            // Unclassified slot: pre-sniff holds are exact file bytes.
            SlotMode::Unknown => {
                let mut covered = Vec::with_capacity(s.holds.len());
                for (hs, span) in &s.holds {
                    let he = hs + span.len() as u64;
                    let qs = off.max(*hs);
                    let qe = (off + len as u64).min(he);
                    if qs < qe {
                        covered.push((qs - off, qe - off));
                    }
                }
                intervals_cover_all(covered, len as u64)
            }
            SlotMode::Discard | SlotMode::SplitPart => false,
        }
    }

    pub fn read_at(&self, slot: usize, off: u64, buf: &mut [u8]) -> io::Result<()> {
        // Plan under the lock (header bytes are memcpy'd right away),
        // pread after releasing it - the mapped-repair path reads
        // thousands of blocks concurrently and must not serialize every
        // disk read behind the extractor lock. Child reads defer the same
        // way; the child plans under its own lock and reads lock-free.
        enum Plan {
            W(Arc<FileWriter>, usize, usize, u64),
            C(Arc<Extractor>, usize, usize, usize, u64),
            /// Plaintext-once output: posted bytes come from the
            /// re-encrypt shim + cipher stashes, not a raw pread.
            X(Arc<CryptoState>, Arc<FileWriter>, usize, usize, u64),
            /// Paged held span: pread from the holds scratch. Safe off
            /// the lock because regions are write-once and the pin below
            /// blocks the idle cursor reset/truncate until we're done.
            S(Arc<(PathBuf, File)>, usize, usize, u64),
        }
        let mut pin = ScratchPin::none();
        let mut reads: Vec<Plan> = Vec::new();
        {
            let inner = self.inner_read();
            let (slot, off) = Self::split_target(&inner, slot, off);
            let s = &inner.slots[slot];
            match s.mode {
                SlotMode::Plain | SlotMode::RarFallback => {
                    let w = s.writer.as_ref().ok_or_else(nofile)?;
                    reads.push(Plan::W(w.clone(), 0, buf.len(), off));
                }
                SlotMode::Rar => {
                    let m = s.mapper.as_ref().ok_or_else(nofile)?;
                    let request_len = buf.len() as u64;
                    let mut covered =
                        Vec::with_capacity(s.header_spans.len().saturating_add(s.holds.len()));
                    // Header stash first, then held spans: bytes parked
                    // behind an unparsed header are exact volume bytes,
                    // and mapped repair reads through here to rebuild
                    // the very header blocks that will free them. A
                    // paged span serves the same bytes via a deferred
                    // pread of its scratch region.
                    for (hs, span) in s.header_spans.iter().chain(&s.holds) {
                        let he = hs + span.len() as u64;
                        let qs = off.max(*hs);
                        let qe = (off + buf.len() as u64).min(he);
                        if qs < qe {
                            let n = (qe - qs) as usize;
                            match span {
                                HoldSpan::Ram(bytes) => {
                                    buf[(qs - off) as usize..(qs - off) as usize + n]
                                        .copy_from_slice(
                                            &bytes[(qs - hs) as usize..(qs - hs) as usize + n],
                                        );
                                }
                                HoldSpan::Paged { off: po, .. } => {
                                    pin.pin(&inner.scratch);
                                    let f = inner.scratch.handle().ok_or_else(nofile)?;
                                    reads.push(Plan::S(f, (qs - off) as usize, n, po + (qs - hs)));
                                }
                            }
                            covered.push((qs - off, qe - off));
                        }
                    }
                    for (ei, piece_off, span_off, len) in m.map_span(off, buf.len() as u64) {
                        // Unresolved base / unrouted destination is not
                        // fatal by itself: a continuation entry whose
                        // head volume is the very damage under repair
                        // keeps its arrived bytes in holds (served
                        // above) - only a range NOBODY can serve fails.
                        let Some(base) = Self::base_for(&inner, slot, ei) else {
                            continue;
                        };
                        match Self::dest_for(&inner, slot, &m.entries[ei].name) {
                            Some(Dest::Writer(w)) => match Self::crypto_of(&inner, &w) {
                                Some(cs) => reads.push(Plan::X(
                                    cs,
                                    w,
                                    span_off as usize,
                                    len as usize,
                                    base + piece_off,
                                )),
                                None => reads.push(Plan::W(
                                    w,
                                    span_off as usize,
                                    len as usize,
                                    base + piece_off,
                                )),
                            },
                            Some(Dest::Child(c, cs)) => reads.push(Plan::C(
                                c,
                                cs,
                                span_off as usize,
                                len as usize,
                                base + piece_off,
                            )),
                            None => continue,
                        }
                        covered.push((span_off, span_off + len));
                    }
                    if !intervals_cover_all(covered, request_len) {
                        return Err(nofile());
                    }
                }
                // Chased slot: byte-exact view from the frontier
                // buffer. Its RAM bytes (frontier + parked spans)
                // memcpy under the lock; the spans a stalled chase
                // paged to the holds scratch defer to preads like every
                // other paged read, because a drop-behind trim made
                // this arm's "RAM memcpy" claim untrue - a request
                // straddling the trim point does real disk I/O, and
                // every other extractor thread is waiting on this lock.
                // A drop-behind trim splits the request the same way:
                // the prefix it spilled is served from the slot's
                // archive file, on the deferred plan like any other
                // pread.
                SlotMode::RarChase | SlotMode::SevenZ => {
                    let ch = s.chase.as_ref().ok_or_else(nofile)?;
                    let base = ch.buf.base();
                    let end = off + buf.len() as u64;
                    if off < base {
                        let w = s.writer.as_ref().ok_or_else(nofile)?;
                        let n = (base.min(end) - off) as usize;
                        reads.push(Plan::W(w.clone(), 0, n, off));
                    }
                    if end > base {
                        let from = base.max(off);
                        let rel = (from - off) as usize;
                        let plans = ch.buf.plan_peek(from, &mut buf[rel..])?;
                        if !plans.is_empty() {
                            // The buffer's own scratch, not the level's:
                            // the plan offsets are regions of that file
                            // and of no other.
                            let sc = ch.buf.scratch().ok_or_else(nofile)?;
                            pin.pin(sc);
                            let f = sc.handle().ok_or_else(nofile)?;
                            for (bo, n, po) in plans {
                                reads.push(Plan::S(f.clone(), rel + bo, n, po));
                            }
                        }
                    }
                }
                // Unclassified slot: serve from pre-sniff holds when they
                // fully cover the range (see covered_intervals).
                SlotMode::Unknown => {
                    let request_len = buf.len() as u64;
                    let mut covered = Vec::with_capacity(s.holds.len());
                    for (hs, span) in &s.holds {
                        let he = hs + span.len() as u64;
                        let qs = off.max(*hs);
                        let qe = (off + buf.len() as u64).min(he);
                        if qs < qe {
                            let n = (qe - qs) as usize;
                            match span {
                                HoldSpan::Ram(bytes) => {
                                    buf[(qs - off) as usize..(qs - off) as usize + n]
                                        .copy_from_slice(
                                            &bytes[(qs - hs) as usize..(qs - hs) as usize + n],
                                        );
                                }
                                HoldSpan::Paged { off: po, .. } => {
                                    pin.pin(&inner.scratch);
                                    let f = inner.scratch.handle().ok_or_else(nofile)?;
                                    reads.push(Plan::S(f, (qs - off) as usize, n, po + (qs - hs)));
                                }
                            }
                            covered.push((qs - off, qe - off));
                        }
                    }
                    if !intervals_cover_all(covered, request_len) {
                        return Err(nofile());
                    }
                }
                SlotMode::Discard | SlotMode::SplitPart => return Err(nofile()),
            }
        }
        for r in reads {
            match r {
                Plan::W(w, buf_start, len, file_off) => {
                    w.read_at(&mut buf[buf_start..buf_start + len], file_off)?;
                }
                Plan::C(c, cs, buf_start, len, file_off) => {
                    c.read_at(cs, file_off, &mut buf[buf_start..buf_start + len])?;
                }
                Plan::X(cs, w, buf_start, len, file_off) => {
                    cs.read_posted(&w, file_off, &mut buf[buf_start..buf_start + len])?;
                }
                Plan::S(f, buf_start, len, file_off) => {
                    crate::disk::read_exact_at(
                        &f.1,
                        &mut buf[buf_start..buf_start + len],
                        file_off,
                    )?;
                }
            }
        }
        Ok(())
    }

    /// The reconstructible sub-ranges of `[off, off+len)` of a slot's
    /// byte space, in slot offsets: writer intervals for plain and
    /// materialized slots, header stash + destination coverage (writers
    /// and routed children alike, recursively) for mapped ones. The
    /// fallback read-back walks these so a sparse hole or an in-flight
    /// deferred write is never copied as zeros.
    pub fn covered_intervals(&self, slot: usize, off: u64, len: u64) -> Vec<(u64, u64)> {
        let inner = self.inner_read();
        // TODO 211 (b): ask in the head's logical space, answer in the
        // part's own.
        let (slot, delta) = Self::split_target(&inner, slot, 0);
        let ivs = Self::covered_intervals_in(&inner, slot, off + delta, len);
        if delta == 0 {
            return ivs;
        }
        ivs.into_iter()
            .map(|(a, b)| (a - delta, b - delta))
            .collect()
    }

    fn covered_intervals_in(inner: &Inner, slot: usize, off: u64, len: u64) -> Vec<(u64, u64)> {
        let s = &inner.slots[slot];
        match s.mode {
            SlotMode::Plain | SlotMode::RarFallback => s
                .writer
                .as_ref()
                .map(|w| w.covered_intervals(off, len))
                .unwrap_or_default(),
            // Same split as `covered`: a drop-behind trim moved the
            // prefix into the slot's archive file, and it is every bit
            // as reconstructible from there.
            SlotMode::RarChase | SlotMode::SevenZ => {
                let Some(ch) = s.chase.as_ref() else {
                    return Vec::new();
                };
                let base = ch.buf.base();
                let end = off + len;
                let mut ivs = Vec::new();
                if off < base
                    && let Some(w) = s.writer.as_ref()
                {
                    ivs.extend(w.covered_intervals(off, base.min(end) - off));
                }
                if end > base {
                    let from = base.max(off);
                    ivs.extend(ch.buf.intervals(from, end - from));
                }
                merge_intervals(ivs)
            }
            SlotMode::Rar => {
                let Some(m) = s.mapper.as_ref() else {
                    return Vec::new();
                };
                let end = off + len;
                let mut ivs: Vec<(u64, u64)> = Vec::new();
                // Header stash + held spans (see read_at: held bytes are
                // exact volume bytes awaiting a header parse, RAM or
                // paged alike).
                for (hs, span) in s.header_spans.iter().chain(&s.holds) {
                    let he = hs + span.len() as u64;
                    let a = off.max(*hs);
                    let b = end.min(he);
                    if a < b {
                        ivs.push((a, b));
                    }
                }
                for (ei, piece_off, span_off, plen) in m.map_span(off, len) {
                    let Some(base) = Self::base_for(inner, slot, ei) else {
                        continue;
                    };
                    let file_lo = base + piece_off;
                    let sub = match Self::dest_for(inner, slot, &m.entries[ei].name) {
                        Some(Dest::Writer(w)) => match Self::crypto_of(inner, &w) {
                            Some(cs) => cs.intervals(file_lo, plen),
                            None => w.covered_intervals(file_lo, plen),
                        },
                        Some(Dest::Child(c, cs)) => c.covered_intervals(cs, file_lo, plen),
                        None => Vec::new(),
                    };
                    // Translate file-space intervals back to slot space.
                    for (a, b) in sub {
                        ivs.push((
                            off + span_off + (a - file_lo),
                            off + span_off + (b - file_lo),
                        ));
                    }
                }
                merge_intervals(ivs)
            }
            // Unclassified slot: pre-sniff holds are exact file bytes at
            // file offsets (a nested child whose offset-0 header is the
            // very damage being repaired sits here).
            SlotMode::Unknown => {
                let end = off + len;
                let mut ivs: Vec<(u64, u64)> = Vec::new();
                for (hs, bytes) in &s.holds {
                    let he = hs + bytes.len() as u64;
                    let a = off.max(*hs);
                    let b = end.min(he);
                    if a < b {
                        ivs.push((a, b));
                    }
                }
                merge_intervals(ivs)
            }
            // An alias was translated to its head above.
            SlotMode::Discard | SlotMode::SplitPart => Vec::new(),
        }
    }

    /// M2c.1 - patch `[off, off+data.len())` of a mapped slot's VOLUME
    /// view with repaired bytes. Routed through the normal streaming
    /// [`write`] path: a rebuilt block is just late-arriving article
    /// data, so mapped pieces land in the extracted output, envelope
    /// bytes stash like any other header bytes, and - crucially - the
    /// volume parser resumes past what the lost articles interrupted
    /// (e.g. the end-of-archive record in a lost tail article), letting
    /// [`finish`] complete the group instead of falling back. The
    /// caller's whole-file MD5 over [`read_at`] remains the arbiter of
    /// whether the patch actually reconstructed the volume. The span
    /// carries the repair marker down the routing chain: rebuilt bytes
    /// REPLACE a range whose earlier (wire-damaged) arrival may already
    /// sit composed in the piece CRCs, and without the marker the
    /// composition would clip the rewrite as a duplicate and keep the
    /// stale value - demoting, at finish, a job whose output healed
    /// cleanly (see [`CrcRuns::overwrite`]).
    ///
    /// A PLAIN slot takes the same patch, and needs none of that
    /// machinery: its volume view IS its output file, so the span lands
    /// as an ordinary positioned write through `plain_job` (which marks
    /// writer coverage like any arrival) and there is no mapper, no
    /// entry, and therefore no `piece_crcs` composition to overwrite -
    /// the repair marker rides along inert. Admitting it is what keeps a
    /// set whose only damage is in a plain member on the mapped lane
    /// instead of demoting every chased volume beside it to disk (TODO
    /// 160).
    ///
    /// `RarFallback` is admitted too, and ONLY because a slot can reach
    /// it in the middle of this very repair. A rebuilt block landing on
    /// a chased slot conflicts inside `chase_span`, which forfeits
    /// before it returns - so the write that tripped it is already in
    /// the frontier buffer and materializes with the volume, and every
    /// REMAINING block of the same repair then arrives at a slot that
    /// demoted a moment ago. Refusing them used to cost the whole
    /// attempt: the write loop propagates the error, `repair_mapped`
    /// returns Err, and blocks already solved in memory are thrown away
    /// for the disk route to fetch recovery for and solve a second time
    /// (measured 23 Aug 2026 at test scale: 1 of 3 blocks written). The
    /// demote is synchronous and complete by the time `chase_span`
    /// returns - the frontier buffer is drained into the volume file and
    /// the holds after it - so a later span writes through `plain_job`
    /// onto a fully materialized volume, exactly as `chase_span`'s own
    /// doc promises ("a span landing after demotion writes through the
    /// slot's current mode like any late span").
    ///
    /// This does NOT put an already-materialized set on the mapped lane:
    /// the repair gate admits a slot by [`Self::is_mapped`],
    /// [`Self::is_plain_patchable`] or [`Self::is_chase_patchable`], and
    /// none of the three matches `RarFallback`. The only way to arrive
    /// here in that mode is to have demoted since. Nor does it weaken
    /// the conflict tripwire, which is the caller's post-check and fires
    /// on exactly this shape: the decode consumed stale bytes and the
    /// set must re-extract off disk. What changes is that the repair
    /// FINISHES first, so the disk route it declines to finds the set
    /// already verifying rather than half-repaired.
    ///
    /// [`write`]: Extractor::write
    /// [`finish`]: Extractor::finish
    /// [`read_at`]: Extractor::read_at
    pub fn patch_volume_span(&self, slot: usize, off: u64, data: &[u8]) -> io::Result<()> {
        let (name, size) = {
            let inner = self.inner.lock_ok();
            let s = &inner.slots[slot];
            if !matches!(
                s.mode,
                SlotMode::Rar
                    | SlotMode::Plain
                    | SlotMode::RarChase
                    | SlotMode::SplitPart
                    | SlotMode::RarFallback
            ) {
                return Err(nofile());
            }
            (s.name.clone(), s.size)
        };
        // Repair bytes REPLACE a range that may already have composed;
        // reuse is excluded for repair anyway.
        self.write_impl(slot, &name, size, off, data, true, None, None)
            .map(|_| ())
    }

    /// Every live output writer (extracted inner files + plain files) -
    /// the streaming server picks media files from this and polls their
    /// coverage. (name, writer).
    /// M11 seek support: translate a byte range of an OUTPUT file (a plain
    /// slot file, or an extracted inner file) to the source-volume pieces
    /// that carry it: `(slot, vol_start, vol_end, slot_total_size)`.
    /// Best-effort - only pieces whose group bases have resolved appear;
    /// `slot_total_size` is the volume's decoded size (0 if unknown yet),
    /// which the caller uses to scale offsets onto the article list.
    pub fn map_output_range(
        &self,
        name: &str,
        start: u64,
        end: u64,
    ) -> Vec<(usize, u64, u64, u64)> {
        let inner = self.inner_read();
        // Plain slot file: identity mapping on that slot.
        for (si, s) in inner.slots.iter().enumerate() {
            // Chased slot FIRST, keyed by name. A chase holds its bytes
            // in a frontier buffer, but since drop-behind trimming it
            // can also own a writer for the prefix it has spilled - and
            // that writer's filename may have been disambiguated, so
            // testing it first made this branch unreachable for exactly
            // the slots that need it.
            if matches!(s.mode, SlotMode::RarChase | SlotMode::SevenZ)
                && !s.name.is_empty()
                && sanitize_filename(&s.name) == name
            {
                return vec![(si, start.min(s.size), end.min(s.size), s.size)];
            }
            if let Some(w) = &s.writer {
                let fname = w.path.file_name().unwrap_or_default().to_string_lossy();
                if fname == name {
                    return vec![(si, start.min(w.size), end.min(w.size), w.size)];
                }
            }
        }
        // Extracted inner file: walk every resolved (volume-slot, entry)
        // piece of the archive and clip the requested inner range to it.
        // `bases` is a HashMap - pieces MUST be re-sorted by their output
        // offset, because callers (M11 seek promotion) treat the returned
        // order as the player's read order; unsorted, a range spanning a
        // volume boundary could promote the later volume's articles ahead
        // of the seek point's own.
        let mut pieces: Vec<(u64, (usize, u64, u64, u64))> = Vec::new();
        for g in inner.groups.values() {
            for (&(slot, ei), &base) in &g.bases {
                let Some(m) = inner.slots[slot].mapper.as_ref() else {
                    continue;
                };
                let Some(e) = m.entries.get(ei) else { continue };
                if e.is_dir {
                    continue;
                }
                // Look up by the RAW entry name (route_dest/inner_writer key);
                // the sanitized form is only the on-disk fallback name.
                let out_name = if let Some(&cs) = g.routed.get(&e.name) {
                    // A routed level-1 file is an OUTPUT only when its
                    // child slot went Plain (real file, possibly under a
                    // disambiguated name). Any other mode is still
                    // addressable by the entry name itself - a child
                    // slot's byte space is that file's byte space by
                    // construction, which is what the nested promote
                    // walk (map_to_root composition) asks by. Seek
                    // mapping INTO a nested archive's outputs stays out
                    // of scope for v1 - those fall to the non-mapped
                    // path.
                    match inner.child.as_ref().and_then(|c| c.plain_slot_out_name(cs)) {
                        Some(n) => n,
                        None => sanitize_filename(&e.name),
                    }
                } else {
                    g.out_names
                        .get(&e.name)
                        .cloned()
                        .unwrap_or_else(|| sanitize_filename(&e.name))
                };
                if out_name != name {
                    continue;
                }
                let piece_end = base + e.data_len;
                let s = start.max(base);
                let en = end.min(piece_end);
                if s < en {
                    pieces.push((
                        s,
                        (
                            slot,
                            e.data_off + (s - base),
                            e.data_off + (en - base),
                            inner.slots[slot].size,
                        ),
                    ));
                }
            }
        }
        let mut out: Vec<(usize, u64, u64, u64)> = Vec::new();
        if !pieces.is_empty() {
            pieces.sort_by_key(|(s, _)| *s);
            return pieces.into_iter().map(|(_, p)| p).collect();
        }
        // Deep seek past the parse frontier: bases resolve in volume order
        // behind the download, so a far-forward seek has no resolved piece
        // yet - exactly the case promotion exists for. Estimate instead:
        // volumes are uniform, so scale the inner offset across the
        // group's volume slots (±1 volume of slack; the caller's article
        // ladder adds its own).
        let Some(g) = inner
            .groups
            .iter()
            .find(|(k, g)| sanitize_filename(k) == name || g.out_names.values().any(|v| v == name))
            .map(|(_, g)| g)
        else {
            return out;
        };
        // Any resolved piece gives the per-volume data size + data offset.
        let Some((per_vol, data_off)) = g.bases.keys().find_map(|&(slot, ei)| {
            let e = inner.slots[slot].mapper.as_ref()?.entries.get(ei)?;
            (e.data_len > 0).then_some((e.data_len, e.data_off))
        }) else {
            return out;
        };
        let mut vols: Vec<usize> = g.slots.clone();
        vols.sort_by_key(|&si| vol_sort_key(&inner.slots[si].name));
        for (vi, &si) in vols.iter().enumerate() {
            let vbase = vi as u64 * per_vol;
            let s = start.max(vbase);
            let en = end.min(vbase + per_vol);
            if s < en {
                out.push((
                    si,
                    data_off + (s - vbase),
                    data_off + (en - vbase),
                    inner.slots[si].size,
                ));
            }
        }
        out
    }

    /// Publish full coverage for every output file an external repair
    /// has just VERIFIED (sweep 8, M5).
    ///
    /// `unpark` restores a parked writer's handle and deliberately
    /// keeps its interval map, on the reading that repair fills bytes
    /// in and never unwrites them. That is true of the bytes we wrote
    /// and silent about the ones we did not: external par2cmdline fills
    /// the sparse ranges that were MISSING, outside the writer, so a
    /// reader still gated on that map goes on waiting for bytes that
    /// are already correct on disk - or, once the dead-span verdict
    /// fires, zero-fills over them.
    ///
    /// `verified` is (filename, length) for each file the recovery set
    /// declares, and a writer must match BOTH: a name alone would mark
    /// a file we disagree about the size of, and a length alone matches
    /// anything. Files outside the set are untouched - par2's exit
    /// status says nothing about them. Returns how many writers were
    /// published, which is what a caller asserts on.
    pub fn publish_repaired_coverage(&self, verified: &[(String, u64)]) -> usize {
        let (writers, child) = {
            let g = self.inner.lock_ok();
            let mut ws: Vec<Arc<FileWriter>> = g.inner_writers.values().cloned().collect();
            ws.extend(g.slots.iter().filter_map(|s| s.writer.clone()));
            (ws, g.child.clone())
        };
        let mut n = 0;
        for w in &writers {
            let name = w
                .current_path()
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            if verified.iter().any(|(vn, vl)| *vn == name && *vl == w.size) {
                w.note_repaired(0, w.size);
                n += 1;
            }
        }
        if let Some(c) = child {
            n += c.publish_repaired_coverage(verified);
        }
        n
    }

    /// Every live output writer with the name its file has ON DISK
    /// RIGHT NOW.
    ///
    /// `current_path`, not `path` (sweep 8, M6): a verified-name publish
    /// renames an obfuscated slot's file under its open writer while the
    /// job is still finishing. Naming the snapshot from the immutable
    /// creation path made the live media pick judge a renamed file by a
    /// name that no longer exists - an extensionless creation name
    /// dropped the writer out of the pick entirely, and when both names
    /// looked like media the pick succeeded and the fresh open behind it
    /// went to the removed path and returned 410.
    pub fn writers_snapshot(&self) -> Vec<(String, Arc<FileWriter>)> {
        let (mut out, child) = {
            let inner = self.inner_read();
            let mut out: Vec<(String, Arc<FileWriter>)> = inner
                .inner_writers
                .iter()
                .map(|(n, w)| (n.clone(), w.clone()))
                .collect();
            for s in &inner.slots {
                if let Some(w) = &s.writer {
                    out.push((
                        w.current_path()
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string(),
                        w.clone(),
                    ));
                }
            }
            (out, inner.child.clone())
        };
        // Routed outputs (the common flat case included) live in the
        // child chain - the streaming server must see them.
        if let Some(c) = child {
            out.extend(c.writers_snapshot());
        }
        out
    }

    /// Output filename of a Plain slot (nested seek mapping: a routed
    /// level-1 file whose child slot went Plain IS the output file).
    /// Poison-tolerant like its caller: `map_output_range` calls this on
    /// the CHILD while holding the PARENT lock, so a poisoned child lock
    /// panicking here would poison the parent too and cascade upward.
    pub(super) fn plain_slot_out_name(&self, slot: usize) -> Option<String> {
        let inner = self.inner_read();
        let s = &inner.slots[slot];
        if !matches!(s.mode, SlotMode::Plain) {
            return None;
        }
        s.writer.as_ref().map(|w| {
            w.path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned()
        })
    }

    /// (name, size) of every slot-owned output file - what a PARENT folds
    /// into its report when this extractor is its child: a Plain slot is
    /// a level-N file delivered as-is, a RarFallback slot is a level-N
    /// archive materialized by a nested demotion (today's output either
    /// way).
    pub(super) fn slot_output_files(&self) -> Vec<(String, u64)> {
        let inner = self.inner.lock_ok();
        inner
            .slots
            .iter()
            .filter(|s| matches!(s.mode, SlotMode::Plain | SlotMode::RarFallback))
            .filter_map(|s| {
                s.writer.as_ref().map(|w| {
                    (
                        w.path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .into_owned(),
                        w.size,
                    )
                })
            })
            .collect()
    }

    /// Path of the slot's on-disk file (plain/materialized), if any -
    /// the file's CURRENT location, tracking any verified-name publish
    /// (see [`note_slot_renamed`](Self::note_slot_renamed)), since every
    /// caller uses this to find the file on disk.
    pub fn slot_path(&self, slot: usize) -> Option<PathBuf> {
        let inner = self.inner.lock_ok();
        inner.slots[slot].writer.as_ref().map(|w| w.current_path())
    }

    /// Bytes of the slot's declared file range that were never written.
    ///
    /// The writer is sized from the post's `=ybegin size`, and the
    /// decoder only ever validates a part against its OWN `=ypart`
    /// begin/end - never against that total. A post declaring 16 MiB
    /// and shipping one CRC-valid byte therefore leaves a file that is
    /// one byte plus a hole, with every article counter at zero
    /// (Codex sweep 3 Aug M7). The interval map already knows exactly
    /// which bytes arrived; this is the question nobody was asking it
    /// at completion.
    ///
    /// `None` for anything but a STABLY PLAIN slot, which is the only
    /// shape whose on-disk file is supposed to hold the whole declared
    /// range. A mapped or chased slot legitimately holds less: a
    /// trimmed 7z chase spills only the prefix the engine has passed
    /// and serves the rest from memory, and a mapped RAR volume owns no
    /// such file at all - counting either as short would fail healthy
    /// jobs.
    pub fn slot_uncovered(&self, slot: usize) -> Option<u64> {
        let w = self.stable_plain_writer(slot)?;
        let covered: u64 = w
            .covered_intervals(0, w.size)
            .iter()
            .map(|&(s, e)| e - s)
            .sum();
        Some(w.size.saturating_sub(covered))
    }

    /// Has this slot demoted to a materialized volume? A parked article
    /// completing after the demote may still carry fragments naming the
    /// inner files the fallback deleted - but the reconstruction put
    /// those same bytes at their final offsets in the volume file, so
    /// the journal writer rewrites them to identity form (the record
    /// lands after the slot's `M` line, whose positional rewrite
    /// deliberately does not reach forward).
    pub fn slot_materialized(&self, slot: usize) -> bool {
        matches!(self.inner.lock_ok().slots[slot].mode, SlotMode::RarFallback)
    }

    /// Does this MATERIALIZED slot's own volume file already hold every
    /// byte of `[off, off+len)`? Answers with the file's (name, size)
    /// when it does, so one lock settles mode, coverage and the name the
    /// record will carry.
    ///
    /// TODO 252 (23 Aug 2026): the journal writer parks an article that
    /// returned [`Persist::Held`](super::Persist) and completes it from
    /// the late placements the drains surface. A demote raises
    /// `refeed_active` so its whole reconstruction surfaces those
    /// placements - but the bytes can reach the volume by routes that
    /// report nothing: the post-write re-route in `write` (which
    /// deliberately returns `Persist::No`) and the forward-delivery
    /// re-check both run with the flag DOWN, and the read-back skips a
    /// range whose pwrite has not landed yet. The article then stayed
    /// parked for the life of the job and refetched on the next run -
    /// ~8% of runs standalone here, ~40% under a loaded suite, always
    /// exactly one article of the post.
    ///
    /// So ask the destination instead of the placement trail. This is
    /// the same claim the slot's `M` line makes, and it is a MEASURED
    /// one: [`FileWriter::covered`](crate::disk::FileWriter::covered) is
    /// the writer's own record of the pwrites that landed, so a range
    /// nothing wrote is a gap and stays parked (the safe direction, and
    /// the one a dropped-and-not-yet-refetched trim prefix takes - that
    /// refetch bypasses the writer entirely and reports no coverage).
    /// Every write that CAN reach a materialized volume puts posted
    /// bytes at their volume offsets: the header stash, the interval-
    /// gated inner read-back (through the re-encrypt shim for a
    /// plaintext-once output, so the volume takes cipher), the chase
    /// buffer, the hold drain, a post-demote write-through, and a repair
    /// patch. A wrong identity claim here is silent corruption on the
    /// next resume, so the slot's OWN writer is the only one consulted:
    /// no split translation (a `SplitPart` alias flips to
    /// `RarFallback` with its own file, whose offsets ARE the article
    /// offsets), and a slot with no writer of its own answers `None`.
    pub fn materialized_span_on_disk(
        &self,
        slot: usize,
        off: u64,
        len: u64,
    ) -> Option<(String, u64)> {
        let inner = self.inner.lock_ok();
        let s = inner.slots.get(slot)?;
        if !matches!(s.mode, SlotMode::RarFallback) {
            return None;
        }
        let w = s.writer.as_ref()?;
        // `covered` and not a walk over `covered_intervals`: the map is
        // kept sorted and MERGED, so a gap-free span is contained in one
        // interval by construction.
        w.covered(off, len).then(|| {
            (
                w.current_path()
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned(),
                w.size,
            )
        })
    }

    /// (file name, size) of the slot's on-disk file - what the journal
    /// records as the slot's restore destination. The LIVE path, not the
    /// creation-time one: a verified-name publish renames the file, and
    /// an `S` emitted afterwards must name the file replay will actually
    /// find (same rule as [`Self::slot_path`], and half of R3).
    pub fn slot_file_info(&self, slot: usize) -> Option<(String, u64)> {
        let inner = self.inner.lock_ok();
        inner.slots[slot].writer.as_ref().map(|w| {
            (
                w.current_path()
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned(),
                w.size,
            )
        })
    }

    /// Crash resume, REPLAY mode (§94 A): reserve `file_name` in the
    /// chain-wide name set without creating a writer for it.
    ///
    /// A replay reads the restored file and pushes its spans back
    /// through `write`, so the file is a live SOURCE for the whole run -
    /// but a fresh extractor starts with an empty `names_taken`, so an
    /// inner member sanitizing to the same name claimed it freely and
    /// the inner output writer opened the very inode the replay loop
    /// was still reading (Codex sweep 3 Aug H3). That both corrupts
    /// unread packed bytes and, when a small shape finishes, lets the
    /// all-good cleanup delete the extracted payload as if it were the
    /// spent source. Claiming the name here pushes the inner output to a
    /// disambiguated one, which is what the disk extractor achieves by
    /// staging into an isolated directory.
    /// `slot` is the slot the restored file BELONGS to, and it is
    /// load-bearing: without it the claim collided with the slot's own
    /// plain writer, `claim_name` disambiguated to `000-<name>`, and a
    /// resumed plain payload finished byte-perfect under a mangled name
    /// while PAR2 verified the orphaned restored stub and condemned it
    /// (1947/2000 blocks bad). A slot may adopt a name it preclaimed
    /// itself; nothing else may.
    pub fn preclaim_name(&self, slot: usize, file_name: &str) {
        let mut inner = self.inner.lock_ok();
        let key = name_collision_key(inner.fold_names, file_name);
        inner.names_taken.lock_ok().insert(key.clone());
        // First claimant owns. A map-mode replay preclaims one source
        // file under EVERY volume that reads it, in volume order, and
        // the grant must sit on the first volume - the one whose parse
        // founds the group - not on the last, which has not parsed when
        // the member routes (Codex F-03).
        inner.preclaimed.entry(key).or_insert(slot);
    }

    /// Crash resume: adopt `file_name` (already restored on disk by the
    /// journal, `spans` of it trusted) as this slot's plain writer. The
    /// slot classifies Plain immediately - refetched articles write
    /// through, and `covered`/`read_at` serve the restored spans to the
    /// M15b backfill so they hash against the PAR2 block map in-download.
    pub fn seed_slot(
        &self,
        slot: usize,
        file_name: &str,
        size: u64,
        spans: &[(u64, u64)],
    ) -> io::Result<()> {
        let mut g = self.inner.lock_ok();
        let inner = &mut *g;
        if inner.slots[slot].writer.is_some() {
            return Ok(());
        }
        let path = self.out_dir.join(file_name);
        let cur = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        // Same reservation ceiling every other writer gets: the journal's
        // `size` came from a slot size the poster declared, so it may not
        // reserve the disk either. `size.max(cur)` stays the writer's
        // `size` (the adopted spans and `s.size` below both read it) - the
        // cap bounds only what is RESERVED, and never below `cur`, so a
        // resumed file keeps every byte it already holds.
        let cap = inner.limits.prealloc_cap();
        let w = Arc::new(FileWriter::create_resume_capped(&path, size.max(cur), cap)?);
        for &(off, len) in spans {
            w.note_written(off, len);
        }
        inner
            .names_taken
            .lock_ok()
            .insert(name_collision_key(inner.fold_names, file_name));
        let s = &mut inner.slots[slot];
        s.mode = SlotMode::Plain;
        s.name = file_name.to_string();
        s.size = size.max(cur);
        s.writer = Some(w);
        // TODO 211 (b): a restored part is a file; its set is a disk set.
        self.split_slot_plain(inner, slot)?;
        Ok(())
    }

    /// Whether the slot is being direct-extracted (no on-disk volume).
    /// Deliberately does NOT consult routed child slots: verifier settle
    /// and mapped repair read the volume view through [`Self::read_at`],
    /// which delegates per range and fails only for ranges the chain
    /// truly cannot serve - a whole-slot veto here would push a healthy
    /// mapped slot onto the no-writer path (worse than a few bad blocks).
    ///
    /// TODO 211 (b): `SplitPart` answers YES, and that is the whole
    /// question this predicate exists to ask - an aliased split part is
    /// direct-extracted through its HEAD and owns no file whatever.
    /// [`Self::read_at`], [`Self::covered`], [`Self::covered_intervals`],
    /// [`Self::materialize`] and [`Self::patch_volume_span`] were all
    /// taught the alias when the mode landed; this seam was not, so
    /// `get::settle` sent every split part down the no-writer path,
    /// read its still-Pending blocks back against a file that does not
    /// exist, and marked EVERY one of them bad. A clean download then
    /// reported "N recovery block(s) needed but the NZB only carries
    /// M" and failed the job (§272, 23 Aug 2026 - the bytes on disk
    /// were byte-identical to the fixture in every captured failure).
    /// Load-dependent only in HOW MANY blocks were still Pending at
    /// settle, which is why it read as a flake: the shape is the same
    /// one `chase.rs` names when it says zip rides the 7z mode "rather
    /// than re-teaching a new mode to every `is_mapped` seam".
    pub fn is_mapped(&self, slot: usize) -> bool {
        matches!(
            self.inner.lock_ok().slots[slot].mode,
            SlotMode::Rar | SlotMode::SplitPart
        )
    }

    /// TODO 160 - may a mapped repair patch this slot's DAMAGED blocks in
    /// place, instead of declining the whole call to the materialize +
    /// `repair_dir` path? True for a plain slot that owns a writer and
    /// reads back as exactly the bytes it was posted as. Reads already
    /// work ([`Self::read_at`] serves a plain slot from its writer) and
    /// so do writes ([`Self::patch_volume_span`]); this is the admission
    /// test the repair gate asks before believing either.
    ///
    /// `plain_by_sniff` is the load-bearing half. A slot that reached
    /// Plain by GIVING UP - the spill/overflow backstop, which flips
    /// mode without ever seeing offset 0 - may well be a RAR volume
    /// whose header article was lost, and those keep declining to the
    /// path that has always owned them. Without that test this admits
    /// every spilled volume too, quietly moving the small-budget
    /// degradation shape off the disk lane it is pinned to.
    ///
    /// The crypto exclusion is the whole reason this is not a bare mode
    /// check. A plaintext-once output holds CIPHERTEXT on disk with its
    /// seams and tail padding in the crypto stashes, and the plain
    /// read/write pair goes straight at the writer - `read_at`'s plain
    /// arm never consults `crypto_of` and `plain_job` sets no `crypto`
    /// on the job. Repair bytes are posted-domain, so patching one
    /// through here would write plaintext into a ciphertext file and
    /// then "verify" it by reading the same wrong bytes back. Those
    /// slots decline and take the fallback, exactly as before.
    pub fn is_plain_patchable(&self, slot: usize) -> bool {
        let inner = self.inner_read();
        let s = &inner.slots[slot];
        if !matches!(s.mode, SlotMode::Plain) || !s.plain_by_sniff {
            return false;
        }
        let Some(w) = s.writer.as_ref() else {
            return false;
        };
        Self::crypto_of(&inner, w).is_none()
    }

    /// Is this slot being CHASED - its bytes retained in a frontier
    /// buffer rather than written to a file? Like a mapped slot it has
    /// no on-disk copy, so PAR2 read-back must come through
    /// [`Self::read_at`] and a repair that wants volume files must
    /// [`Self::materialize`] it first; unlike a mapped slot it cannot
    /// take a [`Self::patch_volume_span`] rewrite, so mapped repair has
    /// to decline it. Only reachable at depth 0 for a posted `.7z`
    /// (TODO 37 step 1); nested chases live below the caller's view.
    pub fn is_chased(&self, slot: usize) -> bool {
        matches!(
            self.inner.lock_ok().slots[slot].mode,
            SlotMode::RarChase | SlotMode::SevenZ
        )
    }

    /// Shape-coverage row 26 - may a mapped repair patch this CHASED
    /// slot's damaged blocks straight into its frontier buffer, instead
    /// of declining the whole call to the materialize + `repair_dir` +
    /// unpack path that costs three writes of the payload?
    ///
    /// The admission is deliberately narrow, and each term is load-
    /// bearing rather than defensive:
    ///
    /// - **`RarChase` only.** The 7z chase reads at arbitrary offsets
    ///   and its set is a byte split whose members share one ctl, so a
    ///   member's forfeit takes the container with it; it is a separate
    ///   account (see the design note). Row 26 as measured is RAR.
    /// - **The chase is still attached and its buffer live.** A slot
    ///   that already forfeited has volume files, which is the ordinary
    ///   path.
    /// - **Nothing was DROPPED.** A dropping trim released the consumed
    ///   prefix with no copy anywhere ([`ChaseSlot::dropped`]); a repair
    ///   there has nothing to patch and the re-fetch that fixes a demote
    ///   (`get/dropped.rs`) has no equivalent here.
    /// - **The buffer has not already conflicted.** Sticky, and it means
    ///   the decode consumed bytes a rewrite has since corrected.
    ///
    /// What is NOT in the list, on purpose: any test that the damaged
    /// blocks sit ahead of the decode. The decode is forward-only and a
    /// blocking read parks at a hole, so it cannot have consumed a
    /// block that never arrived - and where bytes DID arrive and are
    /// wrong, byte-comparing them against the rebuilt copy is exactly
    /// what [`FrontierBuffer::write_span`] already does. The verdict is
    /// therefore read once, afterwards, from
    /// [`Self::chase_repair_conflicted`], under the pause that makes
    /// the whole patch atomic against the engine
    /// ([`Self::pause_chase_reads`]).
    pub fn is_chase_patchable(&self, slot: usize) -> bool {
        let inner = self.inner_read();
        let s = &inner.slots[slot];
        if !matches!(s.mode, SlotMode::RarChase) {
            return false;
        }
        let Some(ch) = s.chase.as_ref() else {
            return false;
        };
        ch.dropped.is_empty() && !ch.buf.conflicted()
    }

    /// Did patching this chased slot rewrite bytes its decode had
    /// already consumed? Read AFTER the whole set is patched and under
    /// the same pause - see [`Self::is_chase_patchable`]. True means the
    /// in-place route is off for this repair: the buffer holds the
    /// corrected bytes either way, so the caller's fall-through
    /// materializes an exact volume, which is what it would have done
    /// from the start.
    ///
    /// A slot whose chase is GONE by the time this runs conflicted in
    /// the strongest possible sense - `chase_span` forfeits the moment
    /// it sees the flag - so an absent chase reads as true.
    pub fn chase_repair_conflicted(&self, slot: usize) -> bool {
        let inner = self.inner_read();
        match inner.slots[slot].chase.as_ref() {
            Some(ch) => ch.buf.conflicted(),
            None => matches!(
                inner.slots[slot].mode,
                SlotMode::RarChase | SlotMode::SevenZ | SlotMode::RarFallback
            ),
        }
    }

    /// Has this slot given up on its in-RAM view and materialized its
    /// volume to disk since the repair gate admitted it?
    ///
    /// The gate admits a slot by [`Self::is_mapped`],
    /// [`Self::is_plain_patchable`] or [`Self::is_chase_patchable`], and
    /// none of the three matches `RarFallback` - so on a slot the gate
    /// passed, this reading true means the demote happened DURING the
    /// patch. That matters because a demote deletes the group's
    /// partially-extracted inner files (`delete_group_out_files`): the
    /// repair can still finish onto the materialized volumes and the
    /// self-prove still passes, but there is no extracted output left
    /// for the caller to claim, so the set has to re-extract off disk.
    ///
    /// Read AFTER the whole set is patched, alongside
    /// [`Self::chase_repair_conflicted`] - which covers the chased slots
    /// and names the sharper reason when it fires, since a forfeited
    /// chase reads true here too. This one is what catches a MAPPED slot
    /// that demoted for a reason of its own (a budget breach, a mapping
    /// error) with no conflict to report.
    ///
    /// `Discard` is folded in as the other "this slot no longer owns its
    /// bytes" ending. Unreachable from the daemon - it needs
    /// `protect_sources`, which the download path never sets - but it is
    /// the same answer to the same question.
    pub fn demoted_to_disk(&self, slot: usize) -> bool {
        matches!(
            self.inner.lock_ok().slots[slot].mode,
            SlotMode::RarFallback | SlotMode::Discard
        )
    }

    /// The RAR flavor of [`Self::is_chased`] alone. The distinction
    /// matters to exactly one caller: a `.7z` materialized for repair is
    /// the 7z post-pass's own input, but a RAR chase demoted the same
    /// way has NO later owner - "materialized for repair" is excluded
    /// from the unrar ladder on the promise that the PAR2 path
    /// re-extracts what it materialized, so the repair path must claim
    /// the set for `reextract_dir` or the job ships packed volumes as
    /// its output with exit 0.
    pub fn is_rar_chased(&self, slot: usize) -> bool {
        matches!(self.inner.lock_ok().slots[slot].mode, SlotMode::RarChase)
    }

    /// PAR2 deobfuscation rename: update the name a future materialization
    /// (or plain-writer creation) will use.
    pub fn rename(&self, slot: usize, new_name: &str) {
        let mut inner = self.inner.lock_ok();
        if inner.slots[slot].writer.is_none() {
            inner.slots[slot].name = new_name.to_string();
            // `sort_key` caches vol_sort_key(name), so renaming without
            // clearing it freezes the PRE-rename ordering for the life of the
            // slot - and `resolve_stamp` does not include the name either, so
            // a later parse progression would not recompute it. Latent today
            // (an obfuscated name sorts as u64::MAX, so the group has already
            // fallen back to materialize+unrar by the time PAR2 renames it),
            // but the cache is only safe if every mutator invalidates.
            inner.slots[slot].sort_key = None;
        }
    }

    /// The on-disk file behind `slot` was renamed (verified-name publish);
    /// keep its writer's by-path reopen in step - see
    /// [`FileWriter::note_renamed`](crate::disk::FileWriter::note_renamed).
    /// No-op for writerless slots: those go through [`rename`](Self::rename),
    /// which retargets the name BEFORE any writer is created.
    pub fn note_slot_renamed(&self, slot: usize, new_path: std::path::PathBuf) {
        let (w, materialized, hook) = {
            let inner = self.inner.lock_ok();
            let s = &inner.slots[slot];
            (
                s.writer.clone(),
                matches!(s.mode, SlotMode::RarFallback | SlotMode::Plain),
                inner.materialized.clone(),
            )
        };
        if let Some(w) = w {
            w.note_renamed(new_path.clone());
            // A MATERIALIZED slot's journal identity must follow the
            // rename. Its `M` record rewrote every placed fragment to
            // identity form under the then-current name, and the
            // in-memory `renamed_to` above reaches no journal line - so
            // after a crash, replay went looking for the OLD file, found
            // nothing, and refetched a complete verified volume sitting
            // right there under its new name (Codex sweep 13 Aug R3).
            // Re-firing the materialized hook appends `S new-name` + `M`
            // in one write: last-S-wins retargets the destination and
            // the positional M rewrites the already-identity fragments
            // to the new name. Root level only, like the hook install -
            // the journal records in the root's slot space.
            //
            // Plain slots need the same retarget (14 Aug sweep): their
            // placements are identity-form by construction (file offset
            // == volume offset, the slot's own file) but the S line and
            // fragments carry the posted name, so after this rename a
            // replay looked for the OLD file, found nothing, and
            // refetched a complete verified payload. The M contract
            // holds trivially for a plain write-through file; fragments
            // placed after the rename still carry the creation-time name
            // and refetch, which is the pre-existing post-M rule.
            if self.depth == 0
                && materialized
                && let Some(h) = hook
                && let Some(name) = new_path.file_name()
            {
                h(slot, &name.to_string_lossy(), w.size);
            }
        }
    }

    /// Which SOURCE VOLUME SLOTS fed each direct-extracted output file.
    ///
    /// The failed-job quarantine asks this so it can withhold only the
    /// payload a still-holed volume touched, instead of every file the
    /// job produced (TODO 159 item 1: a post whose PAR2 set covers two
    /// of three archives had both repaired files withheld along with the
    /// unrecoverable one). Deliberately answers at GROUP granularity,
    /// not per piece: a solid or multi-volume set's members can draw
    /// bytes from any volume in the group, and `bases` only records the
    /// pieces resolution has reached - so every volume of the group is
    /// named as a source of every file that group wrote.
    ///
    /// Being ABSENT from the map is the answer for anything this level
    /// cannot speak for, and every caller must read it that way: a
    /// nested (`routed`) or chased member is written by the child chain
    /// under a name this level never sees, and a group-less slot writes
    /// through a bare `inner_writers` key that no group owns. The map is
    /// therefore a positive claim about the names it lists and says
    /// nothing at all about the rest.
    ///
    /// `None` - no claim about ANY file - when a mapped slot has no
    /// group. Such a slot writes through the group-less branch of
    /// `inner_writer`, which reuses an existing writer by sanitized
    /// name, so it could be feeding a file some group's `out_names`
    /// also claims, and every entry below would then be understating
    /// its sources.
    pub fn payload_sources(&self) -> Option<HashMap<String, Vec<usize>>> {
        let inner = self.inner.lock_ok();
        if inner
            .slots
            .iter()
            .any(|s| matches!(s.mode, SlotMode::Rar) && s.group.is_none())
        {
            return None;
        }
        // Parent lock held across the child lookups, the same order
        // `map_output_range` takes (and for the same reason: the route
        // being read lives in the parent). `direct_slot_out_name` is
        // poison-tolerant so a panicking child cannot cascade upward.
        let child = inner.child.clone();
        let mut out: HashMap<String, Vec<usize>> = HashMap::new();
        for g in inner.groups.values() {
            let mut srcs = g.slots.clone();
            srcs.sort_unstable();
            srcs.dedup();
            // Members this level wrote to its own file: nesting off,
            // or an encrypted store set, which never routes.
            let names = g.out_names.values().cloned().chain(
                // Routed members: with nesting on - the default - an
                // inner file is a CHILD slot, and it is that slot's
                // own file that gets delivered. Only a slot that IS an
                // output answers; a routed member that turned out to be
                // another archive is extracted one level further down,
                // and those outputs stay unattributed here.
                g.routed
                    .values()
                    .filter_map(|&cs| child.as_ref().and_then(|c| c.direct_slot_out_name(cs))),
            );
            for name in names {
                out.entry(name).or_default().extend(srcs.iter().copied());
            }
        }
        for srcs in out.values_mut() {
            srcs.sort_unstable();
            srcs.dedup();
        }
        Some(out)
    }

    /// Output filename of a slot that IS a delivered file - a Plain
    /// slot, or an archive a nested demote materialized. Exactly the
    /// filter [`slot_output_files`](Self::slot_output_files) folds into
    /// the parent's report, so the name matches the one the report
    /// carries. `None` for a slot still being extracted THROUGH, whose
    /// outputs belong to the level below.
    ///
    /// Poison-tolerant for the same reason as
    /// [`plain_slot_out_name`](Self::plain_slot_out_name): the caller
    /// holds the PARENT lock while calling this on the child.
    pub(super) fn direct_slot_out_name(&self, slot: usize) -> Option<String> {
        let inner = self.inner_read();
        let s = inner.slots.get(slot)?;
        if !matches!(s.mode, SlotMode::Plain | SlotMode::RarFallback) {
            return None;
        }
        s.writer.as_ref().map(|w| {
            w.path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned()
        })
    }

    /// Force materialization of a slot's group (e.g. PAR2 repair needs the
    /// volume files on disk).
    pub fn materialize(&self, slot: usize) -> io::Result<()> {
        {
            let mut inner = self.inner.lock_ok();
            let inner = &mut *inner;
            // TODO 211 (b): materializing a split part materializes
            // the set; the head's reconstruction writes every part.
            let (slot, _) = Self::split_target(inner, slot, 0);
            if matches!(
                inner.slots[slot].mode,
                SlotMode::Rar | SlotMode::RarChase | SlotMode::SevenZ
            ) {
                // chase_forfeit, NOT fallback_slot_or_group: a 7z slot is one
                // part of a container and a byte split has no useful half, so
                // demoting one member has to take every member with it. See
                // that function's own comment for what the single-slot route
                // costs - it drains the container's shared sink list, so the
                // payload is deleted while the siblings stay in SevenZ with
                // the set un-aborted, and sevenz_finish then takes the
                // SURVIVORS' success path and drops their retained bytes.
                //
                // The in-crate demote routes were moved onto chase_forfeit;
                // this public entry point was left behind, and PAR2 repair
                // reaches it whenever a set's parts are not all claimed by
                // the recovery set (multi-par2 NZB, or a part outside it).
                self.chase_forfeit(inner, slot, "materialized for repair")?;
            }
        }
        self.flush_pending_fwd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rar::fixtures;

    use crate::extract::testutil::*;

    #[test]
    fn interval_coverage_matches_byte_oracle() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        for len in [0usize, 1, 2, 17, 257] {
            for _ in 0..500 {
                let mut intervals = Vec::new();
                let mut bytes = vec![false; len];
                let count = (state as usize % 24) + 1;
                for _ in 0..count {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    let a = if len == 0 {
                        0
                    } else {
                        state as usize % (len + 1)
                    };
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    let b = if len == 0 {
                        0
                    } else {
                        state as usize % (len + 1)
                    };
                    let (start, end) = (a.min(b), a.max(b));
                    intervals.push((start as u64, end as u64));
                    bytes[start..end].fill(true);
                }
                assert_eq!(
                    intervals_cover_all(intervals, len as u64),
                    bytes.iter().all(|&b| b),
                    "length {len}"
                );
            }
        }
    }

    /// M2c.1: patch_volume_span heals holes in a mapped volume - data
    /// bytes land in the extracted output, envelope bytes (including an
    /// end-of-archive record that never arrived) re-enter the parser so
    /// finish() completes without a fallback, and read_at serves the
    /// patched view byte-exactly.
    #[test]
    fn patch_volume_span_writes_through_the_mapping() {
        let dir = tmpdir("patch");
        let total = payload(500_000, 9);
        let vols: Vec<Vec<u8>> = vec![
            fixtures::rar5_volume(&[("film.mkv", 500_000, &total[..200_000], false, true)]),
            fixtures::rar5_volume(&[("film.mkv", 500_000, &total[200_000..400_000], true, true)]),
            fixtures::rar5_volume(&[("film.mkv", 500_000, &total[400_000..], true, false)]),
        ];
        let ex = Extractor::new(&dir, 3, true);
        feed(&ex, 0, "x.part1.rar", &vols[0], 9000, 21);
        // Volume 2: a mid-data article lost. Volume 3: the TAIL article
        // lost - it carried the end-of-archive record, so the volume
        // parser stalls there until the patch feeds it back.
        let art = 9000usize;
        let v3_tail = (vols[2].len() - 1) / art * art;
        for (si, v, skip) in [(1usize, &vols[1], 45_000usize), (2, &vols[2], v3_tail)] {
            let mut i = 0;
            while i < v.len() {
                let e = (i + art).min(v.len());
                if i != skip {
                    ex.write(
                        si,
                        &format!("x.part{}.rar", si + 1),
                        v.len() as u64,
                        i as u64,
                        &v[i..e],
                    )
                    .unwrap();
                }
                i = e;
            }
        }
        assert!(!ex.covered(1, 45_000, art), "hole really is a hole");
        // Patch the holes with repaired bytes (here: the originals).
        ex.patch_volume_span(1, 45_000, &vols[1][45_000..54_000])
            .unwrap();
        ex.patch_volume_span(2, v3_tail as u64, &vols[2][v3_tail..])
            .unwrap();
        // read_at serves both healed volume views byte-exactly…
        for si in [1usize, 2] {
            let mut back = vec![0u8; vols[si].len()];
            ex.read_at(si, 0, &mut back).unwrap();
            assert_eq!(back, vols[si], "volume {si} view healed");
        }
        // …and the parser resumed past the lost tail: no fallback, the
        // extracted output is pristine, no volume ever materialized.
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
        assert!(!dir.join("x.part2.rar").exists(), "no volume materialized");
        assert!(!dir.join("x.part3.rar").exists(), "no volume materialized");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_at_reconstructs_volume_bytes() {
        let dir = tmpdir("readat");
        let data = payload(150_000, 4);
        let vol = fixtures::rar5_volume(&[("inner.bin", 150_000, &data, false, false)]);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &vol, 6000, 21);
        // Reconstruct arbitrary volume ranges byte-exactly.
        for (off, len) in [(0usize, 64), (5, 200), (100, 149_000), (0, vol.len())] {
            let mut buf = vec![0u8; len.min(vol.len() - off)];
            ex.read_at(0, off as u64, &mut buf).unwrap();
            assert_eq!(&buf[..], &vol[off..off + buf.len()], "range {off}+{len}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The crash-resume adoption path had the same hole as the writer
    /// paths above: `seed_slot` handed the journal's declared size to an
    /// UNcapped `create_resume`. Same ceiling, same reasoning - and the
    /// legitimate half still reserves in full.
    #[test]
    fn seed_slot_reserves_under_the_ceiling_and_in_full_below_it() {
        let dir = tmpdir("prealloc-seed");
        const HUGE: u64 = 8 << 40;
        const POSTED: u64 = 8_000_000;
        // enabled=false, resume=true: exactly how `main` builds the
        // extractor for a resumed run.
        let ex = Extractor::with_resume(&dir, 2, false, true);
        ex.set_prealloc_ceiling(POSTED);

        ex.seed_slot(0, "inflated.bin", HUGE, &[]).unwrap();
        assert_eq!(
            std::fs::metadata(dir.join("inflated.bin")).unwrap().len(),
            POSTED,
            "a journal size past the posted ceiling must not reserve past it"
        );
        ex.seed_slot(1, "legit.bin", 4_000_000, &[]).unwrap();
        assert_eq!(
            std::fs::metadata(dir.join("legit.bin")).unwrap().len(),
            4_000_000,
            "a legitimate resumed file under the ceiling must still be reserved in full"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The regression this fix must never cause: resume adoption may not
    /// shrink a file below the bytes an earlier run already restored into
    /// it, however small the ceiling.
    #[test]
    fn seed_slot_never_shrinks_the_bytes_a_resume_already_holds() {
        let dir = tmpdir("prealloc-seed-cur");
        let restored = payload(400_000, 3);
        std::fs::write(dir.join("part.bin"), &restored).unwrap();
        let ex = Extractor::with_resume(&dir, 1, false, true);
        ex.set_prealloc_ceiling(1024); // absurdly small on purpose
        ex.seed_slot(0, "part.bin", 8 << 40, &[(0, 400_000)])
            .unwrap();
        assert_eq!(
            std::fs::metadata(dir.join("part.bin")).unwrap().len(),
            400_000
        );
        assert_eq!(std::fs::read(dir.join("part.bin")).unwrap(), restored);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A decode-side panic while holding the routing lock poisons it;
    /// the READ accessors (the daemon's live /stream and stats paths)
    /// must recover the guard and keep serving instead of cascading the
    /// panic into every later call (see `inner_read`). The expected
    /// "panicked at" line this prints is the deliberately-poisoning
    /// helper thread, not a failure.
    #[test]
    fn poisoned_lock_still_serves_read_accessors() {
        let dir = tmpdir("poison");
        let data = payload(60_000, 94);
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        // A plain output file, fully written.
        ex.write(0, "file.bin", data.len() as u64, 0, &data)
            .unwrap();
        // Poison the routing lock: a thread panics while holding it -
        // the decode-worker failure mode.
        let ex2 = ex.clone();
        let h = std::thread::spawn(move || {
            let _g = ex2.inner.lock().unwrap();
            panic!("decode-side panic under the routing lock (expected)");
        });
        assert!(h.join().is_err(), "helper thread must have panicked");
        assert!(ex.inner.is_poisoned(), "lock must be poisoned");
        // Every read accessor still answers from the snapshot.
        assert!(ex.covered(0, 0, data.len()));
        let mut buf = vec![0u8; data.len()];
        ex.read_at(0, 0, &mut buf).unwrap();
        assert_eq!(buf, data);
        assert_eq!(
            ex.covered_intervals(0, 0, data.len() as u64),
            vec![(0, data.len() as u64)]
        );
        assert_eq!(ex.writers_snapshot().len(), 1);
        assert_eq!(
            ex.map_output_range("file.bin", 0, 1000),
            vec![(0, 0, 1000, data.len() as u64)]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Invertibility with routing live: `read_at` over outer-volume
    /// ranges returns byte-identical data - outer header regions, the
    /// region carrying the INNER archive's headers (served from the
    /// child's stash), and deep data regions (served from the final
    /// files, two delegation hops down). This is the property verifier
    /// settle and mapped repair stand on.
    #[test]
    fn nested_read_at_reconstructs_outer_volume_bytes() {
        let a = payload(220_000, 87);
        let inner_arch = fixtures::rar5_volume(&[("A.mkv", 220_000, &a, false, false)]);
        let n = inner_arch.len();
        let cut = n / 2;
        let vols: Vec<Vec<u8>> = vec![
            fixtures::rar5_volume_n(
                &[("inner.rar", n as u64, &inner_arch[..cut], false, true)],
                0,
            ),
            fixtures::rar5_volume_n(
                &[("inner.rar", n as u64, &inner_arch[cut..], true, false)],
                1,
            ),
        ];
        let dir = tmpdir("nestedreadat");
        let ex = Extractor::new(&dir, 2, true);
        feed(&ex, 0, "x.part1.rar", &vols[0], 6000, 31);
        feed(&ex, 1, "x.part2.rar", &vols[1], 6000, 32);
        // Whole volumes, byte-exact, mid-download (mapped mode).
        for (si, vol) in vols.iter().enumerate() {
            let mut back = vec![0u8; vol.len()];
            ex.read_at(si, 0, &mut back).unwrap();
            assert_eq!(&back, vol, "volume {si} view");
            assert!(ex.covered(si, 0, vol.len()), "volume {si} coverage");
        }
        // Targeted ranges: outer header bytes; the outer data-area start,
        // which carries the inner archive's own headers; straddling and
        // deep data ranges; the tail (end-of-archive record).
        for &(si, off, len) in &[
            (0usize, 0usize, 64usize),
            (0, 8, 120),
            (0, 40, 9000),
            (0, cut / 2, 9000),
            (1, 0, 300),
            (1, 100, 5000),
            (1, vols[1].len() - 4000, 4000),
        ] {
            let mut buf = vec![0u8; len.min(vols[si].len() - off)];
            ex.read_at(si, off as u64, &mut buf).unwrap();
            assert_eq!(
                &buf[..],
                &vols[si][off..off + buf.len()],
                "range slot {si} {off}+{len}"
            );
        }
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("A.mkv")).unwrap(), a);
        assert_eq!(dir_files(&dir), vec!["A.mkv".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
