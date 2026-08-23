//! The 7-Zip and ZIP container paths: attach, the worker threads that
//! drive `sevenz_rust2` / the zip reader, the split-set join and its
//! fallbacks, and the trim that shortens an over-declared set.
//!
//! Split out of the 19,920-line `extract.rs` under the TODO 43 recipe:
//! a verbatim move of the methods, not a redesign.

use super::*;
use crate::sync::MutexExt;

impl Extractor {
    /// Attach the 7z chase (phase 3) to a child slot whose offset-0
    /// sniff found 7z magic: parse the start header for the end-header
    /// (footer) range, flip the slot to SevenZ, seed a frontier buffer
    /// with everything held so far, and spawn the worker - which first
    /// asks the chain above to front-load the footer's articles (tail
    /// prefetch), then parses and decodes through a blocking Read+Seek
    /// view as bytes arrive. Returns false when ineligible - the slot
    /// then classifies Plain and materializes exactly as before.
    ///
    /// TODO 37 step 1: this runs at depth 0 too, so a POSTED single-file
    /// `.7z` joins the chase and its payload streams out while the
    /// archive downloads. Nothing about the engine is depth-specific -
    /// the guard predated the root promote wiring (see
    /// [`Self::promote_slot_spans`]).
    ///
    /// TODO 37 step 3: a `.7z.001` SPLIT SET joins too. 7z multipart is
    /// a raw byte split, so the set is one container with seams in it:
    /// part 1 carries the start header, and because a 7z end header is
    /// the last thing in a container, `32 + offset + size` reads off as
    /// the size of the WHOLE set - which is how a chase that has only
    /// seen part 1 already knows how far the container runs and where
    /// its map lives. Parts `.002+` carry no signature at all and are
    /// recognized by name; they join the set their base names them into.
    ///
    /// TODO 94 C: `archive_base` is where the container starts inside the
    /// posted file - 0 for a bare `.7z`, the launcher stub's length for a
    /// self-extractor whose signature the offset-0 sniff confirmed behind
    /// it. The start header is read there, the tail range it declares is
    /// shifted by it, and the engine's view ([`ChainedSeekReader`])
    /// subtracts it, so the set, the watermark and the trim all keep
    /// speaking CONTAINER (file) offsets. A stubbed container is never a
    /// split: the signature is found in the first file, whose name is no
    /// part name.
    pub(super) fn try_attach_sevenz(
        &self,
        inner: &mut Inner,
        slot: usize,
        data: &[u8],
        archive_base: u64,
    ) -> io::Result<bool> {
        if (self.depth == 0 && !inner.top_sevenz_on)
            || !inner.nested_on
            || !inner.sevenz_on
            || inner.protect_sources
            || inner.slots[slot].size == 0
            || inner.self_weak.upgrade().is_none()
        {
            return Ok(false);
        }
        let size = inner.slots[slot].size;
        let part = sevenz_part_name(&inner.slots[slot].name);
        // A continuation part: no signature to sniff, so its name is the
        // only thing that identifies it. It joins the container open
        // under its base, or opens a PENDING one - nothing guarantees
        // `.001` classifies first, and a part that materialized because
        // it arrived early can never be taken back.
        if let Some((base, idx)) = part.clone()
            && idx > 1
        {
            let ctl = match inner.sevenz_sets.get(&base) {
                Some(c) => c.clone(),
                None => {
                    let c = Arc::new(SevenZCtl::pending(base.clone()));
                    inner.sevenz_sets.insert(base, c.clone());
                    c
                }
            };
            return self.sevenz_join_set(inner, slot, ctl, idx);
        }
        let Some(head) = usize::try_from(archive_base)
            .ok()
            .and_then(|b| data.get(b..))
        else {
            return Ok(false);
        };
        let Some((ho, hs)) = sevenz_start_header(head) else {
            return Ok(false);
        };
        let tail = 32u64
            .checked_add(archive_base)
            .and_then(|s| s.checked_add(ho))
            .and_then(|s| s.checked_add(hs).map(|e| (s, e)));
        let Some((tail_start, tail_end)) = tail else {
            return Ok(false);
        };
        if hs == 0 {
            return Ok(false);
        }
        // Split only when the end header genuinely lies past this file:
        // a `.7z.001` whose map fits inside itself is a self-contained
        // container that merely got a part-numbered name.
        let split = matches!(part, Some((_, 1))) && tail_end > size && archive_base == 0;
        // A split's whole geometry comes from ONE attacker-controlled
        // start header, so bound it before anything downstream trusts
        // it. 7-Zip's own naming tops out well below this; a header
        // declaring a container of 2^62 would otherwise park every
        // `.7z.NNN` in the job in RAM until the retention cap tripped.
        if split && tail_end.div_ceil(size.max(1)) > SEVENZ_MAX_PARTS as u64 {
            return Ok(false);
        }
        if !split && tail_end > size {
            // Not a split (no part name) and the map is past the end:
            // truncated, or not a container we can drive. Materialize.
            return Ok(false);
        }
        let (part_size, total) = if split {
            (size, tail_end)
        } else {
            (size, size)
        };
        let key = if split {
            part.as_ref().map(|(b, _)| b.clone()).unwrap_or_default()
        } else {
            String::new()
        };
        // Parts that arrived ahead of this one are already waiting under
        // the base name; resolving their set is what turns them from
        // bytes-on-trust into a mapped container.
        let ctl = match inner.sevenz_sets.get(&key) {
            Some(c) if !key.is_empty() => {
                let c = c.clone();
                if !c.set.resolve(part_size, total) {
                    self.sevenz_fallback_set(inner, &c, "7z split parts do not line up")?;
                    return Ok(false);
                }
                c
            }
            _ => {
                let c = Arc::new(SevenZCtl {
                    set: Arc::new(SevenZSet::new(part_size, total)),
                    key: key.clone(),
                    archive_base,
                    low_water: Arc::new(AtomicU64::new(0)),
                    tail: Mutex::new(None),
                    trim_ok: std::sync::atomic::AtomicBool::new(false),
                    worker: Mutex::new(None),
                    sink_slots: Mutex::new(Vec::new()),
                    outcome: Mutex::new(None),
                });
                if !key.is_empty() {
                    inner.sevenz_sets.insert(key.clone(), c.clone());
                }
                c
            }
        };
        *ctl.tail.lock_ok() = Some((tail_start, tail_end));
        // Commit part 1. The worker starts now: it has the whole map's
        // location, and blocks on the parts it has not been given yet
        // exactly as it blocks on bytes that have not arrived.
        let joined = self.sevenz_join_set(inner, slot, ctl.clone(), 1)?;
        if !joined {
            if !ctl.key.is_empty() {
                inner.sevenz_sets.remove(&ctl.key);
            }
            return Ok(false);
        }
        let weak = inner.self_weak.clone();
        let pw = inner.password.clone();
        let ctl2 = ctl.clone();
        let handle = std::thread::Builder::new()
            .name("nzb-7z-chase".into())
            .spawn(move || Self::sevenz_worker(weak, ctl2, (tail_start, tail_end), pw))
            .map_err(io::Error::other)?;
        *ctl.worker.lock_ok() = Some(handle);
        Ok(true)
    }
    /// Attach `slot` to a 7z container as its part `idx`: flip the slot
    /// to SevenZ, seed a frontier buffer with everything held so far,
    /// and register it with the set. Shared by the single-part case
    /// (which is just part 1 of a one-part container) and the split one.
    pub(super) fn sevenz_join_set(
        &self,
        inner: &mut Inner,
        slot: usize,
        ctl: Arc<SevenZCtl>,
        idx: u32,
    ) -> io::Result<bool> {
        let size = inner.slots[slot].size;
        let buf = Arc::new(FrontierBuffer::new_gated(
            size,
            self.chase_gate(inner, slot),
            // No scratch: the 7z reader peeks at arbitrary offsets, so
            // "beyond the gap" is not provably cold - the stalled-chase
            // spill stays a RAR-only bargain. No pager for the same
            // reason.
            None,
            None,
        ));
        if !ctl.set.register(
            idx,
            SetPart {
                buf: buf.clone(),
                slot,
                size,
            },
        ) {
            // Not a uniform split after all - a part of the wrong size,
            // a duplicate, or an index past the container's end. Refuse
            // the whole set rather than guess at the mapping; the disk
            // post-pass joins the parts and extracts them.
            let why = format!(
                "{} split parts do not line up",
                inner.slots[slot].container_fmt.noun()
            );
            self.sevenz_fallback_set(inner, &ctl, &why)?;
            return Ok(false);
        }
        inner.slots[slot].mode = SlotMode::SevenZ;
        inner.slots[slot].pre_bytes = 0;
        let mut stored = 0usize;
        // The holds are OUT of the slot now, so a reclaim that fails
        // (a scratch read error) must uncharge what it did not read:
        // dropping the rest of the vec frees the memory but leaves the
        // budget - and the scratch reservation - charged for it.
        let mut rest = std::mem::take(&mut inner.slots[slot].holds).into_iter();
        let mut failed = None;
        for (off, span) in rest.by_ref() {
            match Self::reclaim_span(inner, span) {
                Ok(bytes) => stored = buf.write_span(off, &bytes),
                Err(e) => {
                    failed = Some(e);
                    break;
                }
            }
        }
        // Installed BEFORE the failure return, exactly as the RAR attach
        // does and for the same reason: the slot is already in
        // `SlotMode::SevenZ`, so a bail-out that leaves `chase` at None
        // sends every later span for it into `chase_span`'s impossible
        // arm, which debug-asserts and silently drops the bytes in
        // release. The set handle goes with it so a later demotion still
        // takes down the whole container.
        inner.budget.add(stored);
        inner.slots[slot].chase = Some(ChaseSlot {
            buf: buf.clone(),
            charged: stored,
            dropped: Vec::new(),
            dropped_as: String::new(),
        });
        inner.slots[slot].sevenz = Some(ctl.clone());
        if let Some(e) = failed {
            for (_, span) in rest {
                Self::uncharge_span(inner, &span);
            }
            // Bytes this part will never hold now: fail the frontier so
            // a blocked read errors instead of waiting for them.
            buf.abort("held bytes could not be reclaimed");
            return Err(e);
        }
        // See the RAR attach: held spans that disagree with each other
        // mean a repair already landed, and nothing has decoded yet
        // (nor been read, so ask for any rewrite, not a served one).
        let seeded_conflict = buf.rewritten().is_some();
        // Tail prefetch for a part that joined after the worker started:
        // on a split set the end header lives in the LAST part, which is
        // usually the last to classify, so the promote that matters most
        // is this one rather than the worker's opening call. QUEUED, not
        // called: the promote walk takes every level's routing lock on
        // the way up and we are holding this one.
        let tail = *ctl.tail.lock_ok();
        if let Some((a, b)) = tail {
            // EVERY part carrying the tail, not just this one. Filtering
            // to `slot` stranded the common case: on a split container
            // the end header lives in the LAST part, and if that part
            // classified before `.7z.001` did, it joined a set that had
            // no tail range yet - and part 1's own join then skipped it.
            // The map never parsed, the trim never armed, and the whole
            // set demoted on the retention cap. Re-promoting a range is
            // harmless: the ladder ranks by first occurrence.
            for (s, ls, le) in ctl.set.map_range(a, b) {
                inner.pending_promote.push((s, vec![(ls, le)], true));
            }
        }
        if seeded_conflict {
            self.sevenz_fallback_set(inner, &ctl, "repair rewrote chased bytes")?;
            return Ok(true);
        }
        if inner.budget.over() {
            self.sevenz_trim_set(inner, &ctl)?;
        }
        if Self::breach_stands(inner) {
            // Same shared budget as the holds cap, so the reason carries
            // the same substring: the caller keys volume-level remediation
            // off "held-bytes cap", and the bare wording this used to have
            // matched nothing, demoting the volumes and then shipping the
            // job with no payload and exit 0.
            self.sevenz_fallback_set(inner, &ctl, HELD_BYTES_CAP_CHASE)?;
        }
        Ok(true)
    }
    /// Demote a whole 7z container: every part that has registered
    /// materializes as its own `.7z.NNN` on disk, which is precisely
    /// what the disk post-pass joins and extracts. One part failing is
    /// the container failing - there is no useful half of a byte split.
    ///
    /// The member outputs the worker had already decoded go with it,
    /// except on the held-bytes-cap forfeit, where they are kept for the
    /// disk pass to resume from - see [`Self::sevenz_teardown_sinks`].
    pub(super) fn sevenz_fallback_set(
        &self,
        inner: &mut Inner,
        ctl: &Arc<SevenZCtl>,
        reason: &str,
    ) -> io::Result<()> {
        if !ctl.key.is_empty() {
            inner.sevenz_sets.remove(&ctl.key);
        }
        ctl.set.abort();
        self.sevenz_teardown_sinks(inner, ctl, reason);
        for member in ctl.set.member_slots() {
            self.fallback_slot_or_group(inner, member, reason)?;
        }
        Ok(())
    }
    /// The 7z chase worker: front-load the footer, then let the engine
    /// parse the archive map and decode block by block behind the
    /// arrival frontier, each entry streaming into a fresh child slot
    /// (the routing seam - a store RAR inside the 7z keeps streaming).
    /// The extractor is reached weakly so a cancelled job can drop; the
    /// outcome is recorded for finish() to act on, with error wording
    /// the parent's nested-reason fold understands.
    fn sevenz_worker(
        me: Weak<Extractor>,
        ctl: Arc<SevenZCtl>,
        tail: (u64, u64),
        password: Option<std::sync::Arc<str>>,
    ) {
        // The tail promote is raised by each PART as it joins the set
        // (`sevenz_join_set`), not from here. On a split container the
        // end header lives in the last part, which is typically the last
        // to classify, so a single call at open would reach only the
        // parts already registered - and would double up with theirs.
        let _ = tail;
        let result = Self::sevenz_run(&me, &ctl, password).map_err(|e| match e {
            sevenz_rust2::Error::PasswordRequired => {
                "inner 7z is encrypted (no password)".to_string()
            }
            sevenz_rust2::Error::MaybeBadPassword(_) => {
                "inner 7z is encrypted (password rejected)".to_string()
            }
            sevenz_rust2::Error::UnsupportedCompressionMethod(m) => {
                format!("inner 7z codec unsupported: {m}")
            }
            e => format!("inner 7z decode failed: {e}"),
        });
        let mut st = ctl.outcome.lock_ok();
        *st = Some(result);
    }
    /// Does this archive's coder map need bytes BEHIND the read frontier,
    /// i.e. must the chase keep everything it has retained?
    ///
    /// Measured on sevenz-rust2 0.21.3 + lzma-rust2 0.16.5 through this
    /// exact call path: for LZMA2, Copy, BZip2, PPMd, Delta chains and
    /// AES256, solid and non-solid, plain / encoded / encrypted headers,
    /// payload reads ascend strictly from offset 32 to the tail header
    /// and never revisit - zero bytes of history, independent of archive
    /// size. BCJ2 is the sole exception and it is total: its four pack
    /// streams are served by four concurrent cursors, the range coder's
    /// at the block's far end read first, needing 100.0% of a 256 MiB
    /// fixture behind the frontier and scaling with size.
    ///
    /// So the test is exactly "is there a BCJ2 coder", and those archives
    /// keep the retain-everything behaviour (and stay bound by the cap).
    /// BCJ2 is an x86-executable filter and the shape census says posted
    /// payload is overwhelmingly already-compressed video, so this should
    /// almost never fire.
    pub(super) fn sevenz_needs_history(archive: &sevenz_rust2::Archive) -> bool {
        archive.blocks.iter().any(|b| {
            b.coders
                .iter()
                .any(|c| c.encoder_method_id() == sevenz_rust2::EncoderMethod::ID_BCJ2)
        })
    }
    /// The worker's engine drive: parse blocks (the initial footer reads
    /// block only until the promoted tail lands), then decode every
    /// entry in block order through the blocking view. CRC-checked per
    /// entry by the engine.
    fn sevenz_run(
        me: &Weak<Extractor>,
        ctl: &SevenZCtl,
        password: Option<std::sync::Arc<str>>,
    ) -> Result<(), sevenz_rust2::Error> {
        let total = ctl.set.total();
        let mut src = ChainedSeekReader {
            set: ctl.set.clone(),
            pos: 0,
            base: ctl.archive_base,
            total: total.saturating_sub(ctl.archive_base),
            low_water: ctl.low_water.clone(),
        };
        // Decompression-bomb gate, the extract half of the verdict the
        // nameprobe entry points already share (TODO 156 item 5):
        // ArchiveReader::new buffers the declared end header whole and
        // decodes a packed (kEncodedHeader) one with the DECLARED sizes
        // as its only bounds, so the declaration is read through the
        // same blocking set view and judged first. These reads block
        // exactly where the parse itself would block (the promoted
        // tail), so no new wait is introduced, and on any malformed
        // shape the gate stands aside for the library's own cheap
        // error. A refusal errors the worker out, which demotes the
        // set: the parts materialize for the disk post-pass, whose
        // entry points hold the same shared gate and refuse with a
        // diagnosable reason instead of an allocation. The declared
        // variant also judges the CONTENT blocks' dictionary and PPMd
        // declarations - this call path is about to decode them, and
        // the library itself puts no bound on what they may allocate.
        if let Some(reason) = crate::nameprobe::sevenz_disk_declared_bomb(&mut src) {
            return Err(sevenz_rust2::Error::Other(reason.into()));
        }
        io::Seek::seek(&mut src, io::SeekFrom::Start(0))?;
        let pw = match &password {
            Some(p) => sevenz_rust2::Password::from(&**p),
            None => sevenz_rust2::Password::empty(),
        };
        let mut reader = sevenz_rust2::ArchiveReader::new(src, pw)?;
        // Drop-behind is decided HERE and only here, between the parse
        // and the first payload read: the coder chains come from the end
        // header, so they are all known before a single payload byte is
        // touched.
        ctl.arm_trim(Self::sevenz_needs_history(reader.archive()));
        reader.for_each_entries(|entry, rd| {
            if entry.is_directory {
                return Ok(true);
            }
            let Some(ex) = me.upgrade() else {
                return Err(io::Error::other("extractor dropped").into());
            };
            // Same single-lock-hold discipline as chase_open_sink: the
            // liveness check and the sink-slot registration must be
            // atomic against a demotion draining sink_slots, or the
            // fresh slot leaks a partial grandchild output.
            let (child, cslot) = {
                let mut g = ex.inner.lock_ok();
                let inner = &mut *g;
                // Every part of the container has to still be chased: a
                // demotion takes them all together, so any one of them
                // having left SevenZ mode means this output is stale.
                let members = ctl.set.member_slots();
                if members.is_empty()
                    || !members
                        .iter()
                        .all(|&m| matches!(inner.slots[m].mode, SlotMode::SevenZ))
                {
                    return Err(io::Error::other("7z chase demoted").into());
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
            io::copy(rd, &mut sink)?;
            Ok(true)
        })
    }
    /// Drop-behind trim (TODO 37 step 2): release the bytes of a chased
    /// 7z slot that the decode engine has already read past, writing
    /// them into the slot's own archive file on the way out.
    ///
    /// Spilling into THAT file, rather than a temp one, is what keeps the
    /// demote path free. A demotion materializes the archive at exactly
    /// these offsets, so the spill is not a cost paid against demotion -
    /// it IS demotion, done incrementally and early. If the chase later
    /// fails, `fallback_slot` writes only what is still in RAM and finds
    /// the rest already on disk; if it succeeds, `sevenz_finish` deletes
    /// the partial file, because the payload came out the other way.
    ///
    /// Declines, leaving the caller to demote, when: the gate is off; the
    /// archive needs history behind its frontier (BCJ2); the map has not
    /// parsed yet, so the watermark means nothing; or the release would
    /// be too small to be worth a `Vec::drain` of what is still live -
    /// which is also the honest answer when arrivals have run so far
    /// ahead of decode that the live window alone fills the cap.
    pub(super) fn sevenz_trim_set(
        &self,
        inner: &mut Inner,
        ctl: &Arc<SevenZCtl>,
    ) -> io::Result<()> {
        // Acquire pairs with arm_trim's Release: seeing trim_ok true must
        // also see the watermark reset that preceded it.
        if !inner.sevenz_trim_on || !ctl.trim_ok.load(Ordering::Acquire) {
            return Ok(());
        }
        // Every part, not just the one whose span breached the budget:
        // on a split set the arrivals are typically running on a LATER
        // part than the one the engine is reading, so the bytes worth
        // releasing belong to a different slot entirely.
        for slot in ctl.set.member_slots() {
            self.sevenz_trim_part(inner, ctl, slot)?;
        }
        Ok(())
    }
    fn sevenz_trim_part(
        &self,
        inner: &mut Inner,
        ctl: &Arc<SevenZCtl>,
        slot: usize,
    ) -> io::Result<()> {
        // The watermark is a CONTAINER offset; this slot is one part of
        // that container, so translate before trimming its buffer. A
        // part the engine has read straight past releases whole.
        let Some((idx, part_size)) = ctl.set.part_of(slot) else {
            return Ok(());
        };
        let Some(buf) = inner.slots[slot].chase.as_ref().map(|ch| ch.buf.clone()) else {
            return Ok(());
        };
        let base = (idx as u64 - 1) * part_size;
        let watermark = ctl.low_water.load(Ordering::Relaxed).saturating_sub(base);
        // Half the cap: bounds the drain's memmove to a constant amount
        // of work per arriving byte, since two trims cannot be closer
        // together than that many bytes of arrival. A part the engine is
        // wholly past is released regardless of size - it is finished
        // with, and holding it buys nothing.
        let min_release = if watermark >= buf.total() {
            1
        } else {
            (inner.budget.cap() / 2) as u64
        };
        // Planned here, written off-lock by `flush_pending_spills`
        // (TODO 37 item 1); the budget is credited at plan time.
        self.queue_trim_spill(inner, slot, &buf, watermark, min_release, false)?;
        Ok(())
    }
    /// Tear down a 7z/zip container's sink outputs for a demotion
    /// carrying `reason` - the resume-aware twin of
    /// [`Self::chase_teardown`], and the only caller of
    /// [`Self::sevenz_abandon_sinks`] that ever declines to call it.
    ///
    /// A container forfeiting on the held-bytes cap KEEPS the members
    /// its worker had already decoded, truncated to the writer's
    /// contiguous prefix, so the disk pass appends instead of extracting
    /// each one from byte zero (TODO 213 item 2 - the RAR half shipped
    /// on 22 Aug 2026 and this arm was explicitly left for later).
    /// Every other reason abandons exactly as before; the test itself is
    /// [`Self::chase_resume_ok`], shared with the RAR path so the two
    /// container families cannot drift apart on what a trustworthy
    /// prefix is.
    ///
    /// One set, one teardown, whatever the container spans: a split
    /// `.7z.001` set registers every part against ONE ctl, and the sink
    /// slots hang off that ctl rather than off any part.
    pub(super) fn sevenz_teardown_sinks(&self, inner: &mut Inner, ctl: &SevenZCtl, reason: &str) {
        if !self.chase_resume_ok(reason) {
            self.sevenz_abandon_sinks(inner, ctl);
            return;
        }
        let Some(c) = inner.child.clone() else {
            return;
        };
        for cs in ctl.sink_slots.lock_ok().drain(..) {
            // `retain_slot_output` abandons the slot itself on the
            // shapes it declines, so a None here wants nothing more.
            if let Some(kept) = c.retain_slot_output(cs) {
                inner.resume_pending.push(kept);
            }
        }
    }

    /// Abandon every partial output slot a 7z chase's sink opened, so
    /// no half-decoded file survives a demotion.
    pub(super) fn sevenz_abandon_sinks(&self, inner: &mut Inner, ctl: &SevenZCtl) {
        if let Some(c) = inner.child.clone() {
            for cs in ctl.sink_slots.lock_ok().drain(..) {
                c.abandon_slot(cs);
            }
        }
    }
    /// Join every 7z chase worker before settling (mirrors
    /// [`Self::chase_finish`]): the download is over, so an incomplete
    /// buffer can never complete - abort it and the blocked worker
    /// unblocks with an error. A failed or panicked worker demotes its
    /// slot to a materialized level-N .7z (the disk post-pass input); a
    /// successful one releases the retained bytes - its outputs already
    /// live in the child chain.
    /// One CONTAINER is joined once, however many slots it spans: every
    /// part of a split set shares the ctl, so the worker is taken and
    /// joined by whichever member reaches it first and the rest settle
    /// off the same outcome.
    pub(super) fn sevenz_finish(&self) -> io::Result<()> {
        let pending: Vec<Arc<SevenZCtl>> = {
            let inner = self.inner.lock_ok();
            let mut seen: Vec<Arc<SevenZCtl>> = Vec::new();
            for s in &inner.slots {
                if let Some(c) = s.sevenz.clone()
                    && !seen.iter().any(|o| Arc::ptr_eq(o, &c))
                {
                    seen.push(c);
                }
            }
            seen
        };
        for ctl in pending {
            // Missing a part, or a part that never filled, is the same
            // thing to a byte split: the container cannot be read.
            if !ctl.set.is_complete() {
                ctl.set.abort();
            }
            // Settle has run: nothing rewrites these bytes any more, and
            // a gate cell parked at an unrepairable block never advances
            // - release so the join is bounded (see chase_finish).
            ctl.set.release_gates();
            // ...but releasing the gate is exactly what lets a
            // footer-seeking 7z/zip worker fall through to the unbounded
            // hole-wait, and `is_complete()` above is not a reliable
            // guard against it (a demoted-then-late-tail set reads
            // complete while its worker still parks on a byte the abort
            // above skipped). Seal every part: a hole read now errors and
            // the worker demotes, while a truly complete set still serves
            // its worker to a clean finish (TODO 255).
            ctl.set.seal_parts();
            let handle = ctl.worker.lock_ok().take();
            if let Some(h) = handle {
                // A worker panic surfaces as a join error and leaves no
                // outcome - handled below as a demotion.
                let _ = h.join();
            }
            let outcome = ctl.outcome.lock_ok().clone();
            let mut g = self.inner.lock_ok();
            let inner = &mut *g;
            if !ctl.key.is_empty() {
                inner.sevenz_sets.remove(&ctl.key);
            }
            let members = ctl.set.member_slots();
            for &m in &members {
                inner.slots[m].sevenz = None;
            }
            let live: Vec<usize> = members
                .iter()
                .copied()
                .filter(|&m| matches!(inner.slots[m].mode, SlotMode::SevenZ))
                .collect();
            if live.is_empty() {
                continue; // demoted earlier (budget breach / abandon)
            }
            match outcome {
                Some(Ok(())) => {
                    // The container decoded: this is where one-pass is
                    // earned (see the attach site's note).
                    self.shape.note(self.depth, SH_ONE_PASS);
                    for m in live {
                        if let Some(ch) = inner.slots[m].chase.take() {
                            inner.budget.sub(ch.charged);
                        }
                        // A trim may have spilled a prefix into the part's
                        // file on the way past. The payload came out the
                        // other way, so that file is a truncated archive
                        // nobody wants - shipping it beside the payload
                        // would look like a second, broken download.
                        Self::drop_slot_file(inner, m);
                    }
                }
                other => {
                    let noun = inner.slots[live[0]].container_fmt.noun();
                    let why = match other {
                        Some(Err(e)) => e,
                        // No outcome and no worker means the container
                        // never opened: a pending split set whose
                        // `.7z.001` never classified, so nothing ever
                        // learned how big it was or where its map lived.
                        None if !ctl.set.resolved() => {
                            format!("{noun} split set never found its first part")
                        }
                        _ => format!("{noun} worker panicked"),
                    };
                    self.sevenz_abandon_sinks(inner, &ctl);
                    for m in live {
                        self.fallback_slot_or_group(inner, m, &why)?;
                    }
                }
            }
        }
        Ok(())
    }
}

/// `<base>.7z.<NNN>` - a 7-Zip container split across parts. Returns the
/// shared base and the 1-based part index.
///
/// 7z multipart is a RAW BYTE SPLIT: the parts concatenate back into the
/// container with nothing added, which is what makes chasing a set the
/// same problem as chasing one file with a seam in it. (The disk
/// post-pass groups the same way, in `split_7z_part` - two copies
/// because that one lives in the daemon crate, and the rule is four
/// lines of string matching.)
pub(super) fn sevenz_part_name(name: &str) -> Option<(String, u32)> {
    let (head, tail) = name.rsplit_once('.')?;
    // 7-Zip names volumes `%s.%03d`, so a genuine part is three digits
    // (four once a set passes 999). Accepting one and two digits let
    // `foo.7z.1` parse as part 1 of the same base as `foo.7z.001`, i.e.
    // two files each claiming to be the container's first part.
    if tail.len() < 3 || tail.len() > 4 || !tail.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if !head.to_lowercase().ends_with(".7z") {
        return None;
    }
    let idx: u32 = tail.parse().ok()?;
    (idx >= 1).then(|| (head.to_lowercase(), idx))
}

/// Most parts a split container may claim. 7-Zip names volumes `%s.%03d`
/// and the live-index census topped out at 255 parts; the bound exists so
/// a corrupt or hostile part-1 start header cannot declare a container so
/// large that every `.7z.NNN` in the job is held in RAM waiting for parts
/// that do not exist.
pub(super) const SEVENZ_MAX_PARTS: u32 = 9999;

/// One part of a chased 7z container: its own frontier buffer, its own
/// slot, its declared size.
pub(super) struct SetPart {
    pub(super) buf: Arc<FrontierBuffer>,
    pub(super) slot: usize,
    pub(super) size: u64,
}

/// The byte space a 7z chase decodes over: one part for a plain `.7z`,
/// N for a `.7z.001` split set. Parts register as their slots classify,
/// in any order; [`ChainedSeekReader`] joins them and blocks on one that
/// has not arrived yet, exactly as the single-part reader blocks on
/// bytes that have not arrived yet.
///
/// Kept deliberately as a map of per-slot buffers rather than one global
/// buffer, because two seams need per-part byte records: a demotion
/// writes `take_spans()` back into that part's OWN file at that buffer's
/// own offsets, and verify/repair read-back serves `peek` in per-slot
/// offsets.
pub(super) struct SevenZSet {
    pub(super) state: Mutex<SevenZSetState>,
    pub(super) arrived: Condvar,
}

#[derive(Default)]
pub(super) struct SevenZSetState {
    /// 1-based part index -> part.
    pub(super) parts: BTreeMap<u32, SetPart>,
    /// The split size: part 1's own size. `7z -v` writes every part at
    /// exactly this size except the last, so it is the whole mapping
    /// from a container offset to a part. A part that arrives claiming a
    /// different size is not a `7z -v` split, and the set forfeits
    /// rather than guess (the disk post-pass joins it instead).
    pub(super) part_size: u64,
    /// Size of the whole container. For a split set this comes from part
    /// 1's start header and nothing else: the end header is the last
    /// thing in a 7z container, so `32 + offset + size` IS the end.
    pub(super) total: u64,
    pub(super) aborted: bool,
}

impl SevenZSet {
    pub(super) fn new(part_size: u64, total: u64) -> SevenZSet {
        SevenZSet {
            state: Mutex::new(SevenZSetState {
                part_size,
                total,
                ..Default::default()
            }),
            arrived: Condvar::new(),
        }
    }

    /// A set opened by a continuation part, before part 1 has been seen.
    /// Nothing about the container's shape is known yet - only part 1
    /// carries the start header - so parts are taken on trust and
    /// checked when [`Self::resolve`] arrives. Nothing reads from an
    /// unresolved set: the worker is spawned by part 1.
    pub(super) fn new_pending() -> SevenZSet {
        SevenZSet {
            state: Mutex::new(SevenZSetState::default()),
            arrived: Condvar::new(),
        }
    }

    pub(super) fn resolved(&self) -> bool {
        self.state.lock_ok().part_size > 0
    }

    /// Part 1 has landed: fix the split size and the container size, then
    /// re-check every part taken on trust before now. False if any of
    /// them does not fit, which forfeits the set.
    pub(super) fn resolve(&self, part_size: u64, total: u64) -> bool {
        let mut st = self.state.lock_ok();
        // Already resolved means a SECOND file is claiming to be part 1
        // - a duplicated NZB entry, or two spellings that lower-case to
        // one base. Refuse rather than re-shape a container the worker
        // is already decoding through: overwriting `part_size`/`total`
        // under a live reader re-maps every container offset mid-flight.
        if st.part_size > 0 {
            return false;
        }
        // Validate against LOCALS and commit only on success, so a set
        // that does not line up is never left half-resolved.
        let n = Self::count_of(total, part_size);
        let ok = st.parts.iter().all(|(&i, p)| {
            let expected = if i >= n {
                total - (n as u64 - 1) * part_size
            } else {
                part_size
            };
            i <= n && p.size == expected
        });
        if !ok {
            return false;
        }
        st.part_size = part_size;
        st.total = total;
        drop(st);
        self.arrived.notify_all();
        true
    }

    /// How many parts a container of `total` bytes splits into.
    pub(super) fn count_of(total: u64, part_size: u64) -> u32 {
        if part_size == 0 {
            return 1;
        }
        total.div_ceil(part_size).max(1).min(u32::MAX as u64) as u32
    }

    /// The size part `idx` must declare if this really is a `7z -v`
    /// split: the split size, or the remainder for the last part.
    pub(super) fn expected_size(&self, idx: u32) -> u64 {
        let st = self.state.lock_ok();
        let n = Self::count_of(st.total, st.part_size);
        if idx >= n {
            st.total - (n as u64 - 1) * st.part_size
        } else {
            st.part_size
        }
    }

    /// Register a part. False if it does not fit the split (wrong size,
    /// index past the end, duplicate) - the caller forfeits the set.
    pub(super) fn register(&self, idx: u32, part: SetPart) -> bool {
        let resolved = self.resolved();
        let expected = self.expected_size(idx);
        let mut st = self.state.lock_ok();
        let n = Self::count_of(st.total, st.part_size);
        if st.parts.contains_key(&idx) {
            return false;
        }
        // An unresolved set has no shape to check against yet; `resolve`
        // re-checks everything taken on trust here.
        if resolved && (idx > n || part.size != expected) {
            return false;
        }
        st.parts.insert(idx, part);
        drop(st);
        self.arrived.notify_all();
        true
    }

    /// §94 B: stop withholding bytes from the decode on every part - the
    /// finish-time release, see `FrontierBuffer::release_gate`.
    pub(super) fn release_gates(&self) {
        let bufs: Vec<Arc<FrontierBuffer>> = self
            .state
            .lock_ok()
            .parts
            .values()
            .map(|p| p.buf.clone())
            .collect();
        for b in bufs {
            b.release_gate();
        }
    }

    /// Finish seal for every part (see [`FrontierBuffer::seal`]): no more
    /// bytes will be routed, so a worker blocked on a hole errors instead
    /// of parking forever. Paired with `release_gates` in
    /// [`Extractor::sevenz_finish`]: releasing the §94 B gate is what
    /// drops a footer-seeking reader onto the unbounded hole-wait, and
    /// this is what bounds it (TODO 255). A complete set's reads all hit
    /// present bytes, so its worker still finishes clean and keeps
    /// one-pass; only a genuinely missing byte becomes the error.
    pub(super) fn seal_parts(&self) {
        let bufs: Vec<Arc<FrontierBuffer>> = self
            .state
            .lock_ok()
            .parts
            .values()
            .map(|p| p.buf.clone())
            .collect();
        for b in bufs {
            b.seal();
        }
    }

    pub(super) fn abort(&self) {
        let mut st = self.state.lock_ok();
        st.aborted = true;
        let bufs: Vec<Arc<FrontierBuffer>> = st.parts.values().map(|p| p.buf.clone()).collect();
        drop(st);
        for b in bufs {
            b.abort("7z set abandoned");
        }
        self.arrived.notify_all();
    }

    pub(super) fn total(&self) -> u64 {
        self.state.lock_ok().total
    }

    /// Block until the set's geometry is known (the zip worker's first
    /// step: a zip split resolves only once every declared part has
    /// registered its decoded size, unlike a 7z split where part 1's
    /// start header sizes the whole container up front). Returns the
    /// container total; errors when the set aborts unresolved.
    pub(super) fn wait_resolved_total(&self) -> io::Result<u64> {
        let mut st = self.state.lock_ok();
        loop {
            if st.aborted {
                return Err(io::Error::other("chase set aborted before it resolved"));
            }
            if st.part_size > 0 {
                return Ok(st.total);
            }
            st = self.arrived.wait(st).unwrap();
        }
    }

    /// Geometry of a DECLARED zip split, once every part is in:
    /// `(part 1's size, container total)`. None while parts are still
    /// missing, or when the registered indices are not exactly `1..=n`
    /// (a rogue index can register on trust before resolution - such a
    /// set never resolves and finish demotes it).
    pub(super) fn zip_geometry(&self, n: u32) -> Option<(u64, u64)> {
        let st = self.state.lock_ok();
        if st.parts.len() as u32 != n
            || st.parts.keys().next() != Some(&1)
            || st.parts.keys().next_back() != Some(&n)
        {
            return None;
        }
        let part_size = st.parts.get(&1).map(|p| p.size)?;
        // Saturating: the sizes are slot sizes, and a slot is sized from
        // the NZB's declared byte counts - untrusted arithmetic, which a
        // debug build turns into a panic on overflow.
        Some((
            part_size,
            st.parts
                .values()
                .fold(0u64, |a, p| a.saturating_add(p.size)),
        ))
    }

    /// Which part is this slot, and what is the split size? Used to turn
    /// the engine's CONTAINER-space watermark into the part-space one a
    /// drop-behind trim needs.
    pub(super) fn part_of(&self, slot: usize) -> Option<(u32, u64)> {
        let st = self.state.lock_ok();
        st.parts
            .iter()
            .find(|(_, p)| p.slot == slot)
            .map(|(&i, _)| (i, st.part_size))
    }

    /// Every registered part's slot, for demoting a set as a whole.
    pub(super) fn member_slots(&self) -> Vec<usize> {
        self.state
            .lock_ok()
            .parts
            .values()
            .map(|p| p.slot)
            .collect()
    }

    /// Have all the parts arrived AND filled? An incomplete set can
    /// never decode, so finish aborts it.
    pub(super) fn is_complete(&self) -> bool {
        let st = self.state.lock_ok();
        // Unresolved: part 1 never arrived, so the container's shape is
        // unknown and it cannot be complete by definition. Without this
        // `count_of(0, 0)` answers 1 and a lone `.7z.002` reads as a
        // whole container.
        if st.part_size == 0 {
            return false;
        }
        let n = Self::count_of(st.total, st.part_size);
        st.parts.len() as u32 == n && st.parts.values().all(|p| p.buf.is_complete())
    }

    /// The parts covering container range `[from, to)`, as
    /// `(slot, local_start, local_end)` - the tail prefetch asks in
    /// container offsets and the promote ladder answers in slot ones.
    pub(super) fn map_range(&self, from: u64, to: u64) -> Vec<(usize, u64, u64)> {
        let st = self.state.lock_ok();
        if st.part_size == 0 || from >= to {
            return Vec::new();
        }
        let mut out = Vec::new();
        for (&i, p) in &st.parts {
            let base = (i as u64 - 1) * st.part_size;
            let a = from.max(base);
            let b = to.min(base + p.size);
            if a < b {
                out.push((p.slot, a - base, b - base));
            }
        }
        out
    }

    /// Blocking container-view read. Never crosses a part boundary in
    /// one call (the caller loops), and blocks on a part that has not
    /// registered yet as readily as on bytes that have not arrived.
    pub(super) fn read_blocking(&self, at: u64, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let (part, room, local) = {
            let mut st = self.state.lock_ok();
            loop {
                if st.aborted {
                    return Err(io::Error::other("7z set aborted"));
                }
                // Unresolved: the container's size is not known yet, so
                // "past the end" cannot be answered. Wait rather than
                // report EOF at offset 0.
                if st.part_size == 0 {
                    st = self.arrived.wait(st).unwrap();
                    continue;
                }
                if at >= st.total {
                    return Ok(0);
                }
                // Mapped INSIDE the loop, against the geometry that is
                // live now: computing it before the wait meant a read
                // issued against an unresolved set kept the placeholder
                // mapping after the set resolved underneath it.
                let idx = (at / st.part_size).checked_add(1);
                let Some(idx) = idx.and_then(|i| u32::try_from(i).ok()) else {
                    return Err(io::Error::other("7z container offset has no part"));
                };
                let local = at % st.part_size;
                let room = (st.total - at).min(st.part_size - local);
                if let Some(p) = st.parts.get(&idx) {
                    break (p.buf.clone(), room, local);
                }
                st = self.arrived.wait(st).unwrap();
            }
        };
        let take = buf.len().min(room as usize);
        part.read_covered_blocking(local, &mut buf[..take])
    }
}

impl SevenZCtl {
    /// Arm (or refuse) drop-behind now that the archive map has parsed.
    ///
    /// The watermark is RESET first, and that is the whole point of this
    /// existing as one step. The parse ends having just read the end
    /// header, so the reader's position - and therefore the published
    /// watermark - is sitting at EOF (measured: exactly `total`). Arming
    /// the trim against that value opens a window, until the engine
    /// seeks back down to the first pack stream, in which a budget
    /// breach would release the ENTIRE buffer and the next read would
    /// land behind the trim point. That forfeits the chase and demotes -
    /// safely and byte-exactly, but it defeats the feature on precisely
    /// the large archives it exists for, intermittently and only under
    /// memory pressure. Zero means "the engine needs everything from the
    /// start", which is true until it says otherwise by reading.
    ///
    /// Same thread as the reader, so the two stores cannot interleave
    /// with a read; the only other party is the routing thread, which
    /// reads both. Release on the enable / Acquire on its load is what
    /// ORDERS the pair for that thread: with both Relaxed, a
    /// weakly-ordered CPU (the arm64 targets) could observe
    /// `trim_ok == true` beside the pre-reset watermark and release the
    /// entire retained buffer - the exact spurious drain the reset
    /// exists to prevent, back intermittently under memory pressure.
    pub(super) fn arm_trim(&self, needs_history: bool) {
        self.low_water.store(0, Ordering::Relaxed);
        self.trim_ok.store(!needs_history, Ordering::Release);
    }

    /// A container opened by a continuation part, waiting for the `.001`
    /// that will say how big it is and where its map lives. No worker
    /// yet - there is nothing it could read.
    pub(super) fn pending(key: String) -> SevenZCtl {
        SevenZCtl {
            set: Arc::new(SevenZSet::new_pending()),
            key,
            archive_base: 0,
            low_water: Arc::new(AtomicU64::new(0)),
            tail: Mutex::new(None),
            trim_ok: std::sync::atomic::AtomicBool::new(false),
            worker: Mutex::new(None),
            sink_slots: Mutex::new(Vec::new()),
            outcome: Mutex::new(None),
        }
    }
}

/// Blocking Read+Seek over a chased 7z container - the view the engine
/// parses and decodes through, whether that container is one posted file
/// or a `.7z.001` split set. Reads block until the requested bytes
/// arrive (the initial footer reads block only until the promoted tail
/// lands); Seek is pure position arithmetic against the declared size,
/// so seeking never blocks.
pub(super) struct ChainedSeekReader {
    pub(super) set: Arc<SevenZSet>,
    /// ARCHIVE position, as the engine sees it: 0 is the 7z signature.
    pub(super) pos: u64,
    /// Container offset of archive position 0 - the SFX stub's length
    /// (TODO 94 C), 0 for a bare container. Added on every read and
    /// folded into the published watermark, so the set and the trim
    /// never learn that the engine is counting from somewhere else.
    pub(super) base: u64,
    /// Archive length: the container's total less `base`.
    pub(super) total: u64,
    /// Lowest CONTAINER offset the engine may still ask for - the
    /// drop-behind trim watermark, published for the routing thread.
    /// Deliberately the READ position and not decode progress: MT-LZMA2
    /// runs its source reads tens of MB ahead of what it has decoded, so
    /// a watermark keyed to decode would trim bytes the prefetcher still
    /// wants.
    ///
    /// A seek REPLACES it rather than raising it, which is what makes
    /// the open phase safe without any phase detection of its own: the
    /// parse seeks to the tail, reads the end header, then seeks back to
    /// 32, and the watermark follows it straight back down.
    ///
    /// (d1cdd2112 renamed the single-file `BlockingSeekReader` to this
    /// one and left the reasoning above behind a pointer at the retired
    /// name; the two paragraphs are its text, re-anchored.)
    pub(super) low_water: Arc<AtomicU64>,
}

impl io::Read for ChainedSeekReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = self.set.read_blocking(self.base + self.pos, out)?;
        self.pos += n as u64;
        self.low_water
            .store(self.base + self.pos, Ordering::Relaxed);
        Ok(n)
    }
}

impl io::Seek for ChainedSeekReader {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        let target = match pos {
            io::SeekFrom::Start(o) => o as i128,
            io::SeekFrom::End(d) => self.total as i128 + d as i128,
            io::SeekFrom::Current(d) => self.pos as i128 + d as i128,
        };
        if target < 0 || target > u64::MAX as i128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek out of range",
            ));
        }
        self.pos = target as u64;
        self.low_water
            .store(self.base.saturating_add(self.pos), Ordering::Relaxed);
        Ok(self.pos)
    }
}

/// 7z container magic at offset 0.
pub(super) const SEVENZ_MAGIC: &[u8] = &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

/// Parse the 32-byte 7z start header: `(end-header offset, size)`,
/// CRC-checked - the offsets are relative to byte 32, so the end header
/// (the archive map, which 7z keeps at the TAIL) occupies
/// `[32 + offset, 32 + offset + size)`. None for anything that is not a
/// well-formed single-container start.
pub(super) fn sevenz_start_header(data: &[u8]) -> Option<(u64, u64)> {
    if data.len() < 32 || !data.starts_with(SEVENZ_MAGIC) {
        return None;
    }
    let crc = u32::from_le_bytes(data[8..12].try_into().unwrap());
    if crc32fast::hash(&data[12..32]) != crc {
        return None;
    }
    let off = u64::from_le_bytes(data[12..20].try_into().unwrap());
    let size = u64::from_le_bytes(data[20..28].try_into().unwrap());
    Some((off, size))
}

/// One 7z chase = one inner .7z file (one child slot): the slot's
/// in-flight bytes, the worker driving the 7z engine over them, and the
/// bookkeeping the demote path needs to unwind cleanly. Single-file
/// containers only - a multipart `.7z.001` part's end header lies past
/// its own bytes, so multipart sets never attach (v1 limitation: the
/// parts materialize and the disk post-pass joins and extracts them).
pub(super) struct SevenZCtl {
    /// The container's byte space: one part for a plain `.7z`, N for a
    /// `.7z.001` split set. Every member slot of a set shares this one
    /// ctl, so the worker is spawned, joined and torn down once.
    pub(super) set: Arc<SevenZSet>,
    /// `sevenz_part_name` base that keys this in `Inner.sevenz_sets`;
    /// empty for a single-file container, which needs no key because
    /// nothing else can join it.
    pub(super) key: String,
    /// Container offset the archive starts at: an SFX stub's length
    /// (TODO 94 C), 0 otherwise. See [`ChainedSeekReader::base`].
    pub(super) archive_base: u64,
    /// Drop-behind watermark, published by [`ChainedSeekReader`]: the
    /// lowest CONTAINER offset the engine may still ask for.
    pub(super) low_water: Arc<AtomicU64>,
    /// The end header's container range, once part 1 has been read.
    /// Held here so a part joining AFTER the worker started still gets
    /// its slice of the tail front-loaded - on a split set the map
    /// lives in the last part, which is usually the last to classify.
    pub(super) tail: Mutex<Option<(u64, u64)>>,
    /// May this chase trim? False until the archive map has been parsed
    /// (before that the watermark means nothing - the open phase is
    /// still seeking around), and false forever if the map contains a
    /// BCJ2 coder. BCJ2 serves four pack streams from four concurrent
    /// cursors, one of them at the block's far end, so it needs the
    /// whole archive behind its read frontier - measured 100.0% on a
    /// 256 MiB fixture, and scaling with size. Every other coder chain
    /// measured needs exactly zero bytes of history, solid included.
    pub(super) trim_ok: std::sync::atomic::AtomicBool,
    pub(super) worker: Mutex<Option<std::thread::JoinHandle<()>>>,
    /// Child-extractor slots the sink opened for extracted entries -
    /// abandoned (partial outputs deleted) if the chase demotes.
    pub(super) sink_slots: Mutex<Vec<usize>>,
    /// The worker's exit status, set exactly once before it returns.
    pub(super) outcome: Mutex<Option<Result<(), String>>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::extract::testutil::*;

    /// A store outer wrapping an LZMA2 7z: both layers stream - the
    /// final payload lands byte-exact and NEITHER the outer volume NOR
    /// the .7z ever exists on disk. Three feed orders, including the
    /// natural one where the promoted tail arrives dead last.
    #[test]
    fn sevenz_inner_extracts_one_pass() {
        let f = payload(300_000, 101);
        let arch = sevenz_archive(&[("F.bin", &f)], None, false);
        let outer = store_outer("inner.7z", &arch);
        let art = 7000usize;
        let n_arts = outer.len().div_ceil(art);
        let orders: Vec<Vec<usize>> = vec![
            (0..n_arts).collect(),                               // tail arrives last
            (0..n_arts).rev().collect(),                         // tail first, sniff last
            (0..n_arts).map(|i| (i * 7 + 3) % n_arts).collect(), // scrambled
        ];
        for (t, order) in orders.iter().enumerate() {
            let dir = tmpdir(&format!("7z-onepass{t}"));
            let ex = Extractor::new(&dir, 1, true);
            let mut seen = vec![false; n_arts];
            for &i in order {
                if std::mem::replace(&mut seen[i], true) {
                    continue;
                }
                let s = i * art;
                let e = (s + art).min(outer.len());
                ex.write(0, "v.rar", outer.len() as u64, s as u64, &outer[s..e])
                    .unwrap();
            }
            let rep = ex.finish().unwrap();
            assert!(rep.fallbacks.is_empty(), "order {t}: {:?}", rep.fallbacks);
            assert!(
                rep.extracted
                    .iter()
                    .any(|(n, s)| n == "F.bin" && *s == f.len() as u64),
                "order {t}: {:?}",
                rep.extracted
            );
            assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f, "order {t}");
            assert_eq!(dir_files(&dir), vec!["F.bin".to_string()], "order {t}");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// The tail-prefetch handle: classifying the inner 7z calls the
    /// installed promote hook with the archive's end-header range, and
    /// the root's output-range map resolves that same range to outer
    /// volume pieces (the composition promote_output_spans runs on) -
    /// whether the tail arrives last naturally or would have been
    /// promoted ahead.
    #[test]
    fn sevenz_tail_promote_hook() {
        let f = payload(220_000, 102);
        let arch = sevenz_archive(&[("F.bin", &f)], None, false);
        let (ho, hs) = sevenz_start_header(&arch).expect("fixture start header");
        let tail = (32 + ho, 32 + ho + hs);
        let outer = store_outer("inner.7z", &arch);
        for (t, forward) in [true, false].iter().enumerate() {
            let dir = tmpdir(&format!("7z-promote{t}"));
            let ex = Arc::new(Extractor::new(&dir, 1, true));
            type Calls = Arc<Mutex<Vec<(String, u64, Vec<(u64, u64)>, bool)>>>;
            let calls: Calls = Default::default();
            let sink = calls.clone();
            ex.set_promote_hook(Arc::new(
                move |n: &str, s: u64, sp: &[(u64, u64)], u: bool| {
                    sink.lock()
                        .unwrap()
                        .push((n.to_string(), s, sp.to_vec(), u));
                },
            ));
            let art = 6000usize;
            let n_arts = outer.len().div_ceil(art);
            let order: Vec<usize> = if *forward {
                (0..n_arts).collect()
            } else {
                (0..n_arts).rev().collect()
            };
            for i in order {
                let s = i * art;
                let e = (s + art).min(outer.len());
                ex.write(0, "v.rar", outer.len() as u64, s as u64, &outer[s..e])
                    .unwrap();
            }
            let rep = ex.finish().unwrap();
            assert!(rep.fallbacks.is_empty(), "order {t}: {:?}", rep.fallbacks);
            assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f, "order {t}");
            // The reverse feed starts out of order, so the offset-0
            // probe fires too (its shape is pinned by its own test) -
            // this test is about the TAIL promote. Probe calls always
            // lead with the (0, 1) span; a tail range never starts at 0.
            // The tail is URGENT (the worker blocks on the footer read).
            let mut got = calls.lock().unwrap().clone();
            got.retain(|(_, _, sp, _)| sp.first() != Some(&(0, 1)));
            assert_eq!(
                got,
                vec![("inner.7z".to_string(), arch.len() as u64, vec![tail], true)],
                "order {t}"
            );
            // The main.rs half of the wiring: the hook's (name, range)
            // resolves through map_output_range to outer volume pieces.
            let pieces = ex.map_output_range("inner.7z", tail.0, tail.1);
            assert!(!pieces.is_empty(), "order {t}: tail range must map");
            let span: u64 = pieces.iter().map(|(_, vs, ve, _)| ve - vs).sum();
            assert_eq!(span, hs, "order {t}: mapped span covers the footer");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// n-deep composition (§3b map_to_root): a 7z at depth 2 under a
    /// store RAR - the promote translates the 7z tail through the mid
    /// archive's mapping, so the root hook sees mid.rar ranges; the
    /// payload still lands one-pass.
    #[test]
    fn sevenz_promote_composes_through_levels() {
        let g = payload(150_000, 103);
        let arch = sevenz_archive(&[("G.bin", &g)], None, false);
        let (ho, hs) = sevenz_start_header(&arch).expect("fixture start header");
        let mid = store_outer("deep.7z", &arch);
        let outer = store_outer("mid.rar", &mid);
        // Where the 7z sits inside mid.rar (the translation the promote
        // walk must apply).
        let data_off = {
            let mut m = VolumeMapper::new(mid.len() as u64);
            m.feed(0, &mid);
            m.entries[0].data_off
        };
        let dir = tmpdir("7z-deep-promote");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        type Calls = Arc<Mutex<Vec<(String, u64, Vec<(u64, u64)>)>>>;
        let calls: Calls = Default::default();
        let sink = calls.clone();
        ex.set_promote_hook(Arc::new(
            move |n: &str, s: u64, sp: &[(u64, u64)], _u: bool| {
                sink.lock().unwrap().push((n.to_string(), s, sp.to_vec()));
            },
        ));
        feed(&ex, 0, "v.rar", &outer, 7000, 44);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("G.bin")).unwrap(), g);
        assert_eq!(dir_files(&dir), vec!["G.bin".to_string()]);
        // Shuffled feed: offset-0 probes (root slot and held child slots
        // alike) may fire; they always lead with the (0, 1) span, which
        // no tail range does. This test pins the tail translation.
        let mut got = calls.lock().unwrap().clone();
        got.retain(|(_, _, sp)| sp.first() != Some(&(0, 1)));
        assert_eq!(
            got,
            vec![(
                "mid.rar".to_string(),
                mid.len() as u64,
                vec![(data_off + 32 + ho, data_off + 32 + ho + hs)]
            )],
            "tail must translate through the mid archive's mapping"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Solid multi-file 7z (one block, entries decode in sequence
    /// through the same BlockDecoder pass).
    #[test]
    fn sevenz_solid_multi_file_one_pass() {
        let a = payload(180_000, 104);
        let b = payload(90_000, 105);
        let c = payload(40_000, 106);
        let arch = sevenz_archive(&[("A.bin", &a), ("B.bin", &b), ("C.bin", &c)], None, true);
        let outer = store_outer("inner.7z", &arch);
        let dir = tmpdir("7z-solid");
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &outer, 7000, 45);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("A.bin")).unwrap(), a);
        assert_eq!(std::fs::read(dir.join("B.bin")).unwrap(), b);
        assert_eq!(std::fs::read(dir.join("C.bin")).unwrap(), c);
        assert_eq!(
            dir_files(&dir),
            vec![
                "A.bin".to_string(),
                "B.bin".to_string(),
                "C.bin".to_string()
            ]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Copy-codec 7z (no compression - the block is an offset remap).
    #[test]
    fn sevenz_copy_codec_one_pass() {
        let f = payload(160_000, 107);
        let arch = sevenz_archive(
            &[("F.bin", &f)],
            Some(vec![sevenz_rust2::EncoderConfiguration::new(
                sevenz_rust2::EncoderMethod::COPY,
            )]),
            false,
        );
        let outer = store_outer("inner.7z", &arch);
        let dir = tmpdir("7z-copy");
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &outer, 7000, 46);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
        assert_eq!(dir_files(&dir), vec!["F.bin".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Header-encrypted 7z without a password: the worker fails at the
    /// parse, finish demotes, and the .7z materializes byte-exact for
    /// the disk post-pass - reported as a nested fallback whose wording
    /// never pattern-matches volume-level remediation.
    #[test]
    fn sevenz_encrypted_without_password_demotes() {
        let f = payload(120_000, 108);
        let arch = sevenz_archive(
            &[("F.bin", &f)],
            Some(vec![
                sevenz_rust2::encoder_options::AesEncoderOptions::new(
                    sevenz_rust2::Password::from("secret"),
                )
                .into(),
            ]),
            false,
        );
        let outer = store_outer("inner.7z", &arch);
        let dir = tmpdir("7z-encrypted");
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &outer, 7000, 47);
        let rep = ex.finish().unwrap();
        let nested: Vec<_> = rep
            .fallbacks
            .iter()
            .filter(|(_, w)| w.starts_with("nested fallback:"))
            .collect();
        assert_eq!(nested.len(), 1, "{:?}", rep.fallbacks);
        for (_, w) in &rep.fallbacks {
            assert!(
                !w.contains("compressed")
                    && !w.contains("encrypted")
                    && !w.contains("password")
                    && !w.contains("held-bytes cap")
                    && !w.contains("incomplete mapping"),
                "nested reason leaks a volume-remediation trigger: {w}"
            );
        }
        assert_eq!(std::fs::read(dir.join("inner.7z")).unwrap(), arch);
        assert!(!dir.join("F.bin").exists(), "no half-decoded output");
        assert_eq!(dir_files(&dir), vec!["inner.7z".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// TODO 156 item 5's extract half: a chased 7z whose packed end
    /// header declares 512 MiB of decoded header out of 16 pack bytes
    /// dies at the shared gate BEFORE ArchiveReader::new decodes on the
    /// declaration's say-so, and the refusal is a demote, not a silent
    /// no - the .7z materializes byte-exact for the (equally gated)
    /// disk post-pass, with the refusal named in the fallback reason.
    /// The fixture is the checked-in bomb seed, whose meaning
    /// nameprobe's checked_in_fuzz_seeds_keep_their_meaning pins; with
    /// the gate neutered the library errors on the garbage pack bytes
    /// instead, so the reason assertion is what discriminates.
    #[test]
    fn sevenz_bomb_header_demotes_at_the_gate() {
        let arch = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/sevenz/bomb-container.7z"
        ))
        .unwrap();
        let outer = store_outer("inner.7z", &arch);
        let dir = tmpdir("7z-bomb-gate");
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &outer, 7000, 48);
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.contains("oversized decode")),
            "the gate's refusal must be the named demote reason: {:?}",
            rep.fallbacks
        );
        assert!(!dir.join("F.bin").exists(), "no decoded output");
        assert_eq!(std::fs::read(dir.join("inner.7z")).unwrap(), arch);
        assert_eq!(dir_files(&dir), vec!["inner.7z".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Bytes never arrive: finish() aborts the still-blocked 7z worker
    /// and demotes cleanly - no hang, job Ok, the materialized .7z
    /// carries everything that DID arrive (the lost range stays an
    /// uncovered hole), partial output deleted.
    #[test]
    fn sevenz_missing_bytes_demotes() {
        // noisy: the packed 7z stays large enough that a whole article
        // sits inside its bytes.
        let f = noisy(300_000, 109);
        let arch = sevenz_archive(&[("F.bin", &f)], None, false);
        assert!(arch.len() > 10_000, "packed too small: {}", arch.len());
        let outer = store_outer("inner.7z", &arch);
        let data_off = {
            let mut m = VolumeMapper::new(outer.len() as u64);
            m.feed(0, &outer);
            m.entries[0].data_off as usize
        };
        let art = 1000usize;
        let lost = (data_off / art) + 2; // fully inside the 7z bytes
        let (ls, le) = (lost * art, ((lost + 1) * art).min(outer.len()));
        let dir = tmpdir("7z-missing");
        let ex = Extractor::new(&dir, 1, true);
        for i in 0..outer.len().div_ceil(art) {
            if i == lost {
                continue;
            }
            let s = i * art;
            let e = (s + art).min(outer.len());
            ex.write(0, "v.rar", outer.len() as u64, s as u64, &outer[s..e])
                .unwrap();
        }
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.starts_with("nested fallback:")),
            "{:?}",
            rep.fallbacks
        );
        assert!(!dir.join("F.bin").exists(), "partial 7z output survived");
        let got = std::fs::read(dir.join("inner.7z")).unwrap();
        let mut expect = arch.clone();
        expect[ls - data_off..le - data_off].fill(0);
        assert_eq!(got, expect);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Budget breach mid-chase: the retained 7z bytes charge the SHARED
    /// holds budget, and crossing the cap demotes to a materialized .7z
    /// - complete and byte-exact, partial output deleted.
    #[test]
    fn sevenz_budget_breach_demotes() {
        let f = noisy(2_400_000, 110);
        let arch = sevenz_archive(&[("F.bin", &f)], None, false);
        assert!(arch.len() > 900_000, "packed too small: {}", arch.len());
        let outer = store_outer("inner.7z", &arch);
        let dir = tmpdir("7z-budget");
        let ex = Extractor::new(&dir, 3, true);
        ex.set_holds_cap(1); // floors at 8 MB
        let junk = payload(65_000, 111);
        for slot in [1usize, 2] {
            for i in 0..60u64 {
                ex.write(
                    slot,
                    &format!("dummy{slot}.bin"),
                    8_000_000,
                    64_000 + i * 65_000,
                    &junk,
                )
                .unwrap();
            }
        }
        for (i, chunk) in outer.chunks(50_000).enumerate() {
            ex.write(0, "v.rar", outer.len() as u64, (i * 50_000) as u64, chunk)
                .unwrap();
        }
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.starts_with("nested fallback:")),
            "{:?}",
            rep.fallbacks
        );
        assert_eq!(std::fs::read(dir.join("inner.7z")).unwrap(), arch);
        assert!(!dir.join("F.bin").exists(), "partial 7z output survived");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A `.7z.001` whose siblings never turn up. The chase now opens a
    /// SET on it - part 1's start header sizes the whole container, so
    /// it knows there is more coming - and when nothing else registers,
    /// the container cannot be read and every part it holds materializes
    /// byte-exact for the disk post-pass to join. The reason is recorded
    /// where it used to be silent; the file on disk is unchanged.
    #[test]
    fn sevenz_multipart_part_without_its_siblings_materializes() {
        let f = payload(200_000, 112);
        let arch = sevenz_archive(&[("F.bin", &f)], None, false);
        let half = arch.len() / 2;
        let outer = store_outer("inner.7z.001", &arch[..half]);
        let dir = tmpdir("7z-multipart");
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &outer, 7000, 48);
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.starts_with("nested fallback:")),
            "{:?}",
            rep.fallbacks
        );
        assert_eq!(
            std::fs::read(dir.join("inner.7z.001")).unwrap(),
            &arch[..half]
        );
        assert_eq!(dir_files(&dir), vec!["inner.7z.001".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A single-file `.7z` posted directly - no RAR around it. The chase
    /// takes it at depth 0 now, so its payload streams out and the
    /// archive itself never touches disk. Three feed orders, including
    /// the natural one where the end header arrives dead last.
    #[test]
    fn sevenz_top_level_extracts_one_pass() {
        let f = payload(280_000, 120);
        let arch = sevenz_archive(&[("F.bin", &f)], None, false);
        let art = 7000usize;
        let n_arts = arch.len().div_ceil(art);
        let orders: Vec<Vec<usize>> = vec![
            (0..n_arts).collect(),                               // tail last
            (0..n_arts).rev().collect(),                         // tail first
            (0..n_arts).map(|i| (i * 7 + 3) % n_arts).collect(), // scrambled
        ];
        for (t, order) in orders.iter().enumerate() {
            let dir = tmpdir(&format!("7z-top-onepass{t}"));
            let ex = Arc::new(Extractor::new(&dir, 1, true));
            ex.anchor();
            let mut seen = vec![false; n_arts];
            for &i in order {
                if std::mem::replace(&mut seen[i], true) {
                    continue;
                }
                let s = i * art;
                let e = (s + art).min(arch.len());
                ex.write(0, "release.7z", arch.len() as u64, s as u64, &arch[s..e])
                    .unwrap();
            }
            let rep = ex.finish().unwrap();
            assert!(rep.fallbacks.is_empty(), "order {t}: {:?}", rep.fallbacks);
            assert!(
                rep.extracted
                    .iter()
                    .any(|(n, s)| n == "F.bin" && *s == f.len() as u64),
                "order {t}: {:?}",
                rep.extracted
            );
            assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f, "order {t}");
            // The point of the whole exercise: no materialized archive.
            assert_eq!(dir_files(&dir), vec!["F.bin".to_string()], "order {t}");
            assert_eq!(shape_of(&ex), ["7z", "one-pass"], "order {t}");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// The root half of the tail-prefetch wiring, which never worked
    /// before: `promote_slot_spans` used to bail at the root because it
    /// looked for a parent, and `map_output_range` could not see a slot
    /// with no writer. Now the posted `.7z` reaches the installed hook
    /// by its own name, and that name resolves back to its own slot.
    #[test]
    fn sevenz_top_level_tail_promote_reaches_the_root_hook() {
        let f = payload(240_000, 121);
        let arch = sevenz_archive(&[("F.bin", &f)], None, false);
        let (ho, hs) = sevenz_start_header(&arch).expect("fixture start header");
        let tail = (32 + ho, 32 + ho + hs);
        let dir = tmpdir("7z-top-promote");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        type Calls = Arc<Mutex<Vec<(String, u64, Vec<(u64, u64)>)>>>;
        let calls: Calls = Default::default();
        let sink = calls.clone();
        ex.set_promote_hook(Arc::new(
            move |n: &str, s: u64, sp: &[(u64, u64)], _u: bool| {
                sink.lock().unwrap().push((n.to_string(), s, sp.to_vec()));
            },
        ));
        feed(&ex, 0, "release.7z", &arch, 6000, 50);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
        // Shuffled feed: the offset-0 probe may fire first (same slot
        // name, spans always leading with (0, 1)); the subject here is
        // the tail promote reaching the root hook.
        let mut got = calls.lock().unwrap().clone();
        got.retain(|(_, _, sp)| sp.first() != Some(&(0, 1)));
        assert_eq!(
            got,
            vec![("release.7z".to_string(), arch.len() as u64, vec![tail])]
        );
        // The main.rs half: the hook's (name, range) resolves to this
        // slot's own bytes, identity - it IS the posted file.
        assert_eq!(
            ex.map_output_range("release.7z", tail.0, tail.1),
            vec![(0usize, tail.0, tail.1, arch.len() as u64)]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Over the retention cap at depth 0: with no drop-behind trimming
    /// the archive cannot be held, so it demotes to a materialized .7z
    /// for the disk post-pass - byte-exact, partial output swept. The
    /// demote reason keeps the "held-bytes cap" substring the caller
    /// reads, under the marker that keeps a lone .7z out of the RAR
    /// unpack ladder.
    #[test]
    fn sevenz_top_level_budget_breach_demotes() {
        let f = noisy(2_400_000, 122);
        let arch = sevenz_archive(&[("F.bin", &f)], None, false);
        assert!(arch.len() > 900_000, "packed too small: {}", arch.len());
        let dir = tmpdir("7z-top-budget");
        let ex = Arc::new(Extractor::new(&dir, 3, true));
        ex.anchor();
        ex.set_holds_cap(1); // floors at 8 MB
        let junk = payload(65_000, 123);
        for slot in [1usize, 2] {
            for i in 0..60u64 {
                ex.write(
                    slot,
                    &format!("dummy{slot}.bin"),
                    8_000_000,
                    64_000 + i * 65_000,
                    &junk,
                )
                .unwrap();
            }
        }
        for (i, chunk) in arch.chunks(50_000).enumerate() {
            ex.write(
                0,
                "release.7z",
                arch.len() as u64,
                (i * 50_000) as u64,
                chunk,
            )
            .unwrap();
        }
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.starts_with(SEVENZ_DISK_FALLBACK_PREFIX)
                    && w.contains("held-bytes cap: chase memory")),
            "{:?}",
            rep.fallbacks
        );
        assert_eq!(std::fs::read(dir.join("release.7z")).unwrap(), arch);
        assert!(!dir.join("F.bin").exists(), "partial 7z output survived");
        // Nothing streamed, so the badge must not claim a partial pass.
        assert_eq!(shape_of(&ex), ["7z", "on-disk"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The same lone-part case at depth 0: a set opens, nothing else
    /// joins it, and the part materializes byte-exact under the marker
    /// that keeps a lone `.7z` out of the RAR unpack ladder.
    #[test]
    fn sevenz_top_level_multipart_without_its_siblings_materializes() {
        let f = payload(200_000, 124);
        let arch = sevenz_archive(&[("F.bin", &f)], None, false);
        let half = arch.len() / 2;
        let dir = tmpdir("7z-top-multipart");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        feed(&ex, 0, "release.7z.001", &arch[..half], 7000, 51);
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.starts_with(SEVENZ_DISK_FALLBACK_PREFIX)),
            "{:?}",
            rep.fallbacks
        );
        assert_eq!(
            std::fs::read(dir.join("release.7z.001")).unwrap(),
            &arch[..half]
        );
        assert_eq!(dir_files(&dir), vec!["release.7z.001".to_string()]);
        assert_eq!(shape_of(&ex), ["7z", "on-disk"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The top-level gate: NZBFAST_NO_TOP_7Z=1 parses as off, and the
    /// runtime setter drives the same latch - with it off a posted .7z
    /// materializes for the disk post-pass exactly as it did before the
    /// depth guard came off, while a NESTED .7z keeps streaming. The env
    /// PARSE is asserted on the pure helper for the same parallel-runner
    /// reason as `nested_disabled_by_env`.
    #[test]
    fn top_level_sevenz_disabled_by_env() {
        assert!(top_sevenz_env_off_value(Some("1")));
        assert!(!top_sevenz_env_off_value(Some("0")));
        assert!(!top_sevenz_env_off_value(None));

        let f = payload(150_000, 125);
        let arch = sevenz_archive(&[("F.bin", &f)], None, false);
        let dir = tmpdir("7z-top-gate");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        assert!(
            ex.inner.lock().unwrap().top_sevenz_on,
            "gate must default on"
        );
        ex.set_top_level_sevenz(false);
        feed(&ex, 0, "release.7z", &arch, 7000, 52);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("release.7z")).unwrap(), arch);
        assert_eq!(dir_files(&dir), vec!["release.7z".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();

        // Same gate off, a .7z one level down: still streams.
        let outer = store_outer("inner.7z", &arch);
        let dir = tmpdir("7z-top-gate-nested");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        ex.set_top_level_sevenz(false);
        feed(&ex, 0, "v.rar", &outer, 7000, 53);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
        assert_eq!(dir_files(&dir), vec!["F.bin".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A deflate-compressed 7z streams. 7z permits deflate and real
    /// archives use it, but the codec was left off the feature list even
    /// though flate2 - the decoder it needs - has always been a direct
    /// dependency for zip, so it declined for nothing.
    #[test]
    fn sevenz_top_level_deflate_extracts_one_pass() {
        let data: Vec<u8> = (0..150_000u32).map(|i| (i / 811 % 239) as u8).collect();
        let arch = sevenz_archive(
            &[("a.bin", &data)],
            Some(vec![sevenz_rust2::EncoderConfiguration::new(
                sevenz_rust2::EncoderMethod::DEFLATE,
            )]),
            false,
        );
        let dir = tmpdir("7z-deflate");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        feed(&ex, 0, "release.7z", &arch, 7000, 63);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), data);
        assert!(!dir.join("release.7z").exists(), "container materialized");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A `.7z.001` split set streams as ONE container. Part 1's start
    /// header sizes the whole thing (a 7z end header is the last thing
    /// in a container, so `32 + offset + size` is the end), which is how
    /// a chase that has only seen part 1 knows how far the container
    /// runs and where its map lives; the other parts carry no signature
    /// at all and join by name. Feed orders include parts arriving
    /// backwards, because nothing guarantees `.001` classifies first.
    #[test]
    fn sevenz_multipart_set_extracts_one_pass() {
        let f = payload(600_000, 140);
        let arch = sevenz_archive(&[("F.bin", &f)], None, false);
        let parts = split_7z(&arch, 3);
        assert_eq!(parts.len(), 3, "fixture must really split");
        for (t, order) in [vec![0, 1, 2], vec![2, 1, 0], vec![1, 2, 0]]
            .iter()
            .enumerate()
        {
            let dir = tmpdir(&format!("7z-split{t}"));
            let ex = Arc::new(Extractor::new(&dir, 3, true));
            ex.anchor();
            for &i in order {
                feed(
                    &ex,
                    i,
                    &format!("big.7z.{:03}", i + 1),
                    &parts[i],
                    7000,
                    60 + i as u64,
                );
            }
            let rep = ex.finish().unwrap();
            assert!(rep.fallbacks.is_empty(), "order {t}: {:?}", rep.fallbacks);
            assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f, "order {t}");
            // No part on disk: the whole set streamed.
            assert_eq!(dir_files(&dir), vec!["F.bin".to_string()], "order {t}");
            assert_eq!(shape_of(&ex), ["7z", "one-pass"], "order {t}");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// A part missing entirely: the container has a hole in it, so it
    /// cannot be read at all and EVERY part that did arrive materializes
    /// byte-exact for the disk post-pass. Half a byte split is worth
    /// nothing on its own, which is why the demote is all-or-nothing.
    #[test]
    fn sevenz_multipart_set_missing_a_part_materializes_the_rest() {
        let f = payload(600_000, 141);
        let arch = sevenz_archive(&[("F.bin", &f)], None, false);
        let parts = split_7z(&arch, 3);
        let dir = tmpdir("7z-split-hole");
        let ex = Arc::new(Extractor::new(&dir, 3, true));
        ex.anchor();
        for i in [0usize, 2] {
            feed(
                &ex,
                i,
                &format!("big.7z.{:03}", i + 1),
                &parts[i],
                7000,
                70 + i as u64,
            );
        }
        let rep = ex.finish().unwrap();
        assert!(!rep.fallbacks.is_empty(), "the set must demote");
        assert!(!dir.join("F.bin").exists(), "partial output survived");
        assert_eq!(std::fs::read(dir.join("big.7z.001")).unwrap(), parts[0]);
        assert_eq!(std::fs::read(dir.join("big.7z.003")).unwrap(), parts[2]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A set whose parts are not a uniform `7z -v` split cannot be
    /// mapped from a container offset to a part at all, so the chase
    /// refuses the whole set rather than guess. Everything materializes
    /// and the disk post-pass joins it, which is what happened to every
    /// split set before this existed.
    #[test]
    fn sevenz_multipart_uneven_parts_refuse_the_set() {
        let f = payload(600_000, 142);
        let arch = sevenz_archive(&[("F.bin", &f)], None, false);
        let cut = arch.len() / 3;
        // Deliberately not a uniform split: part 2 is short.
        let parts = [
            arch[..cut].to_vec(),
            arch[cut..cut + cut / 2].to_vec(),
            arch[cut + cut / 2..].to_vec(),
        ];
        let dir = tmpdir("7z-split-uneven");
        let ex = Arc::new(Extractor::new(&dir, 3, true));
        ex.anchor();
        for i in 0..3 {
            feed(
                &ex,
                i,
                &format!("big.7z.{:03}", i + 1),
                &parts[i],
                7000,
                80 + i as u64,
            );
        }
        let rep = ex.finish().unwrap();
        assert!(!rep.fallbacks.is_empty(), "the set must refuse");
        assert!(!dir.join("F.bin").exists(), "partial output survived");
        for i in 0..3 {
            assert_eq!(
                std::fs::read(dir.join(format!("big.7z.{:03}", i + 1))).unwrap(),
                parts[i],
                "part {} not byte-exact",
                i + 1
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The 7z twin of
    /// `chase_tests::failed_reclaim_at_attach_leaves_the_slot_chased`:
    /// a continuation part whose seed reclaim dies (a paged hold whose
    /// scratch file is gone) must still leave a CHASED slot. The join
    /// flips the slot to `SlotMode::SevenZ` and registers it with the
    /// set BEFORE the seed loop, so a bail-out that leaves `chase` at
    /// None sends every later span for it into `chase_span`'s
    /// impossible `_ =>` arm - a debug assert here, and a silent byte
    /// drop in release. The set handle has to survive the same way, or
    /// a later demote cannot take the whole container down.
    #[test]
    fn sevenz_failed_reclaim_at_join_leaves_the_slot_chased() {
        let f = payload(300_000, 144);
        // COPY, so the parts are big enough to carry a pile of held
        // spans: an LZMA2 pack of this payload is a few hundred bytes.
        let arch = sevenz_archive(
            &[("F.bin", &f)],
            Some(vec![sevenz_rust2::EncoderConfiguration::new(
                sevenz_rust2::EncoderMethod::COPY,
            )]),
            false,
        );
        let parts = split_7z(&arch, 3);
        assert_eq!(parts.len(), 3, "fixture must really split");
        let two = &parts[1];
        assert!(two.len() > 50_000, "part too small: {}", two.len());
        let art = 7000usize;
        let n = two.len().div_ceil(art);
        let dir = tmpdir("7z-split-reclaim-fail");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        // Everything but the head and the tail. A continuation part
        // carries no signature at all, so nothing classifies until the
        // offset-0 span arrives and these all park in the holds.
        for i in (1..n - 1).rev() {
            let s = i * art;
            let e = (s + art).min(two.len());
            ex.write(0, "big.7z.002", two.len() as u64, s as u64, &two[s..e])
                .unwrap();
        }
        // A paged hold whose scratch file is gone, first in the vec:
        // the seed loop's very first reclaim fails.
        {
            let mut g = ex.inner.lock_ok();
            let inner = &mut *g;
            let junk = vec![0x5Au8; 4096];
            let off = inner.scratch.append(&junk, u64::MAX).unwrap();
            inner.slots[0].holds.insert(
                0,
                (
                    art as u64,
                    HoldSpan::Paged {
                        off,
                        len: junk.len(),
                    },
                ),
            );
            inner.scratch.st().file = None;
        }
        // The offset-0 span joins the part to a PENDING set (nothing
        // guarantees `.7z.001` classifies first), which commits the
        // slot - and then the seed fails.
        assert!(
            ex.write(0, "big.7z.002", two.len() as u64, 0, &two[..art])
                .is_err(),
            "a dead scratch must fail the join's seed"
        );
        {
            let g = ex.inner.lock_ok();
            assert!(matches!(g.slots[0].mode, SlotMode::SevenZ));
            assert!(
                g.slots[0].chase.is_some(),
                "the join bailed out leaving a SevenZ slot with no chase"
            );
            assert!(
                g.slots[0].sevenz.is_some(),
                "the set handle went with the chase, or a demote cannot \
                 take the container down"
            );
        }
        // The span that used to hit the impossible arm.
        let s = (n - 1) * art;
        ex.write(0, "big.7z.002", two.len() as u64, s as u64, &two[s..])
            .expect("a later span for the joined slot must still route");
        let rep = ex.finish().unwrap();
        assert!(!rep.fallbacks.is_empty(), "the failed join must demote");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The case step 3 exists for, and the reason it had to wait for
    /// step 2: a split set BIGGER than the retention cap. Every part
    /// drops behind independently into its own `.7z.NNN` path, and a
    /// part the engine has read straight past releases whole. Without
    /// trimming this could only ever demote - which is why multipart was
    /// worth 0.04% of posted bytes before it and ~4% after.
    #[test]
    fn sevenz_multipart_set_over_the_cap_trims_and_streams() {
        let f = noisy(24 << 20, 143);
        let arch = sevenz_archive(
            &[("F.bin", &f)],
            Some(vec![sevenz_rust2::EncoderConfiguration::new(
                sevenz_rust2::EncoderMethod::COPY,
            )]),
            false,
        );
        let parts = split_7z(&arch, 3);
        assert_eq!(parts.len(), 3);
        let dir = tmpdir("7z-split-trim");
        let ex = Arc::new(Extractor::new(&dir, 3, true));
        ex.anchor();
        ex.set_holds_cap(1); // floors at 8 MB, against a 24 MB container
        let chunk = 256 << 10;
        let put = |i: usize, off: usize, end: usize| {
            ex.write(
                i,
                &format!("big.7z.{:03}", i + 1),
                parts[i].len() as u64,
                off as u64,
                &parts[i][off..end.min(parts[i].len())],
            )
            .unwrap();
        };
        // Classify every part first, then deliver the tail. On a split
        // container the end header lives in the LAST part, so the parse
        // cannot even start until that part has registered - which is
        // exactly why the promote ladder front-loads it in the field.
        for i in 0..3 {
            put(i, 0, chunk);
        }
        let last = parts[2].len();
        put(2, last.saturating_sub(chunk * 2).max(chunk), last);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while std::time::Instant::now() < deadline {
            match sevenz_ctl(&ex, 0) {
                Some(c) if c.trim_ok.load(Ordering::Relaxed) => break,
                Some(_) => std::thread::sleep(std::time::Duration::from_millis(1)),
                None => break,
            }
        }
        // Now the bodies, in container order, paced against the engine's
        // read position so the decoder stays in touch with the arrivals.
        let part_size = parts[0].len();
        let mut high = 0u64;
        for i in 0..3 {
            let mut off = chunk;
            while off < parts[i].len() {
                put(i, off, off + chunk);
                off += chunk;
                let fed = (i * part_size + off) as u64;
                let wait = std::time::Instant::now() + std::time::Duration::from_secs(30);
                loop {
                    let Some(c) = sevenz_ctl(&ex, i) else { break };
                    high = high.max(
                        ex.inner.lock().unwrap().slots[0]
                            .chase
                            .as_ref()
                            .map_or(0, |ch| ch.buf.base()),
                    );
                    if c.low_water.load(Ordering::Relaxed) + (2 << 20) >= fed
                        || std::time::Instant::now() > wait
                    {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            }
        }
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert!(
            high > 0,
            "part 1 was never trimmed - the test proved nothing"
        );
        assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
        assert_eq!(
            dir_files(&dir),
            vec!["F.bin".to_string()],
            "a part survived"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Arming the trim must RESET the watermark, not just flip the flag.
    /// The parse ends having read the end header, so the reader's
    /// position is at EOF when the map becomes known - measured exactly
    /// `total` on a real fixture. Arming against that leaves a window,
    /// until the engine seeks back to the first pack stream, in which a
    /// budget breach releases the whole buffer and the next read lands
    /// behind the trim point: a forfeit, and a spurious demote of
    /// precisely the large archive drop-behind exists for.
    #[test]
    fn arming_the_trim_forgets_the_open_phase_watermark() {
        let ctl = SevenZCtl::pending("x.7z".to_string());
        ctl.low_water.store(25_165_914, Ordering::Relaxed);
        ctl.arm_trim(false);
        assert_eq!(
            ctl.low_water.load(Ordering::Relaxed),
            0,
            "an EOF watermark survived into the trim path"
        );
        assert!(ctl.trim_ok.load(Ordering::Relaxed));
        // And a coder chain that needs history is refused outright.
        ctl.low_water.store(999, Ordering::Relaxed);
        ctl.arm_trim(true);
        assert_eq!(ctl.low_water.load(Ordering::Relaxed), 0);
        assert!(!ctl.trim_ok.load(Ordering::Relaxed));
    }

    /// A forfeit raised on ONE part must take the whole container.
    ///
    /// This is the shape of a silent total-data-loss bug: routing the
    /// budget/conflict forfeits through the single-slot demote let
    /// `fallback_slot` drain the container's whole sink list (every
    /// member shares one ctl), deleting the payload, while the other
    /// members stayed in `SevenZ` with the set un-aborted. The worker
    /// read on, wrote into a slot that had become `Discard` (which
    /// swallows writes), and returned Ok - so `sevenz_finish` took the
    /// survivors' SUCCESS path, dropped their retained bytes and
    /// unlinked their spilled prefixes. What survived was one orphaned
    /// `.7z.002`, no payload, and a job reporting completion.
    ///
    /// The assertion that matters is the last one: whatever else
    /// happens, every posted byte has to be somewhere.
    #[test]
    fn sevenz_multipart_forfeit_on_one_part_demotes_the_whole_container() {
        let f = payload(600_000, 144);
        let arch = sevenz_archive(&[("F.bin", &f)], None, false);
        let parts = split_7z(&arch, 3);
        let dir = tmpdir("7z-split-forfeit");
        let ex = Arc::new(Extractor::new(&dir, 3, true));
        ex.anchor();
        ex.set_sevenz_trim(false); // force the breach to demote, not trim
        for i in 0..3 {
            feed(
                &ex,
                i,
                &format!("big.7z.{:03}", i + 1),
                &parts[i],
                7000,
                90 + i as u64,
            );
        }
        // Wait for the worker to have finished SUCCESSFULLY. That is the
        // window the bug lives in: a forfeit arriving afterwards is never
        // seen by the worker (its liveness check only runs at the start
        // of each entry), so finish() would take the success path for
        // every member that was not the one named below.
        let ctl = sevenz_ctl(&ex, 0).expect("chase attached");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while std::time::Instant::now() < deadline {
            if matches!(*ctl.outcome.lock().unwrap(), Some(Ok(()))) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(
            matches!(*ctl.outcome.lock().unwrap(), Some(Ok(()))),
            "worker did not finish - the test never reaches the window"
        );
        // Forfeit through the same route a retention-cap breach takes,
        // naming only ONE member.
        {
            let mut g = ex.inner.lock().unwrap();
            let inner = &mut *g;
            ex.chase_forfeit(inner, 1, "held-bytes cap: chase memory")
                .unwrap();
        }
        let rep = ex.finish().unwrap();
        assert!(!rep.fallbacks.is_empty(), "the container must demote");
        // Every part on disk, byte-exact: the container is recoverable
        // by the disk post-pass exactly as it was before the chase.
        // (The payload is gone - the forfeit abandoned it - which is
        // correct; what must never happen is losing the parts too.)
        for i in 0..3 {
            assert_eq!(
                std::fs::read(dir.join(format!("big.7z.{:03}", i + 1))).unwrap(),
                parts[i],
                "part {} did not materialize",
                i + 1
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The part-name rule, which is the only thing that recognizes a
    /// continuation part - they carry no signature of their own.
    #[test]
    fn sevenz_part_names_parse() {
        assert_eq!(
            sevenz_part_name("Some.Release.7z.001"),
            Some(("some.release.7z".to_string(), 1))
        );
        assert_eq!(
            sevenz_part_name("Some.Release.7Z.012"),
            Some(("some.release.7z".to_string(), 12))
        );
        // Not split parts.
        assert_eq!(sevenz_part_name("plain.7z"), None);
        assert_eq!(sevenz_part_name("movie.mkv"), None);
        assert_eq!(sevenz_part_name("set.rar.001"), None);
        assert_eq!(sevenz_part_name("set.7z.000"), None);
        assert_eq!(sevenz_part_name("set.7z.abc"), None);
        assert_eq!(sevenz_part_name("set.7z.12345"), None);
    }

    /// A `.7z` several times the retention cap streams end to end: the
    /// engine's consumed prefix is dropped out of RAM into the archive's
    /// own path as it goes, and on success that partial file is removed,
    /// so the payload is the only thing left. Before trimming, an
    /// archive this size could only demote.
    #[test]
    fn sevenz_trim_streams_an_archive_over_the_cap() {
        let f = noisy(24 << 20, 130);
        // Copy codec: no compression, so "decode" keeps up with arrival
        // the way it does on the already-compressed video that is the
        // overwhelming majority of posted payload.
        let arch = sevenz_archive(
            &[("F.bin", &f)],
            Some(vec![sevenz_rust2::EncoderConfiguration::new(
                sevenz_rust2::EncoderMethod::COPY,
            )]),
            false,
        );
        assert!(arch.len() > 24 << 20, "fixture too small: {}", arch.len());
        let dir = tmpdir("7z-trim-stream");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        ex.set_holds_cap(1); // floors at 8 MB, so the archive is 3x the cap
        let high_base = feed_paced_tail_first(&ex, 0, "big.7z", &arch, 256 << 10, 2 << 20, 0);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert!(
            high_base > 0,
            "nothing was ever trimmed - the test proved nothing"
        );
        assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
        assert_eq!(
            dir_files(&dir),
            vec!["F.bin".to_string()],
            "spilled archive survived"
        );
        assert_eq!(shape_of(&ex), ["7z", "one-pass"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The demote path stays free. Spilling into the archive's own path
    /// rather than a temp file means a chase that trims and THEN fails
    /// finds its prefix already in the right place: `fallback_slot`
    /// writes only what is still in RAM, and the materialized archive is
    /// whole and byte-exact.
    #[test]
    fn sevenz_trim_then_demote_materializes_byte_exact() {
        let f = noisy(24 << 20, 131);
        let arch = sevenz_archive(
            &[("F.bin", &f)],
            Some(vec![sevenz_rust2::EncoderConfiguration::new(
                sevenz_rust2::EncoderMethod::COPY,
            )]),
            false,
        );
        let dir = tmpdir("7z-trim-demote");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        ex.set_holds_cap(1);
        // Stop short of the end so the chase cannot complete, then feed
        // the remainder and demote: the archive must still be exact.
        let chunk = 256 << 10;
        let high_base = feed_paced_tail_first(&ex, 0, "big.7z", &arch, chunk, 2 << 20, 4);
        assert!(
            high_base > 0,
            "nothing was ever trimmed - the test proved nothing"
        );
        {
            let mut g = ex.inner.lock().unwrap();
            let inner = &mut *g;
            ex.fallback_slot_or_group(inner, 0, "held-bytes cap: chase memory")
                .unwrap();
        }
        // The body chunks the demote never saw arrive afterwards, as
        // late articles would, and land in the materialized file.
        let tail_from = arch.len().saturating_sub(chunk * 2).max(chunk);
        let gap = tail_from - chunk * 4;
        ex.write(
            0,
            "big.7z",
            arch.len() as u64,
            gap as u64,
            &arch[gap..tail_from],
        )
        .unwrap();
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.contains("held-bytes cap: chase memory")),
            "{:?}",
            rep.fallbacks
        );
        assert_eq!(
            std::fs::read(dir.join("big.7z")).unwrap(),
            arch,
            "the materialized archive lost the trimmed prefix"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// PAR2 read-back has to work over a trimmed prefix, or a job whose
    /// archive is being trimmed reports its own blocks bad. The slot's
    /// coverage and read paths split at the trim point: below it the
    /// spilled archive file answers, above it the buffer does.
    #[test]
    fn sevenz_trim_keeps_the_slot_readable_across_the_split() {
        let f = noisy(24 << 20, 132);
        let arch = sevenz_archive(
            &[("F.bin", &f)],
            Some(vec![sevenz_rust2::EncoderConfiguration::new(
                sevenz_rust2::EncoderMethod::COPY,
            )]),
            false,
        );
        let dir = tmpdir("7z-trim-readback");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        ex.set_holds_cap(1);
        let chunk = 256 << 10;
        let high_base = feed_paced_tail_first(&ex, 0, "big.7z", &arch, chunk, 2 << 20, 4);
        assert!(
            high_base > 0,
            "nothing was ever trimmed - the test proved nothing"
        );
        let base = ex.inner.lock().unwrap().slots[0]
            .chase
            .as_ref()
            .unwrap()
            .buf
            .base();
        assert!(base > 0);
        // A window straddling the trim point: half off disk, half out of
        // the frontier buffer, and it has to read as the archive does.
        let lo = (base - 4096) as usize;
        let hi = (base + 4096) as usize;
        assert!(
            ex.covered(0, lo as u64, hi - lo),
            "straddling window not covered"
        );
        let mut got = vec![0u8; hi - lo];
        ex.read_at(0, lo as u64, &mut got).unwrap();
        assert_eq!(got, arch[lo..hi], "read across the trim point differs");
        // And the very first bytes, long since spilled.
        assert!(ex.covered(0, 0, 4096));
        let mut head = vec![0u8; 4096];
        ex.read_at(0, 0, &mut head).unwrap();
        assert_eq!(head, arch[..4096]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The trim gate: NZBFAST_NO_7Z_TRIM=1 parses as off, and with it off
    /// an archive over the cap demotes exactly as it did before trimming
    /// existed. The env PARSE is asserted on the pure helper for the same
    /// parallel-runner reason as `nested_disabled_by_env`.
    #[test]
    fn sevenz_trim_disabled_by_env() {
        assert!(sevenz_trim_env_off_value(Some("1")));
        assert!(!sevenz_trim_env_off_value(Some("0")));
        assert!(!sevenz_trim_env_off_value(None));

        let f = noisy(24 << 20, 133);
        let arch = sevenz_archive(
            &[("F.bin", &f)],
            Some(vec![sevenz_rust2::EncoderConfiguration::new(
                sevenz_rust2::EncoderMethod::COPY,
            )]),
            false,
        );
        let dir = tmpdir("7z-trim-gate");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        assert!(
            ex.inner.lock().unwrap().sevenz_trim_on,
            "gate must default on"
        );
        ex.set_sevenz_trim(false);
        ex.set_holds_cap(1);
        let high_base = feed_paced_tail_first(&ex, 0, "big.7z", &arch, 256 << 10, 2 << 20, 0);
        let rep = ex.finish().unwrap();
        assert_eq!(high_base, 0, "the gate did not stop the trim");
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.contains("held-bytes cap: chase memory")),
            "{:?}",
            rep.fallbacks
        );
        assert_eq!(std::fs::read(dir.join("big.7z")).unwrap(), arch);
        // Since TODO 213 item 2 a cap forfeit KEEPS the member's
        // committed prefix for the disk pass to resume from, so "no
        // partial survived" is no longer the test - the RAR arm's
        // invariant is, and it is the same one for both container
        // families by construction.
        assert_resume_ledger_honest(&dir, "F.bin", &rep, &f);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A span landing BELOW the trim point is the one delivery the
    /// buffer cannot judge - those bytes are on disk, not in `data`, so
    /// there is nothing to compare against. It is treated as a repair
    /// rewrite: the file takes the new bytes (so the materialized
    /// archive carries them) and the chase forfeits, because anything
    /// the engine decoded from that range came from the old copy.
    #[test]
    fn sevenz_span_below_the_trim_point_forfeits_and_corrects_the_file() {
        let f = noisy(24 << 20, 135);
        let arch = sevenz_archive(
            &[("F.bin", &f)],
            Some(vec![sevenz_rust2::EncoderConfiguration::new(
                sevenz_rust2::EncoderMethod::COPY,
            )]),
            false,
        );
        let dir = tmpdir("7z-trim-rewrite");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        ex.set_holds_cap(1);
        let chunk = 256 << 10;
        let high_base = feed_paced_tail_first(&ex, 0, "big.7z", &arch, chunk, 2 << 20, 4);
        assert!(
            high_base > 0,
            "nothing was ever trimmed - the test proved nothing"
        );
        let base = ex.inner.lock().unwrap().slots[0]
            .chase
            .as_ref()
            .unwrap()
            .buf
            .base();
        // A rewrite of a long-spilled range, with DIFFERENT bytes - the
        // poster-side damage shape the conflict guard exists for.
        let at = (base / 2) as usize;
        let mut fixed = arch[at..at + 8192].to_vec();
        fixed[0] ^= 0xff;
        ex.write(0, "big.7z", arch.len() as u64, at as u64, &fixed)
            .unwrap();
        // Deliver the rest so nothing is missing but the forfeit.
        let tail_from = arch.len().saturating_sub(chunk * 2).max(chunk);
        let gap = tail_from - chunk * 4;
        ex.write(
            0,
            "big.7z",
            arch.len() as u64,
            gap as u64,
            &arch[gap..tail_from],
        )
        .unwrap();
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.contains("repair rewrote chased bytes")),
            "the chase did not forfeit: {:?}",
            rep.fallbacks
        );
        assert!(
            !dir.join("F.bin").exists(),
            "partial output survived the forfeit"
        );
        let mut want = arch.clone();
        want[at..at + 8192].copy_from_slice(&fixed);
        assert_eq!(
            std::fs::read(dir.join("big.7z")).unwrap(),
            want,
            "the materialized archive kept the stale bytes"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The BCJ2 opt-out reads the coder map, which is known from the end
    /// header before any payload byte is touched. The encoder half of
    /// sevenz-rust2 cannot WRITE a BCJ2 archive, so the positive case has
    /// no in-process fixture; what is pinned here is that the predicate
    /// runs against a real parsed archive and clears the ordinary chains,
    /// which is what decides whether trimming is allowed at all.
    #[test]
    fn sevenz_needs_history_clears_the_ordinary_coder_chains() {
        let f = payload(200_000, 134);
        for (tag, methods) in [
            ("lzma2", None),
            (
                "copy",
                Some(vec![sevenz_rust2::EncoderConfiguration::new(
                    sevenz_rust2::EncoderMethod::COPY,
                )]),
            ),
        ] {
            let arch = sevenz_archive(&[("F.bin", &f)], methods, false);
            let reader = sevenz_rust2::ArchiveReader::new(
                std::io::Cursor::new(arch),
                sevenz_rust2::Password::empty(),
            )
            .unwrap();
            assert!(
                !Extractor::sevenz_needs_history(reader.archive()),
                "{tag} must be trimmable"
            );
        }
    }

    /// A root that never called [`Extractor::anchor`] has no handle for
    /// a chase worker to reach it through, so a posted `.7z` declines
    /// and materializes. That is the safe direction (it is exactly the
    /// pre-TODO-37 behaviour), and pinning it here says so out loud -
    /// the alternative reading, "the guard lift did nothing", would look
    /// identical from the output directory.
    #[test]
    fn sevenz_top_level_declines_without_an_anchor() {
        let f = payload(150_000, 127);
        let arch = sevenz_archive(&[("F.bin", &f)], None, false);
        let dir = tmpdir("7z-top-unanchored");
        let ex = Extractor::new(&dir, 1, true); // no Arc, no anchor
        feed(&ex, 0, "release.7z", &arch, 7000, 55);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(dir_files(&dir), vec!["release.7z".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A resumed run never chases: extraction is disabled wholesale, so
    /// every slot classifies Plain on its first span and the posted .7z
    /// lands on disk. That is what keeps the journal honest - chase
    /// bytes are held in RAM and never recorded as persisted, so a
    /// resumed job that re-entered the chase would re-download the whole
    /// archive to fill a buffer it then throws away.
    #[test]
    fn sevenz_top_level_never_chases_on_a_resumed_run() {
        let f = payload(160_000, 126);
        let arch = sevenz_archive(&[("F.bin", &f)], None, false);
        let dir = tmpdir("7z-top-resume");
        let ex = Arc::new(Extractor::with_resume(&dir, 1, false, true));
        ex.anchor();
        feed(&ex, 0, "release.7z", &arch, 7000, 54);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("release.7z")).unwrap(), arch);
        assert_eq!(dir_files(&dir), vec!["release.7z".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The 7z gates: NZBFAST_NO_NESTED_7Z=1 parses as off, and the
    /// runtime setter drives the same latch - with it off, an inner .7z
    /// materializes exactly as before the 7z path existed (nested
    /// routing itself stays on). The env PARSE is asserted on the pure
    /// helper for the same parallel-runner reason as
    /// `nested_disabled_by_env`.
    #[test]
    fn sevenz_disabled_by_env() {
        assert!(sevenz_env_off_value(Some("1")));
        assert!(!sevenz_env_off_value(Some("0")));
        assert!(!sevenz_env_off_value(None));

        let f = payload(140_000, 113);
        let arch = sevenz_archive(&[("F.bin", &f)], None, false);
        let outer = store_outer("inner.7z", &arch);
        let dir = tmpdir("7z-gate");
        let ex = Extractor::new(&dir, 1, true);
        assert!(ex.inner.lock().unwrap().sevenz_on, "gate must default on");
        ex.set_nested_sevenz(false);
        feed(&ex, 0, "v.rar", &outer, 7000, 49);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("inner.7z")).unwrap(), arch);
        assert!(!dir.join("F.bin").exists());
        assert_eq!(dir_files(&dir), vec!["inner.7z".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Cancel semantics: dropping an extractor mid-7z-chase aborts the
    /// buffer and the worker exits - the drop returns instead of
    /// hanging on bytes that will never arrive.
    #[test]
    fn sevenz_worker_exits_on_extractor_drop() {
        let f = noisy(300_000, 114);
        let arch = sevenz_archive(&[("F.bin", &f)], None, false);
        let outer = store_outer("inner.7z", &arch);
        assert!(outer.len() > 4000, "fixture too small: {}", outer.len());
        let dir = tmpdir("7z-drop");
        let ex = Extractor::new(&dir, 1, true);
        // Enough for the sniff + 7z attach, then abandon the job.
        ex.write(0, "v.rar", outer.len() as u64, 0, &outer[..4000])
            .unwrap();
        drop(ex);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
