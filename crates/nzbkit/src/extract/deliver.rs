//! Delivery: how a decoded span reaches its writer once routing has
//! decided where it belongs. The plain write-through and the chain-shared
//! output-name claim, forwarded (child) and routed delivery with the
//! re-resolve loop that survives a group merge, the off-lock flushes of
//! the pending forward/promote queues, the header-byte stash for
//! byte-exact reconstruction, and the tail-prefetch promote that walks up
//! the nesting chain one lock at a time. Split out of extract/mod.rs
//! (TODO 106 size gate) as a second `impl Extractor`; callers in the
//! parent reach the methods through `pub(super)`.

use super::*;

impl Extractor {
    /// Queue a plain write of the whole span (lock held; write happens
    /// after it drops).
    pub(super) fn plain_job(
        &self,
        inner: &mut Inner,
        slot: usize,
        offset: u64,
        data: &[u8],
        jobs: &mut Vec<WriteJob>,
    ) -> io::Result<()> {
        let w = self.ensure_plain_writer(inner, slot)?;
        jobs.push(WriteJob {
            writer: w,
            file_off: offset,
            src_start: 0,
            len: data.len(),
            crypto: None,
            repair: false,
        });
        Ok(())
    }

    pub(super) fn ensure_plain_writer(
        &self,
        inner: &mut Inner,
        slot: usize,
    ) -> io::Result<Arc<FileWriter>> {
        if inner.slots[slot].writer.is_none() {
            let s = &inner.slots[slot];
            let base = if s.name.is_empty() {
                format!("slot{slot:03}")
            } else {
                s.name.clone()
            };
            let mut fname = sanitize_filename(&base);
            Self::claim_name(inner, slot, &mut fname);
            let path = self.out_dir.join(&fname);
            // The same two bounds as `inner_writer`, and for the same
            // reason: with nested routing on (the default) a group's inner
            // files are forwarded to the CHILD, so a non-archive inner
            // file materializes HERE, at depth > 0, with the slot size the
            // parent forwarded - i.e. the poster's declared
            // `unpacked_size`. At level 0 the slot size comes from the NZB
            // and is below the posted ceiling by construction, so the cap
            // never binds there and preallocation is untouched.
            let size = inner.slots[slot].size;
            let cap = inner.limits.prealloc_cap();
            let w = if self.resume {
                FileWriter::create_resume_capped(&path, size, cap)?
            } else {
                FileWriter::create_capped(&path, size, cap)?
            };
            // Only a NESTED plain file is extraction output. Level 0's
            // plain files are the downloaded volumes themselves, which the
            // disk-path `BombGuardWriter` does not count either.
            //
            // The prefix hash rides the same condition: a nested plain
            // writer is what a chase sink settles into, so it is the only
            // shape `retain_slot_output` can ever hand to the resume
            // ledger - and the ledger records nothing without a hash
            // (TODO 217). Level 0 stays unhashed so the per-byte download
            // path pays nothing.
            let w = if self.depth > 0 {
                w.with_budget(inner.limits.budget.clone())
                    .with_prefix_hash()
            } else {
                w
            };
            inner.slots[slot].writer = Some(Arc::new(w));
        }
        Ok(inner.slots[slot].writer.clone().unwrap())
    }

    /// Claim an output filename in the chain-shared set, disambiguating
    /// on collision. Shared with nested children, so a child's plain file
    /// can never silently overwrite (or be overwritten by) another
    /// level's output of the same name.
    pub(super) fn claim_name(inner: &Inner, slot: usize, out: &mut String) {
        let fold = inner.fold_names;
        let key = name_collision_key(fold, out);
        // A name THIS slot preclaimed is already its own: the §94 A
        // replay claims a restored file's name before feeding it back
        // through `write`, and the slot's own plain writer must then be
        // allowed to adopt that very file rather than disambiguate away
        // from it (which orphaned the restored bytes and left the
        // payload under `000-<name>`).
        // ...or one a slot of the same archive GROUP preclaimed: a §94 A
        // map-mode replay claims its SOURCE files under the volume's
        // slot, and the archive re-creating that member must adopt them
        // while a foreign archive's same-named member must not (F-03).
        if let Some(&pre) = inner.preclaimed.get(&key) {
            let group = |s: usize| inner.slots.get(s).and_then(|x| x.group.clone());
            if pre == slot || (group(pre).is_some() && group(pre) == group(slot)) {
                return;
            }
        }
        let mut names = inner.names_taken.lock_ok();
        if names.insert(key) {
            return;
        }
        let mut n = 0usize;
        loop {
            let cand = if n == 0 {
                format!("{slot:03}-{out}")
            } else {
                format!("{slot:03}-{n}-{out}")
            };
            if names.insert(name_collision_key(fold, &cand)) {
                *out = cand;
                return;
            }
            n += 1;
        }
    }

    /// Plain write-through under the lock (fallback/drain paths where the
    /// data is locally owned).
    ///
    /// TODO 211 (b): a split HEAD's offsets are its joined volume's, so
    /// its plain writes route to the part files (`split_plain_span`) -
    /// this is the seam that makes a demote materialize the N posted
    /// parts rather than one container under part 1's name.
    pub(super) fn plain_span(
        &self,
        inner: &mut Inner,
        slot: usize,
        offset: u64,
        data: &[u8],
    ) -> io::Result<()> {
        if self.split_plain_span(inner, slot, offset, data)?.is_some() {
            return Ok(());
        }
        self.plain_span_own(inner, slot, offset, data)
    }

    /// [`Self::plain_span`] to the slot's OWN file, no split routing.
    pub(super) fn plain_span_own(
        &self,
        inner: &mut Inner,
        slot: usize,
        offset: u64,
        data: &[u8],
    ) -> io::Result<()> {
        let w = self.ensure_plain_writer(inner, slot)?;
        w.write_at(offset, data)?;
        // A drained held span landing plain (spill/overflow/fallback
        // during a drain): file offset == volume offset by definition.
        // Direct-path fallback rewrites run with refeed_active false and
        // stay unreported HERE. That is no longer a refetch-on-resume,
        // which is what this said until TODO 252 closed it on 23 Aug
        // 2026: a parked article whose bytes reached a MATERIALIZED
        // volume by one of those routes now completes off the volume's
        // own coverage map (`materialized_span_on_disk`, joined in
        // `flush_pending_r`) rather than off this placement trail. The
        // trail stays narrow on purpose - it vouches only for writes
        // whose identity offsets this path knows - and the disk oracle
        // is the wider claim, made where the destination can be asked.
        if inner.refeed_active {
            inner.late_placements.push(LatePlacement {
                slot,
                frag: Frag {
                    file: w
                        .path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned(),
                    file_off: offset,
                    vol_off: offset,
                    len: data.len() as u64,
                },
                crypto: false,
            });
        }
        Ok(())
    }

    /// Deliver queued child forwards. Never called with the routing lock
    /// held - each job re-resolves its destination in
    /// [`Self::deliver_routed`], so a slot that fell back (or a child
    /// slot a merge displaced) in any window still gets its bytes.
    pub(super) fn deliver_fwd(&self, pending: Vec<FwdJob>) -> io::Result<()> {
        for j in pending {
            let p = self.deliver_routed(
                j.parent_slot,
                j.vol_off,
                &j.name,
                j.size,
                j.file_off,
                &j.bytes,
                j.repair,
                None,
            )?;
            // A re-fed (drained-hold) forward has no caller composing
            // its Persist into an article record - surface the result
            // so the article that parked these bytes can still journal.
            // A PlacedCrypto one rides the SAME trail carrying its
            // crypto flag (TODO 27.2): it is what tells the journal
            // writer to complete the article into a `D` record. The
            // invariant that refusal protected is unchanged and now
            // holds by the flag rather than by silence - a held article
            // must never complete into an `R` record over
            // plaintext-once bytes.
            let placed = match p {
                Persist::Placed(cfrags) => Some((cfrags, false)),
                Persist::PlacedCrypto(cfrags) => Some((cfrags, true)),
                Persist::No | Persist::Held(_) => None,
            };
            if j.refeed
                && let Some((cfrags, crypto)) = placed
            {
                let mut inner = self.inner.lock_ok();
                for cf in cfrags {
                    inner.late_placements.push(LatePlacement {
                        slot: j.parent_slot,
                        frag: Frag {
                            file: cf.file,
                            file_off: cf.file_off,
                            vol_off: j.vol_off + (cf.vol_off - j.file_off),
                            len: cf.len,
                        },
                        crypto,
                    });
                }
            }
        }
        Ok(())
    }

    /// Deliver one routed span to whatever destination the routing map
    /// names NOW, re-resolving under the lock until the write has landed
    /// somewhere still live. Between capture and delivery a group merge
    /// can displace the child slot routing picked and abandon it - a
    /// write into an abandoned slot is silently swallowed while the
    /// span's bytes were already composed into the piece CRCs, so
    /// delivering by stale slot index could let the finish gate vouch
    /// for a hole. The loop is bounded by the number of merges (each
    /// retry means the destination changed again), and duplicate
    /// deliveries land on identical offsets (routing is deterministic),
    /// so retries are harmless. Never called with the routing lock held.
    #[expect(clippy::too_many_arguments)]
    pub(super) fn deliver_routed(
        &self,
        parent_slot: usize,
        vol_off: u64,
        name: &str,
        size: u64,
        file_off: u64,
        bytes: &[u8],
        repair: bool,
        mut in_place: Option<&mut InPlace<'_>>,
    ) -> io::Result<Persist> {
        enum Target {
            Child(Arc<Extractor>, usize),
            Writer(Arc<FileWriter>),
            Done,
        }
        loop {
            let tgt = {
                let mut g = self.inner.lock_ok();
                let inner = &mut *g;
                // TODO 211 (b): an alias's routes live on its head; the
                // records stay the part's (`parent_slot`, `vol_off`).
                let (map_slot, _) = Self::split_target(inner, parent_slot, 0);
                match inner.slots[parent_slot].mode {
                    SlotMode::Rar | SlotMode::SplitPart => {
                        match Self::dest_for(inner, map_slot, name) {
                            Some(Dest::Child(c, cs)) => Target::Child(c, cs),
                            Some(Dest::Writer(w)) => Target::Writer(w),
                            // The routed entry vanished while the slot still
                            // maps (structurally unexpected): materialize the
                            // slot rather than drop bytes the piece CRCs
                            // already counted.
                            None => {
                                self.fallback_slot_or_group(
                                    inner,
                                    parent_slot,
                                    "routed span lost its destination",
                                )?;
                                if !matches!(inner.slots[parent_slot].mode, SlotMode::Discard) {
                                    self.plain_span(inner, parent_slot, vol_off, bytes)?;
                                }
                                Target::Done
                            }
                        }
                    }
                    SlotMode::Plain | SlotMode::RarFallback => {
                        self.plain_span(inner, parent_slot, vol_off, bytes)?;
                        Target::Done
                    }
                    // A chase-eligible slot blocks on its FIRST entry, so
                    // it can never have routed a forward while mapped -
                    // nothing to deliver.
                    SlotMode::Unknown
                    | SlotMode::RarChase
                    | SlotMode::SevenZ
                    | SlotMode::Discard => Target::Done,
                }
            };
            match tgt {
                Target::Done => return Ok(Persist::No),
                Target::Writer(w) => {
                    // A promoted routed-plain writer is a plain pwrite
                    // at `file_off` with no `src_start`: the same
                    // in-place test the parent's job loop applies.
                    match in_place.as_deref_mut() {
                        Some(ip)
                            if !repair
                                && ip.off == file_off
                                && w.path.file_name().is_some_and(|f| f == ip.file) =>
                        {
                            w.note_covered(file_off, bytes.len() as u64)?;
                            ip.covered += bytes.len() as u64;
                        }
                        _ => w.write_at(file_off, bytes)?,
                    }
                    return Ok(Persist::No);
                }
                Target::Child(c, cs) => {
                    // No article CRC across the boundary: these are mapped
                    // sub-ranges of OUR span, and the child's own article
                    // boundaries are its own.
                    // The child's out-dir is this one, so the in-place
                    // file-name test reads the same journal name.
                    let p = c.write_impl(
                        cs,
                        name,
                        size,
                        file_off,
                        bytes,
                        repair,
                        None,
                        in_place.as_deref_mut(),
                    )?;
                    // Promotion probe BEFORE re-taking our lock (child and
                    // parent locks are never nested, in either order).
                    let promote = c.stable_plain_writer(cs);
                    let mut g = self.inner.lock_ok();
                    let inner = &mut *g;
                    let (map_slot, _) = Self::split_target(inner, parent_slot, 0);
                    match inner.slots[parent_slot].mode {
                        SlotMode::Rar | SlotMode::SplitPart => {
                            let live = matches!(
                                Self::dest_for(inner, map_slot, name),
                                Some(Dest::Child(ref c2, cs2)) if Arc::ptr_eq(c2, &c) && cs2 == cs
                            );
                            if live {
                                // The route still points at this child and
                                // its slot is stably Plain: later articles
                                // skip the whole ladder (Finding 4).
                                if let Some(w) = promote
                                    && let Some(gk) = inner.slots[map_slot].group.clone()
                                    && let Some(grp) = inner.groups.get_mut(&gk)
                                    && grp.routed.get(name) == Some(&cs)
                                {
                                    grp.routed_plain.insert(name.to_string(), (cs, w));
                                }
                                // The child parked (some of) this forward
                                // and will write it inside ITS drain,
                                // where only child-space placements
                                // exist: record the translation window
                                // now, and surface any partial child
                                // placements (already on disk) so the
                                // parked article can complete.
                                if let Persist::Held(cfrags) = &p {
                                    inner.fwd_windows.push(FwdWindow {
                                        parent_slot,
                                        parent_vol_off: vol_off,
                                        child_slot: cs,
                                        child_off: file_off,
                                        len: bytes.len() as u64,
                                    });
                                    for cf in cfrags {
                                        // A `Held` return carries PLAIN
                                        // fragments only (see
                                        // `compose_persist`), so these
                                        // are never crypto.
                                        inner.late_placements.push(LatePlacement {
                                            slot: parent_slot,
                                            frag: Frag {
                                                file: cf.file.clone(),
                                                file_off: cf.file_off,
                                                vol_off: vol_off + (cf.vol_off - file_off),
                                                len: cf.len,
                                            },
                                            crypto: false,
                                        });
                                    }
                                }
                                return Ok(p);
                            }
                            // Displaced mid-delivery - resolve again.
                        }
                        SlotMode::Plain | SlotMode::RarFallback => {
                            self.plain_span(inner, parent_slot, vol_off, bytes)?;
                            return Ok(Persist::No);
                        }
                        _ => return Ok(Persist::No),
                    }
                }
            }
        }
    }

    /// Run the tail-prefetch promotes queued under the routing lock.
    /// Off-lock by construction: `promote_file` walks up the chain
    /// taking one level's lock at a time, so calling it from under this
    /// level's own lock self-deadlocks.
    pub(super) fn flush_pending_promote(&self) {
        let queued = std::mem::take(&mut self.inner.lock_ok().pending_promote);
        for (slot, spans, urgent) in queued {
            self.promote_slot_spans(slot, &spans, urgent);
        }
        // Same off-lock contract for the §94 D verdicts: closing a
        // child's split set raises ITS tail promote, which walks up
        // through this level's lock.
        self.flush_pending_child_decl();
        self.flush_pending_park();
    }

    /// Take and deliver any queued child forwards (public entry points
    /// that may have re-fed holds under the lock call this after it
    /// drops).
    pub(super) fn flush_pending_fwd(&self) -> io::Result<()> {
        self.flush_pending_promote();
        self.flush_pending_spills()?;
        let pending = std::mem::take(&mut self.inner.lock_ok().pending_fwd);
        if pending.is_empty() {
            return Ok(());
        }
        self.deliver_fwd(pending)
    }

    /// Keep the parts of a span not covered by any data area (header/meta
    /// bytes below the parse cursor) for byte-exact reconstruction.
    /// Returns the bytes newly stashed; they are charged to the shared
    /// holds budget here and released wherever the stash is dropped.
    pub(super) fn retain_header_bytes(
        &self,
        inner: &mut Inner,
        slot: usize,
        offset: u64,
        data: &[u8],
    ) -> usize {
        let s = &mut inner.slots[slot];
        let Some(m) = s.mapper.as_ref() else { return 0 };
        let mut covered: Vec<(u64, u64)> = m
            .map_span(offset, data.len() as u64)
            .into_iter()
            .map(|(_, _, span_off, len)| (span_off, span_off + len))
            .collect();
        covered.sort_unstable();
        let mut pos = 0u64;
        let mut keep: Vec<(u64, u64)> = Vec::new();
        for (cs, ce) in covered {
            if cs > pos {
                keep.push((pos, cs));
            }
            pos = pos.max(ce);
        }
        if pos < data.len() as u64 {
            keep.push((pos, data.len() as u64));
        }
        let mut stashed = 0usize;
        for (ks, ke) in keep {
            let abs_s = offset + ks;
            if abs_s >= m.mapped_through() {
                continue; // not header - just not-yet-mapped data
            }
            let abs_e = (offset + ke).min(m.mapped_through());
            if abs_e > abs_s {
                let part = data[ks as usize..(abs_e - offset) as usize].to_vec();
                stashed += part.len();
                s.header_spans.push((abs_s, HoldSpan::Ram(part)));
            }
        }
        inner.budget.add(stashed);
        stashed
    }

    /// Unlink a slot's own file and release the name it claimed. Used
    /// when a trimmed 7z chase SUCCEEDS: the spilled prefix is a
    /// truncated archive whose payload already shipped by another route.
    pub(super) fn drop_slot_file(inner: &mut Inner, slot: usize) {
        let Some(w) = inner.slots[slot].writer.take() else {
            return;
        };
        w.abandon();
        let _ = std::fs::remove_file(&w.path);
        let name = w
            .path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        inner
            .names_taken
            .lock_ok()
            .remove(&name_collision_key(inner.fold_names, &name));
    }

    /// Ask the chain above to front-load the outer articles carrying
    /// `spans` of this slot's byte space (7z tail prefetch). A slot's
    /// byte space IS its level-N file's byte space, and that file is an
    /// entry of the parent's groups - so the parent handles it as a
    /// file promote. At the ROOT there is no parent and none is needed:
    /// the slot is a posted file already, so it goes straight to this
    /// level's own hook.
    pub(super) fn promote_slot_spans(&self, slot: usize, spans: &[(u64, u64)], urgent: bool) {
        let (name, size) = {
            let inner = self.inner.lock_ok();
            (inner.slots[slot].name.clone(), inner.slots[slot].size)
        };
        if name.is_empty() || size == 0 {
            return;
        }
        let name = sanitize_filename(&name);
        match self.parent.upgrade() {
            Some(p) => p.promote_file(&name, size, spans, urgent),
            // The ROOT: a slot here is a POSTED file, so its byte space
            // is already the byte space the installed hook resolves to
            // articles - no translation left to do, hand it straight
            // over. This used to be `else { return }`, which silently
            // no-opped, which is why a top-level 7z never got its tail
            // front-loaded even after the depth guard came off.
            None => self.promote_file(&name, size, spans, urgent),
        }
    }

    /// Promote byte spans of file `name` (an inner file of one of THIS
    /// extractor's groups): the root hands them to the installed hook
    /// (the daemon's seek/promote ladder resolves them to articles);
    /// a level below the root translates them to its own slot ranges
    /// via [`Self::map_output_range`] and recurses upward - the §3b
    /// map_to_root composition. All-store levels only by construction:
    /// a chased (compressed) level yields no offset mapping, so the
    /// promote quietly stops there. Never called with any routing lock
    /// held; each level takes only its own lock, one at a time.
    pub(super) fn promote_file(&self, name: &str, size: u64, spans: &[(u64, u64)], urgent: bool) {
        let hook = self.inner.lock_ok().promote.clone();
        if let Some(h) = hook {
            h(name, size, spans, urgent);
            return;
        }
        let Some(p) = self.parent.upgrade() else {
            return;
        };
        let mut per_slot: BTreeMap<usize, Vec<(u64, u64)>> = BTreeMap::new();
        for &(s, e) in spans {
            if s >= e {
                continue;
            }
            for (slot, vs, ve, _) in self.map_output_range(name, s, e) {
                if vs < ve {
                    per_slot.entry(slot).or_default().push((vs, ve));
                }
            }
        }
        for (slot, ranges) in per_slot {
            let (sname, ssize) = {
                let inner = self.inner.lock_ok();
                (inner.slots[slot].name.clone(), inner.slots[slot].size)
            };
            if sname.is_empty() {
                continue;
            }
            p.promote_file(&sanitize_filename(&sname), ssize, &ranges, urgent);
        }
    }
}
