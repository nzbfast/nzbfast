//! Routing: how a decoded volume span is translated into placements -
//! the half deliver.rs names when it says "once routing has decided
//! where it belongs". Piece-base resolution for split continuations, the
//! intersection of an arriving span with the volume mapper's parsed data
//! areas (and what happens to the parts that fall outside it), the
//! per-entry destination decision - inner file, nested child slot, chase
//! frontier, 7z engine, or drop - and the writer/group bookkeeping that
//! decision needs (output-file deletion on a group demote, the canonical
//! group key, the stable plain-writer fast path). Split out of
//! extract/mod.rs (TODO 106 size gate) as a further `impl Extractor`;
//! callers in the parent and in sibling modules reach the methods
//! through `pub(super)`.

use super::*;

impl Extractor {
    /// Base offset of (slot, entry) within its inner file: 0 for pieces
    /// that start a file; group-resolved for split continuations.
    pub(super) fn base_for(inner: &Inner, slot: usize, ei: usize) -> Option<u64> {
        let m = inner.slots[slot].mapper.as_ref()?;
        if !m.entries[ei].split_before {
            return Some(0);
        }
        let key = inner.slots[slot].group.as_ref()?;
        inner.groups.get(key)?.bases.get(&(slot, ei)).copied()
    }

    /// Route the mapped parts of a span into inner files or the nested
    /// child (queued when the caller collects a sink, inline/pending
    /// otherwise); hold the rest.
    pub(super) fn extract_span(
        &self,
        inner: &mut Inner,
        slot: usize,
        offset: u64,
        data: &[u8],
        sink: Option<(&mut Vec<WriteJob>, &mut Vec<FwdSpan>)>,
        repair: bool,
        article_crc: Option<u32>,
    ) -> io::Result<()> {
        // Reuse the Inner-owned hit buffer: this runs under the routing
        // lock for every article, and the per-article Vec was measurable
        // allocator traffic. A re-entrant call (fallback re-feed) takes
        // an empty fresh vector and simply allocates like before.
        let mut hits = std::mem::take(&mut inner.map_scratch);
        {
            let m = inner.slots[slot].mapper.as_ref().unwrap();
            m.map_span_into(offset, data.len() as u64, &mut hits);
        }
        let result =
            self.extract_span_hits(inner, slot, offset, data, sink, repair, article_crc, &hits);
        hits.clear();
        inner.map_scratch = hits;
        result
    }

    #[expect(clippy::too_many_arguments)]
    fn extract_span_hits(
        &self,
        inner: &mut Inner,
        slot: usize,
        offset: u64,
        data: &[u8],
        mut sink: Option<(&mut Vec<WriteJob>, &mut Vec<FwdSpan>)>,
        repair: bool,
        article_crc: Option<u32>,
        hits: &[(usize, u64, u64, u64)],
    ) -> io::Result<()> {
        // The yEnc decode already computed and CHECKED this article's
        // CRC32 over exactly these bytes. When the article maps to a
        // single STORE data range covering the whole buffer, that value
        // IS the CRC the stored-file composition needs, so the second
        // scan over ~700 KiB is pure waste (measured on a real corpus:
        // 98.75% of STORE payload bytes qualify; the exceptions are the
        // header-bearing first article, the trailing article, volume and
        // member boundaries, and multi-entry spans).
        //
        // Every reuse condition is checked, not assumed: the CRC exists
        // and matched (`article_crc` is None otherwise, including on the
        // bare-LF scalar path and under delegated verification), this is
        // not a repair rewrite (its bytes deliberately DIFFER from what
        // composed earlier), the entry is `checkable` (unencrypted store,
        // not a directory) at the use site, and the range is untouched -
        // `add_run` refuses an overlap and the hash path takes over. A
        // single hit spanning the whole buffer is what makes the mapped
        // range byte-for-byte the decoded output.
        let single_whole_hit = matches!(
            hits,
            [(_, _, 0, len)] if *len == data.len() as u64
        );
        let whole_article = single_whole_hit && !repair && article_crc.is_some();
        let mut covered_end = offset;
        for &(ei, piece_off, span_off, len) in hits {
            covered_end = covered_end.max(offset + span_off + len);
            let base = match Self::base_for(inner, slot, ei) {
                Some(b) => b,
                None => {
                    let part = data[span_off as usize..(span_off + len) as usize].to_vec();
                    inner.budget.add(part.len());
                    if !inner.refeed_active {
                        inner.span_held = true;
                    }
                    inner.slots[slot]
                        .holds
                        .push((offset + span_off, HoldSpan::Ram(part)));
                    if inner.budget.over()
                        && !self.page_out_holds(inner)
                        && !self.relieve_by_chase(inner, slot)
                    {
                        // Write the whole article through after the
                        // demote, exactly as the sibling demote routes do
                        // (header-stash, blocker, joined-fallen-group).
                        // This `return` is from INSIDE the hits loop, so
                        // every remaining hit of a multi-entry span was
                        // otherwise never queued, forwarded or held - and
                        // the compensating whole-span rewrite in
                        // write_impl_scratched is gated on there being
                        // queued work, which there is not. The volume
                        // then materialized with a sparse hole that
                        // preads as zeros and failed the inner file's
                        // CRC. "A lost span is silent corruption" is
                        // stated a few hundred lines up; this was the one
                        // route that broke it. plain_span writes at the
                        // volume offset, which is what a materialized
                        // volume wants; the already-drained holds rewrite
                        // identical bytes, which the other routes accept
                        // too. The Discard check keeps protect_sources
                        // from opening a writer over a source file.
                        self.fallback_slot_or_group(inner, slot, "held-bytes cap")?;
                        if matches!(inner.slots[slot].mode, SlotMode::Discard) {
                            return Ok(());
                        }
                        return self.plain_span(inner, slot, offset, data);
                    }
                    continue;
                }
            };
            // POD fields only - the entry NAME stays in the mapper and the
            // routing lookups borrow it in place (route_dest/crypto_for key
            // by (slot, ei)). Cloning it here cost a String per article
            // under the routing lock; only the child-forward arms, which
            // queue owned work, still materialize one.
            let (total, encrypted, checkable) = {
                let m = inner.slots[slot].mapper.as_ref().unwrap();
                let e = &m.entries[ei];
                (
                    e.unpacked_size,
                    e.encrypted,
                    matches!(e.method, Method::Store) && !e.encrypted && !e.is_dir,
                )
            };
            // Compose the routed bytes' CRC32 per piece for the
            // finish-time check against the header CRC (encrypted
            // entries have their own post-decrypt check). Nested levels
            // always compose; level 0's PAR2 only vouches for the outer
            // bytes AS POSTED, so the final store payload gets the same
            // treatment under the verify_output_crc gate (default on;
            // `NZBFAST_NO_OUTPUT_CRC=1` restores the skip). A repair
            // span overwrites: its bytes REPLACE a range that may have
            // composed wire-damaged bytes earlier, and clipping it as a
            // duplicate would keep the stale CRC while the file heals.
            if (self.depth > 0 || inner.verify_output_crc) && checkable {
                let part = &data[span_off as usize..(span_off + len) as usize];
                let runs = inner.slots[slot].piece_crcs.entry(ei).or_default();
                if repair {
                    runs.overwrite(piece_off, part);
                } else if !(whole_article && runs.add_run(piece_off, len, article_crc.unwrap())) {
                    // Not the exact-article case, or the range was already
                    // (partly) composed: hash the routed bytes as before.
                    runs.add(piece_off, part);
                }
            }
            match self.route_dest(inner, slot, ei, total, encrypted)? {
                Dest::Writer(w) => {
                    // Plaintext-once: an encrypted store span decrypts at
                    // write time instead of assembling ciphertext for the
                    // finish pass. The state needs the HEAD entry's crypt
                    // parameters; a continuation piece racing its head
                    // volume's headers holds like an unresolved base.
                    // An output that is already plaintext-once must STAY
                    // plaintext-once, whatever the live password cell now
                    // holds. The gate re-reads `inner.password` per span,
                    // so a mid-download re-key - `apply_probed_password`
                    // overwrites it unconditionally, and the probe is
                    // installed on every job - flipped it false for a
                    // file already being decrypted in-stream (one job may
                    // legitimately carry two encrypted sets with
                    // different passwords). Later spans then took the
                    // `crypto == None` path and pwrote RAW CIPHERTEXT at
                    // the offsets plaintext belonged at. Consulting the
                    // writer-keyed state FIRST is strictly narrowing: it
                    // changes behaviour only for a writer whose password
                    // was already check-verified before its first byte
                    // was written.
                    let existing = Self::crypto_of(inner, &w);
                    let crypto = if existing.is_some() {
                        existing
                    } else if encrypted && Self::instream_decrypt_allowed(inner, slot, ei, &w) {
                        match Self::crypto_for(inner, slot, ei, &w) {
                            Some(cs) => Some(cs),
                            None => {
                                let part =
                                    data[span_off as usize..(span_off + len) as usize].to_vec();
                                inner.budget.add(part.len());
                                if !inner.refeed_active {
                                    inner.span_held = true;
                                }
                                inner.slots[slot]
                                    .holds
                                    .push((offset + span_off, HoldSpan::Ram(part)));
                                if inner.budget.over()
                                    && !self.page_out_holds(inner)
                                    && !self.relieve_by_chase(inner, slot)
                                {
                                    // Same write-through as the hold arm
                                    // above - this return also leaves the
                                    // rest of a multi-entry span
                                    // unwritten. See the comment there.
                                    self.fallback_slot_or_group(inner, slot, "held-bytes cap")?;
                                    if matches!(inner.slots[slot].mode, SlotMode::Discard) {
                                        return Ok(());
                                    }
                                    return self.plain_span(inner, slot, offset, data);
                                }
                                continue;
                            }
                        }
                    } else {
                        None
                    };
                    // C1: an encrypted span routing WITHOUT CryptoState
                    // is the ciphertext route, decided HERE, under the
                    // lock - the pwrite runs after it drops, so
                    // `written()` lags the commitment. Latch at enqueue
                    // or a racing sibling span latches plaintext-once
                    // over it (instream_decrypt_allowed rule 2).
                    if encrypted
                        && crypto.is_none()
                        && let Some(k) = w.path.file_name()
                    {
                        let k = k.to_string_lossy();
                        // TODO 158 item 2: an output the journal says
                        // is plaintext-once, with `D` records still
                        // live for it, cannot take the ciphertext
                        // route - the bytes would flip domain under
                        // records nothing rewrites, and the next
                        // resume would re-encrypt ciphertext. The gate
                        // could not re-establish plaintext-once (see
                        // `instream_decrypt_allowed`), so refuse: no
                        // byte lands, the records stay true.
                        if inner.resumed_plaintext.contains_key(k.as_ref()) {
                            return Err(io::Error::other(format!(
                                "{k}: resumed as plaintext-once and cannot re-latch it, \
                                 refusing to write ciphertext over plaintext"
                            )));
                        }
                        inner.ciphertext_files.insert(k.into_owned());
                    }
                    match sink.as_mut() {
                        Some((jobs, _)) => jobs.push(WriteJob {
                            writer: w,
                            file_off: base + piece_off,
                            src_start: span_off as usize,
                            len: len as usize,
                            crypto,
                            repair,
                        }),
                        // Under-the-lock re-feed (drain_holds/reresolve):
                        // cold path, so the AES here is acceptable.
                        None => {
                            let part = &data[span_off as usize..(span_off + len) as usize];
                            match &crypto {
                                Some(cs) if repair => cs.patch(&w, base + piece_off, part)?,
                                Some(cs) => cs.ingest(&w, base + piece_off, part)?,
                                None => w.write_at(base + piece_off, part)?,
                            }
                            // A drained held span landing in an inner
                            // file: report it, so the article that
                            // parked these bytes (Persist::Held) still
                            // journals. A CRYPTO write is reported the
                            // same way and carries the fact (TODO
                            // 27.2): the journal writer completes it
                            // into a `D` record, never an `R`, and
                            // holds it until `crypto_span_on_disk`
                            // says the plaintext really landed - this
                            // route hands `CryptoState` the bytes and
                            // a seam sliver can still be in RAM. Until
                            // that flag existed these writes were
                            // reported NOWHERE, so a whole encrypted
                            // set that arrived before its offset-0
                            // sniff journaled nothing and refetched
                            // entirely on resume.
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
                                        file_off: base + piece_off,
                                        vol_off: offset + span_off,
                                        len,
                                    },
                                    crypto: crypto.is_some(),
                                });
                            }
                        }
                    }
                }
                Dest::Child(..) => {
                    let name = Self::entry_name(inner, slot, ei).to_string();
                    match sink.as_mut() {
                        Some((_, fwd)) => fwd.push(FwdSpan {
                            name,
                            size: total,
                            file_off: base + piece_off,
                            src_start: span_off as usize,
                            len: len as usize,
                            repair,
                        }),
                        // Under-the-lock re-feed: the child cannot be called
                        // here (it defers pwrites behind its own lock), so
                        // queue an owned copy for flush_pending_fwd. Cold
                        // paths only - the hot write path always has a sink.
                        None => inner.pending_fwd.push(FwdJob {
                            parent_slot: slot,
                            vol_off: offset + span_off,
                            name,
                            size: total,
                            file_off: base + piece_off,
                            bytes: data[span_off as usize..(span_off + len) as usize].to_vec(),
                            repair,
                            refeed: inner.refeed_active,
                        }),
                    }
                }
            }
            inner.extracted_bytes += len;
        }
        // Anything past the mapped region: hold until headers advance.
        let m = inner.slots[slot].mapper.as_ref().unwrap();
        let span_end = offset + data.len() as u64;
        let unmapped_from = covered_end.max(m.mapped_through()).max(offset);
        if unmapped_from < span_end && !m.complete {
            let part = data[(unmapped_from - offset) as usize..].to_vec();
            inner.budget.add(part.len());
            if !inner.refeed_active {
                inner.span_held = true;
            }
            inner.slots[slot]
                .holds
                .push((unmapped_from, HoldSpan::Ram(part)));
            if inner.budget.over()
                && !self.page_out_holds(inner)
                && !self.relieve_by_chase(inner, slot)
            {
                return self.fallback_slot_or_group(inner, slot, "held-bytes cap");
            }
        }
        Ok(())
    }

    /// The in-stream decrypt state for entry `name`'s output (keyed by
    /// the writer's on-disk filename), created on first touch from the
    /// HEAD entry's crypt parameters. None while the head volume's
    /// headers have not been seen (the caller holds the span) or when no
    /// usable key exists - the latter cannot normally happen, because an
    /// encrypted entry only maps after the stored password check passed.
    /// The RAW entry name behind `(slot, ei)` - the routing key. Borrowed
    /// in place: the article hot path must not clone a String per span.
    pub(super) fn entry_name(inner: &Inner, slot: usize, ei: usize) -> &str {
        &inner.slots[slot].mapper.as_ref().unwrap().entries[ei].name
    }

    /// The destination for `slot`'s view of inner file `name` - decided
    /// once per (group, name) and sticky thereafter, so write-side routing
    /// and read-side delegation always agree. Non-encrypted files route
    /// into the nested child (whose offset-0 sniff classifies them: RAR
    /// store maps on, everything else lands as a plain file, exactly the
    /// single-level output). Encrypted entries stay on the direct writer
    /// path - the ciphertext-at-store-offsets assembly and the finish
    /// decrypt own that lifecycle.
    fn route_dest(
        &self,
        inner: &mut Inner,
        slot: usize,
        ei: usize,
        total: u64,
        encrypted: bool,
    ) -> io::Result<Dest> {
        // Group identity is the RAW entry name, not its sanitized form: two
        // distinct archive entries whose names sanitize alike (e.g. "a/b.txt"
        // and "a_b.txt" both -> "a_b.txt") must get SEPARATE child slots and
        // writers, or the second silently overwrites/interleaves the first at
        // offset 0. The same raw name across split volumes still maps to one
        // output (the intended "one inner file, many pieces" case). The
        // sanitized form is used only to derive the on-disk filename, in
        // inner_writer/claim_name.
        // Reaching here means the fast path owns this inner file - its
        // bytes go straight to their destination and the volumes never
        // land. That is what "one-pass" on the badge means.
        //
        // This runs per span under the routing lock: the lookups below
        // borrow the group key and entry name in place (cloning them cost
        // two Strings per article); only the once-per-file route insert
        // owns anything.
        self.shape.note(self.depth, SH_ONE_PASS);
        let mut route_new = None;
        if let Some(gk) = inner.slots[slot].group.as_ref() {
            let key = Self::entry_name(inner, slot, ei);
            // Promoted plain child: write straight to its file. The route
            // still exists in `routed` for fallback/finish; only the hot
            // path skips the child extractor.
            // `!encrypted` is load-bearing, not belt-and-braces. Under the
            // pre-promotion ladder a name in `routed` returned Dest::Child,
            // and the Child arm has no crypto handling at all, so an
            // encrypted span could never reach a decrypt path through a
            // routed name. Promotion turns the same name into Dest::Writer,
            // which DOES run the in-stream decrypt arm. An archive where one
            // raw name appears as a plain STORE piece in one volume and an
            // encrypted one in another would
            // then have the parent create a CryptoState keyed by a
            // child-owned filename, journal E/K/T records for a file it does
            // not own, and AES-decrypt into the child's plain output. Falling
            // through to the Child arm keeps the old structural exclusion.
            if !encrypted
                && let Some((_, w)) = inner.groups.get(gk).and_then(|g| g.routed_plain.get(key))
            {
                return Ok(Dest::Writer(Arc::clone(w)));
            }
            if let Some(&cs) = inner.groups.get(gk).and_then(|g| g.routed.get(key)) {
                let c = inner.child.clone().expect("routed name without a child");
                return Ok(Dest::Child(c, cs));
            }
            let already_written = inner
                .groups
                .get(gk)
                .is_some_and(|g| g.out_names.contains_key(key));
            if !already_written && inner.nested_on && !encrypted {
                route_new = Some((gk.clone(), key.to_string()));
            }
        }
        if let Some((gk, key)) = route_new {
            let child = self.ensure_child(inner);
            let cs = child.alloc_slot();
            // A §94 A map-mode replay preclaimed its SOURCE files under a
            // volume slot of this group (Codex F-03); the child's claims
            // are its own, so the grant moves to the routed slot.
            let ck = name_collision_key(inner.fold_names, &sanitize_filename(&key));
            if let Some(&pre) = inner.preclaimed.get(&ck)
                && inner.groups[&gk].slots.contains(&pre)
            {
                child.inner.lock_ok().preclaimed.insert(ck, cs);
            }
            // §94 D: a zip split part routed here opens its set on the
            // child before the first forwarded byte reaches it.
            self.open_zip_split(inner, &gk, &child, &key);
            inner.groups.get_mut(&gk).unwrap().routed.insert(key, cs);
            // §156.1: a member routed AFTER a terminal verdict on one of
            // its group's volumes still inherits the loss mark - the
            // hole lives inside this archive, wherever it routes.
            if inner.groups[&gk]
                .slots
                .iter()
                .any(|&s| inner.slots[s].article_lost)
            {
                child.mark_child_slot_lost(cs);
            }
            return Ok(Dest::Child(child, cs));
        }
        Ok(Dest::Writer(self.inner_writer(inner, slot, ei, total)?))
    }

    /// The output writer for `name` as seen by `slot`'s group. Output
    /// files are group-owned: two archives in one NZB that reuse an inner
    /// filename each get their own file (the second is disambiguated),
    /// instead of interleaving writes into one writer at conflicting
    /// offsets - inner files are not PAR2-covered, so that corruption was
    /// silent and deterministic.
    fn inner_writer(
        &self,
        inner: &mut Inner,
        slot: usize,
        ei: usize,
        total: u64,
    ) -> io::Result<Arc<FileWriter>> {
        // Keyed on the RAW name (see route_dest); the sanitized form is only
        // the on-disk filename. Distinct raw names that sanitize alike get
        // distinct writers (claim_name disambiguates the on-disk name).
        //
        // The existing-writer lookups run per span under the routing lock
        // (encrypted sets never route to a child, so THIS is their hot
        // path) and borrow the key and group in place; only the
        // once-per-file creation below owns strings.
        let key = Self::entry_name(inner, slot, ei);
        match inner.slots[slot].group.as_ref() {
            Some(gk) => {
                if let Some(out) = inner.groups.get(gk).and_then(|g| g.out_names.get(key))
                    && let Some(w) = inner.inner_writers.get(out)
                {
                    return Ok(w.clone());
                }
            }
            None => {
                if let Some(w) = inner.inner_writers.get(sanitize_filename(key).as_str()) {
                    return Ok(w.clone());
                }
            }
        }
        let key = key.to_string();
        let fname = sanitize_filename(&key);
        let gkey = inner.slots[slot].group.clone();
        let mut out = fname;
        Self::claim_name(inner, slot, &mut out);
        let path = self.out_dir.join(&out);
        // `total` is the entry's declared `unpacked_size` - an untrusted
        // header vint. It stays the writer's `size` (resume truncation and
        // the reported extracted size both depend on it) but it does NOT
        // get to reserve the disk: the reservation is capped at the
        // chain's ceiling, and the extracted bytes are charged against the
        // chain's bomb budget. See [`Limits`].
        let cap = inner.limits.prealloc_cap();
        let budget = inner.limits.budget.clone();
        let w = Arc::new(
            if self.resume {
                let w = FileWriter::create_resume_capped(&path, total, cap)?;
                // Rule 2's counter half, restored: the bytes a prior
                // run left under this output are wire-domain, and the
                // gate must see them (TODO 158 item 2). The latch half
                // was stamped at seed time.
                if let Some(&n) = inner.resumed_wire.get(&out) {
                    w.seed_written(n);
                }
                w
            } else {
                FileWriter::create_capped(&path, total, cap)?
            }
            .with_budget(budget),
        );
        inner.inner_writers.insert(out.clone(), w.clone());
        if let Some(gk) = gkey
            && let Some(g) = inner.groups.get_mut(&gk)
        {
            g.out_names.insert(key, out);
        }
        Ok(w)
    }

    /// Resolve `slot`'s view of an inner-file name to its destination -
    /// the read-side mirror of `route_dest`, consulting the group's
    /// routed map first so delegation always agrees with routing.
    pub(super) fn dest_for(inner: &Inner, slot: usize, entry_name: &str) -> Option<Dest> {
        // Keyed on the RAW name, matching route_dest/inner_writer.
        if let Some(gk) = inner.slots[slot].group.as_ref()
            && let Some(g) = inner.groups.get(gk)
        {
            if let Some(&cs) = g.routed.get(entry_name) {
                return inner.child.clone().map(|c| Dest::Child(c, cs));
            }
            if let Some(out) = g.out_names.get(entry_name) {
                return inner.inner_writers.get(out).cloned().map(Dest::Writer);
            }
        }
        inner
            .inner_writers
            .get(&sanitize_filename(entry_name))
            .cloned()
            .map(Dest::Writer)
    }

    /// Unlink and forget every output file a group owns (fallback: the
    /// bytes were reconstructed into the volume files, and a sparse
    /// half-written "extracted" file would masquerade as output). Only
    /// files in the group's own `out_names` are touched - a file another
    /// group is still extracting is structurally unreachable from here.
    /// Routed inner files are abandoned in the child by the same
    /// ownership argument: the child slots drained here belong to this
    /// group alone.
    pub(super) fn delete_group_out_files(inner: &mut Inner, key: &str) {
        let (outs, routed): (Vec<String>, Vec<usize>) = match inner.groups.get_mut(key) {
            Some(g) => {
                g.routed_plain.clear();
                (
                    g.out_names.drain().map(|(_, v)| v).collect(),
                    g.routed.drain().map(|(_, v)| v).collect(),
                )
            }
            None => return,
        };
        for out in outs {
            if let Some(w) = inner.inner_writers.remove(&out) {
                w.abandon();
                let _ = std::fs::remove_file(&w.path);
                inner
                    .names_taken
                    .lock_ok()
                    .remove(&name_collision_key(inner.fold_names, &out));
            }
        }
        if let Some(c) = inner.child.clone() {
            for cs in routed {
                c.abandon_slot(cs);
            }
        }
    }

    /// Follow the alias chain from an inner-file name to the canonical
    /// group key that owns it (itself when unlinked).
    pub(super) fn canon_key(inner: &Inner, name: &str) -> String {
        let mut k = name;
        for _ in 0..64 {
            match inner.alias.get(k) {
                Some(next) if next != k => k = next,
                _ => break,
            }
        }
        k.to_string()
    }

    /// The slot's writer, if it has stably classified as a plain file:
    /// mode Plain, writer created, no held spans, no chase or 7z engine.
    /// Plain is terminal for a slot, so a caller may cache the writer
    /// (Finding 4); takes only OUR lock, so callers must not hold any
    /// other extractor's lock (parent<->child nesting deadlocks).
    pub(super) fn stable_plain_writer(&self, slot: usize) -> Option<Arc<FileWriter>> {
        let inner = self.inner.lock_ok();
        let s = inner.slots.get(slot)?;
        if s.mode == SlotMode::Plain
            && s.holds.is_empty()
            && s.chase.is_none()
            && s.sevenz.is_none()
        {
            s.writer.clone()
        } else {
            None
        }
    }

    /// The offset-0 sniff: classify a still-Unknown slot from the first
    /// article's bytes and route this span the way that classification
    /// says. Runs with the routing lock held (`inner` is the guard's
    /// `&mut`), so it cannot itself drop the lock or run the off-lock
    /// flushes - the two exits that need either are reported back as
    /// [`Sniffed`] and performed by the caller. Split out of
    /// `write_impl_scratched` (TODO 106 function ceiling).
    #[expect(clippy::too_many_arguments)]
    pub(super) fn sniff_and_route(
        &self,
        inner: &mut Inner,
        slot: usize,
        offset: u64,
        data: &[u8],
        jobs: &mut Vec<WriteJob>,
        fwd: &mut Vec<FwdSpan>,
        repair: bool,
        article_crc: Option<u32>,
    ) -> io::Result<Sniffed> {
        let mut routed_rar = false;
        // A NAMED payload file (`.cbr`, `.cb7`) is the
        // deliverable even though its bytes carry an
        // archive magic - it must never map, chase, or
        // attach. Named extension only: an obfuscated
        // post keeps the sniff (the zip side's standing
        // trade-off, see `zip::chase_eligible_name`).
        let payload_name = is_final_name(&inner.slots[slot].name);
        // TODO 94 C: a self-extractor - an `.exe`/`.bin`/
        // `.sfx` with a CONFIRMED archive signature behind
        // its launcher stub, inside this offset-0 article.
        // The mapper (RAR) or the chase (7z) then starts at
        // that offset instead of the file going to disk
        // for the post-pass's SFX arm. Depth 0 ONLY, which
        // is the posted-top-level-only rule the disk side's
        // `is_extractable_archive` keeps: a member a parent
        // produced is never sniffed this way, so a
        // payload's own `setup.exe` is delivered, never
        // exploded. A stub longer than the first article,
        // a file that merely looks like a program, or a
        // signature with no valid header behind it all
        // fall through to the plain sniff below and land
        // on disk exactly as before.
        let sfx = if self.depth == 0 && !payload_name {
            crate::sfx::sfx_archive_behind_stub(&inner.slots[slot].name, data)
        } else {
            None
        };
        let (is_rar, rar_base) = match sfx {
            Some((off, crate::sfx::SfxFamily::Rar)) => (true, off as u64),
            _ => (
                !payload_name
                    && (data.starts_with(b"Rar!\x1a\x07\x01\x00")
                        || data.starts_with(b"Rar!\x1a\x07\x00")),
                0,
            ),
        };
        let sevenz_base = match sfx {
            Some((off, crate::sfx::SfxFamily::SevenZ)) => off as u64,
            _ => 0,
        };
        if is_rar {
            inner.slots[slot].mode = SlotMode::Rar;
            routed_rar = true;
            let size = inner.slots[slot].size;
            // TODO 211 (b): part 1 of a declared byte
            // split maps the whole joined volume, its
            // size closed once every part has reported.
            if !self.split_attach_head(inner, slot, rar_base)? {
                inner.slots[slot].mapper = Some(VolumeMapper::with_password_at(
                    size,
                    inner.password.clone(),
                    rar_base,
                ));
            }
            self.rar_span(
                inner,
                slot,
                offset,
                data,
                Some((&mut *jobs, &mut *fwd)),
                repair,
                article_crc,
            )?;
        } else if !payload_name && self.split_try_attach_part(inner, slot, data)? {
            // TODO 211 (b): a headless continuation of a
            // declared `.rar.NNN` split. Attached, this
            // span feeds the head at its logical offset;
            // still waiting for the head, it parks with
            // the slot's other holds (the record stays
            // Held, exactly like a pre-sniff span).
            if matches!(inner.slots[slot].mode, SlotMode::SplitPart) {
                routed_rar = true;
                self.split_forward_span(
                    inner,
                    slot,
                    offset,
                    data,
                    Some((&mut *jobs, &mut *fwd)),
                    repair,
                    article_crc,
                )?;
            } else {
                self.split_park_span(inner, slot, offset, data)?;
                return Ok(Sniffed::Parked);
            }
        } else if !payload_name && self.try_attach_sevenz(inner, slot, data, sevenz_base)? {
            // Phase 3: a .7z gets the tail-prefetch chase -
            // this span (and everything held) feeds its
            // frontier buffer. Only the FORMAT is known
            // yet; `one-pass` is claimed in sevenz_finish,
            // once the archive actually decoded. Claiming
            // it here would badge a top-level archive that
            // demoted on the retention cap "partly on
            // disk" when every byte of it went to disk.
            self.shape.note(self.depth, SH_7Z);
            self.chase_span(inner, slot, offset, data)?;
        } else if self.try_attach_zip(inner, slot, data)? {
            // One-pass zip (phase 2): the same claim
            // discipline as 7z - only the FORMAT is
            // known yet; `one-pass` is claimed at
            // successful finish.
            self.shape.note(self.depth, SH_ZIP);
            self.chase_span(inner, slot, offset, data)?;
        } else if self.try_attach_tar(inner, slot, data, payload_name)? {
            // TODO 163 item 6, and LAST of the container
            // arms - see `try_attach_tar` for why it can
            // only take what the three above passed on,
            // and why it mints no shape bit.
            self.chase_span(inner, slot, offset, data)?;
        } else if inner.protect_sources {
            // A supposed volume that isn't RAR: writing it
            // out plain would truncate the source file.
            let name = inner.slots[slot].name.clone();
            inner
                .slot_fallbacks
                .push((name, "not a RAR volume".to_string()));
            self.discard_slot(inner, slot);
            return Ok(Sniffed::Discarded);
        } else {
            // No badge for a payload name: a `.cb7` is
            // not a 7z the post-pass will (or should)
            // open.
            if !payload_name && data.starts_with(b"7z\xbc\xaf\x27\x1c") {
                // A .7z the chase can't take (top level, a
                // multipart .001, gate off): it lands on
                // disk for the post-pass, and the badge
                // should say so rather than say nothing.
                self.shape.note(self.depth, SH_7Z | SH_MATERIALIZED);
            } else if self.depth == 0
                && data.starts_with(b"PK\x03\x04")
                && crate::zip::chase_eligible_name(&inner.slots[slot].name)
            {
                // Same for a zip the chase can't take
                // (gate off, too small). The name gate
                // keeps phase 0's rules: a `.cbz` or a
                // named non-zip never reads as packaging.
                // Still depth-0 only, unlike the 7z arm
                // above, because `from_bits` renders the
                // nested word as `inner-7z`/`inner-rar`
                // and has no zip token - a nested note
                // here would set bits nothing reads.
                // Giving nested zip a badge means adding
                // a persisted wire token plus dashboard
                // copy, which is its own piece of work.
                self.shape.note(self.depth, SH_ZIP | SH_MATERIALIZED);
            }
            inner.slots[slot].mode = SlotMode::Plain;
            // The sniff LOOKED at offset 0 and found no
            // shape to map or chase - see `plain_by_sniff`.
            inner.slots[slot].plain_by_sniff = true;
            // TODO 211 (b): a declared `.rar.001` that is
            // not a RAR heads nothing; its waiting parts
            // flush as the plain files they are.
            self.split_slot_plain(inner, slot)?;
            self.plain_job(inner, slot, offset, data, &mut *jobs)?;
        }

        Ok(Sniffed::Routed { rar: routed_rar })
    }
}

/// What [`Extractor::sniff_and_route`] decided for a still-Unknown slot,
/// for a caller that holds the routing lock it must not.
pub(super) enum Sniffed {
    /// Classified and routed under the lock. `rar` is true when the span
    /// went down a RAR path, which the caller re-checks against a
    /// concurrent fallback once its writes have landed.
    Routed { rar: bool },
    /// A headless continuation of a declared split whose head has not
    /// arrived: the whole span parked with the slot's other holds. The
    /// caller drops the lock, flushes the promote queue and returns
    /// `Persist::Held`.
    Parked,
    /// `protect_sources` refused a supposed volume that is not a RAR:
    /// the slot is discarded and the caller returns `Persist::No`.
    Discarded,
}
