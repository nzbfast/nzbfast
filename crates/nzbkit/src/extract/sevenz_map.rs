//! The one-pass 7z DIRECT MAP (TODO 37 step 4): a Copy-coded 7z
//! container's members routed straight to their output files, the way a
//! stored RAR member already is, instead of through a worker and a
//! frontier buffer.
//!
//! Why this exists. Round 12 of the unpack audit
//! (`research/RAR-PERF-AUDIT-2026-09-02.md`) measured the two paths side
//! by side on m1 loopback, 1 GiB, outputs byte-compared:
//!
//! | leg                | download only | one-pass extract | peak RSS |
//! |--------------------|---------------|------------------|----------|
//! | RAR5 store, 21 vol | 0.63 s        | 0.63 s (free)    | 62 MB    |
//! | 7z Copy split      | 0.64 s        | 1.05 s           | 1.29 GB  |
//!
//! A stored RAR member costs NOTHING beyond the download because each
//! article is mapped to an output offset and written once. The 7z chase
//! instead appends every arriving byte to a frontier buffer and has a
//! worker copy it out behind the arrival edge - a second pass over every
//! byte, and at line rate the download outruns the copy, so the frontier
//! ends up holding the whole set. That is the "plain 7z held ENTIRE" row
//! of the shape census, and a held-entire set is what forfeits to the
//! disk route on a 16 GB box.
//!
//! The observation that removes both costs: once the END HEADER has
//! parsed, a Copy-coded member is one contiguous range of the container.
//! Copy is the identity coder, so the member's packed bytes ARE its
//! unpacked bytes - there is nothing to decode, only somewhere to put
//! them. That is precisely what a stored RAR member is, and the
//! extractor's whole stored-member machinery (span routing, split bases
//! across volumes, held-span re-feed, per-piece CRC composition,
//! read-back reconstruction on a demote) reads only a `VolumeMapper`'s
//! `entries` and never asks what format produced them. So this module
//! BUILDS those entries from the 7z map and hands the container to that
//! machinery, rather than growing a second copy of it - see
//! [`crate::rar::VolumeMapper::synthetic`].
//!
//! Shape of the change, end to end:
//!
//!   1. Attach is unchanged. A `.7z` (or `.7z.001` set) sniffs at
//!      offset 0, flips to `SlotMode::SevenZ`, seeds a frontier, has its
//!      TAIL articles front-loaded, and spawns the worker.
//!   2. The worker parses the end header exactly as before. Between the
//!      parse and the first payload read - the same seam `arm_trim`
//!      already uses, and the only point at which the coder chains are
//!      known and no byte has been decoded yet - it asks [`plan`]
//!      whether every folder is Copy.
//!   3. If so, [`Extractor::direct_promote`] converts every
//!      registered part slot to `SlotMode::Rar` under one lock hold,
//!      re-feeds what the frontier had collected through the ordinary
//!      stored-member path, and the worker returns. Every later article
//!      routes straight to its output.
//!   4. A part that classifies AFTER the promote takes
//!      [`Extractor::direct_attach`] instead of joining the
//!      frontier set.
//!
//! What it deliberately does NOT take, each falling through to the
//! worker path untouched (and pinned by a test):
//!
//!   * any folder whose coder chain is not exactly one Copy coder -
//!     LZMA2, BZip2, PPMd, Delta, BCJ/BCJ2, and AES256 (encrypted
//!     entries, `-p` and `-mhe` alike) all still decode through the
//!     engine;
//!   * an archive with an EMPTY member or an entry with no stream: the
//!     worker creates those files with an explicit empty write, and a
//!     direct map has no byte to route that would create them;
//!   * a container whose declared geometry does not close (a member
//!     running past the container, a folder whose packed and unpacked
//!     lengths disagree, blocks with more than one pack stream);
//!   * anything the promote itself finds changed under the lock - a part
//!     that demoted, a repair that rewrote chased bytes.
//!
//! `NZBFAST_NO_7Z_DIRECT=1` turns it off wholesale, leaving exactly the
//! round-12 behaviour.
//!
//! HALF OF THIS MODULE IS FORMAT-INDEPENDENT and is SHARED, which is
//! why [`Extractor::direct_promote`], [`Extractor::direct_attach`] and
//! `direct_install` are not named after 7z. Everything from the promote
//! down reads [`DirectMember`]s and slots and never asks what parsed
//! them, so `extract::zip_map` - the stored-zip twin, audit round 33 -
//! builds its own member list and calls the same functions rather than
//! growing a second copy of them. Only [`plan`] is per-format, and it
//! has to be: zip's map is at the tail of a different structure, and
//! the data offset behind an entry's local header cannot be derived
//! from its directory record at all.

use super::*;

use crate::rar::{FileEntry, VolumeMapper};

/// One directly-mappable member of a container, in CONTAINER coordinates
/// (byte 0 is the container's first byte - for 7z the
/// `7z\xbc\xaf\x27\x1c` signature - so a split set's parts concatenate
/// into this one address space and an SFX stub's length is already
/// folded in).
///
/// Built by [`plan`] for a Copy-coded 7z member and by
/// `zip_map::plan` for a stored zip entry; consumed by the shared
/// promote below, which cannot tell them apart and does not need to.
#[derive(Debug, Clone)]
pub(super) struct DirectMember {
    /// The entry name exactly as the archive stores it - the routing key
    /// (`route_dest` groups on the RAW name, never the sanitized form).
    pub(super) name: String,
    /// Container offset of the member's first byte.
    pub(super) start: u64,
    /// Its length. Copy, so packed length == unpacked length.
    pub(super) size: u64,
    /// The archive's stored CRC32 of the member, when it has one: what
    /// the settle-time composition gate checks the routed bytes against
    /// (`file_crc` on the member's LAST piece, exactly as a RAR5 store
    /// entry carries it).
    pub(super) crc: Option<u32>,
}

/// Can this archive be direct-mapped, and if so where does every member
/// live? `None` means "not for us" - the caller keeps decoding through
/// the engine, which is the behaviour every declined shape had before
/// this module existed.
///
/// `archive_base` is the container's start inside the posted file (an
/// SFX stub's length, 0 otherwise) and `total` the container's whole
/// length; both are the ctl's, so the ranges this returns are directly
/// comparable with the byte space the set maps parts onto.
pub(super) fn plan(
    archive: &sevenz_rust2::Archive,
    archive_base: u64,
    total: u64,
) -> Option<Vec<DirectMember>> {
    // 7z stores pack-stream offsets relative to the end of the 32-byte
    // signature header, so every absolute offset below is
    // `archive_base + 32 + pack_pos + <stream offset>`. `pack_pos` and
    // `pack_stream_offsets` are the crate's own public accessors for
    // exactly this arithmetic.
    let pack_base = archive_base
        .checked_add(32)?
        .checked_add(archive.pack_pos())?;
    let sizes = archive.pack_sizes();
    let offsets = archive.stream_map.pack_stream_offsets();
    let first_pack = archive.stream_map.block_first_pack_stream_index();
    let nblocks = archive.blocks.len();
    if nblocks == 0 || first_pack.len() != nblocks {
        return None;
    }

    // Per block: where its single Copy pack stream starts, and how long
    // it is. A block that is not exactly one Copy coder over exactly one
    // pack stream refuses the whole archive - a mixed container (some
    // folders Copy, some LZMA2) would need the engine for its other
    // half anyway, and half a container cannot be handed over.
    let mut block_at: Vec<(u64, u64)> = Vec::with_capacity(nblocks);
    for (b, block) in archive.blocks.iter().enumerate() {
        if block.coders.len() != 1
            || block.coders[0].encoder_method_id() != sevenz_rust2::EncoderMethod::ID_COPY
        {
            return None;
        }
        let fp = first_pack[b];
        // Exactly one pack stream: the next block's first stream (or the
        // end of the list) must be the very next index. `packed_streams`
        // is crate-private, so this is how the count is asked.
        let next = first_pack.get(b + 1).copied().unwrap_or(sizes.len());
        if next != fp + 1 {
            return None;
        }
        let len = *sizes.get(fp)?;
        // Copy is the identity coder: a folder whose declared unpacked
        // length differs from its packed one is not one, whatever its
        // coder id says.
        if block.get_unpack_size() != len {
            return None;
        }
        let start = pack_base.checked_add(*offsets.get(fp)?)?;
        if start.checked_add(len)? > total {
            return None;
        }
        block_at.push((start, len));
    }

    // Members, in file order. Within a folder the sub-streams tile the
    // folder's output back to back, and for Copy that output IS the pack
    // stream - so a running cursor per block places every member.
    let mut out: Vec<DirectMember> = Vec::with_capacity(archive.files.len());
    let mut covered: Vec<u64> = vec![0; nblocks];
    let mut cur: Option<(usize, u64)> = None;
    for (fi, f) in archive.files.iter().enumerate() {
        if f.is_directory {
            // Directories are not created by the worker path either
            // (`sevenz_run` returns early on them, exactly as the RAR
            // store path skips `is_dir`), so skipping them here changes
            // nothing about the output tree.
            continue;
        }
        // An empty member is the one shape the worker does something a
        // direct map cannot: it performs an explicit zero-length write
        // to bring the file into existence. There is no byte to route
        // for it, so decline the archive rather than silently drop it.
        if !f.has_stream || f.size == 0 {
            return None;
        }
        let b = (*archive.stream_map.file_block_index.get(fi)?)?;
        let (bstart, blen) = *block_at.get(b)?;
        let at = match cur {
            Some((cb, off)) if cb == b => off,
            // Blocks are assigned to files in increasing order by the
            // parse; a cursor that went backwards would place two
            // members at one offset.
            Some((cb, _)) if cb > b => return None,
            _ => 0,
        };
        let end = at.checked_add(f.size)?;
        if end > blen {
            return None;
        }
        cur = Some((b, end));
        covered[b] = end;
        out.push(DirectMember {
            name: f.name.clone(),
            start: bstart.checked_add(at)?,
            size: f.size,
            crc: f.has_crc.then_some(f.crc as u32),
        });
    }
    if out.is_empty() {
        return None;
    }
    // Every folder's pack stream fully claimed by its members. Bytes in
    // a folder that no member accounts for would fall outside every data
    // area, and a complete mapper calls that HEADER: they would be kept
    // in RAM for the life of the slot by `retain_header_bytes`, which is
    // the exact cost this whole module exists to remove. Real Copy
    // containers tile exactly; a header that declares a folder with no
    // sub-streams, or members that come up short of one, keeps the
    // worker.
    if covered
        .iter()
        .zip(block_at.iter())
        .any(|(&c, &(_, len))| c != len)
    {
        return None;
    }
    // The routing map, the settle gate and `map_span_into`'s own
    // debug-assert all require ordered, disjoint data areas. The walk
    // above produces them for a well-formed archive; a header that
    // declares otherwise is refused here rather than trusted.
    if out.windows(2).any(|w| w[0].start + w[0].size > w[1].start) {
        return None;
    }
    // Two members under ONE name would share a single output: routing
    // groups on the raw entry name, so their pieces would interleave at
    // each other's offsets. The settle gate catches it afterwards (the
    // pieces cannot tile the file) and demotes, but declining here says
    // so at the point the map is built rather than after bytes have
    // landed.
    let mut names: Vec<&str> = out.iter().map(|m| m.name.as_str()).collect();
    names.sort_unstable();
    if names.windows(2).any(|w| w[0] == w[1]) {
        return None;
    }
    Some(out)
}

impl Extractor {
    /// Which escape hatch governs this container's direct map. Two
    /// switches, one per format, because the measurement they exist for
    /// is a per-format A/B on a single binary.
    fn direct_map_on(inner: &Inner, fmt: ChaseFormat) -> bool {
        match fmt {
            ChaseFormat::Zip => inner.zip_direct_on,
            ChaseFormat::SevenZ | ChaseFormat::Tar => inner.sevenz_direct_on,
        }
    }

    /// Hand a whole Copy-coded container over to the stored-member path:
    /// every registered part becomes a mapped volume, the frontier's
    /// bytes are re-fed through it, and the worker is done.
    ///
    /// Called from the 7z worker thread between the end-header parse and
    /// the first payload read, so it takes the routing lock itself.
    /// Returns false when the container must keep decoding through the
    /// engine (the gate is off, a part demoted under us, a repair
    /// rewrote chased bytes); the caller then behaves exactly as it did
    /// before this existed.
    ///
    /// Format-INDEPENDENT from here down, which is why it is not named
    /// after 7z: everything below reads `DirectMember`s and slots, never
    /// a coder chain or a central directory, so `extract::zip_map`
    /// builds its members and calls this same function rather than
    /// growing a second copy of it. `fmt` selects only which escape
    /// hatch applies (`NZBFAST_NO_7Z_DIRECT` / `NZBFAST_NO_ZIP_DIRECT`),
    /// kept as two switches so a benchmark round can A/B either map out
    /// of ONE binary without disturbing the other.
    pub(super) fn direct_promote(
        &self,
        ctl: &SevenZCtl,
        members: Vec<DirectMember>,
        fmt: ChaseFormat,
    ) -> io::Result<bool> {
        let mut g = self.inner.lock_ok();
        let inner = &mut *g;
        if !Self::direct_map_on(inner, fmt) {
            return Ok(false);
        }
        let parts = ctl.set.member_slots();
        // Every part still chased: a demotion takes the container as a
        // whole, so one part having left SevenZ mode means this map is
        // already stale. Same single-lock-hold liveness rule as the
        // worker's sink open.
        if parts.is_empty()
            || !parts
                .iter()
                .all(|&m| matches!(inner.slots[m].mode, SlotMode::SevenZ))
        {
            return Ok(false);
        }
        // A repair that rewrote bytes already inside a frontier is the
        // one thing the re-feed cannot reconcile (the bytes it would
        // route disagree with the bytes some earlier article carried);
        // the chase's own seed check refuses the same shape.
        //
        // And a frontier a drop-behind trim has already cut into cannot
        // be re-fed either: the released prefix is in the part's own
        // `.7z.NNN` file, not in the buffer, so the map would place a
        // container with a hole in it and leave a truncated archive on
        // disk that nothing deletes. `sevenz_run` decides the map BEFORE
        // it arms the trim, so `trim_ok` is never true for a container
        // that reaches here and neither test below can fire today; they
        // stand because the cost is two loads and the failure they
        // prevent is silent.
        if parts.iter().any(|&m| {
            inner.slots[m]
                .chase
                .as_ref()
                .is_some_and(|c| c.buf.conflicted() || c.buf.base() != 0 || !c.dropped.is_empty())
        }) {
            return Ok(false);
        }
        let (part_size, total) = {
            let st = ctl.set.state.lock_ok();
            (st.part_size, st.total)
        };
        if part_size == 0 || total == 0 {
            return Ok(false);
        }
        // The geometry [`plan`] bounded its ranges against is re-read
        // here, at the point of use, and the ranges are re-checked
        // against it. It cannot have moved (`SevenZSet::resolve` sets it
        // once and refuses a second part 1, and the worker is spawned by
        // part 1 after that), which is exactly why the check is cheap:
        // it costs one pass over a handful of members and removes the
        // need to reason about it ever again.
        if members
            .iter()
            .any(|m| m.start.saturating_add(m.size) > total)
        {
            return Ok(false);
        }
        // Slot-to-part indexes resolved BEFORE anything is mutated, so
        // an early return here cannot leave half the container converted
        // and half still chased.
        let mut placed: Vec<(usize, u32)> = Vec::with_capacity(parts.len());
        for &m in &parts {
            match ctl.set.part_of(m) {
                Some((i, _)) => placed.push((m, i)),
                None => return Ok(false),
            }
        }
        let map = Arc::new(members);
        // The group key is the first member's name, canonicalized
        // through the alias map - the same rule `rar_span` applies when
        // a RAR volume forms its group, so a 7z container and a RAR set
        // that really do share an inner file still land in one group.
        let key = Self::canon_key(inner, &map[0].name);
        for &(m, idx) in &placed {
            self.direct_install(inner, m, idx, part_size, &map, &key);
        }
        // Published only once every part is installed: a part joining
        // later reads this to take `direct_attach` instead of the
        // frontier, and a half-installed set must never be visible to it.
        *ctl.direct.lock_ok() = Some(map);
        // The bytes the frontier had collected before the map parsed are
        // this container's only backlog - route them now, in part order,
        // one span at a time. Bracketed like `drain_holds`: every
        // under-lock write it performs surfaces a late placement, which
        // is what lets an article parked on a `Persist::Held` return
        // complete its journal record instead of refetching on resume.
        let prev = inner.refeed_active;
        inner.refeed_active = true;
        let mut res = Ok(());
        'parts: for &(m, _) in &placed {
            let Some(ch) = inner.slots[m].chase.take() else {
                continue;
            };
            inner.budget.sub(ch.charged);
            loop {
                match ch.buf.pop_span() {
                    Ok(None) => break,
                    Ok(Some((off, bytes))) => {
                        if let Err(e) = self.rar_span(inner, m, off, &bytes, None, false, None) {
                            res = Err(e);
                            break 'parts;
                        }
                    }
                    Err(e) => {
                        res = Err(e);
                        break 'parts;
                    }
                }
            }
        }
        inner.refeed_active = prev;
        if let Err(e) = res {
            // Half the backlog placed and half lost: the group can no
            // longer describe whole files, so demote it whole while the
            // bases are still intact for the read-back, exactly as a
            // contradicted `reresolve` does.
            self.fallback_group(inner, &key, "7z direct map could not place its backlog")?;
            return Err(e);
        }
        drop(g);
        // A member routed into the nested child was QUEUED by the re-feed
        // (an under-lock write has no sink to push to), and every other
        // caller that re-feeds under the lock flushes on the way out.
        // This one is a worker thread that returns straight afterwards:
        // without the flush those bytes would sit in `pending_fwd` until
        // some other slot's next article happened to drain them, and on a
        // container whose bytes had ALL arrived before the map parsed
        // there is no such article.
        self.flush_pending_fwd()?;
        Ok(true)
    }

    /// A part that classified AFTER its container was direct-mapped:
    /// give it its slice of the map instead of a frontier buffer.
    /// Returns false when the map is not (or no longer) in force, so the
    /// caller falls through to the ordinary `sevenz_join_set`.
    pub(super) fn direct_attach(
        &self,
        inner: &mut Inner,
        slot: usize,
        ctl: &SevenZCtl,
        idx: u32,
    ) -> io::Result<bool> {
        let Some(map) = ctl.direct.lock_ok().clone() else {
            return Ok(false);
        };
        let (part_size, total) = {
            let st = ctl.set.state.lock_ok();
            (st.part_size, st.total)
        };
        // The size checks `SevenZSet::register` would have made, made
        // here instead: a part of the wrong size is not a `7z -v` split
        // and must not be mapped into the container's byte space.
        let n = SevenZSet::count_of(total, part_size);
        let expected = if idx >= n {
            total - (n as u64 - 1) * part_size
        } else {
            part_size
        };
        if idx == 0 || idx > n || inner.slots[slot].size != expected {
            return Ok(false);
        }
        let key = Self::canon_key(inner, &map[0].name);
        self.direct_install(inner, slot, idx, part_size, &map, &key);
        self.drain_holds(inner, slot)?;
        Ok(true)
    }

    /// Install one part's slice of a container map: a synthetic mapper
    /// in the part's OWN byte space, the group it shares with every
    /// other part, and the split bases those entries need.
    ///
    /// Container offsets are part-local here and nowhere else: part
    /// `idx` covers `[(idx-1) * part_size, ...)` of the container, and a
    /// member crossing that seam becomes two entries - one
    /// `split_after`, one `split_before` - which is the exact shape a
    /// stored RAR member spanning two volumes already has.
    fn direct_install(
        &self,
        inner: &mut Inner,
        slot: usize,
        idx: u32,
        part_size: u64,
        map: &Arc<Vec<DirectMember>>,
        key: &str,
    ) {
        let size = inner.slots[slot].size;
        let pstart = (idx as u64 - 1) * part_size;
        let pend = pstart.saturating_add(size);
        let mut entries: Vec<FileEntry> = Vec::new();
        let mut bases: Vec<u64> = Vec::new();
        for m in map.iter() {
            let s = m.start.max(pstart);
            let e = (m.start + m.size).min(pend);
            if s >= e {
                continue;
            }
            let split_before = s > m.start;
            let split_after = e < m.start + m.size;
            entries.push(FileEntry {
                name: m.name.clone(),
                unpacked_size: m.size,
                method: Method::Store,
                encrypted: false,
                crypt: None,
                // The whole-file CRC belongs to the LAST piece, which is
                // where the settle gate looks for it (`hdr` is taken
                // only from a piece with `split_after` clear).
                file_crc: if split_after { None } else { m.crc },
                hash: None,
                is_dir: false,
                size_unknown: false,
                split_before,
                split_after,
                data_off: s - pstart,
                data_len: e - s,
            });
            bases.push(s - m.start);
        }
        inner.slots[slot].mode = SlotMode::Rar;
        inner.slots[slot].mapper = Some(VolumeMapper::synthetic(size, entries));
        inner.slots[slot].group = Some(key.to_string());
        // `sevenz` is deliberately LEFT in place on a part that had one.
        // It is not a live chase any more, but it is the only handle
        // `sevenz_finish` and `Drop` have on the worker thread, and both
        // discover workers by walking slots that still hold a ctl.
        // Clearing it here detached the thread: finish found no container
        // to join and the handle was dropped un-joined. `sevenz_finish`
        // still clears it, and its `live` filter (members still in
        // `SevenZ` mode) is empty for a promoted set, so it joins and
        // moves on without touching the mapped slots.
        let grp = inner
            .groups
            .entry(key.to_string())
            .or_insert_with(Group::new);
        if !grp.slots.contains(&slot) {
            grp.slots.push(slot);
        }
        for (ei, base) in bases.into_iter().enumerate() {
            grp.bases.insert((slot, ei), base);
        }
        // Every base is already known and none of them can move: these
        // mappers are born complete, so no parse can ever progress and
        // nothing will re-derive them. Stamping the group with what
        // `reresolve` would compute keeps its RAR-shaped recompute (and
        // the arithmetic gate under it) off a set it cannot describe,
        // while leaving the held-span re-feed half of `reresolve` doing
        // its job. Recomputed on every install, because each part that
        // joins moves the stamp.
        let stamp = {
            let slots = inner.groups[key].slots.clone();
            let mut numbered = 0usize;
            let mut total_entries = 0u64;
            for si in &slots {
                if let Some(m) = inner.slots[*si].mapper.as_ref() {
                    if m.volume_number.is_some() {
                        numbered += 1;
                    }
                    total_entries += m.entries.len() as u64;
                }
            }
            (slots.len(), numbered, total_entries)
        };
        inner.groups.get_mut(key).unwrap().resolve_stamp = Some(stamp);
        // `SH_7Z` is already latched at attach and `SH_ONE_PASS` by
        // `route_dest` on the first routed span, so the badge reads
        // exactly as it did before the map existed.
        //
        // Deliberately NOT latched here, though both are true of a Copy
        // container: `SH_STORE`, and the `saw_store` flag beside it.
        // `saw_store` is not a badge - it is the positive half of the
        // nested depth cap's store raise (`Inner::saw_compressed`), a
        // decompression-bomb guard whose stated rule is that a 7z layer
        // sets NEITHER flag and counts against the cap like any other.
        // A Copy layer genuinely cannot expand and so could qualify, but
        // relaxing a bomb guard is its own piece of work with its own
        // evidence, not a side effect of a routing change - and the
        // failure mode of getting it wrong is a guard that does not
        // guard. Same reason for the badge: the token would then depend
        // on whether the map fired, so the same archive would describe
        // itself two ways.
    }
}

/// Test hook: how many slots of this extractor (and of its nested
/// child chain) carry a DIRECT-MAPPED 7z part - mode `Rar` under a
/// mapper that no parse produced.
///
/// The output tree cannot answer that on its own. Both paths write the
/// same bytes to the same files, which is the point; what separates
/// them is which machinery did it, and a test that only read the
/// payload would pass just as happily with the map never firing.
#[cfg(test)]
pub(super) fn direct_mapped_parts(ex: &Extractor) -> usize {
    let inner = ex.inner.lock_ok();
    let here = inner
        .slots
        .iter()
        .filter(|s| {
            matches!(s.mode, SlotMode::Rar)
                && s.mapper
                    .as_ref()
                    // A parsed RAR mapper always knows its version by
                    // the time it has entries; a synthetic one never
                    // has one, and is complete from birth.
                    .is_some_and(|m| m.version.is_none() && m.complete && !m.entries.is_empty())
        })
        .count();
    let child = inner.child.clone();
    drop(inner);
    here + child.map_or(0, |c| direct_mapped_parts(&c))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::extract::testutil::*;

    /// One Copy folder, one member: the container is direct-mapped and
    /// its payload lands with NOTHING retained - the holds cap is set
    /// to its 8 MB floor against a 24 MB container and the drop-behind
    /// trim is off, which is exactly the arrangement that demotes on
    /// the worker path (`sevenz_trim_disabled_by_env`). The map has no
    /// buffer to trim because it never buffers.
    #[test]
    fn a_copy_container_maps_direct_and_retains_nothing() {
        let f = noisy(24 << 20, 150);
        let arch = sevenz_archive(
            &[("F.bin", &f)],
            Some(vec![sevenz_rust2::EncoderConfiguration::new(
                sevenz_rust2::EncoderMethod::COPY,
            )]),
            false,
        );
        let dir = tmpdir("7z-direct-one");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        ex.set_sevenz_trim(false);
        ex.set_holds_cap(1); // floors at 8 MB, a third of the container
        // Head and tail first, then WAIT for the promote, then the body.
        // Not `feed_paced_tail_first`: that helper waits on `trim_ok`,
        // which a direct-mapped container never sets (`sevenz_run`
        // decides the map before it arms the trim), and the body must
        // not race the promote here anyway - 24 MB arriving against an
        // 8 MB cap with the trim off would breach and demote before the
        // map could fire, and the test would be measuring that race.
        let n = arch.len();
        let chunk = 256 << 10;
        let put = |off: usize, end: usize| {
            ex.write(0, "big.7z", n as u64, off as u64, &arch[off..end.min(n)])
                .unwrap();
        };
        put(0, chunk);
        let tail_from = n.saturating_sub(chunk * 2).max(chunk);
        put(tail_from, n);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while direct_mapped_parts(&ex) == 0 {
            assert!(std::time::Instant::now() < deadline, "the map never fired");
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let mut off = chunk;
        while off < tail_from {
            put(off, off + chunk);
            off += chunk;
        }
        assert_eq!(direct_mapped_parts(&ex), 1);
        let rep = finish_within(&ex, 60).unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
        assert_eq!(dir_files(&dir), vec!["F.bin".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The shipped shape: a Copy container SPLIT across parts, every
    /// arrival order. A member crossing a part seam becomes two mapped
    /// pieces, one `split_after` and one `split_before`, with the base
    /// the second one needs - the same shape a stored RAR member
    /// spanning two volumes already has.
    #[test]
    fn a_copy_split_set_maps_direct_in_every_order() {
        let f = payload(900_000, 151);
        let arch = sevenz_archive(
            &[("F.bin", &f)],
            Some(vec![sevenz_rust2::EncoderConfiguration::new(
                sevenz_rust2::EncoderMethod::COPY,
            )]),
            false,
        );
        let parts = split_7z(&arch, 4);
        assert_eq!(parts.len(), 4, "fixture must really split");
        for (t, order) in [vec![0, 1, 2, 3], vec![3, 2, 1, 0], vec![1, 3, 0, 2]]
            .iter()
            .enumerate()
        {
            let dir = tmpdir(&format!("7z-direct-split{t}"));
            let ex = Arc::new(Extractor::new(&dir, 4, true));
            ex.anchor();
            for &i in order {
                feed(
                    &ex,
                    i,
                    &format!("big.7z.{:03}", i + 1),
                    &parts[i],
                    7000,
                    70 + i as u64,
                );
            }
            let rep = finish_within(&ex, 60).unwrap();
            assert!(rep.fallbacks.is_empty(), "order {t}: {:?}", rep.fallbacks);
            // Every part mapped, whichever of them classified after the
            // promote (the `direct_attach` half). Read AFTER
            // finish, which is what joins the worker that does the flip:
            // before it, this is a race with a thread the test never
            // synchronised with, and it reads 0 on a fast feed.
            assert_eq!(direct_mapped_parts(&ex), 4, "order {t}");
            assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f, "order {t}");
            assert_eq!(dir_files(&dir), vec!["F.bin".to_string()], "order {t}");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// Several members in ONE Copy folder (`7z a` writes a solid block
    /// even for Copy): each is its own contiguous slice of the same
    /// pack stream, placed by the running sub-stream cursor.
    #[test]
    fn copy_members_tile_one_folder() {
        let a = payload(180_000, 152);
        let b = payload(90_001, 153);
        let c = payload(40_002, 154);
        let arch = sevenz_archive(
            &[("A.bin", &a), ("B.bin", &b), ("C.bin", &c)],
            Some(vec![sevenz_rust2::EncoderConfiguration::new(
                sevenz_rust2::EncoderMethod::COPY,
            )]),
            true,
        );
        let dir = tmpdir("7z-direct-solid");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        feed(&ex, 0, "release.7z", &arch, 7000, 71);
        let rep = finish_within(&ex, 60).unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(direct_mapped_parts(&ex), 1);
        assert_eq!(std::fs::read(dir.join("A.bin")).unwrap(), a);
        assert_eq!(std::fs::read(dir.join("B.bin")).unwrap(), b);
        assert_eq!(std::fs::read(dir.join("C.bin")).unwrap(), c);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Every byte arrives BEFORE the map parses, which is the shape
    /// the direct map is for at line rate - and the one where nothing
    /// else is left to flush the promote's queued work. The payload is
    /// whole the moment the promote lands, with no further article and
    /// no `finish()` needed to complete it.
    #[test]
    fn a_container_whose_bytes_all_beat_the_map_still_completes() {
        let f = payload(500_000, 163);
        let arch = sevenz_archive(
            &[("F.bin", &f)],
            Some(vec![sevenz_rust2::EncoderConfiguration::new(
                sevenz_rust2::EncoderMethod::COPY,
            )]),
            false,
        );
        let dir = tmpdir("7z-direct-allfirst");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        feed(&ex, 0, "release.7z", &arch, 7000, 79);
        // Polled, and deliberately BEFORE finish: the promote is the
        // last thing that will ever touch these bytes, so if the child
        // forward it queued were left sitting in `pending_fwd` this wait
        // is what would run out. Waiting on the OUTPUT rather than on
        // `direct_mapped_parts` is what makes it deterministic - the map
        // is installed under the routing lock but the queued forward is
        // delivered after that lock drops, so the counter goes nonzero a
        // moment before the file is whole.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while std::fs::read(dir.join("F.bin")).unwrap_or_default() != f {
            assert!(
                std::time::Instant::now() < deadline,
                "the payload never completed off the promote alone \
                 (map fired: {})",
                direct_mapped_parts(&ex) > 0
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(direct_mapped_parts(&ex), 1, "the map never fired");
        let rep = finish_within(&ex, 60).unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A nested Copy `.7z` inside a store RAR outer maps too - the map
    /// is a property of the container, not of the depth it sits at.
    #[test]
    fn a_nested_copy_container_maps_direct() {
        let f = payload(300_000, 155);
        let arch = sevenz_archive(
            &[("F.bin", &f)],
            Some(vec![sevenz_rust2::EncoderConfiguration::new(
                sevenz_rust2::EncoderMethod::COPY,
            )]),
            false,
        );
        let outer = store_outer("inner.7z", &arch);
        let dir = tmpdir("7z-direct-nested");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        feed(&ex, 0, "v.rar", &outer, 7000, 72);
        let rep = finish_within(&ex, 60).unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(direct_mapped_parts(&ex), 1, "the child never mapped");
        assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
        assert!(!dir.join("inner.7z").exists(), "inner materialized");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Every shape the map DECLINES still extracts, through the worker
    /// it always used. One test over the list so a new decline arm
    /// cannot be added without an arm here to hold it.
    #[test]
    fn declined_shapes_keep_the_worker() {
        let f = payload(220_000, 156);
        // (tag, archive, password, the files it must produce)
        let cases: Vec<(&str, Vec<u8>, Option<&str>, Vec<(&str, &[u8])>)> = vec![
            // LZMA2 (the writer's default): a real coder, not identity.
            (
                "lzma2",
                sevenz_archive(&[("F.bin", &f)], None, false),
                None,
                vec![("F.bin", &f)],
            ),
            // Deflate: likewise, and a different decoder.
            (
                "deflate",
                sevenz_archive(
                    &[("F.bin", &f)],
                    Some(vec![sevenz_rust2::EncoderConfiguration::new(
                        sevenz_rust2::EncoderMethod::DEFLATE,
                    )]),
                    false,
                ),
                None,
                vec![("F.bin", &f)],
            ),
        ];
        for (tag, arch, pw, want) in cases {
            let dir = tmpdir(&format!("7z-decline-{tag}"));
            let ex = Arc::new(Extractor::new(&dir, 1, true));
            ex.anchor();
            if let Some(p) = pw {
                ex.set_password(p);
            }
            feed(&ex, 0, "release.7z", &arch, 7000, 73);
            let rep = finish_within(&ex, 60).unwrap();
            assert!(rep.fallbacks.is_empty(), "{tag}: {:?}", rep.fallbacks);
            assert_eq!(direct_mapped_parts(&ex), 0, "{tag}: the map took it");
            for (n, want) in want {
                assert_eq!(std::fs::read(dir.join(n)).unwrap(), want, "{tag}/{n}");
            }
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// The header-shape declines, asked of [`plan`] directly.
    ///
    /// They are here rather than as end-to-end feeds because the
    /// vendored writer cannot BUILD most of them: a Copy archive with an
    /// empty member comes back `BadTerminatedStreamsInfo` from its own
    /// reader, so there is no fixture to feed. What there is instead is
    /// a real parsed `Archive` from a real Copy container, mutated in
    /// exactly the one way each rule is about - which is also the
    /// closest a test can get to the hostile header the rule exists for.
    #[test]
    fn plan_declines_the_shapes_it_cannot_place() {
        let a = payload(50_000, 161);
        let b = payload(30_000, 162);
        let arch = sevenz_archive(
            &[("A.bin", &a), ("B.bin", &b)],
            Some(vec![sevenz_rust2::EncoderConfiguration::new(
                sevenz_rust2::EncoderMethod::COPY,
            )]),
            true,
        );
        let total = arch.len() as u64;
        let base = sevenz_rust2::ArchiveReader::new(
            std::io::Cursor::new(arch.clone()),
            sevenz_rust2::Password::empty(),
        )
        .unwrap()
        .archive()
        .clone();
        // The control arm: unmutated, this IS the shape the map takes,
        // and both members are placed inside the container.
        let members = plan(&base, 0, total).expect("the control archive must plan");
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].size, a.len() as u64);
        assert_eq!(members[1].start, members[0].start + members[0].size);
        assert!(members[1].start + members[1].size <= total);
        assert!(members.iter().all(|m| m.crc.is_some()), "{members:?}");

        // A member with no stream (an empty file): nothing to route.
        let mut m = base.clone();
        m.files[1].has_stream = false;
        m.files[1].size = 0;
        assert!(plan(&m, 0, total).is_none(), "empty member");

        // A second coder in the chain - the shape every filter and every
        // AES256 container has.
        let mut m = base.clone();
        let dup = m.blocks[0].coders[0].clone();
        m.blocks[0].coders.push(dup);
        assert!(plan(&m, 0, total).is_none(), "two coders");

        // A member declaring more bytes than its folder holds.
        let mut m = base.clone();
        m.files[1].size = total * 4;
        assert!(plan(&m, 0, total).is_none(), "member past its folder");

        // A container the declared geometry runs off the end of - the
        // set's own total is the only thing that bounds an attacker's
        // pack_pos, and a range past it would map onto parts that do not
        // exist.
        assert!(plan(&base, 0, 64).is_none(), "member past the container");

        // Two members under one name - one output, two claims on it.
        let mut m = base.clone();
        m.files[1].name = m.files[0].name.clone();
        assert!(plan(&m, 0, total).is_none(), "duplicate member name");

        // A folder with bytes no member accounts for: they would be kept
        // in RAM as header bytes for the life of the slot.
        let mut m = base.clone();
        m.files[1].size -= 1;
        assert!(plan(&m, 0, total).is_none(), "folder not fully claimed");

        // Not a container at all: no folders, nothing to place.
        let mut m = base.clone();
        m.blocks.clear();
        assert!(plan(&m, 0, total).is_none(), "no blocks");
    }

    /// An AES-256 container (`7z -p`) keeps the worker: its pack stream
    /// is ciphertext, so a member's bytes are not the container's bytes
    /// and there is nothing to route directly.
    #[test]
    fn an_encrypted_container_keeps_the_worker() {
        let f = payload(200_000, 157);
        let arch = sevenz_archive(
            &[("F.bin", &f)],
            Some(vec![
                sevenz_rust2::EncoderConfiguration::new(sevenz_rust2::EncoderMethod::COPY),
                sevenz_rust2::encoder_options::AesEncoderOptions::new(
                    sevenz_rust2::Password::from("benchpw"),
                )
                .into(),
            ]),
            false,
        );
        let dir = tmpdir("7z-direct-aes");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        ex.set_password("benchpw");
        feed(&ex, 0, "release.7z", &arch, 7000, 74);
        let rep = finish_within(&ex, 60).unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(direct_mapped_parts(&ex), 0, "the map took ciphertext");
        assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The escape hatch: with the map off, a Copy container takes the
    /// worker and its frontier again, which is the round-12 behaviour
    /// the audit measured.
    #[test]
    fn the_gate_turns_the_map_off() {
        let f = payload(200_000, 158);
        let arch = sevenz_archive(
            &[("F.bin", &f)],
            Some(vec![sevenz_rust2::EncoderConfiguration::new(
                sevenz_rust2::EncoderMethod::COPY,
            )]),
            false,
        );
        let dir = tmpdir("7z-direct-off");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        ex.set_sevenz_direct(false);
        feed(&ex, 0, "release.7z", &arch, 7000, 75);
        let rep = finish_within(&ex, 60).unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(direct_mapped_parts(&ex), 0);
        assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A part that never arrives: the container has a hole in it, so
    /// the map cannot describe whole files and every part that DID
    /// arrive materializes byte-exact for the disk post-pass - through
    /// the synthetic mapper's read-back, which is the direct map's half
    /// of the demote contract.
    #[test]
    fn a_missing_part_materializes_the_rest_byte_exact() {
        let f = payload(700_000, 159);
        let arch = sevenz_archive(
            &[("F.bin", &f)],
            Some(vec![sevenz_rust2::EncoderConfiguration::new(
                sevenz_rust2::EncoderMethod::COPY,
            )]),
            false,
        );
        let parts = split_7z(&arch, 3);
        let dir = tmpdir("7z-direct-hole");
        let ex = Arc::new(Extractor::new(&dir, 3, true));
        ex.anchor();
        for i in [0usize, 2] {
            feed(
                &ex,
                i,
                &format!("big.7z.{:03}", i + 1),
                &parts[i],
                7000,
                76 + i as u64,
            );
        }
        let rep = finish_within(&ex, 60).unwrap();
        assert!(!rep.fallbacks.is_empty(), "the hole was not noticed");
        assert_eq!(std::fs::read(dir.join("big.7z.001")).unwrap(), parts[0]);
        assert_eq!(std::fs::read(dir.join("big.7z.003")).unwrap(), parts[2]);
        assert!(!dir.join("F.bin").exists(), "a member survived the demote");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The archive's own stored CRC32 is carried onto the member's LAST
    /// mapped piece, so the settle-time composition gate checks the
    /// routed bytes exactly as it does a stored RAR member's. A byte
    /// flipped inside the pack stream must not ship.
    #[test]
    fn a_corrupt_member_fails_the_composed_crc() {
        let f = payload(400_000, 160);
        let mut arch = sevenz_archive(
            &[("F.bin", &f)],
            Some(vec![sevenz_rust2::EncoderConfiguration::new(
                sevenz_rust2::EncoderMethod::COPY,
            )]),
            false,
        );
        // Well inside the pack stream (which starts at 32), and clear of
        // the end header at the tail.
        arch[1000] ^= 0xff;
        let dir = tmpdir("7z-direct-crc");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        feed(&ex, 0, "release.7z", &arch, 7000, 78);
        let rep = finish_within(&ex, 60).unwrap();
        assert!(!rep.fallbacks.is_empty(), "damage shipped as a success");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
