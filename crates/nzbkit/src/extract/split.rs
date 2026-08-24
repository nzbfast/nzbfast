//! TODO 211 (b): a numbered byte split of ONE `.rar` (`x.rar.001`,
//! `x.rar.002`, ...) mapped one-pass, as a single volume with seams in it.
//!
//! An HJSplit-style split is not a multi-volume RAR: part 1 carries the
//! archive head over a fraction of the data area, and every later part
//! is raw continuation bytes with no signature at all. Fed as its own
//! volume, part 1's mapper refuses at the volume-bounds guard (`data
//! area exceeds volume`) and the set lands on disk for the TODO 211 (a)
//! rescue to join - a whole extra pass of disk for a shape every rival
//! joins on disk too.
//!
//! What 7z has and RAR does not is a header that sizes the container:
//! `try_attach_sevenz` reads the whole set's extent off part 1 alone.
//! A RAR file block states its entry's data size and nothing about the
//! container, so the set's extent has to come from outside the bytes -
//! exactly the gap the zip split closes with `declare_zip_split`, and
//! this follows that precedent: the NZB's file list (which `get` has and
//! the extractor does not) DECLARES the set's part count, every part's
//! exact size arrives with its first article, and the total is their
//! sum once all are in. Until then the head's mapper runs with an
//! unknown volume size (`VolumeMapper::set_volume_size`), which is a
//! state it already supports for a yEnc span with no `size=`.
//!
//! The mechanism is an ALIAS, not a chase: a continuation part becomes
//! [`SlotMode::SplitPart`], and every byte it receives at offset `o`
//! feeds the HEAD's mapper at logical offset `(idx - 1) * P + o`, `P`
//! being part 1's size (byte splitters produce uniform parts; a part
//! that does not line up refuses the set). Read-back, coverage, patch
//! and materialize translate the same way, so the live verifier sees
//! each posted part exactly as it would a volume. A demote reconstructs
//! the head's logical volume through `plain_span`, which routes each
//! logical range back to the part slot it came from - so the disk pass,
//! PAR2 repair and the (a) rescue meet precisely the N part files they
//! would have met before, never a joined container under part 1's name.
//!
//! Scope, stated rather than half-worked: depth 0 and declared sets only
//! (the zip split's scope, for the zip split's reason - nothing declares
//! an outer archive's inner entries); store entries only, because the
//! chase that a compressed head would want drives a frontier buffer per
//! VOLUME and the alias is not one (a compressed split still demotes and
//! is rescued by (a), pinned by an e2e leg); and a part 2+ that carries
//! RAR magic is a genuine volume set in a `.rar.NNN` costume, which
//! refuses the split and classifies as the volume it is.

use super::*;

/// `x.rar.001` -> `("x.rar", 1)`: a numbered byte-split part of a single
/// `.rar`. Same digit discipline as `sevenz_part_name` and
/// `zip::split_part_name` (three digits, four past 999 - `foo.rar.1`
/// must not read as part 1 of the same base as `foo.rar.001`); the base
/// keeps its `.rar`, lowercased, so the NZB-side declaration and the
/// yEnc name agree on the key.
pub fn rar_split_part_name(name: &str) -> Option<(String, u32)> {
    let (head, tail) = name.rsplit_once('.')?;
    if tail.len() < 3 || tail.len() > 4 || !tail.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let lower_head = head.to_ascii_lowercase();
    if !lower_head.ends_with(".rar") {
        return None;
    }
    let idx: u32 = tail.parse().ok()?;
    (idx >= 1).then_some((lower_head, idx))
}

/// Reason a refused set demotes (or never maps) under. Unowned by
/// `fallback_needs_disk_unpack` on purpose: the parts land on disk as
/// they always did and the TODO 211 (a) rescue joins them.
pub const RAR_SPLIT_MISALIGNED: &str = "rar split parts do not line up";

/// One declared `.rar.NNN` set, keyed by its lowercased base.
pub(super) struct RarSplit {
    /// Part count from the NZB file list (`declare_rar_split`).
    pub(super) declared: u32,
    /// Slot of part 1, once it sniffed RAR magic and mapped.
    pub(super) head: Option<usize>,
    /// Part 1's exact size - the seam pitch. 0 until part 1 reports.
    pub(super) part_size: u64,
    /// Attached continuation parts: idx (>= 2) -> alias slot.
    pub(super) parts: BTreeMap<u32, usize>,
    /// Continuation parts that sniffed headless before the head mapped,
    /// still holding their spans as Unknown slots.
    pub(super) pending: Vec<(u32, usize)>,
    /// Every part's reported size, for the total and the uniform check.
    pub(super) sizes: BTreeMap<u32, u64>,
    /// Not a byte split after all (misaligned sizes, a signed part 2+):
    /// nothing further joins and the head maps as an ordinary volume.
    pub(super) refused: bool,
}

impl RarSplit {
    pub(super) fn new(declared: u32) -> RarSplit {
        RarSplit {
            declared,
            head: None,
            part_size: 0,
            parts: BTreeMap::new(),
            pending: Vec::new(),
            sizes: BTreeMap::new(),
            refused: false,
        }
    }

    /// The set's total once every declared part has reported a size,
    /// else `None`. Reported sizes are exact (yEnc `size=`), so this is
    /// the mapper's real volume size, not an estimate.
    pub(super) fn total(&self) -> Option<u64> {
        if self.declared == 0 || self.sizes.len() != self.declared as usize {
            return None;
        }
        let mut t = 0u64;
        for s in self.sizes.values() {
            t = t.checked_add(*s)?;
        }
        Some(t)
    }

    /// Do the sizes seen so far describe a uniform byte split: every part
    /// but the last exactly `part_size`, the last at most that? Judged
    /// only once part 1's size is known (everything is relative to it).
    fn aligned(&self) -> bool {
        if self.part_size == 0 {
            return true;
        }
        self.sizes.iter().all(|(&idx, &s)| {
            if idx == self.declared {
                s <= self.part_size && s > 0
            } else {
                s == self.part_size
            }
        })
    }

    /// Logical offset of a part's byte 0 inside the joined volume.
    pub(super) fn delta(&self, idx: u32) -> u64 {
        (idx as u64 - 1).saturating_mul(self.part_size)
    }
}

impl Extractor {
    /// Declare a `.rar.NNN` byte split from the NZB's own file list:
    /// `base` is [`rar_split_part_name`]'s base, `parts` the count, and
    /// the caller must have checked the indices run exactly `1..=n` (a
    /// set the NZB itself has a hole in can never map, and not declaring
    /// it keeps every part on the disk path). Same set-before-spans
    /// discipline as [`Self::declare_zip_split`].
    pub fn declare_rar_split(&self, base: &str, parts: u32) {
        if parts == 0 {
            return;
        }
        self.inner
            .lock_ok()
            .rar_splits
            .entry(base.to_ascii_lowercase())
            .or_insert_with(|| RarSplit::new(parts));
    }

    /// One-pass `.rar.NNN` split gate (see `NZBFAST_NO_RAR_SPLIT`,
    /// latched at construction). Off, a declared set is ignored and the
    /// parts take the disk path plus the TODO 211 (a) rescue exactly as
    /// before this existed.
    pub fn set_rar_split(&self, on: bool) {
        self.inner.lock_ok().rar_split_on = on;
    }

    /// The declared set a slot belongs to by NAME, if any and if the
    /// feature applies to this level. Pure lookup - no state moves.
    pub(super) fn split_of(&self, inner: &Inner, slot: usize) -> Option<(String, u32)> {
        if self.depth != 0 || !inner.rar_split_on || inner.protect_sources {
            return None;
        }
        let (base, idx) = rar_split_part_name(&inner.slots[slot].name)?;
        let set = inner.rar_splits.get(&base)?;
        (!set.refused && idx <= set.declared).then_some((base, idx))
    }

    /// A slot's name and size just became known (its first write, at
    /// any offset): record the size against its declared set. This is
    /// what eventually closes the head's open-ended mapper, and what
    /// catches a set that is not a uniform byte split before its bytes
    /// are trusted at the wrong seams.
    pub(super) fn split_note_size(&self, inner: &mut Inner, slot: usize) -> io::Result<()> {
        let Some((base, idx)) = self.split_of(inner, slot) else {
            return Ok(());
        };
        let size = inner.slots[slot].size;
        if size == 0 {
            return Ok(());
        }
        let set = inner.rar_splits.get_mut(&base).unwrap();
        if set.sizes.insert(idx, size).is_some_and(|old| old != size) {
            return self.split_refuse(inner, &base);
        }
        if idx == 1 {
            set.part_size = size;
        }
        if !set.aligned() {
            return self.split_refuse(inner, &base);
        }
        self.split_try_close(inner, &base)
    }

    /// Every part has reported: tell the head's mapper how long the
    /// volume really is. A no-op until both the head and the last size
    /// are in; safe to call again.
    fn split_try_close(&self, inner: &mut Inner, base: &str) -> io::Result<()> {
        let (head, total) = {
            let set = &inner.rar_splits[base];
            match (set.head, set.total()) {
                (Some(h), Some(t)) => (h, t),
                _ => return Ok(()),
            }
        };
        if !matches!(inner.slots[head].mode, SlotMode::Rar) {
            return Ok(());
        }
        let Some(m) = inner.slots[head].mapper.as_mut() else {
            return Ok(());
        };
        if m.volume_size() == total {
            return Ok(());
        }
        m.set_volume_size(total);
        self.split_after_resize(inner, head)
    }

    /// The head's mapper was just told its real size, which can
    /// complete the parse (EOF rule) or refuse it (data area past the
    /// end). `rar_span` acts on a blocker the moment a FEED raises one;
    /// a resize raises it with no span in flight, and the head may have
    /// no span still to come, so act here: a blocker demotes now (the
    /// settle loop deliberately skips blocked mappers, reading them as
    /// already handled), a completed parse re-resolves the group.
    fn split_after_resize(&self, inner: &mut Inner, head: usize) -> io::Result<()> {
        let blocker = inner.slots[head]
            .mapper
            .as_ref()
            .and_then(|m| m.blocker.clone());
        if let Some(b) = blocker {
            return self.fallback_slot_or_group(inner, head, blocker_reason(&b));
        }
        if let Some(key) = inner.slots[head].group.clone() {
            self.reresolve(inner, &key)?;
        }
        Ok(())
    }

    /// Part 1 just sniffed RAR magic: if it heads a declared set, install
    /// its mapper open-ended (or closed, if every size is already in),
    /// remember it as the head, and attach whatever parts were waiting -
    /// their held bytes feed the mapper now, ahead of the head's own
    /// offset-0 span, which is just an out-of-order arrival to it.
    /// Returns false for "not a split head, map it as the ordinary
    /// volume it is".
    pub(super) fn split_attach_head(
        &self,
        inner: &mut Inner,
        slot: usize,
        archive_base: u64,
    ) -> io::Result<bool> {
        let Some((base, idx)) = self.split_of(inner, slot) else {
            return Ok(false);
        };
        if idx != 1 {
            // A part 2+ carrying RAR magic is a VOLUME of an oddly named
            // set, not a continuation: the set is no byte split. Refuse
            // it (a mapped head un-splits to its own size; see
            // `split_refuse`) and let this slot map as the volume it is.
            self.split_refuse(inner, &base)?;
            return Ok(false);
        }
        if inner.slots[slot].size == 0 {
            return Ok(false);
        }
        let set = inner.rar_splits.get_mut(&base).unwrap();
        if set.head.is_some() {
            // Two slots claiming part 1 of one set (a duplicate post):
            // the first is the head; this one maps on its own.
            return Ok(false);
        }
        if set
            .pending
            .iter()
            .any(|&(_, ps)| !matches!(inner.slots[ps].mode, SlotMode::Unknown))
        {
            // A waiting part was flushed to disk by the holds overflow
            // before the head arrived: its bytes are a file now and can
            // never feed the map. The set is a disk set; refuse it and
            // let this head map as the ordinary volume it then is.
            self.split_refuse(inner, &base)?;
            return Ok(false);
        }
        let set = inner.rar_splits.get_mut(&base).unwrap();
        set.head = Some(slot);
        set.part_size = inner.slots[slot].size;
        let total = set.total().unwrap_or(0);
        inner.slots[slot].split_head = Some(base.clone());
        // `archive_base` is the SFX stub length the sniff located, 0 for
        // a bare archive - the same base the ordinary mapper takes.
        inner.slots[slot].mapper = Some(VolumeMapper::with_password_at(
            total,
            inner.password.clone(),
            archive_base,
        ));
        let pending = std::mem::take(&mut inner.rar_splits.get_mut(&base).unwrap().pending);
        for (pidx, pslot) in pending {
            self.split_attach_part(inner, pslot, &base, pidx)?;
        }
        Ok(true)
    }

    /// A continuation part sniffed headless at offset 0. With the head
    /// mapped it aliases now (and its held spans feed the head); before
    /// that it parks as a pending Unknown slot - a part that classified
    /// Plain because it arrived early could never be taken back, which
    /// is the 7z split's reason for the same wait. Returns false when
    /// the slot is not a continuation of a live declared set, and the
    /// caller classifies it exactly as before.
    pub(super) fn split_try_attach_part(
        &self,
        inner: &mut Inner,
        slot: usize,
        data: &[u8],
    ) -> io::Result<bool> {
        let Some((base, idx)) = self.split_of(inner, slot) else {
            return Ok(false);
        };
        if idx < 2 {
            return Ok(false);
        }
        if data.starts_with(b"Rar!\x1a\x07") {
            // A signed part 2+ is a genuine volume of an oddly named
            // set, not a byte split: refuse the set so its head maps
            // as a plain volume, and classify this one as the volume
            // it is.
            self.split_refuse(inner, &base)?;
            return Ok(false);
        }
        let set = inner.rar_splits.get_mut(&base).unwrap();
        match set.head {
            Some(head) if matches!(inner.slots[head].mode, SlotMode::Rar) => {
                self.split_attach_part(inner, slot, &base, idx)?;
                Ok(true)
            }
            Some(_) => Ok(false),
            None => {
                if !set.pending.iter().any(|&(_, s)| s == slot) {
                    set.pending.push((idx, slot));
                }
                inner.slots[slot].split_wait = true;
                Ok(true)
            }
        }
    }

    /// A slot of a declared set just became a PLAIN file (spilled or
    /// overflowed out of its pre-sniff holds, settled unclassified, or
    /// adopted off disk on resume): its bytes are in a file of their
    /// own now and can never feed the map, so the set is a disk set.
    /// Refuse it - a mapped head demotes into its parts (or un-splits,
    /// if nothing aliased yet), a head still to come maps as an
    /// ordinary volume, pending parts flush. Without this a part that
    /// spilled BEFORE its offset-0 sniff (so it never entered
    /// `pending`) left a hole in the joined volume that only the
    /// output CRC gate could catch, a whole pass later. Call AFTER the
    /// mode flip, before the slot's own drain.
    pub(super) fn split_slot_plain(&self, inner: &mut Inner, slot: usize) -> io::Result<()> {
        if let Some((base, _)) = self.split_of(inner, slot) {
            self.split_refuse(inner, &base)?;
        }
        Ok(())
    }

    /// Is this Unknown slot parked waiting for its set's head? The
    /// spill that gives up on an unsniffable slot must not fire on one
    /// that HAS sniffed and is waiting by design; the holds budget
    /// (page to scratch, else demote) still bounds it.
    pub(super) fn split_waiting(inner: &Inner, slot: usize) -> bool {
        inner.slots[slot].split_wait && matches!(inner.slots[slot].mode, SlotMode::Unknown)
    }

    /// Flip a continuation slot to an alias of its head and feed the
    /// head everything it holds.
    fn split_attach_part(
        &self,
        inner: &mut Inner,
        slot: usize,
        base: &str,
        idx: u32,
    ) -> io::Result<()> {
        let (head, delta) = {
            let set = inner.rar_splits.get_mut(base).unwrap();
            let head = set.head.expect("attach_part needs a head");
            set.parts.insert(idx, slot);
            (head, set.delta(idx))
        };
        let s = &mut inner.slots[slot];
        s.split_wait = false;
        s.mode = SlotMode::SplitPart;
        s.split_alias = Some((head, delta));
        self.drain_holds(inner, slot)
    }

    /// Feed an alias's span to its head at the logical offset. The
    /// caller keeps the PART's slot and offset for everything after
    /// (jobs, forwards, the journal frags), which is what keeps the
    /// article's record in its own file's address space.
    #[expect(clippy::too_many_arguments)]
    pub(super) fn split_forward_span(
        &self,
        inner: &mut Inner,
        slot: usize,
        offset: u64,
        data: &[u8],
        sink: Option<(&mut Vec<WriteJob>, &mut Vec<FwdSpan>)>,
        repair: bool,
        article_crc: Option<u32>,
    ) -> io::Result<()> {
        let (head, logical) = Self::split_target(inner, slot, offset);
        self.rar_span(inner, head, logical, data, sink, repair, article_crc)
    }

    /// Park a waiting continuation's span with the slot's other holds
    /// (the same budget, paging and overflow rules as a pre-sniff span);
    /// it feeds the head when the head maps.
    pub(super) fn split_park_span(
        &self,
        inner: &mut Inner,
        slot: usize,
        offset: u64,
        data: &[u8],
    ) -> io::Result<()> {
        inner.budget.add(data.len());
        inner.slots[slot].pre_bytes += data.len();
        inner.slots[slot]
            .holds
            .push((offset, HoldSpan::Ram(data.to_vec())));
        if inner.budget.over() && !self.page_out_holds(inner) {
            self.overflow_to_plain(inner)?;
        }
        Ok(())
    }

    /// The (head slot, logical offset) an alias slot's offset maps to;
    /// identity for every other slot. The one translation every
    /// slot-addressed entry point applies first.
    pub(super) fn split_target(inner: &Inner, slot: usize, off: u64) -> (usize, u64) {
        match inner.slots[slot].split_alias {
            Some((head, delta)) if matches!(inner.slots[slot].mode, SlotMode::SplitPart) => {
                (head, delta.saturating_add(off))
            }
            _ => (slot, off),
        }
    }

    /// Route a plain write of the HEAD's logical volume to the part
    /// files it is made of. `None` when the slot is not a split head
    /// (the caller writes to the slot's own file as always); `Some`
    /// when every byte was routed. The head's own range `[0, P)` is
    /// its own file; a range of an index nothing attached can hold no
    /// byte (bytes only ever arrive through a part) and is dropped.
    pub(super) fn split_plain_span(
        &self,
        inner: &mut Inner,
        slot: usize,
        offset: u64,
        data: &[u8],
    ) -> io::Result<Option<()>> {
        let Some(base) = inner.slots[slot].split_head.clone() else {
            return Ok(None);
        };
        let (p, parts) = {
            let set = &inner.rar_splits[&base];
            (set.part_size, set.parts.clone())
        };
        if p == 0 {
            return Ok(None);
        }
        let mut pos = 0u64;
        while pos < data.len() as u64 {
            let abs = offset + pos;
            let idx = (abs / p) as u32 + 1;
            let rel = abs % p;
            let n = ((p - rel).min(data.len() as u64 - pos)) as usize;
            let chunk = &data[pos as usize..pos as usize + n];
            if idx == 1 {
                self.plain_span_own(inner, slot, rel, chunk)?;
            } else if let Some(&ps) = parts.get(&idx) {
                // A part being written to as a file of its own is a
                // materialized part from here on, whatever it was.
                if matches!(inner.slots[ps].mode, SlotMode::SplitPart) {
                    inner.slots[ps].mode = SlotMode::RarFallback;
                }
                self.plain_span_own(inner, ps, rel, chunk)?;
            }
            pos += n as u64;
        }
        Ok(Some(()))
    }

    /// The head demoted: its parts are materialized files now. Flip
    /// every attached alias (the reconstruction already wrote through
    /// most of them) and tell the journal each one's file is whole.
    pub(super) fn split_after_fallback(&self, inner: &mut Inner, head: usize) {
        let Some(base) = inner.slots[head].split_head.clone() else {
            return;
        };
        let parts: Vec<usize> = inner.rar_splits[&base].parts.values().copied().collect();
        for ps in parts {
            if matches!(inner.slots[ps].mode, SlotMode::SplitPart) {
                inner.slots[ps].mode = SlotMode::RarFallback;
            }
            self.note_slot_materialized(inner, ps);
        }
    }

    /// Stop treating `base` as a byte split. A head not yet mapped will
    /// map as an ordinary volume; pending parts classify Plain and
    /// flush. A mapped head with NO alias attached un-splits in place -
    /// its mapper closes to the part's own size, which is exactly the
    /// volume it would have been (a genuine `.rar.NNN` volume set in a
    /// split's costume lands here off its signed part 2). A mapped head
    /// that already took alias bytes at seams the set does not have
    /// demotes, and the reconstruction writes every part out as posted.
    fn split_refuse(&self, inner: &mut Inner, base: &str) -> io::Result<()> {
        let (head, pending, aliased) = {
            let set = inner.rar_splits.get_mut(base).unwrap();
            if set.refused {
                return Ok(());
            }
            set.refused = true;
            (
                set.head,
                std::mem::take(&mut set.pending),
                !set.parts.is_empty(),
            )
        };
        for (_, pslot) in pending {
            inner.slots[pslot].split_wait = false;
            if matches!(inner.slots[pslot].mode, SlotMode::Unknown) {
                inner.slots[pslot].mode = SlotMode::Plain;
                inner.slots[pslot].plain_by_sniff = true;
                self.drain_holds(inner, pslot)?;
            }
        }
        let Some(h) = head else {
            return Ok(());
        };
        if !matches!(inner.slots[h].mode, SlotMode::Rar) {
            return Ok(());
        }
        if aliased {
            return self.fallback_slot_or_group(inner, h, RAR_SPLIT_MISALIGNED);
        }
        inner.slots[h].split_head = None;
        let size = inner.slots[h].size;
        if let Some(m) = inner.slots[h].mapper.as_mut() {
            m.set_volume_size(size);
        }
        self.split_after_resize(inner, h)
    }

    /// End of download: a declared set whose parts never all reported
    /// leaves its head's mapper open-ended. That is the right state - a
    /// missing part is missing articles, and missing articles are the
    /// caller's repair ladder's business, exactly as for any volume: a
    /// rebuilt part arrives through `write_repair` and its slot attaches
    /// then. A set with ONLY a head (the declaration was a lone `.001`
    /// that is a whole archive) closes to the head's own size here so
    /// the EOF rule can complete it like any volume.
    pub(super) fn split_settle(&self, inner: &mut Inner) -> io::Result<()> {
        let bases: Vec<String> = inner.rar_splits.keys().cloned().collect();
        for base in bases {
            let head = {
                let set = &inner.rar_splits[&base];
                match set.head {
                    Some(h) if set.declared == 1 && set.total().is_none() => h,
                    _ => continue,
                }
            };
            let size = inner.slots[head].size;
            if let Some(m) = inner.slots[head].mapper.as_mut()
                && m.volume_size() == 0
            {
                m.set_volume_size(size);
                self.split_after_resize(inner, head)?;
            }
        }
        Ok(())
    }

    /// Late placements a head recorded in LOGICAL offsets belong to the
    /// part slots whose bytes they are: translate each back to
    /// `(part slot, part-relative offset)` for the journal, splitting at
    /// seams (a held span is within one article and one article is
    /// within one part, so a straddle never happens; handled anyway).
    pub(super) fn split_translate_placements(
        inner: &Inner,
        placed: Vec<LatePlacement>,
    ) -> Vec<LatePlacement> {
        let mut out = Vec::with_capacity(placed.len());
        for lp in placed {
            let (slot, f, crypto) = (lp.slot, lp.frag, lp.crypto);
            let Some(base) = inner.slots.get(slot).and_then(|s| s.split_head.as_ref()) else {
                out.push(LatePlacement {
                    slot,
                    frag: f,
                    crypto,
                });
                continue;
            };
            let set = &inner.rar_splits[base];
            let p = set.part_size;
            if p == 0 {
                out.push(LatePlacement {
                    slot,
                    frag: f,
                    crypto,
                });
                continue;
            }
            let mut pos = 0u64;
            while pos < f.len {
                let abs = f.vol_off + pos;
                let idx = (abs / p) as u32 + 1;
                let rel = abs % p;
                let n = (p - rel).min(f.len - pos);
                let target = if idx == 1 {
                    Some(slot)
                } else {
                    set.parts.get(&idx).copied()
                };
                if let Some(t) = target {
                    out.push(LatePlacement {
                        slot: t,
                        frag: Frag {
                            file: f.file.clone(),
                            file_off: f.file_off + pos,
                            vol_off: rel,
                            len: n,
                        },
                        crypto,
                    });
                }
                pos += n;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::testutil::*;
    use crate::rar::fixtures;

    /// Uniform byte split, exactly what hjsplit and `split -b` produce.
    fn split_parts(arch: &[u8], n: usize) -> Vec<Vec<u8>> {
        let parts: Vec<Vec<u8>> = arch
            .chunks(arch.len().div_ceil(n))
            .map(|c| c.to_vec())
            .collect();
        assert_eq!(parts.len(), n);
        parts
    }

    fn store_rar(inner: &[u8]) -> Vec<u8> {
        fixtures::rar5_volume(&[("film.mkv", inner.len() as u64, inner, false, false)])
    }

    fn part_name(i: usize) -> String {
        format!("stage.rar.{:03}", i + 1)
    }

    /// Feed a declared split in the given part order; returns the
    /// extractor and its report.
    fn run_split(tag: &str, inner: &[u8], n: usize, order: &[usize]) -> (PathBuf, ExtractReport) {
        let dir = tmpdir(tag);
        let parts = split_parts(&store_rar(inner), n);
        let ex = Extractor::new(&dir, n, true);
        ex.declare_rar_split("stage.rar", n as u32);
        for &i in order {
            feed(&ex, i, &part_name(i), &parts[i], 7000, 31 + i as u64);
        }
        let rep = ex.finish().unwrap();
        (dir, rep)
    }

    /// The field shape: part 1 heads, parts 2..n are headless, every
    /// byte of the member lands in the output and NO part touches
    /// disk - the whole point of (b) over (a).
    #[test]
    fn declared_split_maps_one_pass_in_order() {
        let inner = payload(600_000, 3);
        let (dir, rep) = run_split("rarsplit-inorder", &inner, 4, &[0, 1, 2, 3]);
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), inner);
        for i in 0..4 {
            assert!(
                !dir.join(part_name(i)).exists(),
                "{} materialized",
                part_name(i)
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Parts arriving ahead of the head park as pending Unknown slots
    /// and attach when it maps; a continuation that sniffed first must
    /// never have classified Plain.
    #[test]
    fn declared_split_maps_one_pass_head_last() {
        let inner = payload(500_000, 9);
        let (dir, rep) = run_split("rarsplit-headlast", &inner, 4, &[3, 2, 1, 0]);
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), inner);
        for i in 0..4 {
            assert!(
                !dir.join(part_name(i)).exists(),
                "{} materialized",
                part_name(i)
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The live verifier reads each POSTED part back by its own slot
    /// and offsets; every byte of every part must come back exactly,
    /// headers, seams and tail included, while nothing is on disk.
    #[test]
    fn split_parts_read_back_byte_exact_through_the_head() {
        let dir = tmpdir("rarsplit-readback");
        let inner = payload(400_000, 5);
        let parts = split_parts(&store_rar(&inner), 3);
        let ex = Extractor::new(&dir, 3, true);
        ex.declare_rar_split("stage.rar", 3);
        for i in [1, 0, 2] {
            feed(&ex, i, &part_name(i), &parts[i], 5000, 41 + i as u64);
        }
        for (i, p) in parts.iter().enumerate() {
            assert!(ex.covered(i, 0, p.len()), "part {i} not fully covered");
            let mut back = vec![0u8; p.len()];
            ex.read_at(i, 0, &mut back).unwrap();
            assert_eq!(back, *p, "part {i} read-back differs");
            // A window across the seam into the next part is still the
            // part's own bytes only.
            let mut tail = vec![0u8; 100];
            ex.read_at(i, p.len() as u64 - 100, &mut tail).unwrap();
            assert_eq!(tail, p[p.len() - 100..]);
            assert_eq!(
                ex.covered_intervals(i, 0, p.len() as u64),
                vec![(0, p.len() as u64)]
            );
        }
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), inner);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// §272: the ADMISSION question in front of the read-back above.
    /// `get::settle` serves a slot's still-Pending PAR2 blocks through
    /// `read_at` only when `is_mapped` (or `is_chased`) says so, and
    /// otherwise reads them back from `slot_path`. An aliased part has
    /// no path, so the byte-exact read-back the test above pins was
    /// never reached: every Pending block on parts 2..n read back
    /// against a file that does not exist and settled BAD, failing a
    /// download whose bytes were perfect. How many blocks are still
    /// Pending at settle is load-dependent, so this surfaced as a
    /// ~10%-under-load flake in the `e2e_split` one-pass leg rather
    /// than as a red test.
    ///
    /// The head has always answered yes; parts 2..n are the regression.
    #[test]
    fn split_parts_admit_as_mapped_so_settle_reads_them_back() {
        let dir = tmpdir("rarsplit-ismapped");
        let inner = payload(400_000, 5);
        let parts = split_parts(&store_rar(&inner), 3);
        let ex = Extractor::new(&dir, 3, true);
        ex.declare_rar_split("stage.rar", 3);
        for i in [1, 0, 2] {
            feed(&ex, i, &part_name(i), &parts[i], 5000, 41 + i as u64);
        }
        for i in 0..3 {
            assert!(
                ex.is_mapped(i),
                "part {i} must admit as mapped - it owns no file for a \
                 read-back to fall back to"
            );
            assert!(
                ex.slot_path(i).is_none(),
                "part {i} owns a file after all; the premise above moved"
            );
        }
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), inner);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A set whose parts are not a uniform byte split refuses, and the
    /// demote must leave the N POSTED PART FILES on disk byte for byte -
    /// what PAR2 and the (a) rescue expect - never a joined container.
    #[test]
    fn misaligned_split_demotes_to_its_posted_parts() {
        let dir = tmpdir("rarsplit-misaligned");
        let inner = payload(300_000, 11);
        let arch = store_rar(&inner);
        // Three parts, the MIDDLE one short: not what any splitter does.
        // The last part stays under the pitch so the only misalignment
        // is part 2's, and part 3 has ATTACHED by the time part 2
        // reports (it is fed whole first) - so this is the alias path
        // of the demote, where the head's reconstruction must route
        // every logical range back to the part file it came from.
        let cut1 = arch.len() / 3 + 400;
        let cut2 = 2 * cut1 - 1000;
        assert!(arch.len() - cut2 < cut1);
        let parts = [
            arch[..cut1].to_vec(),
            arch[cut1..cut2].to_vec(),
            arch[cut2..].to_vec(),
        ];
        let ex = Extractor::new(&dir, 3, true);
        ex.declare_rar_split("stage.rar", 3);
        for i in [0, 2, 1] {
            feed(&ex, i, &part_name(i), &parts[i], 4000, 51 + i as u64);
        }
        let rep = ex.finish().unwrap();
        // The reason is whichever trips first: part 3's bytes sit at a
        // seam the set does not have, so the head's parse can refuse
        // them as a corrupt block before part 2 ever reports its size
        // (and names the misalignment). Either way it is a demote, and
        // the property under test is what the demote leaves on disk.
        assert!(!rep.fallbacks.is_empty(), "the set must demote");
        for (i, p) in parts.iter().enumerate() {
            assert_eq!(
                std::fs::read(dir.join(part_name(i))).unwrap(),
                *p,
                "{} must materialize exactly as posted",
                part_name(i)
            );
        }
        assert!(
            !dir.join("film.mkv").exists(),
            "a demoted set ships no payload"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A declared set with a part the NZB promised but the wire never
    /// delivered is the caller's repair problem, as for any volume: the
    /// head's mapper completes off the end block in the last part, the
    /// output has a hole where the part's bytes go, and a whole-part
    /// `write_repair` (parity as a source) attaches that slot late and
    /// fills the hole through the alias - still one-pass.
    #[test]
    fn split_missing_part_is_healed_by_a_whole_part_repair() {
        let dir = tmpdir("rarsplit-missing");
        let inner = payload(300_000, 13);
        let parts = split_parts(&store_rar(&inner), 3);
        let ex = Extractor::new(&dir, 3, true);
        ex.declare_rar_split("stage.rar", 3);
        for i in [0, 2] {
            feed(&ex, i, &part_name(i), &parts[i], 4000, 61 + i as u64);
        }
        assert!(
            !ex.covered(1, 0, parts[1].len()),
            "the missing part must read as uncovered"
        );
        ex.write_repair(1, &part_name(1), parts[1].len() as u64, 0, &parts[1])
            .unwrap();
        assert!(
            ex.covered(1, 0, parts[1].len()),
            "the repair filled the hole"
        );
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), inner);
        for i in 0..3 {
            assert!(
                !dir.join(part_name(i)).exists(),
                "{} materialized",
                part_name(i)
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A continuation part SPILLED to disk before its offset-0 sniff (so
    /// it never entered `pending`) has its bytes in a file of its own;
    /// the head that maps afterwards must not run open-ended with a
    /// hole where that part's bytes go. The set refuses, the head maps
    /// as an ordinary volume and demotes at the bounds guard, and every
    /// part is on disk exactly as posted. Measured: with the
    /// `split_slot_plain` hook removed from the spill site, the head
    /// maps open-ended and ships a 27 MB `film.mkv` with a 9 MB hole.
    #[test]
    fn part_spilled_before_its_sniff_refuses_the_split() {
        let dir = tmpdir("rarsplit-overflow");
        // 27 MB so one part is 9 MB: the per-slot pre-sniff spill fires
        // at 4 MB (a quarter of the 8 MB cap floor) and, with paging off,
        // no head grace holds it back - part 2 goes Plain with most of
        // its bytes still to arrive.
        let inner = payload(27_000_000, 23);
        let parts = split_parts(&store_rar(&inner), 3);
        let ex = Extractor::new(&dir, 3, true);
        ex.declare_rar_split("stage.rar", 3);
        ex.set_holds_cap(1);
        ex.set_holds_paging(false);
        let p2 = &parts[1];
        let art = 65536usize;
        let mut i = art; // everything but offset 0 first
        while i < p2.len() {
            let e = (i + art).min(p2.len());
            ex.write(1, &part_name(1), p2.len() as u64, i as u64, &p2[i..e])
                .unwrap();
            i = e;
        }
        ex.write(1, &part_name(1), p2.len() as u64, 0, &p2[..art])
            .unwrap();
        assert!(
            dir.join(part_name(1)).exists(),
            "the fixture did not spill part 2 to disk"
        );
        // The head's offset 0 first, so it sniffs and maps before its own
        // pre-sniff holds could breach the same cap: the refusal is what
        // must put it on the ordinary-volume road, not a second overflow.
        let p1 = &parts[0];
        ex.write(0, &part_name(0), p1.len() as u64, 0, &p1[..art])
            .unwrap();
        for i in [0, 2] {
            feed(&ex, i, &part_name(i), &parts[i], 65536, 91 + i as u64);
        }
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, why)| why.contains("data area exceeds volume")),
            "the refused head must map as a volume and refuse at the bounds guard: {:?}",
            rep.fallbacks
        );
        for (i, p) in parts.iter().enumerate() {
            assert_eq!(
                std::fs::read(dir.join(part_name(i))).unwrap(),
                *p,
                "{} must be on disk exactly as posted",
                part_name(i)
            );
        }
        assert!(
            !dir.join("film.mkv").exists(),
            "nothing maps with a hole in it"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An undeclared `.rar.001` set is untouched: part 1 maps as its own
    /// volume, refuses at the bounds guard, and the parts land on disk
    /// for the (a) rescue - the pre-(b) behaviour, and the `NZBFAST_NO_
    /// RAR_SPLIT` behaviour too.
    #[test]
    fn undeclared_split_takes_the_disk_path() {
        let dir = tmpdir("rarsplit-undeclared");
        let inner = payload(200_000, 17);
        let parts = split_parts(&store_rar(&inner), 2);
        let ex = Extractor::new(&dir, 2, true);
        for i in [0, 1] {
            feed(&ex, i, &part_name(i), &parts[i], 4000, 71 + i as u64);
        }
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, why)| why.contains("data area exceeds volume")),
            "{:?}",
            rep.fallbacks
        );
        for (i, p) in parts.iter().enumerate() {
            assert_eq!(std::fs::read(dir.join(part_name(i))).unwrap(), *p);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A genuine volume set in a `.rar.NNN` costume: part 2 carries RAR
    /// magic, so it is a volume, not a continuation. The declaration is
    /// refused and both volumes map as the multi-volume set they are.
    #[test]
    fn signed_part_two_refuses_the_split_and_maps_as_volumes() {
        let dir = tmpdir("rarsplit-signed");
        let total = payload(400_000, 19);
        let vols = [
            fixtures::rar5_volume_n(&[("film.mkv", 400_000, &total[..200_000], false, true)], 0),
            fixtures::rar5_volume_n(&[("film.mkv", 400_000, &total[200_000..], true, false)], 1),
        ];
        let ex = Extractor::new(&dir, 2, true);
        ex.declare_rar_split("stage.rar", 2);
        for i in [0, 1] {
            feed(&ex, i, &part_name(i), &vols[i], 6000, 81 + i as u64);
        }
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rar_split_part_name_grammar() {
        assert_eq!(
            rar_split_part_name("Stage.RAR.001"),
            Some(("stage.rar".to_string(), 1))
        );
        assert_eq!(
            rar_split_part_name("a.b.rar.0042"),
            Some(("a.b.rar".to_string(), 42))
        );
        for n in [
            "stage.rar",
            "stage.r00",
            "stage.part1.rar",
            "stage.rar.1",
            "stage.rar.12",
            "stage.rar.12345",
            "stage.rar.000",
            "stage.7z.001",
            "stage.zip.001",
            "movie.001",
            "stage.rar.abc",
        ] {
            assert!(rar_split_part_name(n).is_none(), "{n}");
        }
    }

    #[test]
    fn split_total_and_alignment() {
        let mut s = RarSplit::new(3);
        assert_eq!(s.total(), None);
        s.sizes.insert(1, 100);
        s.part_size = 100;
        s.sizes.insert(2, 100);
        assert!(s.aligned());
        assert_eq!(s.total(), None);
        s.sizes.insert(3, 40);
        assert!(s.aligned());
        assert_eq!(s.total(), Some(240));
        assert_eq!(s.delta(1), 0);
        assert_eq!(s.delta(3), 200);
        // A middle part of the wrong size is not a byte split.
        s.sizes.insert(2, 99);
        assert!(!s.aligned());
        // A last part longer than the pitch is not either.
        s.sizes.insert(2, 100);
        s.sizes.insert(3, 101);
        assert!(!s.aligned());
    }
}
