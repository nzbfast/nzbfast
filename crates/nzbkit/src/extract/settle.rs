//! Group settlement and the fallback ladder: split-name linking,
//! group merges and re-resolution, the slot/group demotion paths
//! that reconstruct materialized volumes, the composed-CRC runs,
//! and the finish-time inner-CRC verify gate.
//!
//! Split out of the 19,920-line `extract.rs` under the TODO 43
//! recipe: a verbatim move, not a redesign.

use super::*;
use crate::sync::MutexExt;

/// Out-of-order CRC32 accumulator over one mapped store piece's data
/// area: disjoint (start → len, crc) runs that coalesce through
/// `crc32_combine` as gaps fill. Re-fed spans (hold drains, fallback-race
/// re-routes) clip to the not-yet-seen sub-ranges - routing is
/// deterministic, so a duplicate span carries identical bytes and
/// first-writer-wins is exact. The one writer that carries DIFFERENT
/// bytes for a range already seen is mapped PAR2 repair; it enters
/// through [`Self::overwrite`], which replaces the overlapped sub-range
/// instead of clipping.
#[derive(Default)]
pub(super) struct CrcRuns {
    pub(super) runs: BTreeMap<u64, (u64, u32)>,
    /// Sub-ranges whose composed CRC an `overwrite` had to discard: a
    /// repair span landing mid-run invalidates the whole run, and the
    /// parts outside the span cannot be split back out of the composed
    /// value (that value is entangled with the discarded damaged
    /// bytes). They become gaps to recompute from the routed bytes on
    /// disk at verify time - see [`Self::take_stale_gaps`].
    pub(super) stale: Vec<(u64, u64)>,
}

impl CrcRuns {
    pub(super) fn add(&mut self, off: u64, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let end = off + data.len() as u64;
        // Sub-ranges of [off, end) no existing run covers.
        let mut fresh: Vec<(u64, u64)> = Vec::new();
        let mut cur = off;
        for (&s, &(l, _)) in self.runs.range(..end) {
            let e = s + l;
            if e <= cur {
                continue;
            }
            if s > cur {
                fresh.push((cur, s.min(end)));
            }
            cur = cur.max(e);
            if cur >= end {
                break;
            }
        }
        if cur < end {
            fresh.push((cur, end));
        }
        if fresh.is_empty() {
            return;
        }
        for &(s, e) in &fresh {
            let part = &data[(s - off) as usize..(e - off) as usize];
            self.runs.insert(s, (e - s, crc32fast::hash(part)));
        }
        for &(s, _) in &fresh {
            self.coalesce_at(s);
        }
    }

    /// Repair rewrite (mapped PAR2, via patch_volume_span): replace
    /// `[off, off+data.len())` with the rebuilt bytes' CRC. Plain `add`
    /// clips to unseen sub-ranges - correct for every duplicate-bytes
    /// re-feed, but across a repair it would keep the STALE wire-damage
    /// CRC while the file on disk heals, and the finish gate would then
    /// demote a job that one-passed cleanly. Overlapped runs are
    /// removed first; their sub-ranges outside the span move to
    /// `stale`.
    pub(super) fn overwrite(&mut self, off: u64, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let end = off + data.len() as u64;
        let hit: Vec<u64> = self
            .runs
            .range(..end)
            .filter(|&(&s, &(l, _))| s + l > off)
            .map(|(&s, _)| s)
            .collect();
        for s in hit {
            let (l, _) = self.runs.remove(&s).expect("run key just enumerated");
            if s < off {
                self.stale.push((s, off));
            }
            if s + l > end {
                self.stale.push((end, s + l));
            }
        }
        // A pure gap-fill now.
        self.add(off, data);
    }

    /// Drain the stale list into the disjoint sub-ranges still uncovered
    /// by runs (a later add() may have re-covered part of a stale range
    /// with re-fed bytes - those ARE the current disk bytes and need no
    /// recomputation). The caller recomputes each gap from the routed
    /// bytes and feeds it back through [`Self::add_run`]; a gap it
    /// cannot read simply stays a gap, and the piece reads as
    /// unverifiable (skip - today's assurance level).
    pub(super) fn take_stale_gaps(&mut self) -> Vec<(u64, u64)> {
        let mut stale = std::mem::take(&mut self.stale);
        stale.sort_unstable();
        let mut out: Vec<(u64, u64)> = Vec::new();
        for (s, e) in stale {
            // Merge overlap with the previously emitted range (the list
            // can hold overlapping entries after repeated overwrites).
            let s = match out.last() {
                Some(&(_, pe)) if s < pe => pe,
                _ => s,
            };
            let mut cur = s;
            for (&rs, &(rl, _)) in self.runs.range(..e) {
                let re = rs + rl;
                if re <= cur {
                    continue;
                }
                if rs > cur {
                    out.push((cur, rs.min(e)));
                }
                cur = cur.max(re);
                if cur >= e {
                    break;
                }
            }
            if cur < e {
                out.push((cur, e));
            }
        }
        out
    }

    /// Insert a precomputed run (verify-time recompute of a stale gap;
    /// the caller hashed the bytes incrementally, so they never
    /// materialize here). Gap-fill only: `take_stale_gaps` returns
    /// ranges disjoint from the runs, and anything else is a caller bug
    /// that must not corrupt the composition - overlaps are dropped.
    /// Returns whether the run was taken. A caller holding the bytes (the
    /// verified-article-CRC fast path) must hash and use [`Self::add`] on
    /// false, or the overlapped range silently loses coverage and the
    /// piece never composes - a clean job demoted for want of a CRC.
    #[must_use = "a refused run means the range is still uncovered; hash it and use add()"]
    pub(super) fn add_run(&mut self, off: u64, len: u64, crc: u32) -> bool {
        if len == 0 {
            return false;
        }
        let end = off + len;
        if self.runs.range(..end).any(|(&s, &(l, _))| s + l > off) {
            return false;
        }
        self.runs.insert(off, (len, crc));
        self.coalesce_at(off);
        true
    }

    /// Merge the run starting at `s` with the neighbours it now touches
    /// (b starts exactly where a ends), looking only at those neighbours.
    ///
    /// The whole-map rebuild this replaces ran once per `add`, which under
    /// out-of-order article arrival is once per article: a 100 MiB volume
    /// completing out of order holds many disjoint runs, so ~150 rebuilds
    /// each allocated a fresh `BTreeMap` and walked every run - and did it
    /// while the routing lock was held. Only the inserted run's immediate
    /// neighbours can newly touch, so this is O(log n + merged) instead.
    ///
    /// A no-op when `s` is absent: `add` inserts several fresh runs and
    /// coalesces each, and an earlier merge may already have absorbed a
    /// later one.
    pub(super) fn coalesce_at(&mut self, s: u64) {
        if !self.runs.contains_key(&s) {
            return;
        }
        // Fold into the predecessor when it ends exactly here, so the
        // surviving key is the earliest of the merged chain.
        let mut start = s;
        if let Some((&ps, &(pl, pc))) = self.runs.range(..s).next_back()
            && ps + pl == s
        {
            let (l, c) = self.runs.remove(&s).expect("key checked above");
            self.runs
                .insert(ps, (pl + l, crate::yenc_simd::crc32_combine(pc, c, l)));
            start = ps;
        }
        // Absorb successors while they touch.
        while let Some(&(l, c)) = self.runs.get(&start) {
            let Some((&ns, &(nl, nc))) = self.runs.range(start + 1..).next() else {
                break;
            };
            if ns != start + l {
                break;
            }
            self.runs.remove(&ns);
            self.runs
                .insert(start, (l + nl, crate::yenc_simd::crc32_combine(c, nc, nl)));
        }
    }

    /// The CRC32 of [0, len) once every byte has been seen; None while
    /// gaps remain.
    pub(super) fn whole(&self, len: u64) -> Option<u32> {
        match self.runs.iter().next() {
            Some((&0, &(l, c))) if l == len && self.runs.len() == 1 => Some(c),
            _ => None,
        }
    }
}

impl Extractor {
    /// Whole-archive linking. A volume that carries a SPLIT piece of an
    /// inner file proves that file's chain runs through this archive - so
    /// its name belongs to this slot's group, and a group that formed
    /// under that name (the continuation volumes of a multi-file set,
    /// which group by THEIR first entry) is the same archive: merge it.
    /// Without this, a store set holding more than one file splits into a
    /// new group at every file boundary; the continuation group can never
    /// base-resolve, falls back at finish(), and deleted the shared inner
    /// file - silent whole-file loss on a season-pack layout.
    ///
    /// Only split names link: a wholly-contained file (e.g. `sample.mkv`
    /// present in two different archives) is no evidence of shared
    /// identity and must NOT merge two archives.
    pub(super) fn link_split_names(&self, inner: &mut Inner, slot: usize) -> io::Result<()> {
        let Some(my_raw) = inner.slots[slot].group.clone() else {
            return Ok(());
        };
        let my_key = Self::canon_key(inner, &my_raw);
        let names: Vec<String> = match inner.slots[slot].mapper.as_ref() {
            Some(m) => m
                .entries
                .iter()
                .filter(|e| !e.is_dir && (e.split_before || e.split_after))
                .map(|e| e.name.clone())
                .collect(),
            None => Vec::new(),
        };
        for n in names {
            let other = Self::canon_key(inner, &n);
            if other == my_key {
                continue;
            }
            inner.alias.insert(n, my_key.clone());
            if inner.groups.contains_key(&other) {
                self.merge_groups(inner, &my_key, &other)?;
            }
        }
        Ok(())
    }

    /// Merge group `from` into group `into` (one archive, one group, one
    /// fate). Aliases are flattened so future lookups land on `into`.
    pub(super) fn merge_groups(&self, inner: &mut Inner, into: &str, from: &str) -> io::Result<()> {
        if into == from || !inner.groups.contains_key(into) {
            return Ok(());
        }
        let Some(old) = inner.groups.remove(from) else {
            return Ok(());
        };
        for v in inner.alias.values_mut() {
            if v == from {
                *v = into.to_string();
            }
        }
        inner.alias.insert(from.to_string(), into.to_string());
        for &si in &old.slots {
            inner.slots[si].group = Some(into.to_string());
        }
        let into_was_fallback = inner.groups[into].fallback;
        let mut displaced: Vec<usize> = Vec::new();
        {
            let g = inner.groups.get_mut(into).unwrap();
            g.slots.extend(old.slots.iter().copied());
            // Bases carry over so a fallback right after the merge can
            // still read back what the moved slots already extracted;
            // reresolve rebuilds them anyway on the next progress.
            g.bases.extend(old.bases);
            // Arithmetic exposure travels with the slots: bytes the
            // moved group placed under the uniform premise still need
            // confirming - or demoting - in the merged group.
            g.arith_provisional.extend(old.arith_provisional);
            g.arith_ever |= old.arith_ever;
            for (k, v) in old.out_names {
                g.out_names.entry(k).or_insert(v);
            }
            // Same for routed child slots; when both groups had already
            // routed the same inner name (they were one archive all
            // along), the loser's partial child slot is abandoned so no
            // stray half-file survives the merge.
            // Promotions do not survive a merge: the winning route may
            // differ, and repromotion after the next delivery is cheap.
            g.routed_plain.clear();
            for (k, v) in old.routed {
                match g.routed.entry(k) {
                    std::collections::hash_map::Entry::Occupied(_) => displaced.push(v),
                    std::collections::hash_map::Entry::Vacant(e) => {
                        e.insert(v);
                    }
                }
            }
        }
        if let Some(c) = inner.child.clone() {
            for cs in displaced {
                c.abandon_slot(cs);
            }
        }
        if old.fallback && !into_was_fallback {
            let why = old
                .fallback_reason
                .clone()
                .unwrap_or_else(|| "merged into fallen-back group".to_string());
            self.fallback_group(inner, into, &why)?;
        } else if into_was_fallback {
            // The moved slots join the fallback: materialize them, then
            // drop their partial inner files (same contract as
            // fallback_group - the bytes now live in the volumes).
            for si in old.slots {
                self.fallback_slot(inner, si)?;
            }
            Self::delete_group_out_files(inner, into);
        } else {
            self.reresolve(inner, into)?;
        }
        Ok(())
    }

    /// Recompute volume order + split bases for a group; drain any holds
    /// that became mappable.
    ///
    /// Split-continuation bases are only valid over a GAPLESS run of
    /// volumes: resolving `part3` while `part2` is unparsed would assign
    /// part3's piece to part2's offsets. Volume indexes come from RAR5
    /// volume numbers when every member has one, else from the volume
    /// naming (.partNN / .rar,.rNN); resolution walks the sorted list only
    /// while the indexes stay consecutive.
    pub(super) fn reresolve(&self, inner: &mut Inner, key: &str) -> io::Result<()> {
        // A fallen-back group has nothing left to resolve: every slot is
        // materialized (drain below would no-op) and recomputing bases
        // would only churn the arithmetic gate against a dead group.
        if inner.groups[key].fallback {
            return Ok(());
        }
        let slots = inner.groups[key].slots.clone();
        // Order and bases are pure functions of the slot set, which
        // mappers carry volume numbers, and how many entries have parsed;
        // when none of that moved since the last recompute (this fires on
        // every parse progression, roughly twice per volume), only the
        // held-span re-feed below still has work to do.
        let mut numbered = 0usize;
        let mut total_entries = 0u64;
        for &si in &slots {
            if let Some(m) = inner.slots[si].mapper.as_ref() {
                if m.volume_number.is_some() {
                    numbered += 1;
                }
                total_entries += m.entries.len() as u64;
            }
        }
        let stamp = (slots.len(), numbered, total_entries);
        if inner.groups[key].resolve_stamp != Some(stamp) {
            // Either contradiction demotes, and the reason distinguishes
            // them: an arithmetic placement the chain has now disproved,
            // or headers that disagree with THEMSELVES about where a
            // piece sits. `group.bases` still holds the offsets any
            // written bytes went to, which is exactly what the fallback
            // read-back reconstructs the volumes through.
            if let Some(why) = self.reresolve_recompute(inner, key, &slots, stamp) {
                return self.fallback_group(inner, key, why);
            }
            // §94 D: the entry list just advanced - a nested zip split
            // this group routed may now have a non-sibling entry (and no
            // unparsed gap) behind its run, which is what counts it.
            // A no-op lookup on a group with no open set.
            self.close_zip_splits(inner, key);
        }

        for si in slots {
            if inner.slots[si].mode == SlotMode::Rar
                && (!inner.slots[si].holds.is_empty() || inner.slots[si].pre_bytes != 0)
            {
                // Full re-feed, not just re-extraction: a held span may
                // carry block-HEADER bytes that arrived while the parse
                // window was elsewhere (the mapper's stash only keeps
                // bytes near its cursor) - without re-feeding, mapping
                // stalls and a healthy group needlessly falls back.
                self.drain_holds(inner, si)?;
            }
        }
        Ok(())
    }

    /// The recompute half of [`Self::reresolve`]: arithmetic placement
    /// first (uniform single-file store sets are placeable under any
    /// arrival order), else sort the volumes, find the consecutive
    /// prefix, resolve split bases across it.
    ///
    /// Returns the demote reason when the group must fall back, or None.
    /// (The caller demotes; this half only computes.)
    ///
    /// One invariant carries the whole safety argument: a base that was
    /// EXPOSED - installed in `group.bases`, where a span may have been
    /// written through it - never changes value and never disappears
    /// while the group can still demote. Arithmetic values inside the
    /// consecutive-from-0 volume run equal what chain resolution derives
    /// (uniform `data_len` makes both `volnum * data_len`), so switching
    /// between the two modes never moves an exposed base; placements
    /// BEYOND the run are tracked in `arith_provisional` until the chain
    /// confirms them, the closed set proves them (settle), or a
    /// contradiction demotes the group with the bases still intact for
    /// read-back.
    pub(super) fn reresolve_recompute(
        &self,
        inner: &mut Inner,
        key: &str,
        slots: &[usize],
        stamp: (usize, usize, u64),
    ) -> Option<&'static str> {
        // Arithmetic mode: every group slot has parsed entries (group
        // membership starts at first-entry parse), so `slots` IS the
        // parsed set; the gate re-checks the full premise on every
        // recompute as volumes arrive.
        let gate = {
            let mappers: Vec<&VolumeMapper> = slots
                .iter()
                .filter_map(|&si| inner.slots[si].mapper.as_ref())
                .filter(|m| !m.entries.is_empty())
                .collect();
            if mappers.len() == slots.len() {
                ArchiveMap::resolve_arithmetic(&mappers)
            } else {
                ArithGate::Shape
            }
        };
        match gate {
            ArithGate::Place { bases, .. } => {
                // Pieces inside the consecutive-from-0 volume run carry
                // the same base the chain would derive; only pieces
                // beyond it rest on the (unconfirmed) uniform premise.
                let vols: Vec<u64> = slots
                    .iter()
                    .map(|&si| {
                        inner.slots[si]
                            .mapper
                            .as_ref()
                            .unwrap()
                            .volume_number
                            .unwrap()
                    })
                    .collect();
                let mut sorted = vols.clone();
                sorted.sort_unstable();
                let mut run_end = 0u64;
                for v in sorted {
                    if v == run_end {
                        run_end += 1;
                    } else {
                        break;
                    }
                }
                let mut new_bases = HashMap::new();
                let mut provisional = HashMap::new();
                for (i, &si) in slots.iter().enumerate() {
                    // The gate guarantees exactly one entry per volume.
                    new_bases.insert((si, 0), bases[i]);
                    if vols[i] >= run_end {
                        provisional.insert((si, 0), bases[i]);
                    }
                }
                let group = inner.groups.get_mut(key).unwrap();
                group.bases = new_bases;
                group.arith_ever |= !provisional.is_empty();
                group.arith_provisional = provisional;
                group.resolve_stamp = Some(stamp);
                return None;
            }
            // The set looked uniform single-file, bytes were placed on
            // that premise, and the numbers now contradict it: those
            // placements are suspect and nothing can confirm them.
            // Demote whole (never a partial mix of placements) - the
            // volumes hold the truth and unrar takes over. With no
            // provisional placements the premise never mattered: fall
            // through to the chain, today's behavior.
            ArithGate::Numbers if !inner.groups[key].arith_provisional.is_empty() => {
                return Some("non-uniform store set");
            }
            ArithGate::Numbers | ArithGate::Shape => {}
        }
        let all_numbered = stamp.1 == slots.len();
        let mut keyed: Vec<(Option<u64>, (u64, &str), usize)> = slots
            .iter()
            .map(|&si| {
                if inner.slots[si].sort_key.is_none() {
                    let computed = vol_sort_key(&inner.slots[si].name);
                    inner.slots[si].sort_key = Some(computed);
                }
                (
                    si,
                    inner.slots[si]
                        .mapper
                        .as_ref()
                        .and_then(|m| m.volume_number),
                )
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|(si, volume_number)| {
                let (num, lower) = inner.slots[si].sort_key.as_ref().unwrap();
                let idx = if all_numbered {
                    volume_number
                } else if *num != u64::MAX {
                    Some(*num)
                } else {
                    None
                };
                (idx, (*num, lower.as_str()), si)
            })
            .collect();
        keyed.sort();

        // EVERY volume that has an index, not just a consecutive run
        // from the first one. Resolution decides adjacency per
        // neighbouring pair, so an island of volumes away from volume 0
        // now resolves on its own - which is what lets a season pack's
        // later episodes place before its opening volumes have arrived.
        // Slots with no index (unnumbered, dotless RAR4) still place
        // their file-STARTING pieces: `base_for` answers 0 for those
        // without consulting this map at all.
        let placed: Vec<usize> = keyed
            .iter()
            .filter_map(|(i, _, si)| i.map(|_| *si))
            .collect();
        let indexed: Vec<(u64, &VolumeMapper)> = keyed
            .iter()
            .filter_map(|(i, _, si)| i.map(|idx| (idx, inner.slots[*si].mapper.as_ref().unwrap())))
            .collect();
        let resolved = ArchiveMap::resolve_indexed(&indexed);
        let chain_contradiction = resolved.contradiction;
        let mut bases = HashMap::new();
        for ((vi, ei), b) in resolved.bases {
            bases.insert((placed[vi], ei), b);
        }
        let group = inner.groups.get_mut(key).unwrap();
        // Arithmetic afterlife: earlier arithmetic placements the chain
        // has now independently derived are confirmed; a differing chain
        // value contradicts them (demote - and keep the WRITTEN base in
        // `bases` so fallback read-back stays byte-exact); the rest stay
        // provisional, their exposed base preserved, until the chain
        // reaches them or settle rules on the leftovers.
        let mut contradicted = false;
        group.arith_provisional.retain(|k, pv| match bases.get(k) {
            Some(cv) if cv == pv => false,
            Some(_) => {
                contradicted = true;
                true
            }
            None => true,
        });
        for (k, pv) in &group.arith_provisional {
            bases.insert(*k, *pv);
        }
        group.bases = bases;
        group.resolve_stamp = Some(stamp);
        if contradicted {
            return Some("non-uniform store set");
        }
        if chain_contradiction {
            // A piece was reachable from both neighbours and the two
            // answers differed: the headers cannot all be true, so no
            // offset here is trustworthy.
            return Some("inconsistent volume chain");
        }
        None
    }

    /// Parent-group fallback support: this routed slot's bytes were (or
    /// will be) reconstructed into the parent's materialized volumes, so
    /// drop everything it produced - holds, its own file, and the group
    /// outputs once every member slot is abandoned - and swallow all
    /// future spans. Silent by design: the parent already reported the
    /// fallback, a child-side entry would double-count it.
    pub(super) fn abandon_slot(&self, slot: usize) {
        let mut g = self.inner.lock_ok();
        let inner = &mut *g;
        if matches!(inner.slots[slot].mode, SlotMode::Discard) {
            return;
        }
        let holds = std::mem::take(&mut inner.slots[slot].holds);
        for (_, span) in &holds {
            Self::uncharge_span(inner, span);
        }
        inner.slots[slot].pre_bytes = 0;
        let headers = std::mem::take(&mut inner.slots[slot].header_spans);
        for (_, span) in &headers {
            Self::uncharge_span(inner, span);
        }
        inner.slots[slot].piece_crcs = HashMap::new();
        if let Some(ch) = inner.slots[slot].chase.take() {
            inner.budget.sub(ch.charged);
            ch.buf.abort("slot abandoned");
        }
        // An abandoned 7z chase dies with the slot: buffer already
        // aborted above (the worker exits on its next read), and its
        // partial sink outputs go too. The sink-open path re-checks the
        // slot's mode under this lock, so no NEW sink can appear after.
        // The ctl stays in the slot so sevenz_finish / Drop still find
        // and join the worker.
        if let Some(ctl) = inner.slots[slot].sevenz.clone() {
            self.sevenz_abandon_sinks(inner, &ctl);
        }
        // No mapper means finish() sees neither holds nor an incomplete
        // parse here - an abandoned slot must not read as a fallback.
        inner.slots[slot].mapper = None;
        if let Some(w) = inner.slots[slot].writer.take() {
            // The writer leaves the slot here, so nothing downstream can
            // reach it - not finish(), and not
            // `park_outputs_for_repair`'s walk. A live /stream response
            // still holds its own Arc and would park on this frontier
            // for ever; `abandon` is the only thing that ever tells it
            // otherwise (see [`FileWriter::abandon`]).
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
        inner.slots[slot].mode = SlotMode::Discard;
        if let Some(key) = inner.slots[slot].group.clone() {
            let all_gone = inner.groups.get(&key).is_some_and(|g| {
                g.slots
                    .iter()
                    .all(|&si| matches!(inner.slots[si].mode, SlotMode::Discard))
            });
            if all_gone {
                // The group's chase (if any) dies with its last slot -
                // the worker stops, partial sink outputs go too.
                if let Some(ctl) = inner.groups.get(&key).and_then(|g| g.chase.clone()) {
                    self.chase_teardown(inner, &ctl, "group abandoned");
                }
                Self::delete_group_out_files(inner, &key);
            }
        }
    }

    /// Is this slot a volume the offset-0 sniff started INSIDE a
    /// self-extractor's launcher stub (TODO 94 C)? The mapper's archive
    /// base is the stub's length, and it is the one durable tell: it
    /// survives a re-key, and unlike the slot's name it cannot be
    /// spoofed by an ordinary `.exe` that was never mapped at all.
    fn slot_is_sfx(inner: &Inner, slot: usize) -> bool {
        inner.slots[slot]
            .mapper
            .as_ref()
            .is_some_and(|m| m.archive_base() > 0)
    }

    /// Mark a demote the get tail's SFX arm owns - see
    /// [`SFX_DISK_FALLBACK_PREFIX`] for what goes wrong unmarked. Idempotent,
    /// so a group that demotes and is then merged into another keeps one
    /// prefix rather than a stack of them.
    fn mark_sfx_demote(is_sfx: bool, reason: &str) -> String {
        if is_sfx && !reason.starts_with(SFX_DISK_FALLBACK_PREFIX) {
            format!("{SFX_DISK_FALLBACK_PREFIX}{reason}")
        } else {
            reason.to_string()
        }
    }

    pub(super) fn fallback_slot_or_group(
        &self,
        inner: &mut Inner,
        slot: usize,
        reason: &str,
    ) -> io::Result<()> {
        match inner.slots[slot].group.clone() {
            Some(key) => self.fallback_group(inner, &key, reason),
            None => {
                if !matches!(
                    inner.slots[slot].mode,
                    SlotMode::RarFallback | SlotMode::Discard
                ) {
                    // Phase 0(b): a group-less nested inner demotes here (a
                    // 7z - always slot-level - or a RAR that blocked before
                    // forming a group). Emit the `demoted` diagnostic with
                    // the reason BEFORE fallback_slot flips the mode to
                    // RarFallback; the archive itself is tallied under
                    // `disk` when the post-pass re-extracts the materialized
                    // volume, so this is never double-counted. `slot_inner_kind`
                    // returns None for a plain/unclassified slot, so a
                    // demoting non-archive stays silent (no tally bias).
                    if self.depth > 0
                        && let Some(kind) = Self::slot_inner_kind(inner, slot)
                    {
                        note_nested_level(self.depth, kind, NestedDisposition::Demoted(reason));
                    }
                    let name = inner.slots[slot].name.clone();
                    // A TOP-LEVEL 7z chase that gives up leaves the
                    // archive materialized in the output directory,
                    // which is the disk post-pass's own input - mark it
                    // so the caller's volume remediation leaves it
                    // alone (see [`SEVENZ_DISK_FALLBACK_PREFIX`]).
                    // Nested demotes need no marking: the child fold
                    // already prefixes them "nested fallback:".
                    let why =
                        if self.depth == 0 && matches!(inner.slots[slot].mode, SlotMode::SevenZ) {
                            match inner.slots[slot].container_fmt {
                                ChaseFormat::SevenZ => {
                                    format!("{SEVENZ_DISK_FALLBACK_PREFIX}{reason}")
                                }
                                ChaseFormat::Zip => format!("{ZIP_DISK_FALLBACK_PREFIX}{reason}"),
                                ChaseFormat::Tar => format!("{TAR_DISK_FALLBACK_PREFIX}{reason}"),
                            }
                        } else {
                            // ...and the RAR twin: a volume the offset-0
                            // sniff started inside a launcher stub
                            // materializes as the posted `.exe`, which
                            // the SFX arm owns. See
                            // [`SFX_DISK_FALLBACK_PREFIX`].
                            Self::mark_sfx_demote(Self::slot_is_sfx(inner, slot), reason)
                        };
                    inner.slot_fallbacks.push((name, why));
                }
                self.fallback_slot(inner, slot)
            }
        }
    }

    /// Materialize every volume of a group and stop mapping it. The
    /// group's partially-extracted inner files are deleted afterwards -
    /// their bytes were reconstructed into the volume files, and a sparse
    /// half-written "extracted" file would masquerade as output.
    pub(super) fn fallback_group(
        &self,
        inner: &mut Inner,
        key: &str,
        reason: &str,
    ) -> io::Result<()> {
        let grp = inner.groups.get_mut(key).unwrap();
        if grp.fallback {
            return Ok(());
        }
        grp.fallback = true;
        let members = grp.slots.clone();
        // A group whose volumes are self-extractors is the SFX arm's, in
        // the same way and for the same reason as the slot-level marking
        // in [`Self::fallback_slot_or_group`]. Marked here rather than
        // there because a group demotes from a dozen other sites too (an
        // incomplete mapping at end of download, a stored CRC that did
        // not hold), and every one of them leaves the same `.exe` on
        // disk. The re-entry guard above means a group is marked once.
        let why =
            Self::mark_sfx_demote(members.iter().any(|&s| Self::slot_is_sfx(inner, s)), reason);
        inner.groups.get_mut(key).unwrap().fallback_reason = Some(why);
        // A chased group tears its chase down FIRST: the worker stops
        // producing and its partial outputs are abandoned, then each
        // member's frontier buffer materializes below.
        if let Some(ctl) = inner.groups.get(key).and_then(|g| g.chase.clone()) {
            self.chase_teardown(inner, &ctl, reason);
        }
        for si in &members {
            self.fallback_slot(inner, *si)?;
        }
        Self::delete_group_out_files(inner, key);
        Ok(())
    }

    /// Source-protected fallback: no writer, no reconstruction - drop the
    /// held bytes (the source file already has them) and swallow all
    /// future spans.
    pub(super) fn discard_slot(&self, inner: &mut Inner, slot: usize) {
        let holds = std::mem::take(&mut inner.slots[slot].holds);
        inner.slots[slot].pre_bytes = 0;
        for (_, span) in &holds {
            Self::uncharge_span(inner, span);
        }
        let headers = std::mem::take(&mut inner.slots[slot].header_spans);
        for (_, span) in &headers {
            Self::uncharge_span(inner, span);
        }
        inner.slots[slot].piece_crcs = HashMap::new();
        inner.slots[slot].mode = SlotMode::Discard;
    }

    /// Reconstruct one volume into a real file: header stash + extracted
    /// inner-file bytes + holds; future spans write through.
    pub(super) fn fallback_slot(&self, inner: &mut Inner, slot: usize) -> io::Result<()> {
        if matches!(
            inner.slots[slot].mode,
            SlotMode::RarFallback | SlotMode::Discard
        ) {
            return Ok(());
        }
        // TODO 211 (b): an alias has no bytes of its own - demoting it
        // is demoting its head, whose reconstruction writes this part's
        // file and flips it.
        if matches!(inner.slots[slot].mode, SlotMode::SplitPart) {
            let (head, _) = Self::split_target(inner, slot, 0);
            return self.fallback_slot_or_group(inner, head, "split part demoted");
        }
        // Every demote route funnels through here (group fallbacks call
        // this per member), so it is the one place the badge has to learn
        // that some of this set is going to disk after all.
        self.shape.note(self.depth, SH_MATERIALIZED);
        if inner.protect_sources {
            // discard_slot does NOT abort a frontier buffer or abandon a
            // 7z worker's sinks, so reaching here with either live would
            // leave the worker writing into slots nobody tears down. It
            // cannot happen: both chase attaches are gated on
            // `!protect_sources`, and the only production caller sets the
            // flag immediately after `Extractor::new`. That ordering is a
            // contract held in another crate, so assert it here.
            debug_assert!(
                inner.slots[slot].chase.is_none() && inner.slots[slot].sevenz.is_none(),
                "protect_sources reached slot {slot} with a live chase - \
                 set_protect_sources must precede the first write"
            );
            self.discard_slot(inner, slot);
            return Ok(());
        }
        // The whole reconstruction runs with `refeed_active` raised
        // (saved/restored like drain_holds, which nests inside): every
        // plain write it performs - header stash, extracted read-back,
        // chase buffer - surfaces an identity placement, so an article
        // parked on a Held return (header articles above all) completes
        // its journal record at the caller's next flush instead of
        // refetching on resume. Sound for the same reason the `M`
        // record is: these bytes are durably at their final offsets in
        // the volume file the moment the write lands, and the record
        // only ever surfaces AFTER that write.
        let prev = inner.refeed_active;
        inner.refeed_active = true;
        let r = self.fallback_slot_reconstruct(inner, slot);
        inner.refeed_active = prev;
        r?;
        self.note_slot_materialized(inner, slot);
        // TODO 211 (b): the reconstruction above wrote a split head's
        // logical volume back into its part files; the aliases are
        // materialized parts now.
        self.split_after_fallback(inner, slot);
        Ok(())
    }

    /// The body of [`Self::fallback_slot`]: everything from chase/7z
    /// teardown through the held-span drain, split out so the caller
    /// can bracket it with the refeed flag and fire the materialized
    /// notification only on full success.
    fn fallback_slot_reconstruct(&self, inner: &mut Inner, slot: usize) -> io::Result<()> {
        // A demoting 7z chase abandons its worker's partial outputs
        // first; the worker itself unblocks on the buffer abort below.
        // The ctl stays IN the slot: sevenz_finish / Drop discover
        // workers by iterating slots that still hold one, so taking it
        // here would leave the thread detached and still copying into
        // abandoned sinks after finish() returned.
        if let Some(ctl) = inner.slots[slot].sevenz.clone() {
            self.sevenz_abandon_sinks(inner, &ctl);
        }
        // A chased slot's complete byte record lives in its frontier
        // buffer (headers, data, parked repair spans - everything since
        // attach was routed there): materialize it directly and SKIP the
        // entry read-back below, whose destinations hold DECODED member
        // bytes for this slot, not volume bytes.
        if let Some(ch) = inner.slots[slot].chase.take() {
            inner.slots[slot].mode = SlotMode::RarFallback;
            ch.buf.abort("demoted to materialized volume");
            // A dropping trim released this prefix with no disk copy,
            // so the file materialized below has holes there. Hand the
            // ranges to the slot: the caller re-fetches the volume
            // before anything reads it back (`dropped_volumes`).
            if !ch.dropped.is_empty() {
                inner.slots[slot].dropped = ch.dropped.clone();
                inner.slots[slot].dropped_as = ch.dropped_as.clone();
            }
            // Released UP FRONT, like the header stash below and for the
            // same reason: the whole record leaves RAM here either way,
            // and the loop can exit early on a scratch read or a write
            // error. Leaving the release after it charged the budget for
            // bytes nobody owns any more - the chase is already out of
            // the slot, so nothing could ever give them back, and every
            // later slot saw `budget.over()` and demoted.
            inner.budget.sub(ch.charged);
            // One span at a time: a stall-paged span reads back off the
            // scratch only for its own write, so materializing a mostly-
            // paged set never re-inflates it. A scratch read error fails
            // the job here on purpose - the demote needs those very
            // bytes, so demote-with-integrity is impossible without them.
            while let Some((off, bytes)) = ch.buf.pop_span()? {
                self.plain_span(inner, slot, off, &bytes)?;
            }
            return self.drain_holds(inner, slot);
        }
        inner.slots[slot].mode = SlotMode::RarFallback;
        inner.slots[slot].piece_crcs = HashMap::new();

        // 1. Header bytes. The RAM stash is released up front: a
        // materialized slot answers every read from its volume file, so
        // the RAM copy (and the budget it charges) buys nothing once the
        // bytes are on disk - and the whole stash leaves RAM here either
        // way, so a write error mid-loop must not leave the budget
        // charged for bytes nobody owns any more. Paged entries release
        // per-entry AFTER their read-back instead (read-before-release is
        // what keeps an idle truncate off a region still being read); on
        // a mid-loop error the leftovers stay charged to the scratch
        // live-count, which only delays its truncate - the run is failing
        // anyway and finish/Drop unlink the file regardless.
        let headers = std::mem::take(&mut inner.slots[slot].header_spans);
        inner.budget.sub(
            headers
                .iter()
                .filter_map(|(_, s)| match s {
                    HoldSpan::Ram(b) => Some(b.len()),
                    HoldSpan::Paged { .. } => None,
                })
                .sum::<usize>(),
        );
        for (off, span) in headers {
            let bytes = match span {
                HoldSpan::Ram(b) => b,
                HoldSpan::Paged { off: po, len } => {
                    let mut b = vec![0u8; len];
                    inner.scratch.read(po, &mut b)?;
                    inner.scratch.release(len);
                    b
                }
            };
            self.plain_span(inner, slot, off, &bytes)?;
        }

        // 2. Already-extracted data areas: read back from inner files.
        let pieces: Vec<(String, u64, u64, Option<u64>)> = {
            match inner.slots[slot].mapper.as_ref() {
                Some(m) => m
                    .entries
                    .iter()
                    .enumerate()
                    .map(|(ei, e)| {
                        (
                            e.name.clone(),
                            e.data_off,
                            e.data_len,
                            Self::base_for(inner, slot, ei),
                        )
                    })
                    .collect(),
                None => Vec::new(),
            }
        };
        let mut buf = vec![0u8; 1 << 20];
        for (name, data_off, data_len, base) in pieces {
            let Some(base) = base else { continue };
            // Copy back ONLY ranges the destination has actually written.
            // The files are sparse-preallocated, so a hole preads as
            // zeros - and a decoder whose pwrite is queued but not yet
            // landed (the deferred-write window) would have its span
            // turned into zeros in the materialized volume while the
            // verifier had already passed those blocks from RAM. Skipped
            // ranges stay holes here; the bytes reach the volume either
            // via the article's own write-through (not yet arrived) or
            // via the post-write re-route in `write()` / the forward
            // delivery re-check (in flight).
            match Self::dest_for(inner, slot, &name) {
                // Plaintext-once output: the volume needs POSTED bytes,
                // so read back through the re-encrypt shim (which also
                // serves the seam/tail cipher the disk never held),
                // gated on arrived-cipher intervals.
                Some(Dest::Writer(w)) if Self::crypto_of(inner, &w).is_some() => {
                    let cr = Self::crypto_of(inner, &w).unwrap();
                    for (cs, ce) in cr.intervals(base, data_len) {
                        let mut done = cs;
                        while done < ce {
                            let n = (ce - done).min(buf.len() as u64) as usize;
                            if cr.read_posted(&w, done, &mut buf[..n]).is_err() {
                                break;
                            }
                            self.plain_span(inner, slot, data_off + (done - base), &buf[..n])?;
                            done += n as u64;
                        }
                    }
                }
                Some(Dest::Writer(w)) => {
                    let f = std::fs::File::open(&w.path)?;
                    for (cs, ce) in w.covered_intervals(base, data_len) {
                        let mut done = cs;
                        while done < ce {
                            let n = (ce - done).min(buf.len() as u64) as usize;
                            if crate::disk::read_exact_at(&f, &mut buf[..n], done).is_err() {
                                break;
                            }
                            self.plain_span(inner, slot, data_off + (done - base), &buf[..n])?;
                            done += n as u64;
                        }
                    }
                }
                // Routed file: the child serves its own reconstructible
                // view (it composes headers + its outputs recursively),
                // gated on the same interval discipline.
                Some(Dest::Child(c, cslot)) => {
                    for (cs, ce) in c.covered_intervals(cslot, base, data_len) {
                        let mut done = cs;
                        while done < ce {
                            let n = (ce - done).min(buf.len() as u64) as usize;
                            if c.read_at(cslot, done, &mut buf[..n]).is_err() {
                                break;
                            }
                            self.plain_span(inner, slot, data_off + (done - base), &buf[..n])?;
                            done += n as u64;
                        }
                    }
                }
                None => continue,
            }
        }

        // 3. Held spans flush through the plain path.
        self.drain_holds(inner, slot)
    }

    /// Tell the journal this ROOT slot's volume file now holds every
    /// byte its recorded placements describe (see [`MaterializedHook`]).
    /// Fired only after the reconstruction fully landed - a kill before
    /// this point leaves no `M` line and the articles refetch, which is
    /// the safe direction. Depth-gated as a second belt beside the
    /// root-only hook install: a nested slot index must never reach the
    /// journal's root slot space.
    pub(super) fn note_slot_materialized(&self, inner: &Inner, slot: usize) {
        if self.depth == 0
            && let Some(h) = inner.materialized.as_ref()
        {
            // The file that actually exists, not the one the slot was
            // first recorded under: `Extractor::rename` retargets a
            // writerless slot from a PAR2 report, and the writer this
            // demote just created carries the renamed path.
            let s = &inner.slots[slot];
            let name = s
                .writer
                .as_ref()
                .map(|w| w.current_path())
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
                .unwrap_or_else(|| s.name.clone());
            let size = s.writer.as_ref().map(|w| w.size).unwrap_or(s.size);
            h(slot, &name, size);
        }
    }

    /// Download over: no more articles can arrive, so a slot still waiting
    /// on its offset-0 sniff will never classify. Flush its held spans to
    /// a plain file so verification read-back and PAR2 repair see the
    /// bytes on disk - a lost head article must cost one article's worth
    /// of repair blocks, not turn the whole target into "missing".
    /// Propagates down the child chain: a routed level-1 file still
    /// waiting on ITS sniff settles Plain the same way (it can still
    /// receive late repair-patch bytes as an ordinary file).
    pub fn settle_unclassified(&self) -> io::Result<()> {
        let child = {
            let mut g = self.inner.lock_ok();
            self.overflow_to_plain(&mut g)?;
            g.child.clone()
        };
        self.flush_pending_fwd()?;
        if let Some(c) = child {
            c.settle_unclassified()?;
        }
        Ok(())
    }

    /// In-stream store-payload CRC gate: a store set whose DATA was
    /// damaged before the poster packed it maps cleanly - the headers
    /// are intact - and would one-pass extract silently corrupt, because
    /// the download's PAR2 vouches for the outer bytes AS POSTED, damage
    /// included, and the extracted payload has no other verifier. RAR5
    /// file headers carry the unpacked data's CRC32; the routing path
    /// composed each piece's CRC as the bytes flowed (see `CrcRuns`),
    /// and the last split piece's header holds the whole-file value -
    /// the same one unrar checks. Any completed file that mismatches
    /// demotes its group to materialized volumes, where the disk
    /// post-pass can run a packed-alongside par2 set (or fail honestly).
    /// Entries whose bytes never fully arrived are skipped - missing
    /// articles are the outer repair ladder's problem, not proof of
    /// pre-packed damage. A header set that does NOT tile its declared
    /// file is a different matter and DEMOTES: tiling is decided purely
    /// from the headers, so a non-tiling set is a broken (or hostile)
    /// archive description, never a delivery gap. Also skipped are
    /// entries this gate cannot speak to at all (compressed, encrypted)
    /// and level-0 entries whose header carries
    /// no CRC (RAR4, encrypted); a NESTED RAR4 store file demotes
    /// instead, because the disk-path unrar is the only CRC check it
    /// will ever meet. The gate itself never errors the extraction: its
    /// only verdict is the demotion, which routes damage to where
    /// unrar/PAR2 can catch it. Nested levels always run the gate;
    /// level 0 (the FINAL extracted output) runs it under the
    /// verify_output_crc setting.
    pub(super) fn verify_inner_crcs(&self) -> io::Result<()> {
        let mut g = self.inner.lock_ok();
        // Structural, not a checksum. Only a NON-encrypted entry ever
        // creates a child route (see `route_dest`), so a raw name that is
        // in `routed` AND also appears as an encrypted entry describes a
        // set whose same inner file is both plain and encrypted. That
        // shape slipped through everything: the Child forward arm carries
        // no crypto, the finish verdict keys off `inner_writers` which
        // never holds a child-owned output (so it silently found no work
        // and returned success), and the per-name CRC gate below
        // skips any bucket with a non-checkable member - the encrypted
        // twin disabling a check that is a pure header property. The
        // published file could be raw ciphertext, with the source volumes
        // then discarded. No archiver produces this; demote to the disk
        // path, which decrypts correctly.
        //
        // Ahead of the depth-0 early return on purpose: NZBFAST_NO_OUTPUT_CRC
        // turns off a CRC gate, not a routing one. And the reason string
        // must keep the "encrypted" substring - `fallback_needs_disk_unpack`
        // routes on it, which is what sends this set to unrar WITH the
        // job's password rather than to the generic ladder's `-p-`.
        let conflicted: Vec<String> = {
            let (groups, slots) = (&g.groups, &g.slots);
            groups
                .iter()
                .filter(|(_, grp)| !grp.fallback && !grp.routed.is_empty())
                .filter(|(_, grp)| {
                    grp.slots.iter().any(|&si| {
                        slots[si].mapper.as_ref().is_some_and(|m| {
                            m.entries.iter().any(|e| {
                                e.encrypted && !e.is_dir && grp.routed.contains_key(&e.name)
                            })
                        })
                    })
                })
                .map(|(k, _)| k.clone())
                .collect()
        };
        for key in conflicted {
            self.fallback_group(&mut g, &key, "inner file is both plain and encrypted")?;
        }
        // NZBFAST_NO_OUTPUT_CRC (verify_output_crc off) exists to skip
        // the CRC COMPOSITION cost at level 0. The tiling check below is
        // a pure header property - "these volumes do not describe a
        // whole file" - and stays on regardless: with the knob set, a
        // par-less truncated store set would otherwise ship its
        // preallocated size as a silent success.
        let crc_gate = self.depth > 0 || g.verify_output_crc;
        let inner = &mut *g;
        Self::recompose_repair_gaps(inner);
        let keys: Vec<String> = inner.groups.keys().cloned().collect();
        for key in keys {
            if inner.groups[&key].fallback {
                continue;
            }
            let members: Vec<(usize, usize)> = inner.groups[&key]
                .slots
                .iter()
                .flat_map(|&si| {
                    let n = inner.slots[si]
                        .mapper
                        .as_ref()
                        .map_or(0, |m| m.entries.len());
                    (0..n).map(move |ei| (si, ei))
                })
                .collect();
            // name → (base, piece len, composed run, last piece's header
            // CRC). Unverifiable pieces poison their whole file, never
            // the group.
            struct Piece {
                base: Option<u64>,
                len: u64,
                total: u64,
                run: Option<u32>,
                hdr: Option<u32>,
                v4: bool,
                /// Entry carries an FHEXTRA_HASH record (e.g. BLAKE2sp) but
                /// no in-stream CRC - integrity data this gate can't compose.
                has_hash: bool,
                /// Unencrypted STORE: the only shape whose bytes this gate
                /// can compose a CRC over at all.
                checkable: bool,
            }
            let mut files: HashMap<String, Vec<Piece>> = HashMap::new();
            for (si, ei) in members {
                let base = Self::base_for(inner, si, ei);
                let s = &inner.slots[si];
                let m = s.mapper.as_ref().unwrap();
                let e = &m.entries[ei];
                if e.is_dir || e.unpacked_size == 0 {
                    continue;
                }
                let checkable = matches!(e.method, Method::Store) && !e.encrypted;
                files.entry(e.name.clone()).or_default().push(Piece {
                    base,
                    len: e.data_len,
                    total: e.unpacked_size,
                    run: s
                        .piece_crcs
                        .get(&ei)
                        .and_then(|r| r.whole(e.data_len))
                        .filter(|_| checkable),
                    hdr: if !e.split_after { e.file_crc } else { None },
                    v4: matches!(m.version, Some(RarVersion::V4)),
                    has_hash: !e.split_after && e.hash.is_some(),
                    checkable,
                });
            }
            for (_name, mut pieces) in files {
                // A member this gate can never speak to (compressed, or
                // encrypted - the decrypt pass owns that check) is not
                // evidence of anything. Unchanged: skip.
                if pieces.iter().any(|p| !p.checkable) {
                    continue;
                }
                pieces.sort_by_key(|p| p.base);
                let total = pieces[0].total;
                // The pieces must tile [0, total) exactly, and the final
                // one must carry the whole-file CRC.
                //
                // Tiling is computed BEFORE the byte-arrival check on
                // purpose: it is a pure HEADER property (base, data_len,
                // unpacked_size), so "the headers do not describe a whole
                // file" is knowable no matter which articles landed, and it
                // is a different failure from "the bytes never arrived".
                // Conflating them let a single well-formed volume declare
                // `unpacked_size` = 64 GiB against a few hundred KB of real
                // store data and ship the preallocated sparse tail as a
                // successful extraction: `run` was Some, `hdr` was None
                // (split_after set), and every demote below was gated on
                // `tiled`, so the file fell out of the gate entirely.
                let mut at = 0u64;
                let tiled = pieces.iter().all(|p| {
                    let ok = p.base == Some(at) && p.total == total;
                    at += p.len;
                    ok
                }) && at == total;
                if !tiled {
                    self.fallback_group(
                        inner,
                        &key,
                        "inner file's headers do not describe a complete file",
                    )?;
                    break;
                }
                // Everything from here down composes checksums; with the
                // CRC gate off only the structural check above applies.
                if !crc_gate {
                    continue;
                }
                // Bytes that never arrived ARE the outer repair ladder's
                // problem, not proof of pre-packed damage - skip, as before.
                if pieces.iter().any(|p| p.run.is_none()) {
                    continue;
                }
                let Some(expected) = pieces.last().and_then(|p| p.hdr) else {
                    // The mapper DOES read the RAR4 header CRC32 (it has
                    // since 48e0d3c1, which landed hours after this gate
                    // and left the note here saying otherwise). What
                    // reaches this arm is the narrower case: a writer that
                    // left the field zero, which the parser reads as "not
                    // computed" rather than as a real CRC of 0. There is
                    // then nothing to verify against. NESTED, that demotes
                    // to materialized volumes - the disk-path unrar
                    // checks the CRC there - instead of clean-passing
                    // the one family this gate cannot see. At level 0
                    // it skips: the output-CRC gate is best-effort
                    // hardening on top of the outer PAR2, and demoting
                    // every RAR4 job to the double-I/O disk path would
                    // regress the common case the gate exists to keep
                    // fast. Files whose bytes never fully arrived still
                    // skip above: missing articles are the outer repair
                    // ladder's problem, not proof of pre-packed damage.
                    // (Everything here tiles - a header set that doesn't
                    // already demoted.)
                    if self.depth > 0 && pieces.iter().any(|p| p.v4) {
                        self.fallback_group(inner, &key, "inner RAR4 file lacks an in-stream CRC")?;
                        break;
                    }
                    // The entry stores an FHEXTRA_HASH digest (BLAKE2sp) in
                    // place of a CRC. This gate composes CRC32 only, so it
                    // cannot verify the hash - but the digest proves the format
                    // INTENDS integrity checking, so silently passing corrupt
                    // (damaged-before-posting) bytes is wrong. Demote to the
                    // disk path, where the unrar codec verifies BLAKE2sp. Rare
                    // enough (most RAR5 writers still emit CRC32) that the
                    // double-I/O cost is acceptable at any depth.
                    if pieces.iter().any(|p| p.has_hash) {
                        self.fallback_group(
                            inner,
                            &key,
                            "inner file carries only a hash the fast path can't verify",
                        )?;
                        break;
                    }
                    continue;
                };
                let mut crc = 0u32;
                for p in &pieces {
                    crc = crate::yenc_simd::crc32_combine(crc, p.run.unwrap(), p.len);
                }
                if crc != expected {
                    // No file name in the reason: callers branch on
                    // substrings of it ("password", "compressed"…) and a
                    // hostile inner name must not steer them. The group
                    // key names the archive in every report line.
                    self.fallback_group(inner, &key, "inner file failed its stored CRC")?;
                    break;
                }
            }
        }
        Ok(())
    }

    /// Close the composition holes a mapped repair left behind: an
    /// overwrite that lands mid-run discards the run's composed CRC, and
    /// the run's sub-ranges outside the repair span become stale gaps
    /// (see [`CrcRuns`]). Every such byte is already routed and on
    /// disk - exactly what the composition originally hashed - so
    /// recompute each gap from its destination (inner-file writer, or
    /// the nested child's view; downward child calls under our lock
    /// follow the `covered` precedent) and fold it back in. This keeps
    /// the gate's teeth after a repair: pre-packed damage ELSEWHERE in a
    /// repaired file still mismatches and demotes. A gap that cannot be
    /// read back simply stays a gap - the piece reads as unverifiable
    /// and skips, today's assurance level, never a false pass.
    pub(super) fn recompose_repair_gaps(inner: &mut Inner) {
        struct Gap {
            slot: usize,
            ei: usize,
            base: u64,
            dest: Dest,
            ranges: Vec<(u64, u64)>,
        }
        let mut jobs: Vec<Gap> = Vec::new();
        for si in 0..inner.slots.len() {
            if !matches!(inner.slots[si].mode, SlotMode::Rar) {
                continue;
            }
            let eis: Vec<usize> = inner.slots[si]
                .piece_crcs
                .iter()
                .filter(|(_, r)| !r.stale.is_empty())
                .map(|(&ei, _)| ei)
                .collect();
            for ei in eis {
                let Some(base) = Self::base_for(inner, si, ei) else {
                    continue;
                };
                let name = match inner.slots[si]
                    .mapper
                    .as_ref()
                    .and_then(|m| m.entries.get(ei))
                {
                    Some(e) => e.name.clone(),
                    None => continue,
                };
                let Some(dest) = Self::dest_for(inner, si, &name) else {
                    continue;
                };
                let ranges = inner.slots[si]
                    .piece_crcs
                    .get_mut(&ei)
                    .expect("entry enumerated above")
                    .take_stale_gaps();
                if !ranges.is_empty() {
                    jobs.push(Gap {
                        slot: si,
                        ei,
                        base,
                        dest,
                        ranges,
                    });
                }
            }
        }
        for j in jobs {
            for (gs, ge) in j.ranges {
                let len = ge - gs;
                let covered = match &j.dest {
                    Dest::Writer(w) => w.covered(j.base + gs, len),
                    Dest::Child(c, cs) => c.covered(*cs, j.base + gs, len as usize),
                };
                if !covered {
                    continue;
                }
                // Bounded chunks: a gap can span most of a large file
                // (one coalesced run covered it all before the repair).
                let mut h = crc32fast::Hasher::new();
                let mut buf = vec![0u8; (len as usize).min(4 << 20)];
                let mut pos = gs;
                let mut ok = true;
                while pos < ge {
                    let n = ((ge - pos) as usize).min(buf.len());
                    let read = match &j.dest {
                        Dest::Writer(w) => w.read_at(&mut buf[..n], j.base + pos).is_ok(),
                        Dest::Child(c, cs) => c.read_at(*cs, j.base + pos, &mut buf[..n]).is_ok(),
                    };
                    if !read {
                        ok = false;
                        break;
                    }
                    h.update(&buf[..n]);
                    pos += n as u64;
                }
                if ok && let Some(r) = inner.slots[j.slot].piece_crcs.get_mut(&j.ei) {
                    // `take_stale_gaps` yields ranges disjoint from the
                    // runs and from each other, so this cannot be refused.
                    // If it somehow were, the gap simply stays a gap and
                    // the piece reads as unverifiable (skipped at finish),
                    // which is the safe direction - never a false pass.
                    let taken = r.add_run(gs, len, h.finalize());
                    debug_assert!(taken, "recomposed stale gap overlapped a live run");
                }
            }
        }
    }

    /// Settle groups that never finished mapping and flush stray holds.
    pub(super) fn settle_groups(&self) -> io::Result<()> {
        let mut g = self.inner.lock_ok();
        let inner = &mut *g;
        // TODO 211 (b): close a lone-head split to its own size before
        // its group is judged complete or not.
        self.split_settle(inner)?;
        let keys: Vec<String> = inner.groups.keys().cloned().collect();
        for key in &keys {
            let has_holds = inner.groups[key]
                .slots
                .iter()
                .any(|&si| !inner.slots[si].holds.is_empty());
            let incomplete = inner.groups[key].slots.iter().any(|&si| {
                inner.slots[si]
                    .mapper
                    .as_ref()
                    .is_some_and(|m| !m.complete && m.blocker.is_none())
            });
            if (has_holds || incomplete) && !inner.groups[key].fallback {
                self.fallback_group(inner, key, "incomplete mapping at end of download")?;
            }
        }
        // Arithmetic placements still provisional at end of download:
        // the CLOSED set (volumes 0..=last all parsed, uniform, ending
        // in the declared final piece) is itself the proof the premise
        // demanded - confirm and clear. Anything else means bytes sit at
        // offsets only an unproven premise justifies (a volume missing
        // from the NZB, or shape-fail leftovers the chain never
        // reached): demote whole, the volumes hold the truth.
        for key in &keys {
            if inner.groups[key].fallback || inner.groups[key].arith_provisional.is_empty() {
                continue;
            }
            let closed = {
                let g = &inner.groups[key];
                let mappers: Vec<&VolumeMapper> = g
                    .slots
                    .iter()
                    .filter_map(|&si| inner.slots[si].mapper.as_ref())
                    .filter(|m| !m.entries.is_empty())
                    .collect();
                mappers.len() == g.slots.len()
                    && matches!(
                        ArchiveMap::resolve_arithmetic(&mappers),
                        ArithGate::Place { closed: true, .. }
                    )
            };
            if closed {
                inner.groups.get_mut(key).unwrap().arith_provisional.clear();
            } else {
                self.fallback_group(inner, key, "non-uniform store set")?;
            }
        }
        for si in 0..inner.slots.len() {
            if !inner.slots[si].holds.is_empty() {
                // A RAR slot that never formed a group (sniffed at offset
                // 0, but its first FILE header straddled into a lost
                // article) is invisible to both group loops above, and
                // drain_holds just re-holds its spans: the volume then
                // produced no file on disk and no fallback line - the
                // bytes evaporated when the extractor dropped, while the
                // byte-identical situation one parse step later (group
                // formed) materialized for repair/quarantine. Demote it
                // like its grouped twin.
                if matches!(inner.slots[si].mode, SlotMode::Rar) && inner.slots[si].group.is_none()
                {
                    self.fallback_slot_or_group(
                        inner,
                        si,
                        "incomplete mapping at end of download",
                    )?;
                    continue;
                }
                if matches!(inner.slots[si].mode, SlotMode::Unknown) {
                    if inner.protect_sources {
                        let name = inner.slots[si].name.clone();
                        inner
                            .slot_fallbacks
                            .push((name, "never classified".to_string()));
                        self.discard_slot(inner, si);
                        continue;
                    }
                    inner.slots[si].mode = SlotMode::Plain;
                    self.split_slot_plain(inner, si)?;
                }
                self.drain_holds(inner, si)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rar::fixtures;

    use crate::extract::testutil::*;

    /// Sweep 8 M4, defect 3: the demote that materializes a volume set
    /// for repair must ABANDON the extracted output it is throwing away,
    /// because nothing else ever speaks for that file again.
    ///
    /// `materialize` -> `fallback_group` -> `delete_group_out_files`
    /// drains the group's ROUTED members and `abandon_slot` takes the
    /// child slot's writer out of its slot and unlinks the file. From
    /// that moment `Extractor::each_output` cannot reach it - so
    /// `park_outputs_for_repair` never claims it, no lease is revoked
    /// and no custody generation moves. A live `/stream` response still
    /// holds its own `Arc` and used to park on this frozen frontier
    /// until `LiveRangeReader`'s five-minute span timeout: a player hung
    /// for five minutes on a job that repaired fine.
    ///
    /// The end-to-end proof is `nzbfast`'s
    /// `tests/integration/stream_repair.rs` leg 2, but that whole file
    /// skips green on a box with no par2 - so the
    /// mechanism is pinned here too, where it needs neither par2 nor a
    /// daemon.
    #[test]
    fn materializing_for_repair_abandons_the_extracted_output() {
        let dir = tmpdir("demoteabandon");
        let total = payload(600_000, 5);
        let vols: Vec<Vec<u8>> = vec![
            fixtures::rar5_volume_n(&[("movie.mkv", 600_000, &total[..200_000], false, true)], 0),
            fixtures::rar5_volume_n(
                &[("movie.mkv", 600_000, &total[200_000..400_000], true, true)],
                1,
            ),
            fixtures::rar5_volume_n(&[("movie.mkv", 600_000, &total[400_000..], true, false)], 2),
        ];
        let ex = Extractor::new(&dir, 3, true);
        for (i, vol) in vols.iter().enumerate() {
            feed(
                &ex,
                i,
                &format!("r.part{}.rar", i + 1),
                vol,
                9000,
                21 + i as u64,
            );
        }

        // The file a player would be holding. It lives in the CHILD
        // chain - `writers_snapshot` recurses, which is exactly why the
        // streaming server can see it and `each_output` cannot once the
        // slot lets go.
        let snap = ex.writers_snapshot();
        let (_, media) = snap
            .iter()
            .find(|(n, _)| n == "movie.mkv")
            .expect("the set extracted a media file to hold open")
            .clone();
        assert!(!media.is_abandoned(), "nothing has demoted anything yet");
        assert!(media.path.exists());

        // What `get::settle` does when par2 has to repair the VOLUMES.
        ex.materialize(0).unwrap();

        assert!(
            media.is_abandoned(),
            "the demote unlinked the extracted output and dropped its writer, \
             so a live reader on it has nothing left to wait for"
        );
        assert!(
            !media.path.exists(),
            "the extracted output survived the demote - then this test is no \
             longer standing in for the shipped shape"
        );
        // And the claim an external repair takes really does miss it.
        // `writers_snapshot` walks the same three sources as
        // `each_output` - this level's `inner_writers`, its slot
        // writers, and the child - so what it can no longer name is
        // what `park_outputs_for_repair` can no longer claim. What is
        // left is par2's actual targets: the materialized volumes.
        ex.park_outputs_for_repair().unwrap();
        let reachable: Vec<String> = ex.writers_snapshot().into_iter().map(|(n, _)| n).collect();
        assert!(
            !reachable.iter().any(|n| n == "movie.mkv"),
            "the abandoned output is still reachable: {reachable:?}"
        );
        ex.unpark_outputs().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Fallback read-back must skip sparse holes: an unwritten inner-file
    /// region reads back as zeros, and stamping those into the
    /// materialized volume marked the missing range as written -
    /// verification then trusted garbage (the zero-fill half of the
    /// deferred-pwrite race, minus the race).
    #[test]
    fn fallback_readback_skips_unwritten_ranges() {
        let dir = tmpdir("fbholes");
        let data = payload(300_000, 17);
        let vol = fixtures::rar5_volume(&[("f.bin", 300_000, &data, false, false)]);
        let ex = Extractor::new(&dir, 1, true);
        // Feed every article except one mid-data chunk.
        let art = 7000;
        let miss = vol.len() / 2 / art;
        for i in 0..vol.len().div_ceil(art) {
            if i == miss {
                continue;
            }
            let s = i * art;
            let e = (s + art).min(vol.len());
            ex.write(0, "v.rar", vol.len() as u64, s as u64, &vol[s..e])
                .unwrap();
        }
        ex.materialize(0).unwrap();
        let (ms, me) = (miss * art, ((miss + 1) * art).min(vol.len()));
        // The missing article's range must NOT be claimed as written.
        assert!(
            !ex.covered(0, ms as u64, me - ms),
            "hole was stamped into the volume as zeros"
        );
        // Late arrival writes through and completes the volume.
        ex.write(0, "v.rar", vol.len() as u64, ms as u64, &vol[ms..me])
            .unwrap();
        ex.finish().unwrap();
        assert_eq!(std::fs::read(dir.join("v.rar")).unwrap(), vol);
        assert!(!dir.join("f.bin").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The demote must tell the journal (see [`MaterializedHook`]): the
    /// fallback deletes the inner files the slot's R records name as
    /// copy sources, and without the `M` line a retry over intact
    /// volumes refetched the whole post (measured 13 Aug 2026).
    #[test]
    fn fallback_fires_the_materialized_hook_per_slot() {
        let dir = tmpdir("fbhook");
        let data = payload(200_000, 23);
        let vol = fixtures::rar5_volume(&[("g.bin", 200_000, &data, false, false)]);
        let ex = Extractor::new(&dir, 1, true);
        let seen = Arc::new(std::sync::Mutex::new(Vec::<(usize, String, u64)>::new()));
        let s2 = seen.clone();
        ex.set_materialized_hook(Arc::new(move |slot, name: &str, size| {
            s2.lock().unwrap().push((slot, name.to_string(), size))
        }));
        ex.write(0, "v.rar", vol.len() as u64, 0, &vol).unwrap();
        assert!(seen.lock().unwrap().is_empty(), "no demote, no hook");
        ex.materialize(0).unwrap();
        assert_eq!(
            *seen.lock().unwrap(),
            vec![(0, "v.rar".to_string(), vol.len() as u64)],
            "hook fires once, after the reconstruction landed"
        );
        // A second demote of an already-fallen slot is a no-op.
        ex.materialize(0).unwrap();
        assert_eq!(seen.lock().unwrap().len(), 1);
        ex.finish().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A PAR2 report renames a still-WRITERLESS slot, then the repair
    /// path materializes it. The hook must name the file that now
    /// exists - the journal rewrites every placement of the slot onto
    /// that name, and the stale posted name pointed them at nothing.
    #[test]
    fn the_materialized_hook_names_the_renamed_volume() {
        let dir = tmpdir("fbrename");
        let data = payload(200_000, 24);
        let vol = fixtures::rar5_volume(&[("g.bin", 200_000, &data, false, false)]);
        let ex = Extractor::new(&dir, 1, true);
        let seen = Arc::new(std::sync::Mutex::new(Vec::<(usize, String, u64)>::new()));
        let s2 = seen.clone();
        ex.set_materialized_hook(Arc::new(move |slot, name: &str, size| {
            s2.lock().unwrap().push((slot, name.to_string(), size))
        }));
        ex.write(0, "0Bf3qZ.bin", vol.len() as u64, 0, &vol)
            .unwrap();
        ex.rename(0, "verified.part01.rar");
        ex.materialize(0).unwrap();
        assert_eq!(
            *seen.lock().unwrap(),
            vec![(0, "verified.part01.rar".to_string(), vol.len() as u64)]
        );
        assert!(dir.join("verified.part01.rar").exists());
        ex.finish().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Codex sweep 13 Aug R3: the OTHER ordering - materialize FIRST,
    /// verified rename after. The `M` record rewrote the slot's
    /// placements to identity form under the demote-time name, and the
    /// rename then reached only the in-memory `renamed_to`: replay
    /// looked for the old file, found nothing, and refetched a complete
    /// verified volume. The rename must re-fire the hook so the journal
    /// appends `S new-name` + `M`.
    #[test]
    fn a_rename_after_materialize_refires_the_hook_with_the_new_name() {
        let dir = tmpdir("fbrenafter");
        let data = payload(200_000, 25);
        let vol = fixtures::rar5_volume(&[("g.bin", 200_000, &data, false, false)]);
        let ex = Extractor::new(&dir, 1, true);
        let seen = Arc::new(std::sync::Mutex::new(Vec::<(usize, String, u64)>::new()));
        let s2 = seen.clone();
        ex.set_materialized_hook(Arc::new(move |slot, name: &str, size| {
            s2.lock().unwrap().push((slot, name.to_string(), size))
        }));
        ex.write(0, "0Bf3qZ.bin", vol.len() as u64, 0, &vol)
            .unwrap();
        ex.materialize(0).unwrap();
        assert_eq!(
            *seen.lock().unwrap(),
            vec![(0, "0Bf3qZ.bin".to_string(), vol.len() as u64)]
        );
        // The verified-name publish: the file moves on disk, then the
        // extractor is told - the callers' order.
        std::fs::rename(dir.join("0Bf3qZ.bin"), dir.join("verified.part01.rar")).unwrap();
        ex.note_slot_renamed(0, dir.join("verified.part01.rar"));
        assert_eq!(
            seen.lock().unwrap().get(1),
            Some(&(0, "verified.part01.rar".to_string(), vol.len() as u64)),
            "the rename must re-fire the hook with the live name"
        );
        // ...and any S emitted later names the file replay will find.
        assert_eq!(
            ex.slot_file_info(0).map(|(n, _)| n).as_deref(),
            Some("verified.part01.rar")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// 14 Aug sweep: the same stale-record failure for a PLAIN slot. An
    /// obfuscated post's bare payload file journals its placements under
    /// the posted name; the PAR2 verified-name publish renames it on
    /// disk, and the RarFallback-only gate left the journal pointing at
    /// the old name - replay refetched a complete verified file. A Plain
    /// slot's placements are identity-form by construction, so the
    /// `S new-name` + `M` retarget is exactly as valid as it is for a
    /// materialized volume.
    #[test]
    fn a_plain_slot_rename_refires_the_hook_with_the_new_name() {
        let dir = tmpdir("plainrename");
        let data = payload(200_000, 26); // no archive magic: sniffs Plain
        let ex = Extractor::new(&dir, 1, true);
        let seen = Arc::new(std::sync::Mutex::new(Vec::<(usize, String, u64)>::new()));
        let s2 = seen.clone();
        ex.set_materialized_hook(Arc::new(move |slot, name: &str, size| {
            s2.lock().unwrap().push((slot, name.to_string(), size))
        }));
        ex.write(0, "0Bf3qZ.bin", data.len() as u64, 0, &data)
            .unwrap();
        assert!(seen.lock().unwrap().is_empty(), "no rename, no hook");
        std::fs::rename(dir.join("0Bf3qZ.bin"), dir.join("verified.mkv")).unwrap();
        ex.note_slot_renamed(0, dir.join("verified.mkv"));
        assert_eq!(
            *seen.lock().unwrap(),
            vec![(0, "verified.mkv".to_string(), data.len() as u64)],
            "a plain slot's verified rename must retarget its journal identity"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Sweep 8, M6: the live media pick names writers from the file's
    /// CURRENT path.
    ///
    /// A verified-name publish renames an obfuscated slot's file under
    /// its open writer while the job is still finishing. Naming the
    /// snapshot from the immutable creation path made the pick judge it
    /// by a name that no longer existed: an extensionless creation name
    /// dropped the writer out of the media pick entirely, and when both
    /// names looked like media the pick succeeded while the fresh open
    /// behind it went to the removed path and returned 410.
    #[test]
    fn the_writer_snapshot_names_a_published_file_by_its_new_name() {
        let dir = tmpdir("snaprename");
        let data = payload(200_000, 26); // no archive magic: sniffs Plain
        let ex = Extractor::new(&dir, 1, true);
        ex.write(0, "0Bf3qZ", data.len() as u64, 0, &data).unwrap();
        assert_eq!(
            ex.writers_snapshot()
                .iter()
                .map(|(n, _)| n.clone())
                .collect::<Vec<_>>(),
            vec!["0Bf3qZ".to_string()],
            "before the publish it is the creation name"
        );

        std::fs::rename(dir.join("0Bf3qZ"), dir.join("verified.mkv")).unwrap();
        ex.note_slot_renamed(0, dir.join("verified.mkv"));
        let snap = ex.writers_snapshot();
        assert_eq!(
            snap.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>(),
            vec!["verified.mkv".to_string()],
            "an extensionless creation name must not hide a published media file"
        );
        // And the fresh open behind the pick lands on the file that is
        // actually there - the 410 half of the same finding.
        let (_f, _lease) = snap[0].1.open_read().expect("no 410 on a published name");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Sweep 8, M5: a verified external repair publishes the coverage
    /// it added, for the set's files and no others.
    ///
    /// `unpark` keeps the writer's interval map, which is right for the
    /// bytes we wrote and silent about the sparse ranges par2cmdline
    /// filled in outside the writer. A reader gated on that map goes on
    /// waiting for bytes that are already correct on disk, then
    /// zero-fills over them. Matching is by name AND length: par2's
    /// exit status says nothing about a file the recovery set does not
    /// list, and marking one covered would serve its holes as data.
    #[test]
    fn a_verified_external_repair_publishes_only_the_sets_coverage() {
        let dir = tmpdir("extcov");
        let data = payload(300_000, 11);
        let ex = Extractor::new(&dir, 2, true);
        // Two plain outputs; each keeps a hole its own writer never
        // filled - the shape external par2 repairs.
        ex.write(0, "in.set.bin", 300_000, 0, &data[..100_000])
            .unwrap();
        ex.write(1, "outside.bin", 300_000, 0, &data[..100_000])
            .unwrap();
        let snap = ex.writers_snapshot();
        let of = |n: &str| {
            snap.iter()
                .find(|(name, _)| name == n)
                .map(|(_, w)| w.clone())
                .unwrap()
        };
        assert!(!of("in.set.bin").covered(0, 300_000));
        assert!(!of("outside.bin").covered(0, 300_000));

        // A reader that holds its handle straight through the repair -
        // the trigger shape. On Unix nothing revokes it, which is the
        // point: it has to end up serving the repaired bytes.
        let target = of("in.set.bin");
        let (rf, _lease) = target.open_read().unwrap();

        // The external tool: park, fill the hole by path, unpark.
        ex.park_outputs_for_repair().unwrap();
        {
            use std::io::{Seek, SeekFrom, Write};
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(dir.join("in.set.bin"))
                .unwrap();
            f.seek(SeekFrom::Start(100_000)).unwrap();
            f.write_all(&data[100_000..]).unwrap();
        }
        ex.unpark_outputs().unwrap();
        assert!(
            !target.covered(0, 300_000),
            "unpark alone republishes nothing - that IS the finding"
        );

        // par2 verified the set and exited 0. Only its files.
        let published = ex.publish_repaired_coverage(&[("in.set.bin".to_string(), 300_000)]);
        assert_eq!(published, 1);
        assert!(
            target.covered(0, 300_000),
            "the reader must see the repaired bytes without a wait"
        );
        let mut got = vec![0u8; 200_000];
        crate::disk::read_exact_at(&rf, &mut got, 100_000).unwrap();
        assert_eq!(
            got,
            data[100_000..],
            "and the handle it held across the repair reads them"
        );
        assert!(
            !of("outside.bin").covered(0, 300_000),
            "a file outside the recovery set was never verified"
        );

        // A length we disagree about is not our file.
        assert_eq!(
            ex.publish_repaired_coverage(&[("outside.bin".to_string(), 299_999)]),
            0
        );
        assert!(!of("outside.bin").covered(0, 300_000));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn late_fallback_reconstructs_from_extracted() {
        let dir = tmpdir("latefb");
        let data = payload(120_000, 8);
        let vol = fixtures::rar5_volume(&[("f.bin", 120_000, &data, false, false)]);
        let ex = Extractor::new(&dir, 1, true);
        // Feed everything (fully extracted)…
        feed(&ex, 0, "v.rar", &vol, 5000, 31);
        // …then force materialization (as the repair path would).
        ex.materialize(0).unwrap();
        let vpath = ex.slot_path(0).expect("volume materialized");
        assert_eq!(
            std::fs::read(&vpath).unwrap(),
            vol,
            "byte-exact reconstruction"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn crc_runs_compose_out_of_order_with_duplicates() {
        let data = payload(50_000, 77);
        let cuts = [0usize, 9_001, 17_000, 17_003, 31_777, 50_000];
        let mut r = CrcRuns::default();
        // Feed the chunks in a scrambled order; completion only at the end.
        for &i in &[3usize, 0, 4, 2] {
            r.add(cuts[i] as u64, &data[cuts[i]..cuts[i + 1]]);
            assert_eq!(r.whole(50_000), None);
        }
        // A duplicate overlapping span (hold re-feed / repair rewrite of a
        // block whose other articles already landed) must not skew the
        // composition: [17_001, 40_000) is already fully covered.
        r.add(17_001, &data[17_001..40_000]);
        assert_eq!(r.whole(50_000), None);
        // A span straddling covered and fresh ranges clips to the gap.
        r.add(5_000, &data[5_000..20_000]);
        assert_eq!(r.whole(50_000), Some(crc32fast::hash(&data)));
        assert_eq!(r.whole(49_999), None, "wrong length must not verify");
    }

    /// Randomized differential against a byte-coverage oracle, for the
    /// local `coalesce_at` merge that replaced the whole-map rebuild.
    /// Rebuilding could not get the STRUCTURE wrong (it re-derived every
    /// run each time); a neighbour-only merge can, so the invariants that
    /// used to hold by construction are asserted here instead: runs stay
    /// disjoint and non-touching, their spans equal the covered byte set,
    /// and a fully covered piece composes to the same CRC as hashing the
    /// buffer whole. Spans are fed in scrambled order with duplicates and
    /// partial overlaps, which is what out-of-order article arrival and
    /// hold re-feeds actually produce.
    #[test]
    fn crc_runs_match_a_byte_oracle_under_random_feeds() {
        const LEN: usize = 40_000;
        let data = payload(LEN, 91);
        // xorshift64*, so the schedule is varied but reproducible. A
        // periodic payload would let unrelated ranges hash alike and hide
        // a mis-composition, hence payload()'s non-repeating bytes.
        let mut rng = 0x2545_F491_4F6C_DD1Du64;
        let mut next = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        for trial in 0..200 {
            let mut runs = CrcRuns::default();
            let mut covered = vec![false; LEN];
            // Enough spans that full coverage is reached most trials, and
            // heavy overlap when it is not.
            for _ in 0..24 {
                let a = (next() as usize) % LEN;
                let b = (next() as usize) % LEN;
                let (s, e) = (a.min(b), a.max(b));
                if s == e {
                    continue;
                }
                runs.add(s as u64, &data[s..e]);
                covered[s..e].iter_mut().for_each(|c| *c = true);

                // The run set is exactly the covered bytes, disjoint and
                // never touching (a touching pair means a missed merge).
                let mut prev_end: Option<u64> = None;
                let mut from_runs = vec![false; LEN];
                for (&rs, &(rl, _)) in &runs.runs {
                    assert!(rl > 0, "trial {trial}: empty run at {rs}");
                    if let Some(pe) = prev_end {
                        assert!(
                            rs > pe,
                            "trial {trial}: run at {rs} touches or overlaps {pe}"
                        );
                    }
                    prev_end = Some(rs + rl);
                    from_runs[rs as usize..(rs + rl) as usize]
                        .iter_mut()
                        .for_each(|c| *c = true);
                }
                assert_eq!(from_runs, covered, "trial {trial}: run coverage diverged");

                // Composition is exact exactly when everything is covered.
                match covered.iter().all(|&c| c) {
                    true => assert_eq!(
                        runs.whole(LEN as u64),
                        Some(crc32fast::hash(&data)),
                        "trial {trial}: full coverage composed to the wrong CRC"
                    ),
                    false => assert_eq!(
                        runs.whole(LEN as u64),
                        None,
                        "trial {trial}: an incomplete piece claimed a CRC"
                    ),
                }
            }
        }
    }

    /// The level-0 half of the CRC gate (verify_output_crc, default on):
    /// the FINAL extracted store payload - the one the outer PAR2 only
    /// vouches for as-posted - demotes to a materialized volume when its
    /// composed CRC mismatches the header value. The damaged bytes never
    /// masquerade as clean output; they land byte-exact in the volume
    /// file where the disk path (unrar / a packed-alongside par2 set)
    /// can catch them honestly. finish() itself still succeeds.
    #[test]
    fn output_crc_gate_demotes_damaged_final_store() {
        let f = payload(300_000, 91);
        let pristine_crc = crc32fast::hash(&f);
        let mut damaged = f.clone();
        // Poster damage: the header CRC was computed over the original
        // bytes, the packed data area carries the flipped ones.
        for b in &mut damaged[140_000..140_064] {
            *b ^= 0x5A;
        }
        let vol = fixtures::rar5_volume_n_crc(
            &[("F.mkv", 300_000, &damaged, false, false, Some(pristine_crc))],
            0,
        );
        let dir = tmpdir("outcrcbad");
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "o.rar", &vol, 7000, 31);
        let rep = ex.finish().unwrap();
        assert_eq!(rep.fallbacks.len(), 1, "{:?}", rep.fallbacks);
        assert!(
            rep.fallbacks[0].1.contains("failed its stored CRC"),
            "{:?}",
            rep.fallbacks
        );
        assert!(!dir.join("F.mkv").exists(), "corrupt output survived");
        assert_eq!(
            std::fs::read(dir.join("o.rar")).unwrap(),
            vol,
            "volume must materialize byte-exact as packed"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The gate's clean half: a level-0 store payload whose CRC matches
    /// extracts exactly as before - no fallback, no volume on disk, no
    /// behavioral difference beyond the (already-flowing) composition.
    #[test]
    fn output_crc_gate_clean_payload_passes() {
        let f = payload(300_000, 92);
        let vol = fixtures::rar5_volume_n_crc(
            &[(
                "F.mkv",
                300_000,
                &f,
                false,
                false,
                Some(crc32fast::hash(&f)),
            )],
            0,
        );
        let dir = tmpdir("outcrcok");
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "o.rar", &vol, 7000, 32);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("F.mkv")).unwrap(), f);
        assert!(!dir.join("o.rar").exists(), "one-pass: no volume file");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The reversibility contract: with verify_output_crc off (env
    /// escape hatch / setter) the damaged payload ships exactly as
    /// today - clean pass, damaged bytes and all. The env PARSE is
    /// asserted on the pure helper for the same process-global-state
    /// reason as `nested_disabled_by_env`.
    #[test]
    fn output_crc_gate_off_restores_todays_behavior() {
        assert!(output_crc_env_off_value(Some("1")));
        assert!(!output_crc_env_off_value(Some("0")));
        assert!(!output_crc_env_off_value(None));
        let f = payload(300_000, 93);
        let pristine_crc = crc32fast::hash(&f);
        let mut damaged = f.clone();
        for b in &mut damaged[140_000..140_064] {
            *b ^= 0x5A;
        }
        let vol = fixtures::rar5_volume_n_crc(
            &[("F.mkv", 300_000, &damaged, false, false, Some(pristine_crc))],
            0,
        );
        let dir = tmpdir("outcrcoff");
        let ex = Extractor::new(&dir, 1, true);
        assert!(
            ex.inner.lock().unwrap().verify_output_crc,
            "gate must default on"
        );
        ex.set_verify_output_crc(false);
        feed(&ex, 0, "o.rar", &vol, 7000, 33);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("F.mkv")).unwrap(), damaged);
        assert!(!dir.join("o.rar").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A LEVEL-0 RAR4 store archive now carries its header CRC through to
    /// the output gate (finding 9): the v4 parser retains the whole-file
    /// CRC, so a clean payload verifies IN-STREAM (no demote, no double
    /// I/O) and extracts, while damaged bytes are caught. This closes the
    /// old gap where a top-level RAR4 store output bypassed the gate
    /// entirely and shipped pre-packed damage with rc=0.
    #[test]
    fn output_crc_gate_verifies_level0_rar4() {
        // Clean: composed CRC matches the header, one-pass extract, no demote.
        let dir = tmpdir("outcrc-rar4");
        let data = payload(60_000, 95);
        let v4 = fixtures::rar4_volume(&[("old.avi", 60_000, &data, false, false)]);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &v4, 5000, 19);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("old.avi")).unwrap(), data);
        assert!(!dir.join("v.rar").exists(), "one-pass: no volume file");
        std::fs::remove_dir_all(&dir).unwrap();

        // Damaged: the header CRC was computed over the pristine bytes, the
        // packed data area carries flipped ones - the gate must demote to a
        // byte-exact materialized volume instead of shipping corrupt output.
        let dir = tmpdir("outcrc-rar4-bad");
        let mut damaged = data.clone();
        for b in &mut damaged[30_000..30_064] {
            *b ^= 0x5A;
        }
        let mut v4b = fixtures::rar4_volume(&[("old.avi", 60_000, &data, false, false)]);
        // Splice the damaged payload in place of the pristine data area,
        // keeping the pristine-derived header CRC.
        let off = {
            let mut m = crate::rar::VolumeMapper::new(v4b.len() as u64);
            m.feed(0, &v4b);
            m.entries[0].data_off as usize
        };
        v4b[off..off + 60_000].copy_from_slice(&damaged);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &v4b, 5000, 23);
        let rep = ex.finish().unwrap();
        assert_eq!(rep.fallbacks.len(), 1, "{:?}", rep.fallbacks);
        assert!(
            rep.fallbacks[0].1.contains("failed its stored CRC"),
            "{:?}",
            rep.fallbacks
        );
        assert!(
            !dir.join("old.avi").exists(),
            "corrupt RAR4 output survived"
        );
        assert_eq!(std::fs::read(dir.join("v.rar")).unwrap(), v4b);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Repair-awareness at the CrcRuns level: first-writer-wins is exact
    /// for duplicate re-feeds, but a mapped-repair rewrite carries
    /// DIFFERENT bytes for a range already composed - overwrite must
    /// replace it, orphan the entangled remainder of the run as stale
    /// gaps, and let recomputation (or a re-feed of current bytes)
    /// restore a whole-piece value that reflects the healed file.
    #[test]
    fn crc_runs_overwrite_recomposes_repaired_range() {
        let good = payload(50_000, 78);
        let mut bad = good.clone();
        for b in &mut bad[20_000..20_100] {
            *b ^= 0x5A;
        }
        let mut r = CrcRuns::default();
        // Wire-damaged bytes compose first, as one coalesced run.
        r.add(0, &bad);
        assert_eq!(r.whole(50_000), Some(crc32fast::hash(&bad)));
        // The repair rewrite replaces the damaged range; plain add()
        // would clip it as a duplicate and keep the stale value.
        r.overwrite(19_500, &good[19_500..21_000]);
        assert_eq!(r.whole(50_000), None, "orphaned sub-ranges must gap");
        // A duplicate re-feed of current bytes may re-cover part of a
        // stale range - that part needs no recomputation.
        r.add(0, &good[..10_000]);
        let gaps = r.take_stale_gaps();
        assert_eq!(gaps, vec![(10_000, 19_500), (21_000, 50_000)]);
        for &(s, e) in &gaps {
            assert!(r.add_run(s, e - s, crc32fast::hash(&good[s as usize..e as usize])));
        }
        assert_eq!(r.whole(50_000), Some(crc32fast::hash(&good)));
    }

    /// THE repair regression (level 0): a wire-damaged span routes into
    /// the output unverified, mapped PAR2 repair rewrites the same range
    /// with correct bytes via patch_volume_span, and the file on disk
    /// heals - the output gate must NOT demote on the stale pre-repair
    /// CRC. Fails against a composition that keeps first-writer-wins
    /// across the repair; passes with the repair-aware overwrite +
    /// verify-time recompute.
    #[test]
    fn output_crc_gate_survives_mapped_repair() {
        let f = payload(300_000, 96);
        let vol = fixtures::rar5_volume_n_crc(
            &[(
                "F.mkv",
                300_000,
                &f,
                false,
                false,
                Some(crc32fast::hash(&f)),
            )],
            0,
        );
        // The data area is the payload verbatim: locate the damage range
        // inside it and verify the arithmetic before flipping.
        let data_off = vol.len() - 300_000 - 8;
        let (ds, de) = (data_off + 140_000, data_off + 140_064);
        assert_eq!(&vol[ds..de], &f[140_000..140_064], "fixture layout moved");
        let mut wire = vol.clone();
        for b in &mut wire[ds..de] {
            *b ^= 0x3C;
        }
        let dir = tmpdir("outcrcrepair");
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "o.rar", &wire, 7000, 41);
        // Mapped repair rebuilds the damaged range and patches it in.
        ex.patch_volume_span(0, ds as u64, &vol[ds..de]).unwrap();
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks.is_empty(),
            "repaired job must not demote on a stale CRC: {:?}",
            rep.fallbacks
        );
        assert_eq!(std::fs::read(dir.join("F.mkv")).unwrap(), f);
        assert!(!dir.join("o.rar").exists(), "one-pass: no volume file");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The nested twin of the repair regression: the wire damage lands
    /// inside a NESTED store set's data (routed through the child), the
    /// patch re-enters through the parent, and BOTH compositions - the
    /// parent's level-0 entry for the inner archive file and the child's
    /// piece for the payload - must shed their stale values. The
    /// depth>0 half predates the output gate: first-writer-wins across
    /// a repair would false-demote here on its own.
    #[test]
    fn nested_crc_gate_survives_mapped_repair() {
        let f = payload(400_000, 97);
        let whole = crc32fast::hash(&f);
        let iv = [
            // WinRAR-true geometry: volume 0 carries one byte more (its
            // main header has no volume-number field).
            fixtures::rar5_volume_n_crc(
                &[(
                    "F.mkv",
                    400_000,
                    &f[..150_001],
                    false,
                    true,
                    Some(crc32fast::hash(&f[..150_001])),
                )],
                0,
            ),
            fixtures::rar5_volume_n_crc(
                &[(
                    "F.mkv",
                    400_000,
                    &f[150_001..300_001],
                    true,
                    true,
                    Some(crc32fast::hash(&f[150_001..300_001])),
                )],
                1,
            ),
            fixtures::rar5_volume_n_crc(
                &[("F.mkv", 400_000, &f[300_001..], true, false, Some(whole))],
                2,
            ),
        ];
        // Outer entries carry CRCs too, so the level-0 gate composes
        // the inner-archive files alongside the child's payload gate.
        let outer = fixtures::rar5_volume_n_crc(
            &[
                (
                    "i.part1.rar",
                    iv[0].len() as u64,
                    &iv[0],
                    false,
                    false,
                    Some(crc32fast::hash(&iv[0])),
                ),
                (
                    "i.part2.rar",
                    iv[1].len() as u64,
                    &iv[1],
                    false,
                    false,
                    Some(crc32fast::hash(&iv[1])),
                ),
                (
                    "i.part3.rar",
                    iv[2].len() as u64,
                    &iv[2],
                    false,
                    false,
                    Some(crc32fast::hash(&iv[2])),
                ),
            ],
            0,
        );
        // Damage 64 bytes of iv[1]'s DATA area as it sits in the outer
        // volume: iv[1] starts at the third RAR5 signature, its data
        // area holds f[150_001..300_001] verbatim before the 8-byte end
        // block. Verify the arithmetic before flipping.
        let sig_at: Vec<usize> = (0..outer.len().saturating_sub(8))
            .filter(|&i| outer[i..].starts_with(b"Rar!\x1a\x07\x01\x00"))
            .collect();
        assert_eq!(sig_at.len(), 4, "outer + three inner signatures");
        let iv1_data = sig_at[2] + (iv[1].len() - 150_000 - 8);
        let (ds, de) = (iv1_data + 70_000, iv1_data + 70_064);
        assert_eq!(&outer[ds..de], &f[220_001..220_065], "fixture layout moved");
        let mut wire = outer.clone();
        for b in &mut wire[ds..de] {
            *b ^= 0x3C;
        }
        let dir = tmpdir("nestcrcrepair");
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "o.rar", &wire, 7000, 43);
        ex.patch_volume_span(0, ds as u64, &outer[ds..de]).unwrap();
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks.is_empty(),
            "repaired nested job must not demote on a stale CRC: {:?}",
            rep.fallbacks
        );
        assert_eq!(std::fs::read(dir.join("F.mkv")).unwrap(), f);
        assert_eq!(dir_files(&dir), vec!["F.mkv".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The recompute path must keep the gate's teeth: a repaired file
    /// with SEPARATE pre-packed damage (the header CRC never matched the
    /// packed bytes) still demotes after the repair. Dropping the
    /// orphaned runs instead of recomputing them would read this file as
    /// unverifiable and clean-pass the damage the gate exists to catch.
    #[test]
    fn output_crc_gate_still_demotes_prepacked_damage_after_repair() {
        let f = payload(300_000, 98);
        let pristine_crc = crc32fast::hash(&f);
        let mut packed = f.clone();
        // Poster damage at 50k: baked into the posted volume.
        for b in &mut packed[50_000..50_032] {
            *b ^= 0xA5;
        }
        let vol = fixtures::rar5_volume_n_crc(
            &[("F.mkv", 300_000, &packed, false, false, Some(pristine_crc))],
            0,
        );
        let data_off = vol.len() - 300_000 - 8;
        let (ds, de) = (data_off + 140_000, data_off + 140_064);
        assert_eq!(
            &vol[ds..de],
            &packed[140_000..140_064],
            "fixture layout moved"
        );
        // Wire damage at 140k on top; repair rebuilds it as-posted.
        let mut wire = vol.clone();
        for b in &mut wire[ds..de] {
            *b ^= 0x3C;
        }
        let dir = tmpdir("outcrcrepairbad");
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "o.rar", &wire, 7000, 47);
        ex.patch_volume_span(0, ds as u64, &vol[ds..de]).unwrap();
        let rep = ex.finish().unwrap();
        assert_eq!(rep.fallbacks.len(), 1, "{:?}", rep.fallbacks);
        assert!(
            rep.fallbacks[0].1.contains("failed its stored CRC"),
            "{:?}",
            rep.fallbacks
        );
        assert!(!dir.join("F.mkv").exists(), "corrupt output survived");
        assert_eq!(
            std::fs::read(dir.join("o.rar")).unwrap(),
            vol,
            "volume must materialize byte-exact as posted (wire damage healed)"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
