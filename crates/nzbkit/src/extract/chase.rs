//! The RAR volume chase: attaching a posted multi-volume set to a chase
//! controller, the worker that walks volume to volume, the spans it
//! writes, and the teardown/finish bookkeeping.
//!
//! Split out of the 19,920-line `extract.rs` under the TODO 43 recipe:
//! a verbatim move of the methods, not a redesign.

use super::*;
use crate::sync::MutexExt;
use tracing::info;

/// The forfeit reason a chase raises when the shared held-bytes budget
/// is still over after the drop-behind trim has had its pass.
///
/// Load-bearing as a STRING twice over, which is why it is a constant
/// and not a literal at each of its three raise sites. The daemon's
/// volume remediation keys off the "held-bytes cap" substring (a bare
/// wording once matched nothing there, demoting the volumes and then
/// shipping the job with no payload and exit 0), and `chase_teardown`
/// compares the WHOLE reason to decide whether the in-stream partials
/// may be kept for the disk pass to resume from - a test no other
/// forfeit reason may pass. The 7z and zip arms raise the same reason
/// down their own path (`sevenz_fallback_set`, whose sink teardown
/// applies the identical test through `chase_resume_ok`).
pub(super) const HELD_BYTES_CAP_CHASE: &str = "held-bytes cap: chase memory";

/// Escape hatch for [`Extractor::relieve_by_child_chase`]:
/// `NZBFAST_NO_CHASE_RELIEF=1` restores the victim order this repo had
/// before 22 Aug 2026, where a held-bytes breach was resolved by
/// whichever call site happened to notice it first. One binary, two
/// arms, which is what the A/B in TODO 220 needs.
pub(super) fn chase_relief_env_off() -> bool {
    chase_relief_env_off_value(std::env::var("NZBFAST_NO_CHASE_RELIEF").ok().as_deref())
}

/// Pure parse of the relief escape-hatch value (same rationale as the
/// other gates in `extract::config`: the parse is tested, the read is
/// not).
pub(super) fn chase_relief_env_off_value(v: Option<&str>) -> bool {
    v == Some("1")
}

/// One drop-behind trim spill, planned under the routing lock and
/// WRITTEN after it drops (TODO 37 item 1, 23 Aug 2026). The prefix
/// `[at, at+len)` of `buf` is still in RAM while this is queued - only
/// marked pending there, which is what credits the holds budget early -
/// and leaves it in [`Extractor::spill_trimmed`], in bounded chunks,
/// ending in a commit that re-proves the buffer did not move (`seq` is
/// the rewrite tripwire) before `base` advances. A failed write commits
/// nothing: the bytes stay in RAM and the budget is re-charged.
pub(super) struct TrimSpill {
    pub(super) slot: usize,
    pub(super) buf: Arc<FrontierBuffer>,
    pub(super) writer: Arc<FileWriter>,
    pub(super) at: u64,
    pub(super) len: usize,
    pub(super) seq: u64,
    /// `refeed_active` at plan time: the spill's placement is surfaced
    /// through `late_placements` exactly as `plain_span` would have.
    pub(super) refeed: bool,
    /// RAR trims count into `chase_trimmed`; 7z trims do not.
    pub(super) count_trimmed: bool,
}

impl Extractor {
    /// Mapping-mode span: feed headers, extract mapped parts, hold the
    /// rest. With `sink` set (the hot write path), mapped writes queue as
    /// jobs / child forwards for after the lock; without (drain/fallback
    /// paths), writer writes run inline and child forwards queue as owned
    /// pending jobs (the child cannot be called under our lock).
    pub(super) fn rar_span(
        &self,
        inner: &mut Inner,
        slot: usize,
        offset: u64,
        data: &[u8],
        sink: Option<(&mut Vec<WriteJob>, &mut Vec<FwdSpan>)>,
        repair: bool,
        article_crc: Option<u32>,
    ) -> io::Result<()> {
        let progressed = inner.slots[slot]
            .mapper
            .as_mut()
            .unwrap()
            .feed(offset, data);
        if progressed {
            // Everything the shape badge reports about the archive itself
            // is known here, the instant the headers parse: the version
            // is a property of the volume, the method and encryption of
            // each entry. Latching only on parse progress keeps this off
            // the per-span path.
            let m = inner.slots[slot].mapper.as_ref().unwrap();
            let mut bits = match m.version {
                Some(RarVersion::V5) => SH_RAR5,
                Some(RarVersion::V4) => SH_RAR4,
                None => 0,
            };
            for e in &m.entries {
                if e.is_dir {
                    continue;
                }
                bits |= match e.method {
                    Method::Store => SH_STORE,
                    Method::Compressed => SH_COMPRESSED,
                };
                if e.encrypted {
                    bits |= SH_ENCRYPTED;
                }
                // The identity fact in the same header: the whole-file
                // CRC32 of an inner file, which is an exact key into the
                // open release databases (see `srrdb`). Encrypted
                // entries are skipped - RAR5 may tweak the stored CRC so
                // it cannot fingerprint the plaintext, and a header-
                // encrypted archive never reaches here at all, which is
                // precisely the `-hp` case the oracle cannot serve.
                if let (false, Some(crc)) = (e.encrypted, e.file_crc) {
                    self.shape.note_crc(&e.name, crc);
                }
            }
            self.shape.note(self.depth, bits);
        }
        let stashed = self.retain_header_bytes(inner, slot, offset, data);
        // Header bytes parked in RAM hold this article's record exactly
        // like a data hold does: report the span Held (same refeed
        // exclusion as the hold-push sites) so the article parks instead
        // of dropping to Persist::No. It completes if the stash ever
        // lands on disk - the fallback reconstruction surfaces identity
        // placements for it - and an article whose stash stays in RAM
        // just refetches on resume, which was its record before too.
        if stashed > 0 && !inner.refeed_active {
            inner.span_held = true;
        }
        // A slot that already carries a blocker takes the blocker's route
        // below instead of this one. Its reason is the specific, actionable
        // one - encrypted headers ask the user for a password, compressed
        // gets a chase - and reporting the budget here in its place turned
        // "this archive needs a password" into a failed job that ran unrar
        // with no password. Deferring cannot leave the budget over: both of
        // those routes release this same charge.
        let blocked = inner.slots[slot].mapper.as_ref().unwrap().blocker.is_some();
        if stashed > 0
            && !blocked
            && inner.budget.over()
            && !self.page_out_holds(inner)
            && !self.relieve_by_chase(inner, slot)
        {
            // The header stash charges the same budget as holds, and it
            // grows on remote data: service blocks (a RAR recovery
            // record) and anything past the end-of-archive marker sit
            // below the parse cursor, so they are kept for the life of
            // the slot - and once the mapper is complete EVERY byte
            // outside a data area lands here. Over the cap the volume
            // materializes, which puts the stash on disk instead of RAM.
            // The reason MUST carry "held-bytes cap": this is that same
            // budget, and both the caller's volume-level remediation and
            // `nested_reason` key off that substring. A novel string
            // would demote the volumes and then ship the job with no
            // payload and exit 0.
            self.fallback_slot_or_group(inner, slot, "held-bytes cap: header stash")?;
            if matches!(inner.slots[slot].mode, SlotMode::Discard) {
                return Ok(());
            }
            return self.plain_span(inner, slot, offset, data);
        }

        if let Some(b) = inner.slots[slot].mapper.as_ref().unwrap().blocker.clone() {
            // A password blocker is the one shape fact no entry scan can
            // reach: nothing parsed, so say "encrypted" from the blocker.
            if matches!(b, MapBlocker::EncryptedHeaders | MapBlocker::BadPassword) {
                self.shape.note(self.depth, SH_ENCRYPTED);
            }
            // Increment A: a password-shaped blocker with the candidate
            // probe installed parks instead of demoting - the password
            // may be sitting in a sidecar of this very NZB, and a
            // Verified hit re-keys the mapper with every byte still in
            // RAM. A miss resolves through the exact demote below, at
            // budget pressure or at finish.
            if self.try_pw_await(inner, slot, &b, offset, data)? {
                return Ok(());
            }
            // Phase 2: a compressed RAR5 inner archive gets a chase
            // instead of a demotion - the slot flips to RarChase, its
            // seen-so-far bytes seed the frontier buffer, and this span
            // (whose header part the parser just consumed) feeds it too.
            if self.try_attach_chase(inner, slot, &b)? {
                return self.chase_span(inner, slot, offset, data);
            }
            self.fallback_slot_or_group(inner, slot, blocker_reason(&b))?;
            if matches!(inner.slots[slot].mode, SlotMode::Discard) {
                return Ok(());
            }
            // The span's bytes reach the volume file via header_spans +
            // holds + extracted read-back inside the fallback; anything in
            // this span not covered there writes through now.
            return self.plain_span(inner, slot, offset, data);
        }

        // Group assignment happens at first-entry parse (inner name),
        // routed through the alias map so a volume whose first entry is a
        // continuation of an already-linked archive joins that group.
        if inner.slots[slot].group.is_none()
            && !inner.slots[slot]
                .mapper
                .as_ref()
                .unwrap()
                .entries
                .is_empty()
        {
            let raw = inner.slots[slot].mapper.as_ref().unwrap().entries[0]
                .name
                .clone();
            let key = Self::canon_key(inner, &raw);
            inner.slots[slot].group = Some(key.clone());
            let grp = inner.groups.entry(key.clone()).or_insert_with(|| Group {
                slots: Vec::new(),
                bases: HashMap::new(),
                resolve_stamp: None,
                arith_provisional: HashMap::new(),
                arith_ever: false,
                fallback: false,
                fallback_reason: None,
                out_names: HashMap::new(),
                routed: HashMap::new(),
                routed_plain: HashMap::new(),
                chase: None,
                zip_splits_open: Vec::new(),
            });
            grp.slots.push(slot);
            if grp.fallback {
                // Joined a group that already fell back.
                self.fallback_slot(inner, slot)?;
                if matches!(inner.slots[slot].mode, SlotMode::Discard) {
                    return Ok(());
                }
                return self.plain_span(inner, slot, offset, data);
            }
        }

        if progressed {
            self.link_split_names(inner, slot)?;
            if let Some(key) = inner.slots[slot].group.clone() {
                self.reresolve(inner, &key)?;
            }
        }
        if inner.slots[slot].mode == SlotMode::Rar {
            self.extract_span(inner, slot, offset, data, sink, repair, article_crc)?;
        } else if matches!(inner.slots[slot].mode, SlotMode::RarFallback) {
            // The reresolve above demoted this very group (arithmetic
            // premise contradicted by the parse progression THIS span
            // caused). The fallback drained the holds and read back the
            // extracted bytes, but the current span is in neither -
            // write it through, same as the blocker routes above (the
            // already-stashed header part rewrites identical bytes).
            self.plain_span(inner, slot, offset, data)?;
        }
        Ok(())
    }
    /// Attach the chasing decompressor to a slot whose mapper just hit a
    /// blocker, when the blocker is a compressed RAR5 payload the RAR
    /// engine can stream: the slot flips to `RarChase`, everything it has
    /// seen so far (header stash + holds) seeds a frontier buffer, and
    /// the group's chase worker (spawned on first attach) will pull this
    /// volume at its index. Returns false when ineligible - the caller
    /// then demotes exactly as before the chase existed. Eligible only
    /// when the blocker fired on the archive's FIRST entry: a mixed
    /// store/compressed set has already routed store members, and
    /// re-extracting those through a chase is out of scope. (An
    /// all-compressed multi-entry archive is NOT excluded by the
    /// single-entry check below: the blocker fires on the first parsed
    /// entry, so exactly one entry exists at attach time, and the
    /// sequence driver then decodes every member through its own sink.)
    ///
    /// Runs at depth 0 too (the top-level analogue of TODO 37 step 1):
    /// a POSTED compressed RAR chases, its decoded members land in the
    /// level-1 child and promote to the root output - the same rails
    /// nested chases have always used. Nothing about the engine is
    /// depth-specific; the old guard predated the root promote wiring.
    ///
    /// A set larger than the holds cap no longer has to demote: the
    /// engine decodes split members incrementally and publishes how much
    /// of each volume it is finished with, and [`Self::rar_trim_set`]
    /// releases those bytes into the volumes' own files under budget
    /// pressure. What still demotes is a set whose ARRIVALS run so far
    /// ahead of the decode that the live window alone fills the cap -
    /// trimming declines there, and declining is how it says so.
    fn try_attach_chase(&self, inner: &mut Inner, slot: usize, b: &MapBlocker) -> io::Result<bool> {
        if (self.depth == 0 && !inner.top_chase_on)
            || !inner.nested_on
            || !inner.chase_on
            || inner.protect_sources
            || !matches!(b, MapBlocker::NotStore)
            || !matches!(inner.slots[slot].mode, SlotMode::Rar)
            || inner.slots[slot].group.is_some()
            // TODO 211 (b): the chase drives one frontier per VOLUME and
            // a split head's bytes arrive through N alias slots; a
            // compressed split demotes and the (a) rescue joins it.
            || inner.slots[slot].split_head.is_some()
            || inner.slots[slot].size == 0
            || inner.self_weak.upgrade().is_none()
        {
            return Ok(false);
        }
        let (name, vol_index, v4, base) = {
            let Some(m) = inner.slots[slot].mapper.as_ref() else {
                return Ok(false);
            };
            let v4 = match m.version {
                Some(RarVersion::V5) => false,
                Some(RarVersion::V4) => true,
                None => return Ok(false),
            };
            if m.entries.len() != 1 {
                return Ok(false);
            }
            let e = &m.entries[0];
            // An encrypted member without a password can't decode anywhere.
            if e.method != Method::Compressed || (e.encrypted && inner.password.is_none()) {
                return Ok(false);
            }
            // RAR4 headers carry no volume number; the set's order lives in
            // the volume NAMES (.rar < .r00 < .r01, .partNN). RAR5's header
            // number is authoritative and survives renames, so it stays
            // preferred there.
            let vol_index = if v4 {
                Self::v4_vol_index(&inner.slots[slot].name)
            } else {
                m.volume_number.unwrap_or(0) as usize
            };
            (e.name.clone(), vol_index, v4, m.archive_base())
        };
        let key = Self::canon_key(inner, &name);
        let grp = inner.groups.entry(key.clone()).or_insert_with(|| Group {
            slots: Vec::new(),
            bases: HashMap::new(),
            resolve_stamp: None,
            arith_provisional: HashMap::new(),
            arith_ever: false,
            fallback: false,
            fallback_reason: None,
            out_names: HashMap::new(),
            routed: HashMap::new(),
            routed_plain: HashMap::new(),
            chase: None,
            zip_splits_open: Vec::new(),
        });
        if grp.fallback {
            return Ok(false); // joins the fallback via today's path
        }
        // A healthy group with mapped (non-chased) members claiming this
        // first-entry name is a mixed set - out of scope, demote.
        if grp.chase.is_none() && !grp.slots.is_empty() {
            return Ok(false);
        }
        let fresh = grp.chase.is_none();
        let ctl = grp
            .chase
            .clone()
            .unwrap_or_else(|| Arc::new(ChaseCtl::new(v4)));
        // A set whose volumes disagree on the RAR family is not a set.
        if ctl.v4 != v4 {
            return Ok(false);
        }
        {
            let st = ctl.shared.lock_ok();
            // A duplicate volume-index claim means the set's ordering is
            // unreliable; an aborted chase accepts no new volumes.
            if st.vols.contains_key(&vol_index) || st.aborted {
                return Ok(false);
            }
        }
        // Commit.
        let size = inner.slots[slot].size;
        let grp = inner.groups.get_mut(&key).unwrap();
        grp.chase = Some(ctl.clone());
        grp.slots.push(slot);
        inner.slots[slot].group = Some(key.clone());
        inner.slots[slot].mode = SlotMode::RarChase;
        let buf = Arc::new(FrontierBuffer::new_gated(
            size,
            self.chase_gate(inner, slot),
            // Arms the stalled-chase cold spill (RAR chases only - the
            // forward-only reader is what makes "beyond the gap" cold).
            Some(inner.scratch.clone()),
            Some(inner.self_weak.clone()),
        ));
        // §156.1: a terminal verdict that landed before this attach
        // still marks the volume it doomed.
        if inner.slots[slot].article_lost {
            buf.mark_lost();
        }
        // A `ChaseReadPause` is in force: this volume is born paused.
        // Set HERE rather than at registration so the window between the
        // buffer existing and `st.vols.insert` below - which includes the
        // seeding loop and its failure return - is covered too. See
        // [`Extractor::pause_chase_reads`] for why the pause has to
        // reach volumes that arrive during it.
        if inner.chase_reads_paused {
            buf.set_paused(true);
        }
        // Seed with everything already seen. The header stash MOVES in
        // (like the holds): the buffer keeps every byte from offset 0
        // for the life of the chase - reads never consume it, and a
        // demotion materializes the volume straight out of it - so a
        // second RAM copy would only double-charge the shared budget
        // that the stash is now billed to. Nothing reads `header_spans`
        // outside `SlotMode::Rar`, which this slot just left.
        let mut stored = 0usize;
        let headers = std::mem::take(&mut inner.slots[slot].header_spans);
        let holds = std::mem::take(&mut inner.slots[slot].holds);
        inner.slots[slot].pre_bytes = 0;
        // Both stashes are OUT of the slot now, so a reclaim that fails
        // (a scratch read error) must uncharge everything it did not
        // read: dropping the rest frees the memory but leaves the budget
        // - and the scratch reservation - charged for it.
        let mut rest = headers.into_iter().chain(holds);
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
        // Install the ChaseSlot BEFORE the failure return. The slot was
        // committed to `SlotMode::RarChase` at the top of this block, so
        // a bail-out that leaves `chase` at None puts the slot in a state
        // `chase_span` calls impossible: every later span for it takes
        // the `_ =>` arm, which debug-asserts and silently DROPS the
        // bytes in release. With the slot installed the failure demotes
        // through the ordinary paths instead.
        inner.budget.add(stored);
        inner.slots[slot].chase = Some(ChaseSlot {
            buf: buf.clone(),
            charged: stored,
            dropped: Vec::new(),
            dropped_as: String::new(),
        });
        if let Some(e) = failed {
            for (_, span) in rest {
                Self::uncharge_span(inner, &span);
            }
            // The frontier is short bytes that can never arrive now, so
            // fail it: a read that blocks on the gap errors out rather
            // than waiting for a volume this attach never finished.
            buf.abort("held bytes could not be reclaimed");
            return Err(e);
        }
        // The stash and the holds can already disagree with each other if
        // a repair landed before the chase attached. Nothing has been
        // decoded yet, so this is the cheap case: never start. (Nothing
        // has been READ yet either, so the buffer's own served-aware
        // `conflicted` cannot see it - ask for any rewrite at all.)
        let seeded_conflict = buf.rewritten().is_some();
        // An SFX volume (TODO 94 C follow-up): the archive starts `base`
        // bytes into the file, behind the launcher stub. The engine never
        // learns that - `chase_next_volume*` hands it an `OffsetSource`
        // whose range 0 is the signature - so the base is recorded here
        // for the one place the engine's coordinates come back out, the
        // watermark publish in `chase_worker`. Registered BEFORE the
        // volume itself, so the worker cannot see a volume whose base it
        // cannot look up.
        ctl.bases.lock_ok().insert(vol_index, base);
        {
            let mut st = ctl.shared.lock_ok();
            st.vols.insert(vol_index, ChaseVol { buf, size, slot });
        }
        ctl.cv.notify_all();
        if fresh {
            let weak = inner.self_weak.clone();
            let pw = inner.password.clone();
            let ctl2 = ctl.clone();
            let key2 = key.clone();
            let handle = std::thread::Builder::new()
                .name("nzb-chase".into())
                .spawn(move || Self::chase_worker(weak, ctl2, key2, pw))
                .map_err(io::Error::other)?;
            *ctl.worker.lock_ok() = Some(handle);
        }
        if seeded_conflict {
            self.fallback_slot_or_group(inner, slot, "repair rewrote chased bytes")?;
            return Ok(true);
        }
        if inner.budget.over() {
            // A volume joining a chase already in flight: the engine may
            // be far past earlier volumes, so try the drop-behind before
            // giving up on the whole set.
            self.rar_trim_set(inner, &ctl, true)?;
        }
        if inner.budget.over() {
            // Same shared budget as the holds cap, so the reason carries
            // the same substring: the caller keys volume-level remediation
            // off "held-bytes cap", and the bare wording this used to have
            // matched nothing, demoting the volumes and then shipping the
            // job with no payload and exit 0.
            self.fallback_slot_or_group(inner, slot, HELD_BYTES_CAP_CHASE)?;
        }
        Ok(true)
    }
    /// Route a chased slot's span into its frontier buffer, charging the
    /// shared budget for the retained delta; a breach demotes the whole
    /// group to materialized volumes. A span landing after demotion
    /// writes through the slot's current mode like any late span.
    pub(super) fn chase_span(
        &self,
        inner: &mut Inner,
        slot: usize,
        offset: u64,
        data: &[u8],
    ) -> io::Result<()> {
        // Anything below the trim point is not the buffer's to reconcile
        // - it is already in the archive file. A late span there is
        // either a routing re-feed (which cannot happen after a trim:
        // re-feeds all land at classification) or a PAR2 repair rewrite,
        // and we cannot tell cheaply. So take the safe reading: write it
        // to the file, where it OVERWRITES whatever the trim spilled, and
        // force the forfeit below - the engine may already have decoded
        // from the stale copy. Same shape and same direction as the
        // conflict guard, which is what actually fires here.
        //
        // Unreachable in practice: `patch_volume_span` refuses a SevenZ
        // slot outright, and at depth 0 the caller materializes a chased
        // slot before repair runs at all.
        let trimmed = inner.slots[slot]
            .chase
            .as_ref()
            .map(|ch| (ch.buf.clone(), ch.buf.base()));
        if let Some((buf, base)) = trimmed
            && offset < base
        {
            let n = crate::disk::chunk_len(base - offset, data.len());
            buf.mark_conflict();
            self.plain_span(inner, slot, offset, &data[..n])?;
        }
        let Some(ch) = inner.slots[slot].chase.as_mut() else {
            return match inner.slots[slot].mode {
                SlotMode::Plain | SlotMode::RarFallback => {
                    self.plain_span(inner, slot, offset, data)
                }
                // Still a chase mode but the chase is gone means finish()
                // already took it on success, so this span goes nowhere -
                // and the conflict check that would catch a differing
                // rewrite lives on the chase we no longer have. Nothing in
                // this crate reaches it (the daemon is strictly download ->
                // repair -> finish), but that sequencing is a caller
                // contract, so assert rather than trust it.
                _ => {
                    debug_assert!(
                        false,
                        "span for slot {slot} arrived after finish() took its chase - \
                         a differing rewrite here would go undetected"
                    );
                    Ok(())
                }
            };
        };
        let stored = ch.buf.write_span(offset, data);
        let conflicted = ch.buf.conflicted();
        if stored > ch.charged {
            let delta = stored - ch.charged;
            ch.charged = stored;
            inner.budget.add(delta);
        }
        if conflicted {
            // A repair rewrote bytes the chase had already decoded. The
            // buffer now holds the corrected copy, so materializing the
            // volume out of it is exact and the disk pass re-extracts it;
            // carrying on would ship what was decoded from the stale
            // bytes, with every CRC on the path still passing.
            return self.chase_forfeit(inner, slot, "repair rewrote chased bytes");
        }
        // Proactive cold spill: a RAR chase WEDGED behind an unfillable
        // gap is holding bytes nothing can decode - as cold as parked
        // ciphertext - so they page to the holds scratch beyond a small
        // window instead of riding RAM to the cap (the 11 Aug 2026 soak
        // held a whole damaged 3.5 GB set resident this way). §156.1:
        // the wedge test is what arms this, not the verdict alone - a
        // healthy chase that merely shares a job with a lost article
        // used to skim its entire pile through scratch and pread it
        // straight back (527 MB of doubled I/O on the A/B's 614 MB
        // set). A gap that does fill later (retry, repair) reads paged
        // spans straight back through the frontier buffer; a demote
        // materializes from them byte-exact. The paging itself runs on
        // the detached pager (§156.3b) - this path holds the extractor
        // lock, and the pass does disk I/O.
        if inner.lost_articles.load(Ordering::Relaxed)
            && inner.slots[slot].sevenz.is_none()
            && inner.budget.len() > chase_stall_spill(inner.budget.cap())
            && let Some(ctl) = Self::rar_chase_of(inner, slot)
            && Self::chase_first_doomed(&ctl).is_some()
            && let Some(me) = inner.self_weak.upgrade()
        {
            me.wake_pager();
        }
        if inner.budget.over() {
            // Drop-behind first: an archive whose decode is keeping up
            // has a long prefix nobody will read again, and releasing it
            // is what lets a container larger than the cap stream at all.
            if let Some(ctl) = inner.slots[slot].sevenz.clone() {
                self.sevenz_trim_set(inner, &ctl)?;
            } else if let Some(ctl) = Self::rar_chase_of(inner, slot) {
                self.rar_trim_set(inner, &ctl, true)?;
            }
        }
        if Self::breach_stands(inner) {
            // Same shared budget as the holds cap, so the reason carries
            // the same substring: the caller keys volume-level remediation
            // off "held-bytes cap", and the bare wording this used to have
            // matched nothing, demoting the volumes and then shipping the
            // job with no payload and exit 0.
            self.chase_forfeit(inner, slot, HELD_BYTES_CAP_CHASE)?;
        }
        Ok(())
    }
    /// Record a dropped range, coalescing with the one before it (drops
    /// are prefix-contiguous, so in practice one entry per volume).
    fn note_dropped(ranges: &mut Vec<(u64, u64)>, at: u64, len: u64) {
        if let Some(last) = ranges.last_mut()
            && last.0 + last.1 == at
        {
            last.1 += len;
        } else {
            ranges.push((at, len));
        }
    }
    /// Bytes the RAR drop-behind released with NO disk copy, this
    /// extractor and every child below it - the part of
    /// [`Self::chase_trimmed_bytes`] that cost nothing. A child never
    /// drops (it cannot be re-fetched), so this is the top level's own
    /// count in practice; the walk keeps the two accessors symmetrical.
    pub fn chase_dropped_bytes(&self) -> u64 {
        let (own, child) = {
            let inner = self.inner_read();
            (inner.chase_dropped, inner.child.clone())
        };
        own + child.map_or(0, |c| c.chase_dropped_bytes())
    }
    /// Slots that demoted AFTER a dropping trim, with the volume-offset
    /// ranges their materialized file is missing. The caller re-fetches
    /// these volumes (the whole NZB file - a drop is volume-granular in
    /// practice) and clears them with [`Self::note_dropped_refetched`].
    /// Top level only by construction (see `rar_trim_set`), and only
    /// demoted slots: a slot whose chase succeeded has no file at all.
    pub fn dropped_volumes(&self) -> Vec<DroppedVolume> {
        let inner = self.inner_read();
        inner
            .slots
            .iter()
            .enumerate()
            .filter(|(_, s)| !s.dropped.is_empty())
            .map(|(i, s)| DroppedVolume {
                slot: i,
                posted: s.dropped_as.clone(),
                current: s.name.clone(),
                ranges: s.dropped.clone(),
            })
            .collect()
    }
    /// The caller has re-fetched this slot's volume in full (or given
    /// up, in which case the holes stay and the disk pass reports them).
    pub fn note_dropped_refetched(&self, slot: usize) {
        let mut inner = self.inner.lock_ok();
        if let Some(s) = inner.slots.get_mut(slot) {
            s.dropped.clear();
        }
    }
    /// Seed a slot's dropped-range claim directly, as the demote after a
    /// dropping trim leaves it: the file on disk is missing `ranges`,
    /// and the volume was posted under `posted` (which a later rename
    /// may have moved the slot away from).
    ///
    /// A test hook, and `#[doc(hidden)] pub` rather than `#[cfg(test)]`
    /// because the only consumer of [`Self::dropped_volumes`] lives in
    /// the crate ABOVE this one - the re-fetch driver in nzbfast's
    /// `get::dropped` module - so a hook that stops at this crate's
    /// boundary cannot reach the code it exists to cover. The only
    /// other way to put an extractor into this state from up there is
    /// to replay a whole chase, forfeit and demote, which is a rig
    /// rather than a test and was the reason that driver went untested
    /// through two rounds of the Codex F-05 fix.
    #[doc(hidden)]
    pub fn seed_dropped_volume(&self, slot: usize, posted: &str, ranges: Vec<(u64, u64)>) {
        let mut inner = self.inner.lock_ok();
        if let Some(s) = inner.slots.get_mut(slot) {
            s.dropped = ranges;
            s.dropped_as = posted.to_string();
        }
    }
    /// Bytes the RAR chase drop-behind has spilled out of RAM, this
    /// extractor and every child below it. A chased set that finishes
    /// with a nonzero count here is one that only fit because of the
    /// drop-behind.
    pub fn chase_trimmed_bytes(&self) -> u64 {
        let (own, child) = {
            let inner = self.inner_read();
            (inner.chase_trimmed, inner.child.clone())
        };
        own + child.map_or(0, |c| c.chase_trimmed_bytes())
    }
    /// Bytes chased volumes are holding in RAM right now, this extractor
    /// and every child below it - what the drop-behind is keeping down.
    pub fn chase_retained_bytes(&self) -> usize {
        let (own, child) = {
            let inner = self.inner_read();
            (
                inner
                    .slots
                    .iter()
                    .filter_map(|s| s.chase.as_ref().map(|ch| ch.charged))
                    .sum::<usize>(),
                inner.child.clone(),
            )
        };
        own + child.map_or(0, |c| c.chase_retained_bytes())
    }
    /// Volumes the RAR engine has said it is wholly finished with, over
    /// every live chase in this extractor and its children. What the
    /// drop-behind is allowed to release, and the only honest way to
    /// watch a chase keep up with its arrivals.
    pub fn chase_consumed_volumes(&self) -> usize {
        let (groups, child) = {
            let inner = self.inner_read();
            (
                inner
                    .groups
                    .values()
                    .filter_map(|g| g.chase.clone())
                    .collect::<Vec<_>>(),
                inner.child.clone(),
            )
        };
        let own: usize = groups
            .iter()
            .map(|ctl| {
                ctl.low_water
                    .lock_ok()
                    .values()
                    .filter(|&&at| at == u64::MAX)
                    .count()
            })
            .sum();
        own + child.map_or(0, |c| c.chase_consumed_volumes())
    }
    /// Bytes the RAR engine has said it will never read again, over every
    /// live chase in this extractor and its children - a volume reported
    /// WHOLLY consumed counting its full size.
    ///
    /// The sibling of [`Self::chase_consumed_volumes`] that can see a
    /// PARTIAL watermark, and the only way to tell "the engine has not
    /// finished a volume yet" from "the engine has not started". TODO 220
    /// turned on that distinction: a chase whose volume parse pinned the
    /// whole volume reported zero here while decoding nothing, and read
    /// from the outside exactly like a chase merely one volume behind.
    pub fn chase_watermark_bytes(&self) -> u64 {
        let (groups, child) = {
            let inner = self.inner_read();
            (
                inner
                    .groups
                    .values()
                    .filter_map(|g| g.chase.clone())
                    .collect::<Vec<_>>(),
                inner.child.clone(),
            )
        };
        let own: u64 = groups
            .iter()
            .map(|ctl| {
                let st = ctl.shared.lock_ok();
                ctl.low_water
                    .lock_ok()
                    .iter()
                    .map(|(index, &at)| {
                        let total = st.vols.get(index).map_or(0, |v| v.size);
                        at.min(total)
                    })
                    .sum::<u64>()
            })
            .sum();
        own + child.map_or(0, |c| c.chase_watermark_bytes())
    }
    /// Report a TERMINAL article verdict for `slot`: that slot's bytes
    /// will never all arrive from the wire (a 430 on every provider, an
    /// article outside retention, a dead transport). Sticky and
    /// idempotent; the chain-wide flag arms the arrival-path and
    /// reader-path wedge checks, and the SLOT mark (§156.1) is what
    /// makes the trigger honest: only volumes that can actually contain
    /// the hole are marked, so a healthy chase that merely shares the
    /// job with the loss never pages. The immediate pass here matters
    /// because verdicts typically land AFTER the pile has built (retries
    /// exhaust last), and a set already wedged at its hole sees no
    /// further spans to re-arm from. A later repair (or a rescheduled
    /// fetch) that fills the gap resumes the decode straight off the
    /// paged bytes.
    pub fn note_article_lost(&self, slot: usize) {
        {
            let mut g = self.inner.lock_ok();
            let inner = &mut *g;
            inner.lost_articles.store(true, Ordering::Relaxed);
            Self::mark_slot_lost(inner, slot);
        }
        // §156.3b: the pass does disk I/O - it runs with the extractor
        // lock RELEASED (this is the decode consumer thread, which does
        // its own pwrites anyway), taking it back only for the short
        // per-volume guard and budget settles.
        self.run_stalled_page_pass();
    }

    /// §156.1: sticky terminal-loss mark for one slot, propagated to
    /// wherever the hole can actually live. A chased slot marks its own
    /// frontier buffer. A mapped volume's hole lands in whichever inner
    /// files its group routed to the child, so every routed child slot
    /// is marked (the group IS the archive containing the hole; finer
    /// than that would need the article's byte offset, which the caller
    /// does not have). Routes created after the verdict pick the mark up
    /// at the routing site, chases attached after it at the attach site.
    pub(super) fn mark_slot_lost(inner: &mut Inner, slot: usize) {
        if slot >= inner.slots.len() || std::mem::replace(&mut inner.slots[slot].article_lost, true)
        {
            return;
        }
        if let Some(ch) = inner.slots[slot].chase.as_ref() {
            ch.buf.mark_lost();
        }
        if let Some(g) = inner.slots[slot]
            .group
            .as_ref()
            .and_then(|gk| inner.groups.get(gk))
            && let Some(child) = inner.child.clone()
        {
            for cs in g.routed.values().copied().collect::<Vec<_>>() {
                child.mark_child_slot_lost(cs);
            }
        }
    }

    /// [`Self::mark_slot_lost`] across a nesting boundary: the parent
    /// calls this holding its own lock (parent-then-child is the
    /// established order - the read planners do the same).
    pub(super) fn mark_child_slot_lost(&self, slot: usize) {
        let mut g = self.inner.lock_ok();
        Self::mark_slot_lost(&mut g, slot);
    }

    /// §156.1 wedge test for one chase: the LOWEST volume that is
    /// terminally wedged - marked lost, coverage stopped short - if
    /// any. The decode is strictly volume-ordered, so every byte beyond
    /// that volume's frontier is provably cold: the engine cannot reach
    /// it until the hole fills, wherever the engine currently is. That
    /// is the whole narrowing - a chase none of whose volumes hold an
    /// unfillable hole returns None here and never pages, however many
    /// terminal verdicts the rest of the job collects. Volumes BELOW
    /// the doomed one stay warm (the engine is still coming for them),
    /// which `page_wedged_chase` enforces with this index.
    pub(super) fn chase_first_doomed(ctl: &Arc<ChaseCtl>) -> Option<usize> {
        let vols: Vec<(usize, Arc<FrontierBuffer>)> = {
            let st = ctl.shared.lock_ok();
            st.vols.iter().map(|(&i, v)| (i, v.buf.clone())).collect()
        };
        vols.into_iter()
            .find(|(_, b)| b.terminally_wedged())
            .map(|(i, _)| i)
    }

    /// Coalesced wake for the stalled-chase pager: a detached thread
    /// that runs [`Self::run_stalled_page_pass`] until no wake is
    /// pending, then exits. Callers hold arbitrary locks - this is
    /// atomics and a spawn, nothing more. Reached weakly from the
    /// blocking readers so a cancelled extractor can drop; the thread's
    /// next upgrade fails and it exits.
    pub(super) fn wake_pager(self: &Arc<Self>) {
        self.pager_armed.store(true, Ordering::Release);
        if self.pager_active.swap(true, Ordering::AcqRel) {
            return;
        }
        let me = Arc::downgrade(self);
        let spawned = std::thread::Builder::new()
            .name("nzb-stall-pager".into())
            .spawn(move || {
                loop {
                    let Some(ex) = me.upgrade() else { return };
                    if !ex.pager_armed.swap(false, Ordering::AcqRel) {
                        ex.pager_active.store(false, Ordering::Release);
                        // A wake racing this shutdown saw `active` still
                        // set and returned; re-take the slot ourselves.
                        if ex.pager_armed.load(Ordering::Acquire)
                            && !ex.pager_active.swap(true, Ordering::AcqRel)
                        {
                            continue;
                        }
                        return;
                    }
                    ex.park_progress();
                    ex.run_stalled_page_pass();
                }
            });
        if spawned.is_err() {
            self.pager_active.store(false, Ordering::Release);
        }
    }

    /// One stalled-chase paging pass over this extractor and its chain:
    /// page every chase that is terminally wedged (§156.1) while the
    /// shared budget sits past the [`chase_stall_spill`] window. Takes
    /// no lock across any I/O; safe to run concurrently with itself
    /// (`page_cold` commits re-verify, and a lost race just releases
    /// the orphaned scratch region).
    pub(super) fn run_stalled_page_pass(&self) {
        let (armed, chases, child) = {
            let inner = self.inner.lock_ok();
            (
                inner.holds_page_on && inner.lost_articles.load(Ordering::Relaxed),
                inner
                    .groups
                    .values()
                    .filter_map(|g| g.chase.clone())
                    .collect::<Vec<_>>(),
                inner.child.clone(),
            )
        };
        if armed {
            for ctl in chases {
                if let Some(doom) = Self::chase_first_doomed(&ctl) {
                    self.page_wedged_chase(&ctl, doom);
                }
            }
        }
        if let Some(c) = child {
            c.run_stalled_page_pass();
        }
    }

    /// The chase controller driving this slot's group, if any.
    pub(super) fn rar_chase_of(inner: &Inner, slot: usize) -> Option<Arc<ChaseCtl>> {
        let key = inner.slots[slot].group.as_ref()?;
        inner.groups.get(key)?.chase.clone()
    }
    /// Drop-behind trim for a chased RAR set: release the bytes the
    /// engine has read past - DROPPED outright when the chase is healthy
    /// and keeping pace (the decision in the body), else written into
    /// each volume's own archive file on the way out.
    ///
    /// The spill is the same bargain as the 7z trim it copies, for the
    /// same reasons. Spilling into THAT file rather than a temp one is
    /// what keeps the demote path free: a demotion materializes the
    /// volume at exactly these offsets, so the spill is not a cost paid
    /// against demotion - it IS demotion, done early and in pieces.
    /// `fallback_slot` then writes only what is still in RAM and finds
    /// the rest on disk; a chase that SUCCEEDS deletes the partial file
    /// in `chase_finish`, because the payload came out the other way.
    /// The drop gives that bargain up for the common case, where the
    /// spill is a write of consumed input nobody reads back: a demote
    /// after a drop materializes with HOLES, records them on the slot
    /// ([`Self::dropped_volumes`]), and the caller re-fetches.
    ///
    /// The watermark is the engine's own promise (see
    /// `rars::rar50::extract_volume_sequence_to_with_progress`): nothing
    /// at or below it will be read again. Before the engine has said
    /// anything a volume's watermark is 0 and nothing trims, which is why
    /// there is no arming step here - unlike 7z, whose watermark is a raw
    /// reader position that starts at EOF.
    ///
    /// `drop_ok` is the caller's veto on the DROP arm below, and only a
    /// veto: a caller that allows it still gets a drop only if every
    /// condition on that gate holds. Vetoing is what a relief call site
    /// wants (TODO 251): the rung after the trim is a forfeit, and a
    /// drop followed by a forfeit is TODO 214's worst ending - it does
    /// not save the spill, it converts it into a re-download AND stands
    /// the post-forfeit resume ledger down, so the disk pass re-extracts
    /// every member from byte zero. The relief path spills, and the
    /// forfeit it may go on to raise keeps its ledger.
    pub(super) fn rar_trim_set(
        &self,
        inner: &mut Inner,
        ctl: &Arc<ChaseCtl>,
        drop_ok: bool,
    ) -> io::Result<()> {
        if !inner.rar_trim_on {
            return Ok(());
        }
        // Every volume, not just the one whose span breached the budget:
        // arrivals typically run on a LATER volume than the one the
        // engine is decoding, so the bytes worth releasing belong to a
        // different slot entirely.
        // In volume order (the map is ordered by index): the pace gate
        // below walks the set's contiguous frontier.
        let volumes: Vec<(Arc<FrontierBuffer>, usize, u64)> = {
            let st = ctl.shared.lock_ok();
            let low = ctl.low_water.lock_ok();
            st.vols
                .iter()
                .map(|(index, vol)| {
                    (
                        vol.buf.clone(),
                        vol.slot,
                        low.get(index).copied().unwrap_or(0),
                    )
                })
                .collect()
        };
        // Drop or spill, decided ONCE per pass (measured 21 Aug 2026,
        // research/MEASURED-HOLDS-LADDER-2026-08-21.md: a set 2-5x over
        // the cap on a 110 MB/s line spilled 16 of 19 volumes, and that
        // spill was the entire 0.48x of disk over payload - a write of
        // consumed input a clean job never reads back). A healthy chase
        // DROPS the prefix instead; the bargain the spill bought (a free
        // demote) is paid by the caller re-fetching the dropped volumes
        // IF a demote ever comes. Conditions, each load-bearing:
        // - depth 0: only a top-level slot is an NZB file the caller can
        //   re-fetch. A nested chase's volumes are inner members of an
        //   outer archive, refetchable by nobody.
        // - no lost article anywhere in the job: a demote waiting to
        //   happen, and a demote after a drop is a re-download. (A
        //   conflicted buffer declines `trim_to` itself.)
        // - the engine is keeping pace with the line. The same round
        //   measured the regime as line rate vs decode rate: at 110 MB/s
        //   every breach finds a finished volume, at 250 MB/s the trim
        //   wins a few rounds and the forfeit fires anyway, and THAT
        //   ending - trim, then forfeit - is where a drop would turn the
        //   spill into a re-download of the same bytes. Bytes consumed
        //   (the engine's watermarks) against bytes arrived (the
        //   buffers' contiguous frontiers) since the chase began is the
        //   ratio that separates them: ~1.0 when the engine keeps up,
        //   ~0.5 at 250 MB/s, ~0.13 at 950. Re-read every pass, so an
        //   engine that falls behind later spills from then on; the
        //   volumes already dropped are the only ones a demote refetches.
        // - the set can finish inside the cap AT that pace at all. The
        //   three conditions above are all about how healthy the chase is
        //   right now and none of them knows how big the set is, which is
        //   the hole the 22 Aug joint round fell through: past five times
        //   the cap a keeping-pace chase still forfeits, and there the
        //   drop buys nothing and costs a re-download AND the resume
        //   ledger. See `rar_drop_can_finish`.
        // - OR the held-bytes backpressure is engaged (TODO 94 item E).
        //   The two gates above both ask "will this chase outrun the
        //   cap and forfeit?", and a parked set cannot: its arrivals
        //   are held to the engine's pace, which also makes the pace
        //   ratio unmeetable by construction - the engine is always
        //   exactly a runway behind. Measured on the 22 Aug loopback
        //   rig: 752 MB trimmed, 0 dropped, every byte of it spilled
        //   into the volume files the park exists to never write.
        let parked = !inner.park.parked.is_empty();
        let drop = drop_ok
            && inner.rar_drop_on
            && self.depth == 0
            && !inner.lost_articles.load(Ordering::Relaxed)
            && (parked
                || (Self::rar_engine_keeping_pace(&volumes)
                    && Self::rar_drop_can_finish(
                        inner.budget.cap(),
                        volumes.iter().map(|(b, _, _)| b.total()).sum(),
                    )));
        for (buf, slot, watermark) in volumes {
            self.rar_trim_volume(inner, slot, &buf, watermark, drop)?;
        }
        Ok(())
    }
    /// Fraction of the set's arrived bytes the engine has consumed above
    /// which a trim drops rather than spills. See `rar_trim_set`.
    const RAR_DROP_PACE: f64 = 0.8;
    /// Is the engine keeping pace with arrivals? Consumed = the sum of
    /// the watermarks (a finished volume counts whole); arrived = the
    /// set's CONTIGUOUS frontier in volume order - every complete
    /// volume up to the first incomplete one, plus that one's frontier.
    /// Contiguous, not total: the scheduler fetches every volume's
    /// offset-0 article early (the sniff probe), so summing frontiers
    /// counts a head per volume the engine cannot reach yet, and on a
    /// 35-volume set that alone read a keeping-pace engine as 0.79.
    /// Both sums are cumulative over the chase, so one slow second does
    /// not flip the answer.
    fn rar_engine_keeping_pace(volumes: &[(Arc<FrontierBuffer>, usize, u64)]) -> bool {
        let mut consumed = 0u64;
        let mut arrived = 0u64;
        let mut contiguous = true;
        for (buf, _, wm) in volumes {
            let total = buf.total();
            consumed += (*wm).min(total);
            if contiguous {
                let f = buf.frontier().min(total);
                arrived += f;
                contiguous = f >= total;
            }
        }
        arrived > 0 && consumed as f64 >= Self::RAR_DROP_PACE * arrived as f64
    }
    /// Can a chase that keeps pace carry THIS set inside the cap at all?
    ///
    /// The pace gate above is a RATE test and knows nothing about how big
    /// the set is. A drop-eligible chase is holding at most
    /// `1 - RAR_DROP_PACE` of what has arrived, so it cannot breach a cap
    /// of `cap` until the set is larger than `cap / (1 - RAR_DROP_PACE)` -
    /// five times it at the current threshold. Below that line a drop is
    /// free money and the trim carries the set one-pass. PAST it the
    /// forfeit is coming however healthy the chase looks at this instant,
    /// and a drop is then loss twice over: it does not save the spill, it
    /// converts the spill into a RE-DOWNLOAD of the same bytes, and the
    /// re-fetch stands the post-forfeit resume ledger down
    /// (`nzbfast::get::tail`) so the disk pass re-extracts every member
    /// from byte zero.
    ///
    /// Measured 22 Aug 2026 (`research/MEASURED-HOLDS-JOINT-2026-08-22.md`)
    /// on a set TEN times the holds slice at 110 MB/s, where the regime is
    /// a coin flip: the legs that forfeited cost 1.79-2.12x of payload
    /// with the drop on and 1.55x with it off, and one of them dropped SIX
    /// megabytes and paid 1.8 GB of re-extraction for it, because the
    /// stand-down is per-JOB. The legs that stayed one-pass were 1.09x
    /// with the drop and 1.51x without, so what this gives up is a gamble,
    /// not a win.
    ///
    /// The total is what the chase has SEEN. That is the whole set from
    /// early on - the scheduler fetches every volume's offset-0 article as
    /// its sniff probe, which is the same fact
    /// [`Self::rar_engine_keeping_pace`] has to correct for - and an
    /// underestimate can only be transient and errs toward the old
    /// behaviour for at most a trim.
    fn rar_drop_can_finish(cap: usize, set_total: u64) -> bool {
        (1.0 - Self::RAR_DROP_PACE) * set_total as f64 <= cap as f64
    }
    /// Budget-breach relief a demoting group asks for BEFORE it demotes:
    /// trim, and then if need be forfeit, the CHILD chase that this
    /// group's routed inner files feed.
    ///
    /// WHY THIS EXISTS, measured 22 Aug 2026 on the TODO 220 `gran`
    /// ladder (`research/MEASURED-HOLDS-NEST-2026-08-22.md`). Two reps of
    /// ONE configuration - same fixture, same binary, same 110 MB/s
    /// loopback - cost 2.083x and 4.566x of payload in device I/O, on
    /// byte-identical output with no damage, no repair and no re-fetch.
    /// They are not one path with two trim sizes. They are the two
    /// different call sites that can notice `budget.over()` first, and a
    /// budget shared down the nesting chain makes that a race:
    ///
    /// - `chase_span` notices, TRIMS, and forfeits the chase only if the
    ///   trim did not relieve. The outer stays one-pass, its in-stream
    ///   inner volumes survive on disk and the disk pass unpacks them.
    /// - `retain_header_bytes` notices on an OUTER volume, and the outer
    ///   GROUP demotes for a few megabytes of header stash. That is not
    ///   a smaller version of the same thing: `delete_group_out_files`
    ///   deletes the inner volumes already written in-stream and
    ///   `abandon_slot` aborts the child chase under them, so the outer
    ///   materializes, is unpacked again from disk, and the inner
    ///   volumes are written a SECOND time.
    ///
    /// The hole is that the second site had no ladder at all. It never
    /// asked the chase to trim - only `chase_span` does that - so a
    /// breach it happened to see first went straight to the single most
    /// expensive action available, skipping the two cheaper ones that
    /// would have relieved it. This is that ladder, in cost order:
    /// trim (spill), then forfeit the chase, then the demote the caller
    /// was already going to do.
    ///
    /// Returns whether the budget is back under the cap. `false` leaves
    /// the caller on the exact demote it performs today, with the same
    /// reason string.
    pub(super) fn relieve_by_child_chase(&self, inner: &mut Inner, slot: usize) -> bool {
        if chase_relief_env_off() {
            return false;
        }
        let Some(child) = inner.child.clone() else {
            return false;
        };
        let Some(key) = inner.slots[slot].group.clone() else {
            return false;
        };
        // A group already falling back has had its routed slots drained
        // and its chase torn down; there is nothing left to trade.
        let routed: Vec<usize> = match inner.groups.get(&key) {
            Some(g) if !g.fallback => g.routed.values().copied().collect(),
            _ => return false,
        };
        if routed.is_empty() {
            return false;
        }
        let over = inner.budget.len().saturating_sub(inner.budget.cap());
        child.relieve_chase_for_parent(&routed, over);
        !inner.budget.over()
    }

    /// The same ladder for a chase THIS extractor owns - the TOP-LEVEL
    /// case [`Self::relieve_by_child_chase`] cannot reach (TODO 251).
    ///
    /// That one finds its victim through the demoting slot's group
    /// `routed` map, i.e. the child chase the group's inner files feed.
    /// A compressed RAR posted DIRECTLY has no store outer and no
    /// routed members at all - `chase_open_sink` registers its decoded
    /// members in the ctl's `sink_slots`, never in `routed` - so on that
    /// shape the relief declined and the caller went straight to its
    /// demote.
    ///
    /// WHAT THAT COSTS, driven deterministically in
    /// `a_top_level_breach_relieves_the_chase_before_demoting_a_volume`:
    /// a live 20-volume chase, 18 volumes consumed, one 7000-byte
    /// PRE-SNIFF span on the last volume with the budget one byte over.
    /// `overflow_to_plain` flips that unsniffed slot to `Plain`, so it
    /// can never join the set; the engine then reaches it and dies with
    /// `chase failed: RAR 5 split entry is incomplete`; all twenty
    /// volumes materialize and the job produces NO payload in-stream.
    /// Not even the cap reason, so no resume ledger either - the disk
    /// pass starts from byte zero. That is the pre-TODO 220 race, and
    /// TODO 220 fixed the nested shape only.
    ///
    /// Same two rungs and the same order as the child arm: trim
    /// (SPILL only - see `rar_trim_set`'s `drop_ok`), then forfeit a
    /// chase that holds at least the overshoot, then the caller's own
    /// demote. The forfeit is worth taking here even though it
    /// materializes the whole set, because it raises
    /// [`HELD_BYTES_CAP_CHASE`] - the one reason `chase_resume_ok`
    /// lets the in-stream output survive - where the ending it replaces
    /// keeps nothing.
    ///
    /// The caller's OWN group is skipped, and that is a safety rule
    /// rather than a policy: forfeiting it runs `abandon_slot` over the
    /// caller's slot, which takes its mapper away under `rar_span`'s
    /// feet (`inner.slots[slot].mapper.as_ref().unwrap()` on the line
    /// after the call site). Demoting that group is what the caller is
    /// about to do anyway.
    ///
    /// Returns whether the caller should stand its demote down: the
    /// budget is back under the cap, or a spill in flight has deferred
    /// the breach (`breach_stands`), which is the state that must NOT
    /// demote - a chase being relieved this instant is exactly what the
    /// deferral exists to protect.
    pub(super) fn relieve_by_own_chase(&self, inner: &mut Inner, slot: usize) -> bool {
        if chase_relief_env_off() {
            return false;
        }
        // Distinct live RAR chases, with the volume slots each one
        // holds. Identity by pointer, as `relieve_chase_for_parent`
        // does it and for the same reason: a `ChaseCtl` has no equality
        // worth the name. A group already falling back has had its
        // chase torn down and has nothing left to trade.
        let mut sets: Vec<(Arc<ChaseCtl>, Vec<usize>)> = Vec::new();
        for g in inner.groups.values() {
            let Some(ctl) = g.chase.clone() else { continue };
            if g.fallback
                || g.slots.contains(&slot)
                || sets.iter().any(|(c, _)| Arc::ptr_eq(c, &ctl))
            {
                continue;
            }
            sets.push((ctl, g.slots.clone()));
        }
        if sets.is_empty() {
            return false;
        }
        for (ctl, _) in &sets {
            // An error here is a spill write failing, which the owning
            // slot sees again on its next span; the relief either way is
            // whatever the trim released before it stopped.
            let _ = self.rar_trim_set(inner, ctl, false);
        }
        if !Self::breach_stands(inner) {
            return true;
        }
        // Re-read AFTER the trim: the overshoot the forfeit still has to
        // clear is what decides whether it is worth taking, and a trim
        // credits the budget the instant it plans its spill.
        let need = inner.budget.len().saturating_sub(inner.budget.cap());
        for (_, slots) in &sets {
            let held: usize = slots
                .iter()
                .filter_map(|&s| inner.slots.get(s))
                .filter(|s| s.sevenz.is_none())
                .filter_map(|s| s.chase.as_ref())
                .map(|ch| ch.charged)
                .sum();
            // Below the overshoot the forfeit does not save the demote,
            // so it would cost the whole set for nothing. RAR chases
            // only, as the child arm has it: a 7z chase charges the
            // budget through its own sinks and forfeits through
            // `sevenz_fallback_set`.
            if held == 0 || held < need {
                continue;
            }
            for &s in slots {
                let live = inner
                    .slots
                    .get(s)
                    .is_some_and(|sl| sl.chase.is_some() && sl.sevenz.is_none());
                // The first forfeit demotes the whole group, which
                // clears every member's chase - the rest of the walk
                // then skips.
                if live {
                    let _ = self.chase_forfeit(inner, s, HELD_BYTES_CAP_CHASE);
                }
            }
            if !inner.budget.over() {
                return true;
            }
        }
        !inner.budget.over()
    }

    /// The whole chase ladder a demote site asks for before demoting:
    /// the child arm (TODO 220) and then the own arm (TODO 251). One
    /// entry point so a new call site cannot pick up half of it - the
    /// two cover disjoint shapes (nested vs top-level), and which one a
    /// job is depends on how the poster wrapped it, not on the site.
    pub(super) fn relieve_by_chase(&self, inner: &mut Inner, slot: usize) -> bool {
        self.relieve_by_child_chase(inner, slot) || self.relieve_by_own_chase(inner, slot)
    }

    /// The child half of [`Self::relieve_by_child_chase`], run under the
    /// child's own lock with the parent's held - the same nesting and
    /// the same order `delete_group_out_files` already uses to reach
    /// `abandon_slot`, and safe for the same reason: every child-to-
    /// parent call takes no lock on the way up, and a teardown aborts
    /// the chase worker without joining it.
    ///
    /// The trim is unconditional and cannot drop: it passes
    /// `rar_trim_set`'s `drop_ok` veto (TODO 251), so every byte it
    /// releases is spilled into the volume's own file and the demote
    /// below (or later) still materializes byte-exact. The veto is
    /// belt-and-braces here - `rar_trim_set` also gates the drop on
    /// `self.depth == 0` and this is a child - and load-bearing in
    /// [`Self::relieve_by_own_chase`], which is at depth 0.
    ///
    /// The forfeit is conditional on the chase holding at least `need`
    /// bytes - the overshoot the caller has to clear. Below that the
    /// forfeit does not save the demote, so it would cost the chase for
    /// nothing. RAR chases only: a 7z chase charges the budget through
    /// its own sinks and forfeits through `sevenz_fallback_set`, so it
    /// is left to the site that owns it.
    pub(super) fn relieve_chase_for_parent(&self, slots: &[usize], need: usize) {
        let mut guard = self.inner.lock_ok();
        let inner = &mut *guard;
        // One trim per CHASE, not per slot: a volume set's slots share
        // one ctl, and `rar_trim_set` already walks every volume in it.
        // Identity by pointer - a `ChaseCtl` has no equality worth the
        // name, and a derived one would compare the contents of two
        // different live chases.
        let mut done: Vec<Arc<ChaseCtl>> = Vec::new();
        for &s in slots {
            if s >= inner.slots.len() {
                continue;
            }
            let Some(ctl) = Self::rar_chase_of(inner, s) else {
                continue;
            };
            if done.iter().any(|c| Arc::ptr_eq(c, &ctl)) {
                continue;
            }
            done.push(ctl.clone());
            // An error here is a spill write failing, which the owning
            // slot sees again on its next span; the relief either way is
            // whatever the trim released before it stopped.
            let _ = self.rar_trim_set(inner, &ctl, false);
        }
        if !Self::breach_stands(inner) {
            drop(guard);
            let _ = self.flush_pending_spills();
            return;
        }
        let held: usize = slots
            .iter()
            .filter_map(|&s| inner.slots.get(s))
            .filter(|s| s.sevenz.is_none())
            .filter_map(|s| s.chase.as_ref())
            .map(|ch| ch.charged)
            .sum();
        if held == 0 || held < need {
            return;
        }
        for &s in slots {
            let live = inner
                .slots
                .get(s)
                .is_some_and(|sl| sl.chase.is_some() && sl.sevenz.is_none());
            // The first forfeit demotes the whole group, which clears
            // every member's chase - the rest of the walk then skips.
            if live {
                let _ = self.chase_forfeit(inner, s, HELD_BYTES_CAP_CHASE);
            }
        }
        drop(guard);
        // The trims above planned their spills under the lock; write
        // them now that it is down (an error here is the same spill
        // failure the owning slot sees again on its next span).
        let _ = self.flush_pending_spills();
    }

    /// Half the cap: bounds the drain's memmove to a constant amount of
    /// work per arriving byte, since two trims cannot be closer together
    /// than that many bytes of arrival. A volume the engine is wholly
    /// past is released regardless of size - it is finished with, and
    /// holding it buys nothing.
    fn rar_trim_min_release(inner: &Inner, buf: &FrontierBuffer, watermark: u64) -> u64 {
        if watermark >= buf.total() {
            1
        } else {
            (inner.budget.cap() / 2) as u64
        }
    }
    fn rar_trim_volume(
        &self,
        inner: &mut Inner,
        slot: usize,
        buf: &Arc<FrontierBuffer>,
        watermark: u64,
        drop: bool,
    ) -> io::Result<()> {
        if watermark == 0 {
            return Ok(());
        }
        // The slot must still be chased, and still be chasing THIS
        // buffer: a demote takes the chase out of the slot, and a
        // registration this ctl no longer owns is not ours to spill.
        match inner.slots[slot].chase.as_ref() {
            Some(ch) if Arc::ptr_eq(&ch.buf, buf) => {}
            _ => return Ok(()),
        }
        let min_release = Self::rar_trim_min_release(inner, buf, watermark);
        // A conflicted buffer declines a trim, so a prefix that DOES
        // release comes off an unconflicted set: dropping is safe on
        // this volume whenever the pass said so - AND the PAR2 verifier
        // has vouched for every byte of it. A dropped range has no copy
        // anywhere, and the settle read-back reads a live chase's
        // still-Pending blocks back through `read_at`, which answers
        // `nofile` below the buffer's base: every such block was marked
        // Bad, inflating `needed` up to a false "unrepairable" on a set
        // with no damage at all (bug sweep 22 Aug 2026). Bytes under the
        // engaged watermark are BlockState::Ok and are never read back,
        // so those drop; an unengaged slot (set not yet active, or no
        // set) spills as the trim always did. No gate attached at all
        // means no verifier will ever read back, and the drop stands.
        //
        // ONE MARK MOVES FOR A REASON OTHER THAN VERIFICATION, and a
        // lane measuring trimmed-vs-spilled bytes needs to know it:
        // once a mapped repair has PROVED the set, settle calls
        // `Extractor::release_verify_gate`, which takes every engaged
        // cell to `u64::MAX` (row 27, 22 Aug 2026). From that point
        // `vouched` is true for every engaged slot, so a post-repair
        // trim on a DAMAGED root set drops bytes that would have
        // spilled before. That is sound for the same reason the release
        // is - the repair re-read every file of the set through the view
        // it wrote through, so nothing will read back - but it means a
        // damaged-set leg's spill numbers are not comparable across
        // binaries either side of that change. A CHILD slot is
        // untouched by it: its `verify_gate` is None by design, so this
        // arm has always answered true there.
        //
        // The cut is the same for both arms (`trim_plan` and `trim_to`
        // share it), so the vouch is judged against the end the drop
        // WOULD reach; a spill that does not vouch goes through the
        // off-lock route instead.
        let cut = watermark.min(buf.frontier_ram_edge());
        let vouched = match inner.verify_gate.as_ref() {
            None => true,
            Some(g) => g.engaged_mark(slot).is_some_and(|mark| mark >= cut),
        };
        if !(drop && vouched) {
            // Spill, with no disk I/O under this lock: planned here,
            // written by `flush_pending_spills` once the lock drops.
            self.queue_trim_spill(inner, slot, buf, watermark, min_release, true)?;
            return Ok(());
        }
        let Some((at, bytes)) = buf.trim_to(watermark, min_release) else {
            return Ok(());
        };
        inner.chase_trimmed += bytes.len() as u64;
        inner.chase_dropped += bytes.len() as u64;
        let name = inner.slots[slot].name.clone();
        if let Some(ch) = inner.slots[slot].chase.as_mut() {
            if ch.dropped.is_empty() {
                ch.dropped_as = name;
            }
            Self::note_dropped(&mut ch.dropped, at, bytes.len() as u64);
        }
        let now = buf.stored();
        let released = match inner.slots[slot].chase.as_mut() {
            Some(ch) => {
                let delta = ch.charged.saturating_sub(now);
                ch.charged = now;
                delta
            }
            None => 0,
        };
        inner.budget.sub(released);
        Ok(())
    }
    /// Plan a drop-behind spill of a chased slot's consumed prefix
    /// (TODO 37 item 1): decide under the routing lock, write after it.
    /// `trim_plan` marks the prefix pending - which is what credits the
    /// holds budget NOW, so the `budget.over()` check that follows every
    /// trim sees the relief without waiting for the disk - and the job
    /// queued on `pending_spills` does the pwrite in
    /// [`Self::spill_trimmed`] once the caller's lock is down. Nothing
    /// leaves RAM until that job commits. Returns whether a spill was
    /// planned. The writer is created here (one `open`, as `plain_job`
    /// does) because its name claim belongs under this lock.
    pub(super) fn queue_trim_spill(
        &self,
        inner: &mut Inner,
        slot: usize,
        buf: &Arc<FrontierBuffer>,
        watermark: u64,
        min_release: u64,
        count_trimmed: bool,
    ) -> io::Result<bool> {
        let Some((at, len, seq)) = buf.trim_plan(watermark, min_release) else {
            return Ok(false);
        };
        let writer = match self.ensure_plain_writer(inner, slot) {
            Ok(w) => w,
            Err(e) => {
                buf.trim_abandon();
                return Err(e);
            }
        };
        inner.pending_spills.push(TrimSpill {
            slot,
            buf: buf.clone(),
            writer,
            at,
            len,
            seq,
            refeed: inner.refeed_active,
            count_trimmed,
        });
        inner.spills_in_flight += 1;
        Self::settle_chase_charge(inner, slot, buf);
        Ok(true)
    }
    /// A holds-cap breach on a chased slot, after the trim had its say:
    /// forfeit - UNLESS a spill is still in flight, in which case the
    /// relief is already on its way and the breach is deferred instead
    /// (the carrying write then waits for it off-lock). Without this,
    /// the off-lock spill demoted the 1 GB COPY 7z that the under-lock
    /// one streamed (measured 23 Aug 2026 on the loopback mock, 20
    /// connections): a second thread breached during the first's
    /// write, `trim_plan` declined because one was pending, and the
    /// breach forfeited on a set that was being relieved that instant.
    /// True when the caller should forfeit.
    pub(super) fn breach_stands(inner: &mut Inner) -> bool {
        if !inner.budget.over() {
            return false;
        }
        if inner.spills_in_flight > 0 {
            inner.defer_breach = true;
            return false;
        }
        true
    }
    /// Off-lock: wait for every in-flight spill to settle. Bounded, so
    /// a spill job that died with its thread can never wedge an
    /// arrival: past the bound the arrival simply proceeds and the next
    /// breach makes its own decision.
    pub(super) fn await_spills_settled(&self) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut g = self.inner.lock_ok();
        while g.spills_in_flight > 0 {
            let now = std::time::Instant::now();
            if now >= deadline {
                break;
            }
            let (ng, _) = self
                .spill_settled
                .wait_timeout(g, deadline - now)
                .unwrap_or_else(|e| e.into_inner());
            g = ng;
        }
    }
    /// Bring a chased slot's `charged` back to what its buffer retains
    /// and move the shared budget by the difference - in EITHER
    /// direction, because an abandoned spill re-inflates `stored()`.
    /// Only while the slot still chases THIS buffer: a demote in the
    /// window released the whole charge and drained the spans, so
    /// touching it again would double-settle.
    fn settle_chase_charge(inner: &mut Inner, slot: usize, buf: &Arc<FrontierBuffer>) {
        let now = buf.stored();
        let Some(ch) = inner.slots.get_mut(slot).and_then(|s| s.chase.as_mut()) else {
            return;
        };
        if !Arc::ptr_eq(&ch.buf, buf) {
            return;
        }
        if now > ch.charged {
            inner.budget.add(now - ch.charged);
        } else {
            inner.budget.sub(ch.charged - now);
        }
        ch.charged = now;
    }
    /// Run the trim spills queued under the routing lock. Off-lock by
    /// construction, like [`Self::flush_pending_promote`]: every queued
    /// job writes up to half the holds cap, which is exactly the I/O
    /// that used to stall every other extractor thread behind the
    /// lock. Every job runs even if one fails; the first error is
    /// returned, as the under-lock write's would have been.
    pub(super) fn flush_pending_spills(&self) -> io::Result<()> {
        let jobs = std::mem::take(&mut self.inner.lock_ok().pending_spills);
        let mut first_err = None;
        for j in jobs {
            if let Err(e) = self.spill_trimmed(j)
                && first_err.is_none()
            {
                first_err = Some(e);
            }
        }
        first_err.map_or(Ok(()), Err)
    }
    /// One planned spill, start to finish, with no lock held across any
    /// write: copy a bounded chunk out under the buffer's own lock,
    /// pwrite it with nothing held, repeat; then, under the routing
    /// lock, commit (the buffer drains the prefix and `base` moves) or
    /// abandon (the prefix stays in RAM, budget re-charged). The commit
    /// is refused if the buffer moved under the spill - a demote popped
    /// the run, a conflict, a differing rewrite - and the bytes on disk
    /// are then a harmless duplicate of what RAM still holds.
    ///
    /// An ENOSPC mid-way therefore leaves NO hole (TODO 37 item 3): the
    /// written part is a partial duplicate below a `base` that never
    /// moved, the whole prefix is still retained, and the error reaches
    /// the article exactly as the under-lock write's did.
    fn spill_trimmed(&self, j: TrimSpill) -> io::Result<()> {
        // Same batch as `page_cold`: the transient copy is bounded to
        // this whatever the release is, and the memmove that the
        // `min_release` bar exists to amortize happens ONCE, at commit.
        const CHUNK: usize = 16 << 20;
        let mut done = 0usize;
        let mut failed: Option<io::Error> = None;
        while done < j.len {
            let Some(bytes) = j.buf.trim_chunk(j.at, done, CHUNK, j.seq) else {
                break;
            };
            if let Err(e) = j.writer.write_at(j.at + done as u64, &bytes) {
                failed = Some(e);
                break;
            }
            done += bytes.len();
        }
        let mut g = self.inner.lock_ok();
        let inner = &mut *g;
        inner.spills_in_flight = inner.spills_in_flight.saturating_sub(1);
        if inner.spills_in_flight == 0 {
            self.spill_settled.notify_all();
        }
        let committed = if failed.is_none() && done == j.len {
            j.buf.trim_commit(j.at, j.seq)
        } else {
            j.buf.trim_abandon();
            None
        };
        Self::settle_chase_charge(inner, j.slot, &j.buf);
        if let Some(n) = committed {
            self.trim_spilled_off_lock
                .fetch_add(n as u64, Ordering::Relaxed);
            if j.count_trimmed {
                inner.chase_trimmed += n as u64;
            }
            // What `plain_span` reported for a re-fed span landing
            // plain: file offset == volume offset by definition.
            if j.refeed {
                inner.late_placements.push(LatePlacement {
                    slot: j.slot,
                    frag: Frag {
                        file: j
                            .writer
                            .path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .into_owned(),
                        file_off: j.at,
                        vol_off: j.at,
                        len: n as u64,
                    },
                    // A drop-behind trim spills the frontier buffer's
                    // own raw bytes with a plain pwrite; an
                    // in-stream-decrypted file is fed through
                    // `CryptoState` and never reaches this route.
                    crypto: false,
                });
            }
        }
        failed.map_or(Ok(()), Err)
    }
    /// Bytes the drop-behind trim spilled through the off-lock route
    /// and committed - the lock-placement oracle (see the field).
    /// Walks the child chain like [`Self::chase_trimmed_bytes`]: a
    /// nested chase trims in the CHILD, and a counter read at the root
    /// alone reads 0 there.
    pub fn trim_spilled_off_lock(&self) -> u64 {
        let own = self.trim_spilled_off_lock.load(Ordering::Relaxed);
        let child = self.inner.lock_ok().child.clone();
        own + child.map_or(0, |c| c.trim_spilled_off_lock())
    }
    /// Page a WEDGED RAR chase's cold frontier bytes to the holds
    /// scratch, until the shared budget sits back at the
    /// [`chase_stall_spill`] window. Volumes walk in DESCENDING index -
    /// the farthest-ahead arrivals are the coldest - and within one, the
    /// buffer pages parked spans (never engine-readable until their gap
    /// fills) before anything else. `doom` (the lowest volume holding
    /// an unfillable hole, from [`Self::chase_first_doomed`]) is the
    /// coldness boundary: contiguous runs page only beyond it, volumes
    /// below it are skipped wholesale unless the engine is wholly past
    /// them. Budget bookkeeping is the drop-behind trim's exact
    /// contract: re-read `stored()` and release the delta. A scratch
    /// refusal leaves the rest in RAM, where the cap arbiter stands
    /// exactly as before this spill existed.
    ///
    /// §156.3b: runs with NO caller-held locks. The extractor lock is
    /// taken per volume for the guard and the budget settle only - the
    /// paging I/O in between holds neither it nor (see `page_cold`) the
    /// buffer's own state lock. The predecessor held the extractor lock
    /// across the whole pass, disk writes included, so a pool teardown
    /// sealing thousands of ids stalled every slot's deliveries behind
    /// scratch I/O.
    fn page_wedged_chase(&self, ctl: &Arc<ChaseCtl>, doom: usize) {
        let (budget, scratch) = {
            let inner = self.inner.lock_ok();
            (inner.budget.clone(), inner.scratch.clone())
        };
        // Auto ceiling: 4x the RAM cap, resolved per pass so a later
        // set_holds_cap is respected and an explicit ceiling wins.
        let cap = match scratch.cap.load(Ordering::Relaxed) {
            0 => 4 * budget.cap() as u64,
            c => c,
        };
        let window = chase_stall_spill(budget.cap());
        // The coldness boundary is `doom`, the lowest volume with an
        // unfillable hole (§156.1): everything beyond its frontier is
        // unreachable until the hole fills. Volumes below it are warm -
        // the engine is still coming for them - and stay untouched,
        // except ones the engine is wholly PAST, whose leftovers page
        // like any cold bytes. Inside the doomed volume only the parked
        // pile beyond its hole pages, never its contiguous run (the
        // engine will still decode up to the hole).
        let volumes: Vec<(Arc<FrontierBuffer>, usize, bool)> = {
            let st = ctl.shared.lock_ok();
            let low = ctl.low_water.lock_ok();
            st.vols
                .iter()
                .filter_map(|(&index, vol)| {
                    let past = low.get(&index) == Some(&u64::MAX);
                    (index >= doom || past)
                        .then(|| (vol.buf.clone(), vol.slot, index > doom || past))
                })
                .collect()
        };
        let mut paged_any = false;
        for (buf, slot, cold_data) in volumes.into_iter().rev() {
            let need = budget.len().saturating_sub(window);
            if need == 0 {
                break;
            }
            // The slot must still be chasing THIS buffer (same guard as
            // the trim): a demote takes the chase out of the slot.
            {
                let inner = self.inner.lock_ok();
                match inner.slots[slot].chase.as_ref() {
                    Some(ch) if Arc::ptr_eq(&ch.buf, &buf) => {}
                    _ => continue,
                }
            }
            if buf.page_cold(cap, need, cold_data) == 0 {
                continue;
            }
            paged_any = true;
            // Settle only while the slot still owns this buffer: a
            // demote in the window has already released its full charge
            // and drained the spans, so touching it again would
            // double-release.
            let mut g = self.inner.lock_ok();
            let inner = &mut *g;
            if let Some(ch) = inner.slots[slot].chase.as_mut()
                && Arc::ptr_eq(&ch.buf, &buf)
            {
                let now = buf.stored();
                let delta = ch.charged.saturating_sub(now);
                ch.charged = now;
                budget.sub(delta);
            }
        }
        if paged_any && !scratch.announced.swap(true, Ordering::Relaxed) {
            info!(
                target: "extract",
                "🧊 archive decode blocked on missing articles - paging to scratch"
            );
        }
    }

    /// Give up on whatever CONTAINER this slot belongs to.
    ///
    /// A 7z slot is one part of a container, and a byte split has no
    /// useful half - so a part failing is the container failing, and the
    /// demote has to take every member with it. Routing these two
    /// forfeits through the single-slot path instead was a silent
    /// data-loss bug, not just untidy: `fallback_slot` drains the
    /// container's WHOLE sink list (every member shares one ctl), so the
    /// payload output was deleted while the other members stayed in
    /// `SevenZ` mode with the set un-aborted. The worker then read on
    /// from parts nobody had touched, wrote into a slot that had become
    /// `Discard` (which swallows writes), and returned `Ok` - at which
    /// point `sevenz_finish` took the survivors' success path, dropped
    /// their retained bytes and unlinked their spilled prefixes. Output
    /// directory: one orphaned `.7z.002`, no payload, exit 0.
    pub(super) fn chase_forfeit(
        &self,
        inner: &mut Inner,
        slot: usize,
        reason: &str,
    ) -> io::Result<()> {
        match inner.slots[slot].sevenz.clone() {
            Some(ctl) => self.sevenz_fallback_set(inner, &ctl, reason),
            None => self.fallback_slot_or_group(inner, slot, reason),
        }
    }
    /// The chase worker: drives the RAR engine's volume-sequence
    /// extraction over the group's frontier buffers, in volume order,
    /// decoding behind the arrival frontier. Runs on its own thread; the
    /// extractor is reached weakly so a cancelled job can drop (Drop
    /// aborts the buffers, the next upgrade here fails, the worker
    /// exits). The outcome is recorded for finish() to act on.
    fn chase_worker(
        me: Weak<Extractor>,
        ctl: Arc<ChaseCtl>,
        key: String,
        password: Option<std::sync::Arc<str>>,
    ) {
        let pw: Option<Vec<u8>> = password.map(|p| p.as_bytes().to_vec());
        // Drop-behind: the engine says how much of each volume it will
        // never read again, and routing releases those bytes on budget
        // pressure (`rar_trim_set`). Recording only - the trim itself
        // needs the extractor lock, which this thread must never take
        // while a blocking volume read could be holding a buffer.
        // The engine counts from the ARCHIVE's first byte; `low_water`
        // is read by the trim, the pace gate and `chase_watermark_bytes`
        // in FILE coordinates (the frontier buffer's), which differ by
        // the stub's length on an SFX volume. Translate at this one
        // publish point and nothing downstream learns the difference.
        // Held-bytes backpressure: while the root has this set parked,
        // engine progress is what releases it, so each mark wakes the
        // pager to re-read the holds (`Extractor::park_progress`). One
        // relaxed load when nothing is parked; the upgrade and wake are
        // atomics and at most a spawn, which is what this thread may do.
        let park_root = me.upgrade().map(|ex| ex.park_root());
        let mark = |index: usize, offset: u64| {
            let base = ctl.bases.lock_ok().get(&index).copied().unwrap_or(0);
            let offset = file_watermark(base, offset);
            {
                let mut low = ctl.low_water.lock_ok();
                let at = low.entry(index).or_insert(0);
                *at = (*at).max(offset);
            }
            if let Some(root) = park_root.as_ref().and_then(|w| w.upgrade())
                && root.park_live.load(Ordering::Relaxed)
            {
                root.wake_pager();
            }
        };
        let result = if ctl.v4 {
            rars::rar15_40::extract_volume_sequence_to_with_progress(
                |index| Self::chase_next_volume_v4(&ctl, index, pw.as_deref()),
                crate::mem::rar_read_options(pw.as_deref()),
                |meta| {
                    // The size rides on the open callback, as it does for
                    // RAR5: a v4 volume now opens incrementally too, so
                    // its size map cannot promise the later members.
                    Self::chase_open_sink(
                        &me,
                        &ctl,
                        &key,
                        &meta.name,
                        meta.is_directory,
                        meta.unpacked_size,
                    )
                },
                mark,
            )
        } else {
            rars::rar50::extract_volume_sequence_to_with_progress(
                |index| Self::chase_next_volume(&ctl, index, pw.as_deref()),
                crate::mem::rar_read_options(pw.as_deref()),
                |meta| {
                    Self::chase_open_sink(
                        &me,
                        &ctl,
                        &key,
                        &meta.name,
                        meta.is_directory,
                        meta.unpacked_size,
                    )
                },
                mark,
            )
        };
        let mut st = ctl.shared.lock_ok();
        st.outcome = Some(result.map_err(|e| e.to_string()));
        drop(st);
        ctl.cv.notify_all();
    }
    /// Natural 0-based volume index from a RAR4 volume NAME. Old-style
    /// naming is already 0-based (`.rar` then `.r00`, `.r01`, rolling to
    /// `.s00`…); `.partNN.rar` and bare-numeric `.001` naming start at 1,
    /// so those shift down by one.
    fn v4_vol_index(name: &str) -> usize {
        let lower = name.to_ascii_lowercase();
        if let Some(p) = lower.rfind(".part") {
            let tail = &lower[p + 5..];
            let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(n) = digits.parse::<u64>() {
                return (n.saturating_sub(1)) as usize;
            }
        }
        if let Some(p) = lower.rfind('.') {
            let tail = &lower[p + 1..];
            if tail.len() >= 2
                && tail.bytes().all(|c| c.is_ascii_digit())
                && let Ok(n) = tail.parse::<u64>()
            {
                return (n.saturating_sub(1)) as usize;
            }
        }
        crate::extract::vol_sort_key(name).0 as usize
    }
    /// The wait shared by both families: block until routing registers
    /// volume `index` (volumes classify in any order), then hand back
    /// the source the engine reads it through and the length it should
    /// believe. `no_more` (set at finish) turns the wait into a clean
    /// end-of-set, `None`.
    ///
    /// An SFX volume (TODO 94 C follow-up) is served through an
    /// [`OffsetSource`]: rars' stream parsers want the signature at range
    /// 0 of their source and do not scan for it, so the adapter shifts
    /// every read by the stub's length and shortens the declared length
    /// by the same amount. The buffer underneath still holds the file
    /// from byte 0 - the stub included - so a demote materializes the
    /// posted `.exe` exactly as before.
    fn chase_wait_volume(
        ctl: &ChaseCtl,
        index: usize,
    ) -> rars::Result<Option<(Arc<dyn rars::BlockingRangeSource>, u64)>> {
        let (buf, size) = {
            let mut st = ctl.shared.lock_ok();
            loop {
                if st.aborted {
                    return Err(io::Error::other("chase aborted").into());
                }
                if let Some(vol) = st.vols.get(&index) {
                    break (vol.buf.clone(), vol.size);
                }
                if st.no_more {
                    return Ok(None);
                }
                st = ctl.cv.wait(st).unwrap();
            }
        };
        let base = ctl.bases.lock_ok().get(&index).copied().unwrap_or(0);
        let len = size.saturating_sub(base);
        if base == 0 {
            return Ok(Some((buf, len)));
        }
        Ok(Some((Arc::new(OffsetSource { buf, base }), len)))
    }
    /// [`Self::chase_next_volume`], RAR4 family: same wait, the
    /// `rar15_40` incremental parse (TODO 220: the eager walk waited for
    /// the volume's tail, pinning a whole volume in the holds budget
    /// before the engine read a byte of it).
    fn chase_next_volume_v4(
        ctl: &ChaseCtl,
        index: usize,
        password: Option<&[u8]>,
    ) -> rars::Result<Option<rars::rar15_40::Archive>> {
        let Some((buf, len)) = Self::chase_wait_volume(ctl, index)? else {
            return Ok(None);
        };
        let archive = rars::rar15_40::Archive::parse_stream_incremental(
            buf,
            len,
            crate::mem::rar_read_options(password),
        )?;
        Ok(Some(archive))
    }
    /// Supply volume `index` to the sequence driver: wait until routing
    /// registers that volume's buffer (volumes classify in any order),
    /// then run the engine's header parse over it - which returns as soon
    /// as the volume's first entries are readable, NOT once the volume
    /// has fully arrived (TODO 220). `no_more` (set at finish) turns a
    /// wait into a clean end-of-set.
    fn chase_next_volume(
        ctl: &ChaseCtl,
        index: usize,
        password: Option<&[u8]>,
    ) -> rars::Result<Option<rars::rar50::Archive>> {
        let Some((buf, len)) = Self::chase_wait_volume(ctl, index)? else {
            return Ok(None);
        };
        // INCREMENTAL: the walk stops where the arrived bytes stop
        // rather than at the volume's END header, so this returns as
        // soon as the volume's first entry is readable instead of once
        // the whole volume has landed. TODO 220 - the eager walk pinned
        // an entire volume in the holds budget before the engine read a
        // byte, so a set whose VOLUMES were larger than the cap broke
        // the budget with no watermark published at all and forfeited at
        // every rung and at either depth. The engine finishes the walk
        // itself, at the point it needs an entry it does not have.
        let archive = rars::rar50::Archive::parse_stream_incremental(
            buf,
            len,
            crate::mem::rar_read_options(password),
        )?;
        Ok(Some(archive))
    }
    /// Open the routing-seam sink for one extracted member: a fresh slot
    /// of the nested child extractor, whose offset-0 sniff classifies the
    /// decompressed bytes (store RAR maps on, anything else lands Plain).
    /// The slot is recorded so a demotion can abandon partial outputs.
    fn chase_open_sink(
        me: &Weak<Extractor>,
        ctl: &ChaseCtl,
        key: &str,
        member_name: &[u8],
        is_directory: bool,
        size: u64,
    ) -> rars::Result<Box<dyn io::Write>> {
        if is_directory {
            return Ok(Box::new(io::sink()));
        }
        let Some(ex) = me.upgrade() else {
            return Err(io::Error::other("extractor dropped").into());
        };
        let name = String::from_utf8_lossy(member_name).into_owned();
        // Liveness check, slot allocation and registration under ONE
        // routing-lock hold: a demotion (chase_teardown drains
        // sink_slots under the same lock) either runs before this - the
        // fallback flag bounces us - or after, and then it sees the slot
        // we just registered. Split apart, a slot allocated after the
        // drain would leak a partial grandchild output.
        let (child, slot) = {
            let mut g = ex.inner.lock_ok();
            let inner = &mut *g;
            if inner.groups.get(key).is_none_or(|g| g.fallback) {
                return Err(io::Error::other("chase demoted").into());
            }
            let child = ex.ensure_child(inner);
            let slot = child.alloc_slot();
            ctl.sink_slots.lock_ok().push(slot);
            (child, slot)
        };
        Ok(Box::new(ChaseSink {
            child,
            slot,
            name,
            size,
            pos: 0,
        }))
    }
    /// Every registered chase volume's buffer, this extractor's groups
    /// only (a nested chase is the CHILD's, and neither the pause nor
    /// its resume has ever reached down there). Read under the routing
    /// lock; the buffers are touched off it.
    fn chase_buffers(inner: &Inner) -> Vec<Arc<FrontierBuffer>> {
        let mut bufs: Vec<Arc<FrontierBuffer>> = Vec::new();
        for g in inner.groups.values() {
            let Some(ctl) = g.chase.as_ref() else {
                continue;
            };
            for vol in ctl.shared.lock_ok().vols.values() {
                bufs.push(vol.buf.clone());
            }
        }
        bufs
    }

    /// Hold every chased volume's decode still for the duration of a
    /// mapped repair (TODO 94 B, shape-coverage row 26). Returns a
    /// guard: the decode resumes when it drops, on the success path and
    /// on every early return alike, so a declined repair can never
    /// leave a worker parked into `chase_finish`'s join.
    ///
    /// Every group, not just the one being patched: one repair covers a
    /// whole PAR2 set and a set can span more than one volume group, and
    /// a paused engine costs nothing at settle - the download is over,
    /// so no arrival is waiting on it.
    ///
    /// A VOLUME THAT REGISTERS DURING THE PAUSE IS HELD TOO (§287, 24 Aug
    /// 2026), through the `chase_reads_paused` latch this sets: the attach
    /// reads it and the new buffer is born paused, and the guard's `Drop`
    /// clears the latch and resumes the registry as it stands THEN rather
    /// than the snapshot taken here. Until that landed the pause was a
    /// snapshot of the volumes already registered, which is a hold on the
    /// SET only for as long as the engine is still inside one of them -
    /// pass the last snapshotted volume and the engine runs away through
    /// buffers nothing paused. That is not a settle-time concern (the
    /// network phase has drained, so no volume can register). The one
    /// production shape that CAN register a volume under a live pause is
    /// `nzbfast::repair`'s parity-as-a-source feed, which declined the
    /// pair outright until this landed and stopped declining it on 24 Aug
    /// 2026 (TODO 287.1) - but the snapshot is exactly what made
    /// `holds_backpressure_parks_near_the_cap_and_reopens_as_the_engine_catches_up`
    /// load-dependent, and a hold that is only true by argument is not one
    /// a test can be built on.
    pub fn pause_chase_reads(&self) -> ChaseReadPause {
        let (ex, bufs) = {
            let mut inner = self.inner.lock_ok();
            let ex = inner.self_weak.clone();
            // The latch goes on only where something could ever clear
            // it: the guard's `Drop` reaches this extractor through the
            // same weak. A root with no live `self_weak` can never carry
            // a chase either (`try_attach_chase` refuses on exactly
            // that), so there is nothing to hold and nothing to leak.
            if ex.strong_count() > 0 {
                inner.chase_reads_paused = true;
            }
            (ex, Self::chase_buffers(&inner))
        };
        for b in &bufs {
            b.set_paused(true);
        }
        ChaseReadPause { ex, bufs }
    }
    /// Stop a group's chase (demotion/abandon): the worker unblocks with
    /// errors, and every partial output slot the sink opened is
    /// abandoned in the child so no half-decoded file survives.
    /// Idempotent; the join happens off-lock at finish/drop.
    ///
    /// The one exception is the held-bytes-cap forfeit at depth 0, whose
    /// partials are KEPT for the disk pass to resume from - see
    /// [`ResumeOutput`](crate::extract::ResumeOutput) for what makes that
    /// prefix trustworthy and why no other reason qualifies.
    pub(super) fn chase_teardown(&self, inner: &mut Inner, ctl: &Arc<ChaseCtl>, reason: &str) {
        ctl.abort(reason);
        let resume = self.chase_resume_ok(reason);
        if let Some(c) = inner.child.clone() {
            for cs in ctl.sink_slots.lock_ok().drain(..) {
                if !resume {
                    c.abandon_slot(cs);
                    continue;
                }
                // `retain_slot_output` abandons the slot itself on the
                // shapes it declines, so a None here wants nothing more.
                if let Some(kept) = c.retain_slot_output(cs) {
                    inner.resume_pending.push(kept);
                }
            }
        }
    }
    /// Join every chase worker before settling. The download is over, so
    /// a buffer short of its declared size can never complete - abort it
    /// and the blocked worker unblocks with an error. The join is bounded
    /// by construction: after `no_more` + those aborts every blocking
    /// read either has its bytes or errors, so the worker always
    /// terminates (a complete chase just runs its decode out). A failed
    /// or panicked worker demotes its group to materialized volumes; a
    /// successful one releases the retained volume bytes - its outputs
    /// already live in the child chain.
    pub(super) fn chase_finish(&self) -> io::Result<()> {
        let chases: Vec<(String, Arc<ChaseCtl>)> = {
            let inner = self.inner.lock_ok();
            inner
                .groups
                .iter()
                .filter_map(|(k, g)| g.chase.clone().map(|c| (k.clone(), c)))
                .collect()
        };
        for (key, ctl) in chases {
            {
                let mut st = ctl.shared.lock_ok();
                st.no_more = true;
                for vol in st.vols.values() {
                    if !vol.buf.is_complete() {
                        vol.buf.abort("bytes never arrived");
                    }
                    // §94 B: settle has run, so no repair can rewrite
                    // these bytes any more - and a cell parked at a
                    // block no repair could fix never advances. Release
                    // the gate so the join below stays bounded; a decode
                    // fed an unrepaired block fails its own CRC and
                    // demotes, exactly as an ungated one would.
                    vol.buf.release_gate();
                }
            }
            ctl.cv.notify_all();
            let handle = ctl.worker.lock_ok().take();
            if let Some(h) = handle {
                // A worker panic surfaces as a join error and leaves no
                // outcome - handled below as a demotion, never a
                // propagated panic.
                let _ = h.join();
            }
            let outcome = ctl.shared.lock_ok().outcome.clone();
            let mut g = self.inner.lock_ok();
            let inner = &mut *g;
            if !inner.groups.contains_key(&key) {
                continue;
            }
            let already_fallback = inner.groups[&key].fallback;
            match &outcome {
                Some(Ok(())) if !already_fallback => {
                    for si in inner.groups[&key].slots.clone() {
                        let Some(ch) = inner.slots[si].chase.take() else {
                            // Not a chased volume. A group can pick up a
                            // MAPPED member by name (`rar_span`'s group
                            // assignment), and that slot's file, if it has
                            // one, is not ours to delete.
                            continue;
                        };
                        inner.budget.sub(ch.charged);
                        // A drop-behind trim may have spilled a prefix
                        // into this volume's own file on the way past.
                        // The payload came out the other way, so that
                        // file is a truncated volume nobody wants -
                        // leaving it beside the payload would look like a
                        // second, broken download (and would break the
                        // one-pass promise that no archive ever lands on
                        // disk). Same cleanup `sevenz_finish` does.
                        Self::drop_slot_file(inner, si);
                    }
                }
                _ => {
                    if !already_fallback {
                        let why = match &outcome {
                            Some(Err(e)) => format!("chase failed: {e}"),
                            None => "chase worker panicked".to_string(),
                            Some(Ok(())) => unreachable!(),
                        };
                        self.fallback_group(inner, &key, &why)?;
                    }
                }
            }
            if let Some(grp) = inner.groups.get_mut(&key) {
                grp.chase = None;
            }
        }
        Ok(())
    }
}

/// A live hold on every chased volume's decode, from
/// [`Extractor::pause_chase_reads`]. Resuming is this guard's Drop and
/// nothing else's: a repair that returns early, errors, or panics still
/// releases the engines.
pub struct ChaseReadPause {
    /// The extractor whose chases are held, weakly - the guard must not
    /// keep a cancelled job alive. Its `self_weak`, which `anchor()`
    /// sets; an attach already refuses on a root that has none, so a
    /// pause with anything to hold always has one. When it does not
    /// upgrade there is no extractor left to read a registry off, no
    /// latch was set, and `bufs` below is what resumes - which is
    /// exactly what this guard did before the latch existed.
    ex: Weak<Extractor>,
    /// The volumes registered when the pause was taken. A fallback for
    /// the no-upgrade path above, not the resume set: volumes that
    /// registered DURING the pause are not in it.
    bufs: Vec<Arc<FrontierBuffer>>,
}

impl Drop for ChaseReadPause {
    fn drop(&mut self) {
        let mut bufs = std::mem::take(&mut self.bufs);
        if let Some(ex) = self.ex.upgrade() {
            // Clear the latch and re-read the registry under ONE hold of
            // the routing lock, so an attach racing this either sees the
            // latch set and is resumed by the list below, or sees it
            // clear and never pauses. Either way nothing is left paused.
            let mut inner = ex.inner.lock_ok();
            inner.chase_reads_paused = false;
            bufs = Extractor::chase_buffers(&inner);
        }
        // Off the routing lock: resuming notifies each buffer's arrival
        // condvar, which wakes the chase worker, and the first thing it
        // does with the bytes is ask this extractor for more.
        for b in &bufs {
            b.set_paused(false);
        }
    }
}

/// A demoted volume whose file is missing the ranges a dropping trim
/// released - see [`Extractor::dropped_volumes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DroppedVolume {
    pub slot: usize,
    /// The posted (yEnc) name, which a re-fetch writes under.
    pub posted: String,
    /// The slot's name now - the same, unless a PAR2 rename moved it.
    pub current: String,
    /// `(volume offset, len)`, ascending.
    pub ranges: Vec<(u64, u64)>,
}

/// Which container format a `SlotMode::SevenZ` chase is actually
/// driving. The chase machinery (frontier buffers, the one-part/N-part
/// set, tail promote, trim, demote, finish joining) is format-agnostic;
/// only the worker parsing the container differs - so zip rides the 7z
/// mode rather than re-teaching a new mode to every `is_mapped` seam
/// (the six TODO-37 findings all lived in those seams). This tag is
/// what keeps the user-facing words honest: the demote prefix, the
/// badge kind and the finish diagnostics read it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum ChaseFormat {
    SevenZ,
    Zip,
    Tar,
}

impl ChaseFormat {
    pub(super) fn noun(self) -> &'static str {
        match self {
            ChaseFormat::SevenZ => "7z",
            ChaseFormat::Zip => "zip",
            ChaseFormat::Tar => "tar",
        }
    }
}

/// Per-slot chase attachment: the slot's volume bytes live here (instead
/// of holds / a writer) while the chase runs. `charged` is what this
/// buffer currently holds against the shared budget.
pub(super) struct ChaseSlot {
    pub(super) buf: Arc<FrontierBuffer>,
    pub(super) charged: usize,
    /// Consumed prefix ranges the drop-behind trim released WITHOUT a
    /// disk copy (`(offset, len)`, ascending, coalesced). Empty for a
    /// spilling trim. A demote carries them to `Slot::dropped` so the
    /// caller can re-fetch what the volume file is now missing.
    pub(super) dropped: Vec<(u64, u64)>,
    /// The slot's name when the first drop happened - the posted yEnc
    /// name, which is what a re-fetch lands under. A PAR2 rename can
    /// move the slot before a demote, so the demote keeps this one.
    pub(super) dropped_as: String,
}

/// One chase = one compressed inner archive (one group): its registered
/// volume buffers, the worker driving the streaming decode, and the
/// bookkeeping the demote path needs to unwind cleanly.
pub(super) struct ChaseCtl {
    pub(super) shared: Mutex<ChaseShared>,
    pub(super) cv: Condvar,
    /// Drop-behind watermarks published by the RAR engine: volume index
    /// -> the lowest offset it may still ask for, `u64::MAX` once it is
    /// finished with the volume entirely. Its own lock because the engine
    /// writes it from the decode thread while routing reads it under the
    /// extractor lock; taking `shared` for that would put the extractor
    /// lock ahead of the one every blocking volume wait holds.
    pub(super) low_water: Mutex<BTreeMap<usize, u64>>,
    /// Volume index -> where the archive starts inside the volume's
    /// file: the stub's length on an SFX volume (TODO 94 C), 0 for every
    /// other. Written at attach, before the volume is registered; read
    /// by [`Extractor::chase_wait_volume`] to build the engine's source
    /// and by the watermark publish to translate back. Its own lock for
    /// the same reason as `low_water`.
    pub(super) bases: Mutex<BTreeMap<usize, u64>>,
    pub(super) worker: Mutex<Option<std::thread::JoinHandle<()>>>,
    /// Child-extractor slots the sink opened for extracted members -
    /// abandoned (partial outputs deleted) if the chase demotes.
    pub(super) sink_slots: Mutex<Vec<usize>>,
    /// RAR family of this set: `true` drives the `rar15_40` engine, `false`
    /// the `rar50` one. Fixed at attach; a slot of the other family never
    /// joins (mixed families are not a set).
    pub(super) v4: bool,
}

/// One registered volume of a chased set.
pub(super) struct ChaseVol {
    pub(super) buf: Arc<FrontierBuffer>,
    /// Declared volume size (the level-N entry's unpacked size).
    pub(super) size: u64,
    /// The slot holding this volume - the drop-behind trim spills into
    /// its archive file, and adjusts its budget charge.
    pub(super) slot: usize,
}

#[derive(Default)]
pub(super) struct ChaseShared {
    /// Volume index -> its buffer, size and slot.
    pub(super) vols: BTreeMap<usize, ChaseVol>,
    /// Download over: an index past the registered set means "no more
    /// volumes" rather than "not arrived yet".
    pub(super) no_more: bool,
    /// Demoted/cancelled: the worker unblocks with an error.
    pub(super) aborted: bool,
    /// The worker's exit status, set exactly once before it returns.
    pub(super) outcome: Option<Result<(), String>>,
}

impl ChaseCtl {
    pub(super) fn new(v4: bool) -> ChaseCtl {
        ChaseCtl {
            shared: Mutex::new(ChaseShared::default()),
            cv: Condvar::new(),
            low_water: Mutex::new(BTreeMap::new()),
            bases: Mutex::new(BTreeMap::new()),
            worker: Mutex::new(None),
            sink_slots: Mutex::new(Vec::new()),
            v4,
        }
    }

    /// Stop the worker: abort every registered buffer and flag the state
    /// so a wait for an unregistered volume wakes with an error. Join
    /// happens later, off-lock (finish / drop).
    pub(super) fn abort(&self, reason: &str) {
        let mut st = self.shared.lock_ok();
        st.aborted = true;
        for vol in st.vols.values() {
            vol.buf.abort(reason);
        }
        drop(st);
        self.cv.notify_all();
    }
}

/// The chase's routing-seam sink: extracted member bytes stream into a
/// slot of the nested child extractor, whose offset-0 sniff classifies
/// them - a store RAR below the compressed layer keeps streaming, plain
/// payloads land as ordinary files. Writes are sequential from 0.
pub(super) struct ChaseSink {
    pub(super) child: Arc<Extractor>,
    pub(super) slot: usize,
    pub(super) name: String,
    pub(super) size: u64,
    pub(super) pos: u64,
}

impl io::Write for ChaseSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.child
            .write(self.slot, &self.name, self.size, self.pos, buf)?;
        self.pos += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "chase_tests.rs"]
pub(super) mod chase_tests;

#[cfg(test)]
#[path = "chase_shape_tests.rs"]
pub(super) mod chase_shape_tests;

/// A RAR archive's view of a volume that starts `base` bytes into its
/// file - the SFX case (TODO 94 C), where a launcher stub precedes the
/// signature. Every coordinate the engine speaks is shifted by `base`
/// on the way in; the watermark it publishes is shifted back by
/// [`file_watermark`] on the way out, so the [`FrontierBuffer`] and
/// everyone reading it (the trim, the pace gate, the demote) stay in
/// file coordinates.
#[derive(Debug)]
pub(super) struct OffsetSource {
    pub(super) buf: Arc<FrontierBuffer>,
    pub(super) base: u64,
}

impl rars::BlockingRangeSource for OffsetSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let Some(at) = offset.checked_add(self.base) else {
            return Ok(0);
        };
        rars::BlockingRangeSource::read_at(&*self.buf, at, buf)
    }

    fn known_len(&self) -> u64 {
        rars::BlockingRangeSource::known_len(&*self.buf).saturating_sub(self.base)
    }

    fn total_len(&self) -> Option<u64> {
        rars::BlockingRangeSource::total_len(&*self.buf).map(|t| t.saturating_sub(self.base))
    }
}

/// The engine's drop-behind watermark, published in ARCHIVE coordinates
/// (`u64::MAX` = the whole volume), as a FILE offset of the volume that
/// starts `base` bytes in. The whole-volume marker survives unchanged,
/// which is what the trim's "finished with" test relies on.
pub(super) fn file_watermark(base: u64, offset: u64) -> u64 {
    if offset == u64::MAX {
        u64::MAX
    } else {
        offset.saturating_add(base)
    }
}
