//! The tentative-binding LIFECYCLE: what promotes a nomination to a
//! claim, what re-judges one, and what takes one away again.
//!
//! `try_match` in the parent lets a NAME and (since M4-103) a HEAD
//! nominate a descriptor; these three are every way a nomination stops
//! being one before finish. The fourth is `nametier::settle_binding`,
//! which runs at finish and is a `SlotState` method rather than a
//! `LiveVerifier` one because by then there is nothing global left to
//! wind back.
//!
//! Split out of `live.rs` (TODO 106 size gate), bodies verbatim; a
//! child module, so `SlotState`'s private fields stay private to this
//! file's parent and its descendants.

use super::*;

impl LiveVerifier {
    /// An Ok block is content proof, and the first one turns a name's
    /// tentative nomination into a claim ([`SlotState::confirmed`]).
    ///
    /// Its own function, taking the plan and then the slot, because that
    /// is the order `on_data_inner` takes them in and the promotion is
    /// decided at the foot of the span path where the plan lock has been
    /// released for hashing. Taking it back under the slot lock there
    /// would invert the order against every other caller.
    ///
    /// A descriptor the real owner claimed by content in the meantime
    /// simply drops the binding: two slots may nominate the same
    /// descriptor precisely because a nomination locks nobody out.
    pub(super) fn promote_binding(&self, slot: usize) {
        let plan = self.plan.read_ok();
        let Plan::Active(active) = &*plan else {
            return;
        };
        let mut s = self.slots[slot].lock_ok();
        let Some(fi) = s.file else {
            return;
        };
        if s.confirmed || s.live_ok == 0 {
            return;
        }
        let mut claimed = active.claimed.lock_ok();
        if claimed[fi].is_none() {
            claimed[fi] = Some(slot);
            s.confirmed = true;
            return;
        }
        drop(claimed);
        self.forget_binding(&mut s, slot, active);
        // §94 B, F13: this slot engaged the gate when its nomination was
        // made and the nomination has just lost the claim, so a chase
        // reader parked on this slot ticks at 100 ms until the gate is
        // released - which costs the one-pass extraction of that whole
        // chase group. THE RELEASE IS NOT DONE HERE, and an in-stream
        // one landed briefly on 1 Sep 2026 and was taken back out the
        // same day: the frontier latches whatever it reads with
        // `fetch_max`, so a release seen by a reader is permanent for
        // that buffer, while a slot with no binding can still rebind on
        // a later article and would then run ungated. See the note
        // beside `VerifyGate::advance`. `finish_slot_from` releases
        // every engaged, unbound slot instead.
    }

    /// Re-judge a tentative binding once the head has completed.
    ///
    /// The binding is DROPPED only when the head both denies the
    /// nominated descriptor AND names another one outright - a unique
    /// unclaimed md5-16k match. Denial alone is not enough and must not
    /// be: a truthfully-named member damaged inside its own first
    /// 16 KiB denies exactly the same way, and dropping that one would
    /// cost it its in-stream verification and price a repairable file as
    /// wholly missing. What is left after this is the case with no rival
    /// at all, which `settle_binding` settles at finish on the whole
    /// file.
    ///
    /// The blocks verified under the old binding go with it: they were
    /// judged against the wrong descriptor. They are read back at
    /// finish, which is the right price for a slot whose name lied.
    pub(super) fn rejudge_binding(&self, slot: usize, s: &mut SlotState, active: &Active) {
        let Some(fi) = s.file else {
            return;
        };
        if s.head_rival_ruled_out {
            return;
        }
        let Some(key) = s.head_key() else {
            return;
        };
        let want = s.head_want();
        if head_says(active.file(fi), want, key) != HeadSays::Deny {
            return;
        }
        let (rival, seen) = {
            let claimed = active.claimed.lock_ok();
            let (mut hit, mut seen) = (None, 0usize);
            for (gi, g) in active.files() {
                if gi == fi || claimed[gi].is_some() {
                    continue;
                }
                if head_says(g, want, key) == HeadSays::Confirm {
                    seen += 1;
                    hit = if seen == 1 { Some(gi) } else { None };
                }
            }
            (hit, seen)
        };
        let Some(_) = rival else {
            s.head_rival_ruled_out = seen == 0;
            return;
        };
        self.forget_binding(s, slot, active);
        // A false return means the rival was claimed between the scan
        // above and the re-match, so this slot ends the article with no
        // binding at all - and its gate cell is still engaged at
        // whatever watermark the dropped binding reached (F13). It STAYS
        // engaged: a re-match on a later article re-engages from zero,
        // and a reader that had already seen a release would never
        // consult the gate again (the frontier caches with `fetch_max`),
        // so the rebound slot would be ungated. `finish_slot_from`
        // releases it if no later article rebinds this slot.
        s.try_match(slot, active, true);
    }

    /// [`SlotState::unbind`] plus the global wind-back it owes - and the
    /// CLAIM, where this slot's binding was holding one tentatively.
    ///
    /// Only the md5-16k tier's nomination ever does (M4-103); a name's
    /// locks nobody out, so the release is a no-op for it, and the
    /// `Some(slot)` test keeps it one - a descriptor some OTHER slot
    /// claimed by content while we verified is not ours to hand back.
    /// Releasing matters because a dropped nomination goes back on the
    /// table for `try_match_whole` and `try_match_named`; left claimed
    /// by a slot that is not its file it is reported neither verified
    /// nor missing.
    pub(super) fn forget_binding(&self, s: &mut SlotState, slot: usize, active: &Active) {
        use std::sync::atomic::Ordering;
        if let Some(fi) = s.file
            && !s.confirmed
        {
            let mut claimed = active.claimed.lock_ok();
            if claimed[fi] == Some(slot) {
                claimed[fi] = None;
            }
        }
        let (ok, bad, held) = s.unbind();
        // The prefix digest describes THIS binding's file. The slot now
        // holds nothing, and whatever it binds next has its own length,
        // block size and bytes - so the digest goes with the binding it
        // was taken under (`live/prefix.rs`, "when it is void").
        self.prefix_void(slot);
        self.live_ok_total.fetch_sub(ok, Ordering::Relaxed);
        self.live_bad_total.fetch_sub(bad, Ordering::Relaxed);
        self.partials_used.fetch_sub(held, Ordering::Relaxed);
    }
}
