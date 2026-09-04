//! The matcher's REFERENCE half: the pre-B6 linear drain kept as the
//! differential oracle, and the microbench hook that drives both drains.
//!
//! Neither is production code. `try_match_linear` exists so any drift
//! between the indexed tiers in the parent and the semantics they
//! replaced fails a test instead of crossing a claim, and `bench_match`
//! is what `examples/live_match_bench.rs` calls.
//!
//! Split out of `live.rs` (TODO 106 size gate), body verbatim; a child
//! module, so `SlotState`'s private fields stay private to this file's
//! parent and its descendants.

use super::*;

impl SlotState {
    /// The pre-B6 linear matcher, byte-for-byte: full descriptor scans and
    /// per-candidate `sanitize_filename` calls. NOT called in production -
    /// kept as the oracle for the differential tests and as the baseline
    /// leg of [`bench_match`], so any drift between the indexed tiers and
    /// the original semantics fails a test instead of crossing a claim.
    pub(super) fn try_match_linear(
        &mut self,
        slot: usize,
        active: &Active,
        tentative: bool,
    ) -> bool {
        let head_key = self.head_key();
        let mut claimed = active.claimed.lock_ok();

        let mut name_ambiguous = false;
        let mut nominee: Option<usize> = None;
        if let Some(name) = &self.name {
            let sname = crate::disk::sanitize_out_name(name);
            let exact: Vec<usize> = active
                .files()
                .filter(|(fi, f)| claimed[*fi].is_none() && f.name == **name)
                .map(|(fi, _)| fi)
                .collect();
            let cands: Vec<usize> = if !exact.is_empty() {
                exact
            } else {
                let mut it = active.files().filter(|(fi, f)| {
                    claimed[*fi].is_none()
                        && (f.name.eq_ignore_ascii_case(name)
                            || crate::disk::sanitize_out_name(&f.name) == sname)
                });
                let first = it.next();
                if it.next().is_none() {
                    first.map(|(fi, _)| fi).into_iter().collect()
                } else {
                    name_ambiguous = true;
                    Vec::new()
                }
            };
            let want = self.head_want();
            let hit = arbitrate_by_head(&cands, active, want, head_key);
            if hit.is_none() && !cands.is_empty() {
                name_ambiguous = true;
                // The tentative nominee, taken below only if the
                // content tiers find nothing better. With NO head yet
                // the first candidate is taken however many there are -
                // that is the pre-nomination answer, and it is safe
                // again because the binding is tentative: the head
                // completing re-judges it (`rejudge_binding`) and moves
                // it to the descriptor the content names, so FileDesc
                // order no longer DECIDES anything (W4-02B). With a head
                // that denied every candidate there is nothing to
                // re-judge, so a sole candidate is the only one worth
                // verifying against.
                nominee = if head_key.is_none() {
                    cands.first().copied()
                } else if cands.len() == 1 {
                    Some(cands[0])
                } else {
                    None
                };
            }
            if let Some((fi, sure)) = hit {
                if sure {
                    claimed[fi] = Some(slot);
                }
                self.file = Some(fi);
                self.confirmed = sure;
                self.head_nominated = false;
                self.blocks = vec![BlockState::Pending; active.file(fi).blocks.len()];
                return true;
            }
        }
        let want = self.head_want();
        let mut head_ambiguous = false;
        if want > 0
            && self
                .head
                .as_ref()
                .is_some_and(|h| h.buf.len() == want && h.complete())
        {
            let head_md5: [u8; 16] = Md5::digest(&self.head.as_ref().unwrap().buf).into();
            let mut hit: Option<usize> = None;
            // F9, and kept in step with the parent's head tier by hand:
            // a descriptor this head names but another slot HOLDS is not
            // a head that matched nothing, so it must not feed the latch
            // below. The claimed test runs after the content filter for
            // the same reason it does there.
            let mut claimed_rival = false;
            for (fi, f) in active.files() {
                if f.length.min(HEAD_LEN as u64) != want as u64 {
                    continue;
                }
                if f.md5_16k != head_md5 {
                    continue;
                }
                if claimed[fi].is_some() {
                    claimed_rival = true;
                    continue;
                }
                match hit {
                    None => hit = Some(fi),
                    // W4-15, and the reason this file exists: the same
                    // cross-set identity rule the parent's head tier
                    // applies. Two descriptors agreeing on the length AND
                    // the whole-file MD5 describe ONE file - the ordinary
                    // shape of a post carrying two overlapping sets over
                    // one member - and are not the rivals this tier
                    // declines on. Kept in step by hand because that is
                    // what `differential_fuzz_variant_pools` checks: it
                    // caught this arm the first time it was not.
                    Some(h) if active.file(h).length == f.length && active.file(h).md5 == f.md5 => {
                        continue;
                    }
                    Some(_) => {
                        head_ambiguous = true;
                        hit = None;
                        break;
                    }
                }
            }
            if let Some(fi) = hit {
                // M4-103, and kept in step with the parent's head tier by
                // hand, `head_nominated` included: a head that does not
                // cover the descriptor WHOLE is a nomination, so the
                // claim it takes is revocable and `settle_binding` gets
                // the last word. `differential_a_head_shorter_than_its_
                // descriptor_nominates_in_both_drains` is what checks
                // that this file did not stay on the old rule - the fuzz
                // pool above it cannot, since every descriptor in it is
                // smaller than a 16 KiB head.
                let whole_file = active.file(fi).length <= HEAD_LEN as u64;
                claimed[fi] = Some(slot);
                self.file = Some(fi);
                self.confirmed = whole_file;
                self.head_nominated = !whole_file;
                self.blocks = vec![BlockState::Pending; active.file(fi).blocks.len()];
                return true;
            }
            if self.name.is_some() && !name_ambiguous && !head_ambiguous && !claimed_rival {
                // Kept in step with the parent's latch by hand, the
                // generation included: a refusal records the adopted
                // population it was reached against, and a reference
                // drain that recorded a different one would disagree
                // with production the moment a second set activates.
                self.unmatchable = Some(active.adopted_gen);
            }
        }
        if tentative
            && let Some(fi) = nominee
            && claimed[fi].is_none()
        {
            self.file = Some(fi);
            self.confirmed = false;
            self.head_nominated = false;
            self.blocks = vec![BlockState::Pending; active.file(fi).blocks.len()];
            return true;
        }
        false
    }
}

/// Matcher microbench hook (`examples/live_match_bench.rs`) - drives the
/// match tiers the way `on_data` hits them: `calls` attempts round-robin
/// over one slot per probe name, against a fresh claim table for `set`
/// (map build included, as activation pays it). `indexed` picks the
/// production pre-index matcher or the pre-B6 linear reference. Returns
/// how many probes ended claimed, so the harness can assert both paths
/// agree and the work is not optimized away.
#[doc(hidden)]
pub fn bench_match(
    set: &Arc<Par2Set>,
    probe_names: &[String],
    calls: usize,
    indexed: bool,
) -> usize {
    let active = Active::new(vec![set.clone()]);
    let mut slots: Vec<SlotState> = probe_names
        .iter()
        .map(|n| {
            let mut s = SlotState::empty();
            if !n.is_empty() {
                s.name = Some(n.clone());
            }
            s
        })
        .collect();
    for c in 0..calls {
        let i = c % slots.len();
        let s = &mut slots[i];
        if s.file.is_none() && !s.refused(&active) {
            if indexed {
                s.try_match(i, &active, true);
            } else {
                s.try_match_linear(i, &active, true);
            }
        }
    }
    slots.iter().filter(|s| s.file.is_some()).count()
}
