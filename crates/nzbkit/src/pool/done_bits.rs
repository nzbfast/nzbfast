//! C4 (perf audit): the run's completion set as a dense bit vector.
//!
//! The old `HashSet<String>` cost ~110 B and one String clone per
//! completed article - ~30 MiB of set on a 128k-article job, held for
//! the whole run. Every servable unique article now gets a `u32`
//! ordinal at queue construction (its accepted-request index), the set
//! becomes one bit per ordinal (~0.03 MiB at 128k), and the ordinal
//! rides `Work` and `Inflight` exactly as A2's `age_days`/`part` do -
//! so a hedge dup claims the SAME bit as its original and the
//! one-outcome-per-article arbitration is unchanged.
//!
//! Deliberately a plain struct behind the same mutex the set lived
//! behind: `claim`/`clear` and the exact set-bit count must move
//! together (the hedge budget reads the count against membership taken
//! in the same lock hold), and per the audit's own note, atomics do
//! not simplify that invariant.

/// Dense completion bitset indexed by `Work::ord`, plus the exact
/// set-bit count maintained on every flip.
pub(super) struct DoneBits {
    bits: Vec<u64>,
    n: usize,
}

impl DoneBits {
    /// Sized for the run's ordinal space (the constructed queue). Test
    /// rigs that invent extra articles past it are absorbed by `claim`
    /// growing on demand; production never claims past `cap`.
    pub(super) fn new(cap: usize) -> Self {
        DoneBits {
            bits: vec![0; cap.div_ceil(64)],
            n: 0,
        }
    }

    /// First-emitter claim: set the bit, true exactly once per ordinal.
    pub(super) fn claim(&mut self, ord: u32) -> bool {
        let (slot, bit) = (ord as usize / 64, 1u64 << (ord % 64));
        if slot >= self.bits.len() {
            self.bits.resize(slot + 1, 0);
        }
        let newly = self.bits[slot] & bit == 0;
        if newly {
            self.bits[slot] |= bit;
            self.n += 1;
        }
        newly
    }

    /// Un-claim (requeue-after-claim, cancel's requeue): clear the bit,
    /// true when it was set.
    pub(super) fn clear(&mut self, ord: u32) -> bool {
        let (slot, bit) = (ord as usize / 64, 1u64 << (ord % 64));
        let was = self.bits.get(slot).is_some_and(|w| w & bit != 0);
        if was {
            self.bits[slot] &= !bit;
            self.n -= 1;
        }
        was
    }

    pub(super) fn contains(&self, ord: u32) -> bool {
        self.bits
            .get(ord as usize / 64)
            .is_some_and(|w| w & (1u64 << (ord % 64)) != 0)
    }

    /// Exact number of claimed articles (the hedge issue-rate budget).
    pub(super) fn count(&self) -> usize {
        self.n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The claim/clear/count invariant the mutex exists to protect:
    /// the count equals the set bits after any interleaving of flips,
    /// and claim answers true exactly once per ordinal until cleared.
    #[test]
    fn claim_clear_and_count_stay_mutually_consistent() {
        let mut d = DoneBits::new(130);
        assert_eq!(d.count(), 0);
        assert!(!d.contains(0));
        assert!(d.claim(0));
        assert!(!d.claim(0), "second claim loses the arbitration");
        assert!(d.claim(63));
        assert!(d.claim(64), "word boundary");
        assert!(d.claim(129), "last ordinal of the space");
        assert_eq!(d.count(), 4);
        assert!(d.contains(64) && !d.contains(65));
        // Un-claim reopens exactly that ordinal.
        assert!(d.clear(64));
        assert!(!d.clear(64), "a second clear is a no-op");
        assert_eq!(d.count(), 3);
        assert!(!d.contains(64));
        assert!(d.claim(64), "a cleared ordinal is claimable again");
        assert_eq!(d.count(), 4);
    }

    /// Out-of-space ordinals (test rigs inventing articles): claim
    /// grows, contains/clear answer false without growing.
    #[test]
    fn ordinals_past_the_constructed_space_grow_on_claim_only() {
        let mut d = DoneBits::new(1);
        assert!(!d.contains(500));
        assert!(!d.clear(500));
        assert_eq!(d.count(), 0);
        assert!(d.claim(500));
        assert!(d.contains(500));
        assert_eq!(d.count(), 1);
        // A zero-capacity run (every request unservable) still works.
        let mut z = DoneBits::new(0);
        assert!(!z.contains(0));
        assert!(z.claim(0));
    }
}
