//! Who may take this article: the fill gate and the masks that open it.
//!
//! A level-N server is held off queued work until every live server
//! below it is done with the article. "Done" is two different things,
//! and conflating them was M5 of the 14 Aug sweep: `tried_430` is a
//! server ANSWERING that it does not have the article, while `spent`
//! records a server that answered nothing at all and simply ran out of
//! attempts - resets, stalls, protocol errors. Only the first is
//! evidence. `tried_430` feeds unanimous-Missing, the M29 oracle's miss
//! ledger and the §146 give-up census, so a bit forged there invents a
//! `Gone` for an article some backbone still holds. But BOTH must open
//! the gate, because a primary that kills the same article's connection
//! every time never 430s it, and until this split the healthy demoted
//! tier stayed locked out by `required_mask` and watched the article
//! die on the one server that had proved it could not fetch it.
//!
//! Split out of `pool.rs` whole (TODO 106 size gate) - the code is
//! verbatim, only visibility changed. A child module, so `Shared`,
//! `Work` and `server_bit` stay in scope as they were inline;
//! `pub(super)` reads "pub in pool", which puts these back in front of
//! pool.rs AND its other children (pool/queue.rs calls
//! `other_can_take`) exactly as the private ones were.

use super::*;

/// The routing bit for a server index.
///
/// This used to be spelled `1u32 << si.min(31)`, which ALIASED every server
/// from index 31 upward onto bit 31. Server 31 returning 430 therefore set
/// the bit that server 32 reads as "I already tried here", so once servers
/// 0-31 had missed, an article could go terminal Missing without server 32
/// ever being sent a BODY - even when it held the article. A hostile or
/// merely broken provider at index 31 could suppress the last healthy one.
///
/// Returning 0 for an unrepresentable index is defence in depth only: no bit
/// is strictly safer than another server's bit, but the config cap above is
/// what actually keeps this reachable.
#[inline]
pub(super) fn server_bit(si: usize) -> u32 {
    debug_assert!(si < MAX_SERVERS, "server index {si} has no routing bit");
    if si < MAX_SERVERS { 1u32 << si } else { 0 }
}

pub(super) fn servers_mask(n: usize) -> u32 {
    if n >= MAX_SERVERS {
        u32::MAX
    } else {
        (1u32 << n) - 1
    }
}

impl Shared {
    /// Bits a level-L server must see in tried_430 before it may take
    /// queued work: every live server on a lower level.
    pub(super) fn required_mask(&self, level: u32) -> u32 {
        let mut m = 0u32;
        for (si, &l) in self.levels.iter().enumerate() {
            if l < level && self.alive[si].load(Ordering::Relaxed) > 0 {
                m |= server_bit(si);
            }
        }
        m
    }

    /// Bits of the servers that have spent their whole retry budget on
    /// this article (see [`Shared::spent`]). One atomic load when
    /// nothing ever exhausted a budget, which is every healthy run.
    pub(super) fn spent_mask(&self, id: &str) -> u32 {
        if self.spent_n.load(Ordering::Acquire) == 0 {
            return 0;
        }
        self.spent.lock_ok().get(id).copied().unwrap_or(0)
    }

    /// M5: the server this `bit` belongs to just used the last of
    /// `article_retries` on this article without ever being answered:
    /// every attempt died in transport, so `tried_430` is still empty
    /// and `required_mask` holds the article on the one tier that has
    /// demonstrably failed to fetch it.
    /// Records the bit and answers whether the ladder has somewhere
    /// left to go: some LIVE server that has neither refused this
    /// article, nor killed it in transport, nor spent a budget of its
    /// own on it. True means the caller re-arms `attempts` and requeues
    /// instead of declaring the article lost while a healthy server
    /// still holds it.
    ///
    /// Termination is structural, not a hope: the re-arm is granted
    /// only the FIRST time a given server exhausts itself here, so the
    /// whole article costs at most (article_retries + 1) attempts per
    /// configured server before a Failed, the same bound the 430 ladder
    /// has always carried.
    /// M8 (sweep 8): put back the `spent` bits [`Shared::claim_done`]
    /// dropped when a body was provisionally claimed, because the
    /// decode verdict has now sent that article back into the queue.
    /// The article is not terminal after all, so the evidence that
    /// opened its fill tier has to be live again before a worker can
    /// adopt the requeue - `next_work`'s pickup gate reads the same map
    /// (`tried_430 | spent_mask`), so without this the steer's chosen
    /// server is admitted by `other_can_take` and then gated out at the
    /// pick. Caller holds the steer inbox, which is what keeps the
    /// restore ahead of any adoption.
    pub(super) fn restore_spent(&self, id: &str, bits: u32) {
        if bits == 0 {
            return;
        }
        let mut m = self.spent.lock_ok();
        *m.entry(Arc::from(id)).or_insert(0) |= bits;
        self.spent_n.store(m.len(), Ordering::Release);
    }

    pub(super) fn note_spent(&self, w: &Work, bit: u32) -> bool {
        let (fresh, spent) = {
            let mut m = self.spent.lock_ok();
            let e = m.entry(w.id.clone()).or_insert(0);
            let fresh = *e & bit == 0;
            *e |= bit;
            let spent = *e;
            self.spent_n.store(m.len(), Ordering::Release);
            (fresh, spent)
        };
        if !fresh {
            return false;
        }
        let touched = w.tried_430 | w.tried_fail | spent;
        self.alive
            .iter()
            .enumerate()
            .any(|(si, a)| a.load(Ordering::Relaxed) > 0 && touched & server_bit(si) == 0)
    }

    /// True when some OTHER live server could take this work item: it
    /// hasn't 430'd it, hasn't transport-failed it, and its fill gate (if
    /// any) is satisfied. Used to steer a transport-failed article's retry
    /// away from the server that just failed it.
    pub(super) fn other_can_take(&self, w: &Work, me: usize) -> bool {
        self.other_can_take_with(w, me, 0)
    }

    /// [`Shared::other_can_take`] with routing evidence the live map no
    /// longer holds folded in.
    ///
    /// M8 (sweep 8): a provisional `claim_done` drops the article's
    /// `spent` entry at HANDOFF, before the decode verdict that may yet
    /// send the article back down the ladder - so the bad-body steer
    /// asked this question with the exact evidence that opened the fill
    /// tier already erased, and refused an otherwise valid retry. The
    /// steer carries the pre-claim mask on its stashed `Handed` record
    /// and passes it here; every other caller reads the live map alone
    /// and passes 0.
    pub(super) fn other_can_take_with(&self, w: &Work, me: usize, extra_spent: u32) -> bool {
        // A spent lower tier counts toward the gate exactly as a 430
        // does: it is done with this article either way, and without
        // that the failing primary reads "nobody else can have it" and
        // retakes its own casualty until the budget is gone.
        let evidence = w.tried_430 | self.spent_mask(&w.id) | extra_spent;
        for (si, &level) in self.levels.iter().enumerate() {
            if si == me || self.alive[si].load(Ordering::Relaxed) == 0 {
                continue;
            }
            let bit = server_bit(si);
            if w.tried_430 & bit != 0 || w.tried_fail & bit != 0 {
                continue;
            }
            let required = if level > 0 {
                self.required_mask(level)
            } else {
                0
            };
            if evidence & required == required {
                return true;
            }
        }
        false
    }
}
