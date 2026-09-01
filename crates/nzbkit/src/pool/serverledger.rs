//! Per-server observation ledger: what this run has learned about one
//! server, and nothing about the articles it was learned from.
//!
//! Split out of `pool.rs` whole under the size gate (TODO 106). Two
//! groups of inherent `impl Shared` methods that were never adjacent in
//! the parent but answer one question - what has this server cost, what
//! has it answered, and how has it refused: the §96.5 prepaid-block
//! latch, the TODO 96.1 time-to-status EWMA and the budgets derived from
//! it, the session-end and 430-attribution tallies, the flap breaker,
//! and the cap-bounce clamp that prices a capacity refusal into a keeper
//! target. Every one of them reads or writes a `self.<field>[idx]` cell
//! keyed by server index; not one of them touches the queue.
//!
//! The bodies are verbatim. A child module sees the parent's private
//! items (`Shared` and its fields, `PoolConfig`, the tuning constants,
//! the `pacing` helpers), so only the twelve still-private methods
//! widened to `pub(super)` for the call sites in pool/session.rs,
//! pool/stats.rs, pool/runlife.rs and the sibling test modules -
//! `over_budget` and `note_budget_spent` already were.

use super::*;

impl Shared {
    /// §96.5: has this server spent its remaining prepaid block on this
    /// run? One relaxed load and a compare - the fast path the top-up
    /// loop and the pre-dial gate check per pass. `bytes` only grows,
    /// so a true answer is permanent for the run.
    pub(super) fn over_budget(&self, idx: usize) -> bool {
        let b = self.budget_bytes[idx];
        b > 0 && self.bytes[idx].load(Ordering::Relaxed) >= b
    }

    /// §96.5: first worker past the budget emits the one "block spent"
    /// event; the latch also keeps `note_server_dark` from relabelling
    /// the exit as a connection failure.
    pub(super) fn note_budget_spent(&self, idx: usize) {
        if self.budget_noted[idx].swap(true, Ordering::Relaxed) {
            return;
        }
        if let Some(live) = &self.live {
            live.note(
                idx,
                "block",
                "prepaid block spent - stopped fetching mid-download; \
                 any remaining articles go to the other servers",
            );
        }
    }

    /// Adaptive pre-byte budget for a server (TODO 96.1): 4x its
    /// time-to-status EWMA, clamped to [2 s, 10 s]. Unmeasured servers
    /// budget at the ceiling - generosity until the first sample, never
    /// a guess. With pipelining the status line is often already
    /// buffered (a ~0 ms sample); the floor keeps the budget honest
    /// against that collapse.
    pub(super) fn ttfb_budget(&self, idx: usize) -> Duration {
        let mut ms = ttfb_budget_ms(self.ttfb_ms[idx].load(Ordering::Relaxed));
        // A sole-server fleet has nowhere to re-place a killed article,
        // so it budgets against a doubled floor - see
        // [`pacing::sole_server_floor_ms`] for the measurement.
        if self.ttfb_ms.len() == 1 {
            ms = ms.max(pacing::sole_server_floor_ms());
        }
        Duration::from_millis(ms)
    }

    /// TTFB-suspicion bound for a server (TODO 115): see
    /// [`ttfb_suspect_ms`].
    pub(super) fn ttfb_suspect_after(&self, idx: usize) -> Duration {
        Duration::from_millis(ttfb_suspect_ms(self.ttfb_ms[idx].load(Ordering::Relaxed)))
    }

    /// Feed one measured time-to-status into the server's EWMA
    /// (alpha 0.2, integer ms, floor 1 so a fast loopback sample can't
    /// re-zero the cell back to "unmeasured"). Plain load/store: a lost
    /// update under a race is one dropped sample, not a wrong number.
    pub(super) fn note_ttfb(&self, idx: usize, sample: Duration) {
        let ms = (sample.as_millis() as u64).max(1);
        let cell = &self.ttfb_ms[idx];
        let old = cell.load(Ordering::Relaxed);
        let new = if old == 0 { ms } else { (old * 4 + ms) / 5 };
        cell.store(new.max(1), Ordering::Relaxed);
    }

    /// A pre-byte timeout on this server: widen the budget instead of
    /// leaving it where it was.
    ///
    /// Only SUCCESSFUL status reads feed the EWMA, so a budget trained
    /// down to the floor by pipelined ~0 ms samples had no way back
    /// up if the provider then settled at a stable latency above it:
    /// every read timed out, every timeout produced no sample, and
    /// healthy articles failed forever on a link the flat 30 s path
    /// would have served (Codex sweep 3 Aug M4). A timeout is evidence
    /// too - censored evidence ("at least this long"), so it is folded
    /// in as a doubling rather than a measurement, and the next
    /// successful sample decays it back down through the ordinary EWMA.
    ///
    /// The doubling is applied to the budget that just EXPIRED, not to
    /// the raw EWMA, because the floor routinely hides the EWMA far
    /// below the budget it produced. Doubling the raw value took a
    /// 1 ms EWMA through 2, 4, 8, 16 ms - four charged attempts that
    /// every one of them still spent at the flat floor (2 s when this
    /// was found), so a provider that settled just above it failed
    /// every article before the budget could widen a millisecond
    /// (Codex sweep 2, 3 Aug M6). Escalating from the expired budget
    /// makes the next attempt's budget strictly larger than the one
    /// that just failed - 4 s, 8 s, ceiling at today's floor - so the
    /// retry allowance is spent probing upwards instead of re-testing
    /// the same floor four times.
    pub(super) fn note_ttfb_timeout(&self, idx: usize) {
        let cell = &self.ttfb_ms[idx];
        let old = cell.load(Ordering::Relaxed);
        cell.store(escalated_ttfb_ms(old), Ordering::Relaxed);
    }

    /// Record WHY a session ended. `slot` indexes [`SessionEnds`] in
    /// field order (0 peer, 1 protocol, 2 prebyte, 3 stall, 4 ours).
    /// Snapshot this server's session-end tally for [`PoolStats`].
    pub(super) fn session_ends(&self, server: usize) -> SessionEnds {
        let Some(row) = self.ends.get(server) else {
            return SessionEnds::default();
        };
        let g = |i: usize| row[i].load(Ordering::Relaxed);
        SessionEnds {
            peer: g(0),
            protocol: g(1),
            prebyte: g(2),
            stall: g(3),
            ours: g(4),
        }
    }

    /// Count one authoritative 430/423 wire answer from a server -
    /// proven attribution (echoed id, or fenced) in slot 0, bare
    /// positional attribution in slot 1. See the `miss_answers` field
    /// for why the split matters.
    pub(super) fn note_miss_answer(&self, server: usize, proven: bool) {
        if let Some(row) = self.miss_answers.get(server) {
            row[usize::from(!proven)].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Count a session end by cause - slots 0 peer, 1 protocol, 2
    /// prebyte, 3 stall, 4 ours - in BOTH the CLI tally (`ends`) and
    /// the dashboard's live per-server counters, from the one call so
    /// the two can never diverge (ends_ours used to be initialized and
    /// never incremented because the live bump was pasted per site).
    pub(super) fn note_session_end(&self, server: usize, slot: usize) {
        if let Some(row) = self.ends.get(server)
            && let Some(c) = row.get(slot)
        {
            c.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(l) = &self.live
            && let Some(sl) = l.servers.get(server)
        {
            let c = match slot {
                0 => &sl.ends_peer,
                1 => &sl.ends_protocol,
                2 => &sl.ends_prebyte,
                3 => &sl.ends_stall,
                _ => &sl.ends_ours,
            };
            c.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Flap breaker: record an established-session death, trimming the
    /// window in the same visit.
    pub(super) fn note_flap(&self, idx: usize) {
        let mut d = self.flap_deaths[idx].lock_ok();
        let now = Instant::now();
        d.push_back(now);
        while d
            .front()
            .is_some_and(|t| now.duration_since(*t) > FLAP_WINDOW)
        {
            d.pop_front();
        }
    }

    /// Flap breaker: has this server accumulated [`FLAP_DEATHS`]
    /// established-session deaths inside [`FLAP_WINDOW`]?
    pub(super) fn is_flapping(&self, idx: usize) -> bool {
        let mut d = self.flap_deaths[idx].lock_ok();
        let now = Instant::now();
        while d
            .front()
            .is_some_and(|t| now.duration_since(*t) > FLAP_WINDOW)
        {
            d.pop_front();
        }
        d.len() >= FLAP_DEATHS
    }

    /// Cap estimation (TODO 115): a dial just bounced off this server's
    /// capacity refusal, so the sessions we hold at this instant are
    /// what the provider is willing to serve concurrently. Keep the
    /// high-water across bounces.
    ///
    /// Returns the sampled count, so the caller can price the SAME
    /// sample into the dashboard's gauge ([`ServerLive::note_cap`])
    /// rather than re-reading a counter that has moved since.
    /// `held` is passed IN, never re-read here. The refusal handler
    /// samples the session count once, before either clock, precisely so
    /// the outage gauge and this clamp describe the same observation -
    /// and this function used to reload it, so sessions finishing in
    /// between could stamp a ceiling of zero for an event that was
    /// classified while two were held (Codex sweep 5, L7).
    pub(super) fn note_cap_bounce(&self, idx: usize, held: usize) {
        self.flap_cap_seen[idx].fetch_max(held, Ordering::AcqRel);
    }

    /// How many keeper connections a flap-clamped server is worth.
    /// The shipped answer is one. With `flap_cap_keepers` on and an
    /// OBSERVED accept cap (a capacity bounce sampled while we held at
    /// least one session), it is the observed cap - never above the
    /// per-server connection budget, which is where the account's own
    /// limits already landed; an unobserved cap stays at one, so a
    /// server that flaps without ever refusing a dial (a throttling
    /// account, a middlebox) keeps the conservative clamp.
    pub(super) fn flap_keeper_target(&self, idx: usize, cfg: &PoolConfig) -> usize {
        if !cfg.flap_cap_keepers {
            return 1;
        }
        match self.flap_cap_seen[idx].load(Ordering::Acquire) {
            0 => 1,
            cap => cap.min(cfg.connections.max(1)),
        }
    }

    /// Some OTHER server has live workers - the precondition for
    /// clamping this one (a lone server keeps its whole fleet: churn
    /// beats zero throughput when there is no alternative).
    pub(super) fn other_live(&self, me: usize) -> bool {
        self.alive
            .iter()
            .enumerate()
            .any(|(i, a)| i != me && a.load(Ordering::Relaxed) > 0)
    }
}
