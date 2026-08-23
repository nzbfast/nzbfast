//! TODO 208 item 1: the fleet cap.
//!
//! `--connections` is a PER-SERVER ceiling, so a five-server config
//! dials 360 sockets into whatever pipe it finds. Measured 21-22 Aug
//! 2026 on a 99 Mbit line (TODO.md §208): fleet 50 walls 546 s against
//! fleet 360's 585 s, with stall-deadline kills 0 against 299-491, dup
//! spend 23 MB against 312 MB, RSS 172 MB against 800 MB and the
//! queue-dry drain 18 s against 94 s - every column monotone, no knee
//! inside the ladder, and the line LESS full at 360 (66-71% saturated)
//! than at 50 (84%), because each socket was a 35 KB/s trickle that
//! stalled, re-dialled and raced. A single provider knees at ~20.
//!
//! The rule: a small CONSTANT fleet ([`LINE_CAP_DEFAULT_FLEET`]), split
//! equally across the servers, each share still subject to the
//! account's own `connections` and to a pin. It reads no line rate at
//! all.
//!
//! **The line rate used to BE the rule** - `fleet = line Mbit x 0.5`,
//! standing down entirely from 720 Mbit up - **and the floor rounds
//! retired it** (§208 Rounds A and B, 22 Aug 2026). They went looking
//! for the rung where too few sockets start to cost wall and did not
//! find one: at 99 Mbit fleet 50 / 35 / 25 all wall 544-547 s, and at
//! 247 Mbit fleet 25 beat the per-Mbit rule's own prediction for that
//! line (125) on every column - wall 218 against 223 s, RSS 136-139
//! against 276-396 MB, cpu -13%, duplicate wire 7.6-17.3 against
//! 86.6-102.8 MB, the drain 4.5 against 20.2 s, per-article latency 7
//! against 50 s. On an unshaped 1 GbE A/B, where the old rule stood
//! down and dialled everything, fleet 20 finished a second ahead of
//! fleet 360 at the same saturation. The best fleet measured does not
//! scale with the line, so the `linkpeak` anchor is not load-bearing
//! for the seed and the 720 Mbit stand-down protected nothing.
//!
//! **What is NOT measured, because a constant cuts both ways.** Nothing
//! has run this fleet on a line slower than it: at 10 Mbit, 25 sockets
//! are 50 KB/s each, which is the trickle regime the rule exists to
//! prevent, and the one low-line round measured a fleet of EIGHT (§208,
//! a bench line shaped to 10 Mbit with 250 ms of added round trip:
//! capped 304 s against uncapped 352 s, its own ladder flat from fleet
//! 1 to 8, and the gauge reading that line as 2 Mbit at shed time - 5x
//! low, which is why the old rule needed a floor bolted under it). 25
//! is also an upper bound on the floor rather than the floor: it is the
//! lowest rung either ladder ran and it won at both rates. The sub-25
//! rungs (§208 owed item 2) place it, and a slow-line rung is owed with
//! them.
//!
//! The SEED (`nzbfast::get::fleet`) sizes the fleet at job build, which
//! is where the damage is front-loaded - the backlog is dialled in the
//! first seconds - and it now caps whether or not the install knows its
//! line, because a constant needs no line to divide. That is new
//! behaviour on a CLI run and on a daemon's first job, both of which
//! the per-Mbit rule left alone for want of an anchor, and it is the
//! point of the constant. A bench leg that wants a fleet bigger than
//! the cap must now say so (`NZBFAST_LINE_CAP=0`, as the A/B arms
//! already do), where before an anchorless CLI leg was uncapped by
//! construction.
//!
//! The in-run SHED ([`Shared::line_cap_tick`]) holds the live targets
//! inside the cap for the rest of the run. It still stands down without
//! the daemon's persisted link anchor, and that requirement is left
//! exactly where the download that bought it put it - see
//! [`Shared::line_cap_tick`] for the measurement. Under a constant cap
//! it no longer guards an arithmetic mistake, since there is no line
//! reading left to divide; what it says now is that a run with no
//! independent estimate of its line dials what it was told and is never
//! resized mid-flight.
//! The §112 `live_tune` walker is deliberately NOT the owner: it is
//! per-provider, sheds one socket per ~7 epochs by design and has no
//! fleet view; it walks inside the cap.
//!
//! The constant is a parameter (`NZBFAST_LINE_CAP=<fleet connections>`,
//! `0` disables) so the bench drivers can A/B it and so the sub-25
//! rungs can move it without a code change. **The knob's UNIT changed
//! with the rule**: it used to be connections per Mbit, so a stale
//! `NZBFAST_LINE_CAP=0.5` in a box's environment no longer parses and
//! reads as OFF - the old control arm, and visible as an empty `line
//! cap` field in the `[pool]` line rather than as a fleet of one.

use super::*;

/// The whole fleet's connection budget, in sockets: the small constant
/// that beat every larger fleet at 99, 247 and ~1000 Mbit (module doc),
/// split equally across the servers, so five providers get 5 each. It
/// is an upper bound on the floor rather than the floor itself - 25 is
/// the lowest rung §208 ran, and it won at both rates - so the sub-25
/// rungs may lower it. There is deliberately no separate minimum under
/// it any more: the old `LINE_CAP_FLOOR` of 8 existed to stop a MISREAD
/// line dividing the fleet away (a 10 Mbit line read as 2 Mbit gave one
/// connection), and a constant cannot misread a line it never reads.
pub const LINE_CAP_DEFAULT_FLEET: usize = 25;

/// How often the in-run shed re-reads its targets.
const LINE_CAP_TICK_MS: u64 = 1_000;

/// The fleet-wide connection budget under a cap of `fleet` sockets.
/// `None` = no cap, i.e. the rule is off.
///
/// The line rate is no longer an argument (module doc: three rounds
/// took it out), so all this decides is what `0` means - in the one
/// place both halves of the rule read it from.
pub fn fleet_cap(fleet: usize) -> Option<usize> {
    (fleet > 0).then_some(fleet)
}

/// One server's equal share of a fleet budget. Rounds UP so the fleet
/// never lands under the budget through truncation (50 over 3 servers
/// is 17 each, not 16), and never below one connection.
pub fn server_share(fleet: usize, n_servers: usize) -> usize {
    fleet.div_ceil(n_servers.max(1)).max(1)
}

/// The in-run shed's state on `Shared`: the fleet cap (0 = off), the
/// anchor that arms the shed, the per-server live targets it may move
/// with their spawn ceilings (None = pinned or no target), the last
/// value IT set per server (usize::MAX = never - a target holding
/// another value was moved by someone else and is only ever lowered),
/// the ms stamp of the last tick, the fleet cap it last applied (0 =
/// none yet) and the shed tally for the `[pool]` line.
pub(super) struct LineCap {
    cap: usize,
    pub(super) anchor_bps: u64,
    targets: Vec<Option<(Arc<ConnTarget>, usize)>>,
    set: Vec<AtomicUsize>,
    at: AtomicU64,
    fleet: AtomicUsize,
    sheds: AtomicU64,
}

impl LineCap {
    /// Cap and anchor MAX-fold across the fleet, like the gauge's
    /// `pct`; a server contributes a target only if its config carries
    /// one (a pinned server never does).
    pub(super) fn new(servers: &[(ServerConfig, PoolConfig)]) -> Self {
        LineCap {
            cap: servers
                .iter()
                .map(|(_, c)| c.line_cap_fleet)
                .max()
                .unwrap_or(0),
            anchor_bps: servers
                .iter()
                .map(|(_, c)| c.line_anchor_bps)
                .max()
                .unwrap_or(0),
            targets: servers
                .iter()
                .map(|(_, c)| c.live_target.clone().map(|t| (t, c.connections)))
                .collect(),
            set: servers
                .iter()
                .map(|_| AtomicUsize::new(usize::MAX))
                .collect(),
            at: AtomicU64::new(0),
            fleet: AtomicUsize::new(0),
            sheds: AtomicU64::new(0),
        }
    }
}

impl Shared {
    /// The in-run half of the cap: walk every server's live target to
    /// its share of the fleet cap. Called from the delivered-bytes
    /// fold, so it costs one atomic load per article and does real work
    /// once a second.
    ///
    /// A target the pool lowered is raised again if the cap loosens
    /// (the knob is per job, so in practice it does not), but only
    /// while it still holds the value the pool set - a target somebody
    /// else moved since (the §112 walker) is theirs, and the pool will
    /// only ever LOWER it.
    ///
    /// **Why the shed still requires the daemon's link anchor, even
    /// though the cap is now a constant** (the rule bought on 22 Aug
    /// 2026, when the cap was still divided out of a measured line; it
    /// halved a live download). A trained peak is an ACHIEVED rate, and
    /// an achieved rate is `min(line, supply)` - a LOWER bound on the
    /// line, never an upper one. A fleet that is supply-bound - a slow
    /// or far provider, small articles, TLS on a weak core, anything
    /// under ~250 KB/s per socket - read as a slow LINE, and the cap
    /// divided it away. Worse, the reading latched: the peak is
    /// monotone, so the smaller fleet's lower rate could never raise it
    /// back. Measured on the daemon suite's
    /// `prefetch_borrows_from_the_busy_server_when_no_healthy_idle`: a
    /// 4-connection fleet on a 250 ms/article server moved 0.3 MB/s,
    /// read as a 3 Mbit line, shed 4 -> 1 at 8 s and finished in 24.6 s
    /// against a 12.5 s connection-bound ideal - 2x, unrecoverable.
    /// The constant removes that arithmetic, so the gate now carries a
    /// narrower rule: a run with no independent estimate of its line -
    /// a CLI run, or the daemon's first job - dials what it was told
    /// and is not resized mid-flight. Its seed is capped either way.
    pub(super) fn line_cap_tick(&self, now: u64) {
        let lc = &self.line_cap;
        if lc.cap == 0 || lc.targets.iter().all(Option::is_none) {
            return;
        }
        let last = lc.at.load(Ordering::Relaxed);
        if now.saturating_sub(last) < LINE_CAP_TICK_MS
            || lc
                .at
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        // No independent line estimate = no mid-run resize; see the doc
        // above for the download that bought this.
        if lc.anchor_bps == 0 {
            return;
        }
        lc.fleet.store(lc.cap, Ordering::Relaxed);
        let share = server_share(lc.cap, lc.targets.len());
        for (si, slot) in lc.targets.iter().enumerate() {
            let Some((target, ceiling)) = slot else {
                continue;
            };
            let want = share.min(*ceiling);
            let mine = lc.set[si].load(Ordering::Relaxed);
            // One atomic decide-and-set (F-24): the read, the rule and
            // the write run under the watch's lock, so a §112 walker
            // moving the target between them can neither be clobbered
            // nor mistaken for our own value.
            let seen = std::cell::Cell::new(0usize);
            let shed = std::cell::Cell::new(false);
            let moved = target.update(|cur| {
                seen.set(cur);
                if cur > want {
                    shed.set(true);
                    Some(want)
                } else if cur < want && cur == mine {
                    Some(want)
                } else {
                    None
                }
            });
            if !moved {
                continue;
            }
            let cur = seen.get();
            if shed.get() {
                lc.sheds.fetch_add(1, Ordering::Relaxed);
            }
            lc.set[si].store(want, Ordering::Relaxed);
            if let Some(l) = &self.live
                && let Some(sl) = l.servers.get(si)
            {
                sl.budget.store(want, Ordering::Relaxed);
            }
            info!(
                "line cap: {} using {want} of {ceiling} (was {cur}; fleet cap {})",
                self.live
                    .as_ref()
                    .and_then(|l| l.servers.get(si))
                    .map_or_else(|| format!("s{si}"), |s| s.host.clone()),
                lc.cap,
            );
        }
    }

    /// The ledger's fragment for the `[pool]` line: empty unless the
    /// rule was armed AND the shed ran, so short runs, anchorless runs
    /// and capped-off A/B arms keep their exact log shape.
    pub(super) fn line_cap_summary(&self) -> String {
        if self.line_cap.cap == 0 {
            return String::new();
        }
        match self.line_cap.fleet.load(Ordering::Relaxed) {
            0 => String::new(),
            f => format!(
                " · line cap {f} ({} sheds)",
                self.line_cap.sheds.load(Ordering::Relaxed)
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cap_is_a_constant_and_not_a_function_of_the_line() {
        // §208 Rounds A and B: the best fleet measured is the same
        // small one at 99, 247 and ~1000 Mbit, so no line rate reaches
        // this function and no rate can stand it down.
        assert_eq!(fleet_cap(LINE_CAP_DEFAULT_FLEET), Some(25));
        assert_eq!(fleet_cap(4), Some(4));
        // And the 720 Mbit stand-down is retired with it: there is no
        // rate that can hand this rule back its whole fleet, because
        // fleet 20 beat fleet 360 on a gigabit too.
    }

    #[test]
    fn off_means_no_cap() {
        assert_eq!(fleet_cap(0), None);
    }

    #[test]
    fn the_default_puts_five_connections_on_each_of_five_providers() {
        let fleet = fleet_cap(LINE_CAP_DEFAULT_FLEET).unwrap();
        assert_eq!(server_share(fleet, 5), 5);
        assert_eq!(server_share(fleet, 1), 25);
        assert_eq!(server_share(fleet, 3), 9);
    }

    #[test]
    fn shares_round_up_and_never_go_below_one() {
        assert_eq!(server_share(50, 5), 10);
        assert_eq!(server_share(125, 5), 25);
        assert_eq!(server_share(50, 3), 17);
        assert_eq!(server_share(2, 5), 1);
        assert_eq!(server_share(50, 0), 50);
    }
}
