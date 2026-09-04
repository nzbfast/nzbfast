//! One worker's session lifecycle: dial a connection, keep a pipeline of
//! BODY requests in flight on it, read the responses back, and decide -
//! at each of the dozen ways a session can end - whether to redial, park
//! the connection, or retire the worker.
//!
//! The four `*Step` enums are the seam between the phases: each helper
//! returns the decision it reached and [`session_loop`] does the control
//! flow, so no helper reaches for a `'session` continue from inside a
//! call it cannot see the top of.
//!
//! Split out of `pool.rs` whole (TODO 106) - the code is verbatim, only
//! visibility changed. The parent had been trimmed to 6,171 lines against
//! a 6,172 limit, so the very next commit that touched it went red; this
//! is the seam that buys the file real margin instead of one line.
//!
//! A child module sees its parent's private items, so `Shared`, `Work`
//! and the rest resolve through `use super::*` exactly as they did when
//! all of this was one file.

use super::*;

// Session-lifecycle unit tests (coverage §122) - a child of THIS module,
// not a sibling in pool/, so the private helpers (`top_up_window`, the
// two death paths) and `ReadStep`'s private fields stay reachable.
#[cfg(test)]
mod unit_tests;

/// One dial attempt: the `None` arm of `session_loop`'s warm-claim
/// match, moved verbatim (TODO 113). Owns the connect, the AUTHINFO
/// refusal taxonomy (permanent vs capacity, §15e / TODO 115) and the
/// connect backoff ladder; the counters live in `session_loop` and
/// cross as `&mut` so the ladder state survives across sessions.
pub(super) enum DialStep {
    /// A connected, validated session - proceed to the pipeline.
    Conn(Connection),
    /// Transient refusal or dial error, backoff already served - go
    /// around for another session.
    Retry,
    /// This worker is done (auth settled, attempts exhausted, or the
    /// run ended while we waited).
    Quit,
}

#[expect(clippy::too_many_arguments)]
pub(super) async fn dial_session(
    server: &ServerConfig,
    cfg: &PoolConfig,
    ctx: ServerCtx,
    shared: &Arc<Shared>,
    connects: &Arc<AtomicU64>,
    reconnects: &Arc<AtomicU64>,
    finished: &mut tokio::sync::watch::Receiver<bool>,
    connect_failures: &mut u32,
    flap_bounces: &mut u32,
    cap_bounces: &mut u32,
    ever_connected: &mut bool,
    am_keeper: bool,
    // Why this worker's PREVIOUS session ended ([`SessionEnds`] slot
    // order), so the redial can be painted as what it is: a rotation
    // we chose, or a session genuinely lost.
    last_end: &mut Option<usize>,
) -> DialStep {
    // Settled already: this server has told us the account is
    // no good. Workers that reach here later must not re-ask -
    // that is the storm this exists to stop, and it is also
    // how a wrong password used to cost every worker its full
    // backoff ladder before anyone bowed out.
    if shared.auth[ctx.idx].is_rejected() {
        return DialStep::Quit;
    }
    // Cumulative outage budget. Checked BEFORE the dial as well as on
    // the park ladder, because the case it exists for never reaches the
    // ladder: a server that grants a session every few minutes resets
    // `connect_failures` each time, so its workers cycle through this
    // arm forever and `park_or_probe` is never entered at all.
    if outage_budget_blown(cfg, shared, ctx.idx) {
        // Release anyone parked, so the run can seal rather than wait on
        // workers watching a server nobody will dial again.
        shared.auth[ctx.idx].publish_episode(CapEpisode::Dead);
        return DialStep::Quit;
    }
    // The stated-cap canary (`dialgate`): while this server sits at a
    // connection cap it named in words, one dial is in flight at a time
    // and everyone else waits a spread delay and asks again. Ahead of
    // the warm miss, which is a statistic about a dial we then make.
    let canary =
        match dialgate::wait_for_canary(&shared.auth[ctx.idx].dial, cfg, finished, shared).await {
            dialgate::Permit::Go(c) => c,
            dialgate::Permit::Retry => return DialStep::Retry,
            dialgate::Permit::Quit => return DialStep::Quit,
        };
    if let Some(w) = &cfg.warm {
        w.miss();
    }
    // §35: the dial is the one blocking call in this loop that
    // never watched the run. The session backoff above selects
    // on `finished`, `backoff_or_finish` slices its sleep - but
    // `connect` ran to its own CONNECT_TIMEOUT (20 s) whatever
    // had happened to the job meanwhile, so a worker inside a
    // dial when the last article went terminal kept the WHOLE
    // run alive until `join_fleet` gave up on it after
    // EXIT_GRACE.
    //
    // That cost a flat 5.0 s and it needed no dead server: 40
    // of 40 farm runs paid it, the healthy six-server config
    // included, because a provider bouncing a redundant
    // connection off its simultaneous-IP cap (`502 max number
    // of simultaneous IP addresses reached`) leaves a worker
    // redialling exactly like an unreachable one. A 0.35 GB
    // job whose bytes were all in at 0.65 s returned at 5.65 s.
    // Racing the dial: same job, same box, 0.74 s.
    let dialed = tokio::select! {
        r = Connection::connect(server) => r,
        _ = run_over(finished, shared) => return DialStep::Quit,
    };
    // The permit covers the DIAL and nothing after it: `park_or_probe`
    // below waits minutes, and holding it across that would queue the
    // whole server's fleet behind one worker.
    drop(canary);
    match dialed {
        Ok((c, _)) => {
            connects.fetch_add(1, Ordering::Relaxed);
            if *ever_connected {
                reconnects.fetch_add(1, Ordering::Relaxed);
                // The daemon's copy. `reconnects` above is
                // the run total and only the CLI prints it;
                // this is per-server, live, and timestamped,
                // so a dip can be laid against it.
                if let Some(live) = &cfg.live {
                    if let Some(sl) = live.servers.get(ctx.idx) {
                        sl.reconnects.fetch_add(1, Ordering::Relaxed);
                    }
                    // The cause of the previous end decides the mark.
                    // Pre-byte expiry (slot 2) and a deliberate hangup
                    // (slot 4) are OUR tuning choices - `rotate`, drawn
                    // amber. A peer death, protocol desync or mid-flow
                    // wedge stays `reconnect`, drawn as a fault.
                    let (kind, detail) = match last_end.take() {
                        Some(2) => (
                            "rotate",
                            "gave up waiting for a quiet server (our pre-byte \
                             time budget) and moved the work to a fresh session",
                        ),
                        Some(4) => (
                            "rotate",
                            "ended the session on purpose to rebalance \
                             connections, then redialled",
                        ),
                        _ => ("reconnect", "session lost, redialled"),
                    };
                    live.note(ctx.idx, kind, detail);
                }
            }
            // The outage (if any) is over the moment a session is
            // GRANTED, whatever the reason it started - a dial error,
            // a capacity bounce or a refusal that has since been fixed.
            if let Some(live) = &cfg.live
                && let Some(sl) = live.servers.get(ctx.idx)
            {
                sl.note_up();
            }
            // The budget's own clock, which unlike the gauge above is
            // always present (a CLI run configures no `live`) and unlike
            // the counters below is BANKED rather than zeroed.
            shared.auth[ctx.idx].mark_up();
            *ever_connected = true;
            shared.connected[ctx.idx].store(true, Ordering::Relaxed);
            *connect_failures = 0;
            *flap_bounces = 0;
            *cap_bounces = 0;
            // A GRANTED session is the only evidence a stated cap has
            // room again, so it alone stands the canary gate down.
            shared.auth[ctx.idx].dial.reopen();
            // The capacity episode (if any) is over: free the probe
            // role for a future episode and wake the parked yielders -
            // a session was just GRANTED, so the cap has room again
            // and the fleet should ease back in (issue #16's second
            // half: recovering to one connection is not recovering).
            if shared.auth[ctx.idx]
                .cap_prober
                .swap(false, Ordering::AcqRel)
            {
                shared.auth[ctx.idx].publish_episode(CapEpisode::Reopened);
            }
            DialStep::Conn(c)
        }
        // §15e: an AUTHINFO refusal is the server's answer to this
        // ACCOUNT, so it is settled once for every worker rather than
        // rediscovered by each of them. The two kinds want opposite
        // responses, and conflating them is what made a Giganews cap
        // so expensive.
        Err(crate::nntp::NntpError::AuthFailed { kind, line }) => {
            let first = shared.auth[ctx.idx].note(kind, &line);
            // Read ONCE, and read it before either clock: both the public
            // gauge and the budget clock have to answer the same question
            // ("is this server serving anything right now?") from the same
            // observation, or the two can disagree about one refusal.
            let held = shared.sessions[ctx.idx].load(Ordering::Acquire);
            // Out to the dashboard, so the user is told which server
            // stopped pulling its weight and in whose words.
            if let Some(live) = &cfg.live
                && let Some(sl) = live.servers.get(ctx.idx)
            {
                *sl.refusal.lock_ok() = Some(Refusal {
                    permanent: kind == crate::nntp::AuthRefusal::Permanent,
                    source_ips: kind == crate::nntp::AuthRefusal::Capacity
                        && crate::nntp::capacity_limit(&line)
                            == crate::nntp::CapacityLimit::SourceIps,
                    line: line.clone(),
                });
                // Same fact on the LIVE outage gauge, so the queue row
                // can say a provider is granting nothing and for how
                // long. The Providers card has carried the refusal
                // since §35, but nothing carried it to the job whose
                // articles were stuck behind it.
                //
                // Guarded by `held` exactly as `mark_down` below is, and
                // for the same reason: asking a provider for more
                // connections than the plan grants is the NORMAL case (we
                // ask 30, the account allows 20), so the surplus workers
                // bounce off a capacity refusal for the whole job. This
                // gauge had no guard, so one surplus dial stamped
                // `down_since` on a server that never stopped serving -
                // and `server_outages` trusts that stamp, so the queue row
                // said "no usable connection" and the total==0 watchdog
                // branch could demote a job off a false outage. The
                // refusal above is unguarded on purpose: the Providers
                // card SHOULD show what the server said, whether or not
                // the account is also serving (Codex sweep 12 Aug F11).
                if held == 0 {
                    sl.note_down(
                        if kind == crate::nntp::AuthRefusal::Permanent {
                            "refused"
                        } else {
                            "capacity"
                        },
                        line.clone(),
                    );
                }
            }
            shared.auth[ctx.idx].mark_down(held);
            match kind {
                crate::nntp::AuthRefusal::Permanent => {
                    // Retrying cannot fix a credential. Say it once,
                    // per SERVER, and take every worker off it.
                    if first {
                        warn!(
                            target: "pool",
                            "{}: authentication rejected, not retrying: {line}",
                            server.host
                        );
                        // A 502 is what a server says for a bad
                        // password AND, on several providers, for
                        // "too many addresses on this account" -
                        // same code, opposite remedies. We must not
                        // reclassify it (a genuinely wrong password
                        // has to stay permanent, or every worker
                        // would retry it forever), but a user
                        // staring at "authentication rejected" on an
                        // account they know is fine deserves the
                        // other possibility spelled out. Especially
                        // on a multi-WAN link, where this host
                        // presents several public addresses and can
                        // exhaust a 2-address allowance by itself.
                        if server.source_ips_are_tight() {
                            warn!(
                                target: "pool",
                                "{}: this account limits how many addresses \
                            may connect at once, and that is refused with the \
                            same code as a bad password. If the credentials \
                            are known good, something else is using the \
                            account. Two shapes to check: another machine on \
                            the same account, or THIS one leaving by more \
                            than one public address. The second is the one \
                            that surprises people - a router balancing \
                            several WAN links makes one host look like \
                            several, and it cannot be fixed from here, \
                            because `bind_ip` picks a LOCAL address and the \
                            balancing happens after the packets leave. That \
                            needs a policy route on the router pinning this \
                            traffic to one WAN; bind_ip only helps when this \
                            machine itself is multi-homed.",
                                server.host
                            );
                        }
                    }
                    // The account is settled, so this is the third way
                    // an episode ends and it owes the parked fleet the
                    // same verdict the prober's horizon publishes. Every
                    // worker still in the dial loop reads `rejected` at
                    // the top and quits - but a worker that yielded to
                    // an EARLIER capacity episode is not in that loop at
                    // all, and wakes only for a newer Reopened, a Dead,
                    // `finished` or `draining`. On a single-server run
                    // nothing else can finish the work, so `finished`
                    // never comes either: the parkers held `workers_live`
                    // above zero and the run never reached its terminal
                    // seal (read-only sweep 2, M3). Unconditional, as at
                    // the two `outage_budget_blown` sites - `first` is
                    // about who gets to LOG, and a later refusal may be
                    // the first one any parker could have heard.
                    shared.auth[ctx.idx].publish_episode(CapEpisode::Dead);
                    DialStep::Quit
                }
                crate::nntp::AuthRefusal::Capacity => {
                    // TODO 115: price the refusal in sessions we hold
                    // right now - that count IS the observed accept
                    // cap, and it is what widens the flap clamp past
                    // one keeper.
                    // `held` is the ONE sample taken above, deliberately
                    // not re-read (Codex sweep 5, L7).
                    shared.note_cap_bounce(ctx.idx, held);
                    // ...and price it for the person, not just for the
                    // clamp: the sessions we hold at a refusal ARE the
                    // ceiling this provider grants, and until now that
                    // number reached nothing but the log.
                    // ...and price it for the person, but ONLY when the
                    // refusal is about connection count. A
                    // simultaneous-IP limit is about where the account is
                    // being used from: the sessions we happened to hold
                    // are incidental, and recording them as the ceiling
                    // told the user to ask their provider about
                    // connection tiers when the answer lay elsewhere
                    // (Codex sweep 5, M9). The clamp above still widens
                    // either way - backing off is right for both.
                    if crate::nntp::capacity_limit(&line) == crate::nntp::CapacityLimit::Connections
                    {
                        if let Some(sl) = cfg.live.as_ref().and_then(|l| l.servers.get(ctx.idx)) {
                            sl.note_cap(held);
                        }
                        // Serialise dials behind one canary until a
                        // session is granted. Outside the `live` guard
                        // on purpose: a CLI run configures no gauge
                        // and storms just as hard.
                        shared.auth[ctx.idx].dial.arm();
                    }
                    // The account is fine; the server will not give us
                    // ANOTHER session. Retrying at the same connection
                    // count re-provokes exactly the limit being hit, so
                    // this worker permanently yields its slot and the
                    // survivors carry the job at a count the provider
                    // will actually accept.
                    if first {
                        warn!(
                            target: "pool",
                            "{}: at its connection/IP cap, reducing connections: {line}",
                            server.host
                        );
                        // TODO 110: a DECLARED address allowance means
                        // the bounce is probably not about this fleet's
                        // size - an address cap counts machines, and
                        // this host is one however many sockets it
                        // opens. Name the number so the operator reads
                        // "the account is in use elsewhere" instead of
                        // rediscovering the cap from the bounce.
                        if let Some(n) = server.max_source_ips.filter(|&n| n > 0)
                            && server.source_ips_are_tight()
                        {
                            warn!(
                                target: "pool",
                                "{}: this account is declared to allow {n} source \
                                 address(es) at once; if nothing else is using it, \
                                 check whether this host reaches the provider over \
                                 more than one public address (multi-WAN)",
                                server.host
                            );
                        }
                    }
                    // The ring gets EVERY bounce, not just the
                    // first. `if first` is right for the log -
                    // a flapping provider would drown it - but
                    // it is why a run that hit the cap at 16 s
                    // and again fifteen minutes later looked
                    // like it hit it once. The ring is capped,
                    // so it can absorb what the log must not.
                    if let Some(live) = &cfg.live {
                        live.note(ctx.idx, "cap", line.clone());
                    }
                    // TODO 115: a flap KEEPER never yields to a
                    // capacity bounce and never walks toward
                    // connect exhaustion on one - it holds one of
                    // the min(observed cap, budget) slots the
                    // provider does serve, and a bounce only means
                    // the cap is momentarily full (a sibling
                    // keeper mid-redial, or ghosts of sessions
                    // the server has not reaped). Paced retry,
                    // never a tight loop: each bounce waits the
                    // exponential connect backoff before the next
                    // dial, and the normal redial trigger stays
                    // "my own session died". Gated on the env
                    // knob so the shipped path is unchanged.
                    if cfg.flap_cap_keepers && am_keeper {
                        // Own counter: via connect_failures a
                        // few bounces + ONE dial error retired
                        // the keeper - the exhaustion promised
                        // above never to happen on a bounce. Its
                        // own, and not the PROBE ladder's either
                        // (see the two locals in `worker`).
                        *flap_bounces = flap_bounces.saturating_add(1).min(5);
                        // Spread: every keeper of one server shares this
                        // ladder, so without it they bounce in lockstep.
                        if !backoff_or_finish(
                            dialgate::spread_delay(
                                cfg.connect_backoff * 2u32.pow(*flap_bounces - 1),
                                shared.auth[ctx.idx].dial.ticket(),
                            ),
                            finished,
                            shared,
                        )
                        .await
                        {
                            return DialStep::Quit;
                        }
                        return DialStep::Retry;
                    }
                    // Keep at least one worker trying, or a cap that
                    // clears later would leave the server unused for
                    // the rest of the run.
                    park_or_probe(cfg, ctx, shared, finished, cap_bounces, connect_failures).await
                }
            }
        }
        Err(e) => {
            *connect_failures += 1;
            // Live outage gauge (the dashboard's, not the ladder's):
            // a dial that fails is the ONE flavour of dead server that
            // used to leave nothing behind anywhere but a single `warn!`
            // at t=0 - no refusal line, no event, no per-server state.
            let held = shared.sessions[ctx.idx].load(Ordering::Acquire);
            if let Some(live) = &cfg.live
                && let Some(sl) = live.servers.get(ctx.idx)
                // Guarded by `held` exactly as the capacity arm above is,
                // and for the same reason (Codex sweep 12 Aug F11): we
                // deliberately ask for more connections than the plan
                // grants, so surplus workers failing to dial is the
                // NORMAL case. Unguarded, one surplus dial failure
                // stamped `down_since` on a server currently serving N
                // sessions - and only a later SUCCESSFUL dial clears it,
                // which a server already at its granted ceiling will
                // never produce. `server_outages` trusts that stamp, so
                // the queue row said "no usable connection" about a
                // provider that never stopped serving. The F11 fix
                // reached the refusal arm and not this one.
                && held == 0
            {
                sl.note_down("unreachable", e.to_string());
            }
            shared.auth[ctx.idx].mark_down(held);
            // Say WHY, once per worker per run. This was a bare
            // `Err(_)` and the silence was expensive: a server that
            // cannot authenticate, cannot resolve, or is refusing
            // the TLS handshake looks EXACTLY like a server whose
            // articles are all missing - every article ends up
            // Failed/Missing with no hint which of the two it was.
            // First failure only, so a flapping provider cannot
            // flood the log, and the message names the fix.
            if *connect_failures == 1 {
                warn!(target: "pool", "{}: connect failed: {e}", server.host);
            }
            if *connect_failures >= cfg.max_connect_attempts {
                // Outage keeper: this used to be a permanent bow-out,
                // which turned any transient TOTAL outage (wifi drop,
                // VPN reconnect, router reboot) into a failed or
                // stranded job inside ~15-30 s - the exact class the
                // ghost-capacity fix (issue #16) already survives on
                // the refusal path. A hard connect failure is just as
                // transient, so it takes the same machinery: one
                // elected prober per server rides the paced ladder,
                // the rest park and rejoin on the first successful
                // connect, and the ~10 min horizon still guarantees a
                // truthful terminal for a server that is dead for good.
                return park_or_probe(cfg, ctx, shared, finished, cap_bounces, connect_failures)
                    .await;
            }
            // The ladder that produced the 29 Aug bursts: a pure
            // function of this worker's own counter, so workers that
            // bounced together redial together. `spread_delay` only
            // ever SHORTENS a step, never lengthens one.
            let backoff = dialgate::spread_delay(
                cfg.connect_backoff * 2u32.pow((*connect_failures).min(5) - 1),
                shared.auth[ctx.idx].dial.ticket(),
            );
            if !backoff_or_finish(backoff, finished, shared).await {
                return DialStep::Quit;
            }
            DialStep::Retry
        }
    }
}

/// One pipelined read: the select over the BODY read, the run-finished
/// watch, the promote-shed trigger and the TTFB-suspicion timer, moved
/// verbatim out of `session_loop` (TODO 113).
pub(super) struct ReadStep {
    /// `None`: the run ended or a promote shed abandoned the read.
    /// `Some(Err(()))` is a read timeout; the inner result is the BODY
    /// answer (true = 222 with a body in `buf`, false = 430/423).
    read: Option<Result<Result<bool, crate::nntp::NntpError>, ()>>,
    /// Promoted work is starving and this pipeline holds none of it -
    /// shed and reconnect.
    shed_for_promote: bool,
    /// The suspicion timer fired and no status line ever arrived: the
    /// peer is mute, so skip the courtesy QUIT (its 500 ms bound would
    /// ride the job's wall - the run is over when this matters).
    ///
    /// TODO 202 §17 widened the timer that sets this from the dark
    /// `ttfb_hedge` to the whole adaptive path, so a dead-air socket at
    /// run end now skips its QUIT on shipped configurations too. That
    /// is what the field always meant - it is a fact about the SOCKET,
    /// not about the hedge - and the read it describes is by
    /// construction one that has produced nothing for over a second.
    mute_suspect: bool,
    /// TODO 121.1/.2: the adaptive read expired with NO status byte
    /// seen - the pre-byte budget ran out, as opposed to a mid-body
    /// no-progress stall. The caller escalates the front article's own
    /// budget and does NOT count the expiry as a flap death: giving up
    /// pre-byte was OUR budget choice, and a heavy-tailed but healthy
    /// provider (cold storage at 2-4 s trained budgets) produces six
    /// of these a minute without a single session actually dying.
    prebyte_expired: bool,
    /// This response's status line echoed a matching message-id. On a
    /// miss (`Ok(Ok(false))`) that makes the attribution authoritative
    /// rather than positional (see `Work::soft_430`); on any response it
    /// is proof that the socket was still aligned here, which is what
    /// closes §129 3g's suspect window.
    id_echoed: bool,
    /// On a miss: the refusal SAID the article was removed rather than
    /// not found ([`crate::nntp::takedown_flavoured`]). A hint riding
    /// beside the verdict, never part of it.
    takedown: bool,
}

#[expect(clippy::too_many_arguments)]
pub(super) async fn read_one(
    conn: &mut Connection,
    buf: &mut Vec<u8>,
    cfg: &PoolConfig,
    ctx: ServerCtx,
    shared: &Arc<Shared>,
    inflight: &VecDeque<Work>,
    finished: &mut tokio::sync::watch::Receiver<bool>,
    promote_gen: &mut tokio::sync::watch::Receiver<u64>,
    fence_read_seen: &mut bool,
) -> ReadStep {
    // A worker mid-read must notice global completion: once a tail
    // duplicate wins somewhere, waiting out a slow original here
    // would stall the whole pool's return. It must also notice a
    // PROMOTE while its in-flight article is non-promoted work: a
    // streaming seek needs the whole line NOW, and 100+ conns
    // placidly finishing frontier articles hold the promoted wave
    // to one conn's fair share (measured 4-6 s per 32 MB window).
    // Abandoning the read (reconnect, uncharged requeue) frees
    // this conn for promoted work within ~a TLS handshake.
    let mut shed_for_promote = false;
    // Pre-byte silence marker (TODO 115): while this read is still
    // pre-byte, a timer at the suspicion bound marks the front
    // article suspect so other workers can dup-race it without
    // waiting out the full adaptive budget. `status_seen` is the
    // read's own report that bytes arrived - after that, silence
    // is a body pacing question, not a dead connection, and the
    // timer must not fire.
    // TODO 96.4: never arm it behind a verdict probe. The timer marks
    // the FRONT ARTICLE suspect so other workers race its owner, and a
    // probe's front article is owned by somebody else entirely - a slow
    // 430 from this backbone would be read as pre-byte silence on a
    // connection that is not even the one being waited on.
    //
    // TODO 202 §17: armed on the WHOLE adaptive path, not only under
    // `ttfb_hedge`. The mark is a fact about the socket - this article
    // has moved no bytes for longer than the suspicion bound - and two
    // separate consumers want it. `pick_suspect_dup` (opt-in, still
    // dark in `shipped()`) races on it; the line-saturation gate's
    // per-article escape (`Shared::not_using_the_line`) reads it to
    // tell a STALLED owner from a merely slow one, and that consumer
    // ships. Gating the fact on the dark hedge left the escape with
    // nothing to read on every configuration that runs.
    let prebyte_mark_armed = cfg.adaptive_timeout && !inflight.front().is_some_and(|w| w.probe);
    let status_seen = AtomicBool::new(false);
    let id_echoed = AtomicBool::new(false);
    let takedown = AtomicBool::new(false);
    // Borrowed, not cloned: `inflight` is a shared reference that
    // outlives this read, and the only consumer is `mark_suspect`
    // below, which takes a `&str`. Cloning it bought an owned id per
    // read on a reactor thread for nothing. (R4 item 4 - which R9's
    // interning would have made a refcount bump rather than an
    // allocation, but a borrow beats a bump, so the borrow stands.)
    let suspect_front: Option<&str> = if prebyte_mark_armed {
        inflight.front().map(|w| &*w.id)
    } else {
        None
    };
    let suspect_timer = tokio::time::sleep(if prebyte_mark_armed {
        shared.ttfb_suspect_after(ctx.idx)
    } else {
        Duration::from_secs(0)
    });
    tokio::pin!(suspect_timer);
    let mut suspect_armed = prebyte_mark_armed;
    let mut suspect_fired = false;
    // TODO 313 item 7: the surge dial's only arming path.
    //
    // Everything else in this pool that could tick rides delivered
    // bytes (`note_srv_bytes`, and the fleet cap's own governor with
    // it), and the regime the surge exists for is the one where NOTHING
    // is delivering - so a surge armed there would be switched off in
    // exactly its own regime. A read in progress is the one thing that
    // is still happening when a socket is stuck, so the wake-up rides
    // it: a timer at the SHARED staleness bound, re-armed on each fire
    // so a read that stays stuck keeps the loan's deadline enforced.
    //
    // The timer is a wake-up ticket and nothing more - every gate,
    // including whether this read's own article is actually stale, is
    // re-asked in `Shared::surge_tick` against the in-flight map. It is
    // never armed with the mechanism off, so a shipped install pays
    // nothing for it.
    let surge_armed = shared.surge_armed();
    let surge_timer = tokio::time::sleep(match surge_armed {
        true => shared.hedge_stale_bound(),
        false => Duration::from_secs(0),
    });
    tokio::pin!(surge_timer);
    let read = {
        let read_fut = async {
            // Echoed-id enforcement: this read is attributed to the
            // front of the pipeline POSITIONALLY, so when the status
            // line echoes a plausible message-id it must be the front
            // article's - anything else means a response was dropped
            // or reordered and every later body on this socket would
            // be filed under the wrong article. The mismatch surfaces
            // as an NntpError and takes the existing protocol-error
            // exit (drop the session, requeue the pipeline).
            let expected = inflight.front().map(|w| &*w.id);
            // TODO 96.4: a verdict probe answers with one status line
            // and nothing else, so there is no post-byte phase to bound
            // - the pre-byte budget is the whole read. Attribution,
            // the echoed-id check and the fence behind it are the BODY
            // path's, unchanged.
            if inflight.front().is_some_and(|w| w.probe) {
                let budget = if cfg.adaptive_timeout {
                    article_prebyte_budget(
                        shared.ttfb_budget(ctx.idx),
                        inflight.front().map_or(0, |w| w.prebyte_expiries),
                    )
                } else {
                    cfg.read_timeout
                };
                return match conn
                    .read_stat_noting(expected, budget, &status_seen, &id_echoed, &takedown)
                    .await
                {
                    Ok((hit, ttfb)) => {
                        if cfg.adaptive_timeout {
                            shared.note_ttfb(ctx.idx, ttfb);
                        }
                        Ok(Ok(hit))
                    }
                    Err(crate::nntp::NntpError::Timeout) => {
                        if cfg.adaptive_timeout {
                            shared.note_ttfb_timeout(ctx.idx);
                        }
                        Err(())
                    }
                    Err(e) => Ok(Err(e)),
                };
            }
            // TODO 208.2 over-read: the line gauge is fed as the body's
            // chunks land, not when it completes - on both read paths.
            // `last` is this read's previous-chunk stamp, seeded with
            // its start: the pipeline is read in order, so that is when
            // this body's bytes began to flow.
            let last = AtomicU64::new(shared.start.elapsed().as_millis() as u64);
            let arrive = |n: u64| shared.note_arrival(n, &last);
            let arrivals: crate::nntp::Arrivals<'_> = if shared.sat.arrivals {
                Some(&arrive)
            } else {
                None
            };
            if cfg.adaptive_timeout {
                // TODO 96.1: two-phase bound. Pre-byte budget
                // adapts to this server's measured TTFB; once
                // bytes flow only a genuine no-progress stall
                // trips. Both expiries land in the same stall
                // arm as the flat path's timeout (requeue with
                // uncharged pipeline-mates, reconnect, no
                // session strike).
                let budget = article_prebyte_budget(
                    shared.ttfb_budget(ctx.idx),
                    inflight.front().map_or(0, |w| w.prebyte_expiries),
                );
                // TODO 208.2: share-aware, never under the flat
                // ADAPTIVE_STALL - see `Shared::stall_bound`. Live
                // (re-read before every socket wait) so a body that
                // began before the line trained picks up the trained
                // bound; `NZBFAST_STALL_LIVE=0` samples it once here.
                let live_bound = || shared.stall_bound();
                let stall: crate::nntp::StallBound<'_> = if shared.sat.stall_live {
                    (&live_bound as &(dyn Fn() -> Duration + Sync)).into()
                } else {
                    shared.stall_bound().into()
                };
                match conn
                    .read_body_into_two_phase_noting(
                        buf,
                        expected,
                        budget,
                        stall,
                        arrivals,
                        &status_seen,
                        &id_echoed,
                        &takedown,
                    )
                    .await
                {
                    Ok((hit, ttfb)) => {
                        shared.note_ttfb(ctx.idx, ttfb);
                        Ok(Ok(hit))
                    }
                    Err(crate::nntp::NntpError::Timeout) => {
                        // Censored sample: widen, or a budget
                        // trained to the floor can never recover
                        // from a provider that got slower (M4).
                        shared.note_ttfb_timeout(ctx.idx);
                        // Mark the graph, once a second per
                        // server at most (a provider gone slow
                        // expires budgets on every worker at
                        // once) - same discipline as `blocked`.
                        if let Some(l) = &cfg.live
                            && let Some(sl) = l.servers.get(ctx.idx)
                        {
                            let now = now_ms();
                            let prev = sl.last_timeout_note.load(Ordering::Relaxed);
                            if now.saturating_sub(prev) >= 1000
                                && sl
                                    .last_timeout_note
                                    .compare_exchange(
                                        prev,
                                        now,
                                        Ordering::Relaxed,
                                        Ordering::Relaxed,
                                    )
                                    .is_ok()
                            {
                                l.note(
                                    ctx.idx,
                                    "timeout",
                                    "a response ran past its adaptive time budget - \
                                     widened the budget and retried",
                                );
                            }
                        }
                        Err(())
                    }
                    Err(e) => Ok(Err(e)),
                }
            } else {
                tokio::time::timeout(
                    cfg.read_timeout,
                    conn.read_body_into(buf, expected, arrivals, &id_echoed, &takedown),
                )
                .await
                .map_err(|_| ())
            }
        };
        tokio::pin!(read_fut);
        loop {
            tokio::select! {
                r = &mut read_fut => break Some(r),
                // TODO 313 item 7: a stuck read's periodic wake-up.
                // Re-armed rather than one-shot, because the loan's
                // deadline has to be enforced by SOMETHING while the
                // socket stays silent, and this is the only thing still
                // running when it does.
                _ = &mut surge_timer, if surge_armed => {
                    shared.surge_tick(shared.run_ms());
                    let next = tokio::time::Instant::now() + shared.hedge_stale_bound();
                    surge_timer.as_mut().reset(next);
                }
                // TTFB-suspicion: fires at most once per read.
                // Racing the status line's arrival is benign -
                // a mark on an article that completes a moment
                // later dies with its inflight entry.
                _ = &mut suspect_timer, if suspect_armed => {
                    suspect_armed = false;
                    suspect_fired = true;
                    if !status_seen.load(Ordering::Acquire)
                        && let Some(id) = suspect_front
                    {
                        shared.mark_suspect(id);
                    }
                }
                _ = async {
                    let _ = finished.wait_for(|f| *f).await;
                } => break None,
                _ = promote_gen.changed() => {
                    // Immune if ANY in-flight article is promoted
                    // work - by flag (popped after the promote) OR
                    // by id (dispatched before the promote but
                    // inside its span; shedding those would just
                    // refetch the same bytes after a reconnect).
                    let fetching_promoted = inflight.iter().any(|w| w.promoted) || {
                        let ids = shared.promoted_ids.lock_ok();
                        inflight.iter().any(|w| ids.contains(&w.id))
                    };
                    // And only abandon a read that has already
                    // proven slower than a reconnect (see
                    // PROMOTE_SHED_MIN_AGE).
                    let old_enough = inflight.front().is_none_or(|w| {
                        shared
                            .inflight
                            .lock_ok()
                            .get(&w.id)
                            .is_none_or(|inf| inf.dispatched.elapsed() >= PROMOTE_SHED_MIN_AGE)
                    });
                    if shared.stream_active()
                        && shared.promoted_pending.load(Ordering::Acquire) > 0
                        && !fetching_promoted
                        && old_enough
                    {
                        shed_for_promote = true;
                        break None;
                    }
                    // Already fetching promoted work (or no
                    // promoted work left): keep reading.
                }
            }
        }
    };
    // §129 3g: the fence's own answer sits in the slot behind the one we
    // just read, and reading it is the check. A status a BODY could have
    // answered means what we read belonged to somebody else - the stream
    // is off by one - and `read_fence` turns that into the same
    // session-level error `check_echoed_id` raises for an id-echoing
    // provider, so a misaligned session dies here instead of quietly
    // charging its refusal to an article the server holds. Nothing
    // arriving at all is the other face of the same fault (the server
    // owes one response fewer than it was asked for), so that takes the
    // stall arm, which charges the article and voids the passes this
    // session's refusals spent.
    let read = match read {
        Some(Ok(Ok(hit))) if inflight.front().is_some_and(|w| w.fenced) => {
            let budget = if cfg.adaptive_timeout {
                article_prebyte_budget(shared.ttfb_budget(ctx.idx), 0)
            } else {
                cfg.read_timeout
            };
            let first_fence = !std::mem::replace(fence_read_seen, true);
            match tokio::time::timeout(budget, conn.read_fence()).await {
                Ok(Ok(())) => {
                    shared.fence_ok[ctx.idx].store(true, Ordering::Release);
                    Some(Ok(Ok(hit)))
                }
                Ok(Err(e)) => {
                    // A BODY-shaped answer in the fence slot is normally
                    // the desync the fence exists to catch, and the
                    // session dies for it either way. But on a session's
                    // FIRST fenced read the socket was aligned by
                    // construction (fresh dial, or a warm connection the
                    // pool validated with its own DATE), so there is
                    // nothing to be off by: the only way the next BODY's
                    // answer lands here is a server that never wrote a
                    // DATE response at all. That case, and only that
                    // case, counts toward retirement - and only while
                    // this server has never answered a fence.
                    if first_fence && matches!(e, crate::nntp::NntpError::Unexpected { .. }) {
                        shared.note_fence_dud(ctx.idx, cfg);
                    }
                    Some(Ok(Err(e)))
                }
                Err(_) => {
                    shared.note_fence_dud(ctx.idx, cfg);
                    Some(Err(()))
                }
            }
        }
        other => other,
    };
    let no_status = !status_seen.load(Ordering::Acquire);
    ReadStep {
        prebyte_expired: cfg.adaptive_timeout && matches!(read, Some(Err(()))) && no_status,
        read,
        shed_for_promote,
        mute_suspect: suspect_fired && no_status,
        id_echoed: id_echoed.load(Ordering::Acquire),
        takedown: takedown.load(Ordering::Acquire),
    }
}

/// A 222 body arrived: ownership, dup racing, recycle heuristics - the
/// `Ok(Ok(true))` arm of `session_loop`'s response match, moved
/// verbatim (TODO 113). Returns `Recycle` when this session has proven
/// slow (race losses or a collapsed rate slope) and should be redialled.
pub(super) enum BodyStep {
    Proceed,
    Recycle,
}

#[expect(clippy::too_many_arguments)]
pub(super) async fn handle_body(
    cfg: &PoolConfig,
    ctx: ServerCtx,
    shared: &Arc<Shared>,
    out: &mpsc::Sender<FetchOutcome>,
    inflight: &mut VecDeque<Work>,
    buf: PooledBuf<'_>,
    race_losses: &mut u32,
    session_bytes: &mut u64,
    session_start: Instant,
) -> BodyStep {
    let w = inflight.pop_front().expect("response without command");
    shared.release_wire(1);
    // TODO 315: if this article was holding a late re-ask, that re-ask
    // has now been answered - with the article itself, which is the
    // outcome the hold exists to buy - so give its slot back. Answered
    // is answered whichever way it went; the refusal path releases at
    // its own verdict.
    shared.release_recheck(&w);
    *session_bytes += buf.len() as u64;
    shared.bytes[ctx.idx].fetch_add(buf.len() as u64, Ordering::Relaxed);
    // M7b.2 speed signal: fold the same delivered bytes into the
    // windowed per-server rate. This 222 path is its ONLY feeder.
    shared.note_srv_bytes(ctx.idx, buf.len() as u64);
    if let Some(l) = &cfg.live {
        l.servers[ctx.idx]
            .bytes
            .fetch_add(buf.len() as u64, Ordering::Relaxed);
    }
    // Speed limiter: charge the body and sleep off any debt
    // BEFORE processing continues (async - the runtime
    // thread stays free for other workers' I/O).
    if let Some(rate) = &cfg.rate {
        rate.throttle(buf.len() as u64).await;
    }
    // M29 oracle: a served body is a labeled "this
    // backbone HAS articles of this age" sample - charged
    // per 222 regardless of who owns the outcome (dups
    // included; the response is real evidence either way).
    if let Some(o) = &cfg.oracle {
        o.hit(ctx.idx, w.age_days);
    }
    shared.deregister_inflight_done(&w);
    // M8 (sweep 8): read the routing evidence BEFORE the claim, because
    // `claim_done` drops the article's `spent` entry - and under
    // `crc_steer` the claim is only provisional: a bad-body verdict can
    // still send this article back down the ladder, and the fill tier
    // that has to take it is opened by exactly these bits. One atomic
    // load on every run that never exhausted a retry budget, and not
    // taken at all when nothing can steer.
    let spent_ev = if cfg.crc_steer {
        shared.spent_mask(&w.id)
    } else {
        0
    };
    if shared.claim_done(&w.id, w.ord) {
        *race_losses = 0;
        if w.dup {
            shared.dup_wins.fetch_add(1, Ordering::Relaxed);
            shared.mirror_dup_win();
        }
        // Handing a body downstream is where a SLOW DISK
        // becomes visible: when decode/verify/write cannot
        // keep up the channel fills, this await parks, and
        // the TCP windows close behind it. That is the
        // designed response - but it is indistinguishable
        // from a network dip on the graph unless somebody
        // measures it, so this does.
        //
        // try_send first, so the healthy path costs no
        // clock read at all: only a body that actually had
        // to WAIT is timed. Everything else would put an
        // Instant::now() on the hot path of every article
        // to observe a number that is almost always zero.
        // Mark ARRIVED across the (possibly parked)
        // handoff - see the `done_ok` field doc.
        let arrived = w.id.clone();
        shared.done_ok.lock_ok().insert(arrived.clone());
        // TODO 114 consumer steer - see `stash_handed`.
        if cfg.crc_steer {
            shared.stash_handed(&w, ctx, spent_ev);
        }
        // Memory-floor gauge (instrument-first): raw bytes queued in the
        // fetch->decode channel. Charged by capacity here, released by
        // capacity in the consumer's drain - capacity cannot change while
        // the buffer sits in the channel, so the pair is exact.
        //
        // Held as a `Charge`, so the two ways this send can fail need no
        // release of their own: the charge simply drops with the outcome
        // it was made for. Only the DELIVERED path acts, handing the
        // charge on to the consumer that will release it.
        let chan_charge = cfg
            .channel_gauge
            .map(|g| crate::memgauge::Charge::new(g, buf.capacity() as u64));
        // The buffer now outlives this borrow: disarm the guard and let
        // the consumer's `adopt` own the release at the far end.
        let done = FetchOutcome::Done {
            id: w.id,
            raw: buf.into_vec(),
        };
        use tokio::sync::mpsc::error::TrySendError;
        let mut delivered = true;
        match out.try_send(done) {
            Ok(()) => {
                // In the channel: the consumer's drain owns the release.
                if let Some(c) = chan_charge {
                    c.hand_off();
                }
            }
            Err(TrySendError::Closed(done)) => {
                // Never entered the channel. The charge drops with this
                // arm; the BUFFER has to be given back by hand, because
                // it was disarmed for the send and a bare `Vec`'s drop
                // releases nothing - the pool's outstanding gauge would
                // carry these bytes for the rest of the run, since
                // `BufPool::Drop` reconciles only the free list.
                // Reachable only when the consumer is gone early (it
                // drains to closed-and-empty otherwise), which is why
                // this sat unnoticed in the hand-`give` era too (v1.2.4
                // tranche sweep, 27 Aug 2026).
                if let (FetchOutcome::Done { raw, .. }, Some(p)) = (done, &cfg.buf_pool) {
                    p.give(raw);
                }
                delivered = false;
            }
            Err(TrySendError::Full(done)) => {
                let waited = std::time::Instant::now();
                delivered = match out.send(done).await {
                    Ok(()) => true,
                    // Same as the Closed arm above: the failed send
                    // hands the outcome back, and the disarmed buffer
                    // owes the pool its outstanding release.
                    Err(tokio::sync::mpsc::error::SendError(done)) => {
                        if let (FetchOutcome::Done { raw, .. }, Some(p)) = (done, &cfg.buf_pool) {
                            p.give(raw);
                        }
                        false
                    }
                };
                if delivered && let Some(c) = chan_charge {
                    c.hand_off();
                }
                let ms = waited.elapsed().as_millis() as u64;
                if let Some(c) = shared.blocked_ms.get(ctx.idx) {
                    c.fetch_add(ms, Ordering::Relaxed);
                }
                if let Some(live) = &cfg.live
                    && let Some(sl) = live.servers.get(ctx.idx)
                {
                    sl.blocked_ms.fetch_add(ms, Ordering::Relaxed);
                    // A pause long enough to bend the graph
                    // earns a mark on it. Brief parks are
                    // NORMAL - the channel is meant to fill -
                    // so only a wait a person could see counts,
                    // and at most one a second per server.
                    if ms >= BLOCKED_NOTE_MS {
                        let now = now_ms();
                        let prev = sl.last_blocked_note.load(Ordering::Relaxed);
                        if now.saturating_sub(prev) >= 1000
                            && sl
                                .last_blocked_note
                                .compare_exchange(prev, now, Ordering::Relaxed, Ordering::Relaxed)
                                .is_ok()
                        {
                            live.note(
                                ctx.idx,
                                "blocked",
                                format!("waited {ms} ms for the write side"),
                            );
                        }
                    }
                }
            }
        }
        // Terminal bookkeeping - see `settle_handoff`.
        shared.settle_handoff(cfg.crc_steer, cfg.arrival_ack, delivered, &arrived);
    } else {
        // A duplicate dispatch beat us to it. Whichever copy lost -
        // this one, dup or original - its bytes are racing spend,
        // charged against the hygiene cap (design 5.2).
        shared.charge_dup_loss(buf.len() as u64);
        drop(buf); // returned to the pool here, not at scope end
        // Recycle experiment: losing races back to back
        // means THIS session is the slow one - a fresh
        // dial to the same host routinely beats a
        // degraded TCP session. Deliberate reconnect:
        // no session strike, no backoff (same shape as
        // the promote shed above); the redial path
        // counts it into `reconnects`.
        //
        // Endgame losses do NOT count (TODO 111 gauntlet):
        // once the fan-out arms, idle workers race EVERY
        // straggler, so a healthy-but-jittery session
        // loses races routinely through no fault of its
        // own - the gauntlet measured a satellite-shaped
        // server recycled mid-tail for exactly this.
        // Normal-phase losses - the rate rule or the
        // hedge picking on this session's articles
        // specifically - remain the evidence they were.
        // Same stance as the slope recycle below, which
        // has excluded the endgame from day one.
        let endgame = shared.pending.load(Ordering::Acquire) <= ENDGAME_MAX
            || (shared.tail_fanout_early && shared.tail_started.lock_ok().is_some());
        if !endgame {
            *race_losses += 1;
        }
        if cfg.recycle_slow && *race_losses >= RECYCLE_RACE_LOSSES {
            if let Some(l) = &cfg.live {
                l.note(
                    ctx.idx,
                    "rotate",
                    format!(
                        "recycled a slow session after losing \
                         {race_losses} article races in a row"
                    ),
                );
            }
            *race_losses = 0;
            shed_pipeline(shared, inflight).await;
            return BodyStep::Recycle;
        }
    }
    // Slope-recycle experiment: this session's own rate
    // collapsed against the fleet's per-worker average -
    // redial before it strands anything. Normal phase
    // only (endgame workers are legitimately idle-ish,
    // and the tail machinery owns that ground), and only
    // once the session has had 10 s to prove itself.
    // Checked ONLY on a completed article, so an idle
    // worker's decaying average can never trip it.
    if cfg.recycle_slope
        && shared.pending.load(Ordering::Acquire) > ENDGAME_MAX
        && session_start.elapsed() > Duration::from_secs(10)
    {
        let mine = *session_bytes as f64 / session_start.elapsed().as_secs_f64();
        let fleet = shared.rate_per_worker(ctx.idx);
        if fleet > 0.0 && mine < 0.25 * fleet {
            if let Some(l) = &cfg.live {
                l.note(
                    ctx.idx,
                    "rotate",
                    format!(
                        "recycled a degraded session ({:.1} MB/s vs the \
                         fleet's {:.1} MB/s per connection)",
                        mine / 1e6,
                        fleet / 1e6
                    ),
                );
            }
            shed_pipeline(shared, inflight).await;
            return BodyStep::Recycle;
        }
    }
    BodyStep::Proceed
}

/// TODO 96.4: a verdict probe came back 223 - this backbone HOLDS the
/// article. Nothing terminal happens here and no outcome is sent: a
/// probe is always a dup, so the original still owns the article and is
/// either delivering it right now or about to requeue it. What the
/// answer buys is the end of the ladder - recorded on the in-flight
/// entry, where `pick_dup` reads it and stops asking a question whose
/// answer cannot be "missing everywhere" any more.
pub(super) fn handle_probe_hit(
    ctx: ServerCtx,
    shared: &Arc<Shared>,
    inflight: &mut VecDeque<Work>,
    buf: PooledBuf<'_>,
) {
    let w = inflight.pop_front().expect("response without command");
    shared.release_wire(1);
    drop(buf); // returned to the pool here, not at scope end
    shared.note_found(&w.id, ctx.group_bits);
    if std::env::var_os("NZBFAST_POOL_DEBUG").is_some() {
        info!(target: "stat-probe", "{} present on server {}", w.id, ctx.idx);
    }
}

/// Tell the extractor that a terminal verdict is being HELD BACK, when
/// the refusal in hand is the article's LAST evidence.
///
/// Two sites call it and both are holds: §129's confirming repeat for a
/// bare refusal (attribution doubt) and TODO 315's late re-ask (was the
/// answer TRUE). Between either hold and the verdict it defers, the
/// extractor's own `lost_articles` flag is still false, and that flag is
/// what stops the drop-behind trim releasing a prefix a repair will
/// need - measured 30 Aug 2026 doing exactly that, five megabytes of a
/// PAR2-vouched prefix under the holds park, after which the mapped
/// repair declined and the set took the disk ladder with a re-fetch on
/// top (`research/CHASE-TRIM-DROPS-BEFORE-VERDICT-2026-08-30.md`).
///
/// THE `mask == live` TEST IS THE WHOLE OF THE PRECISION HERE, and it
/// is why this is not simply called on every 430. A refusal from one
/// backbone of several is ordinary ladder business - the next server
/// answers and nothing about the job is in doubt - while a refusal that
/// completes the live mask is an article that is GONE unless the hold's
/// own question comes back the other way. The extractor's veto is
/// per-JOB and sticky, so raising it on the ordinary case would stand
/// the drop down for whole clean downloads and give back the 0.48x of
/// spilled disk the drop exists to avoid (measured 21 Aug 2026,
/// `research/MEASURED-HOLDS-LADDER-2026-08-21.md`).
///
/// A store and nothing else: no lock, and nothing here reads it back.
fn note_doubt(cfg: &PoolConfig, mask: u32, live: u32) {
    if let Some(d) = &cfg.loss_doubt
        && mask & live == live
    {
        d.raise();
    }
}

/// An authoritative 430/423 "no such article": per-server evidence,
/// dup-mask merging and Missing/requeue routing - the `Ok(Ok(false))`
/// arm of `session_loop`'s response match, moved verbatim (TODO 113).
pub(super) async fn handle_missing(
    cfg: &PoolConfig,
    ctx: ServerCtx,
    shared: &Arc<Shared>,
    out: &mpsc::Sender<FetchOutcome>,
    inflight: &mut VecDeque<Work>,
    buf: PooledBuf<'_>,
    echoed: bool,
    takedown: bool,
    bare_refused: &mut VecDeque<Arc<str>>,
) {
    let mut w = inflight.pop_front().expect("response without command");
    shared.release_wire(1);
    drop(buf); // returned to the pool here, not at scope end
    // Proven-vs-bare tally: one count per WIRE ANSWER, like the oracle
    // miss below, so a run summary can say what kind of evidence its
    // Missing verdicts rest on. A fence is the same proof as an echoed
    // id, arrived at differently (see the dup branch below).
    shared.note_miss_answer(ctx.idx, echoed || w.fenced);
    // Reliability: this server said "no such article" -
    // charged even for dups (the response is authoritative
    // for this server regardless of who owns the outcome).
    if let Some(l) = &cfg.live {
        l.servers[ctx.idx]
            .articles_missing
            .fetch_add(1, Ordering::Relaxed);
        // Windowed: a take-down or backfill hole answers
        // 430 by the hundred, and each one lands here.
        l.note_missing_burst(ctx.idx);
    }
    // M29 oracle: the mirror of the hit above - one miss
    // per actual 430/423 wire response. Derived Missing
    // verdicts (retention seeding, unanimity) are NOT
    // recorded; only real answers train the ledger. A
    // takedown-flavoured refusal trains it harder: the
    // server said REMOVED, which a bare 430 never does.
    if let Some(o) = &cfg.oracle {
        let age = w.age_days;
        if takedown {
            o.miss_takedown(ctx.idx, age);
        } else {
            o.miss(ctx.idx, age);
        }
    }
    if w.dup {
        // An un-echoed dup miss is positional-only evidence on a
        // possibly desynced socket - dropping it costs one redundant
        // attempt (the original walks its own ladder), while merging
        // it could push the union to a false unanimous Missing.
        //
        // Unless it came back FENCED (§129 3g): the fence's own answer
        // sits in the slot behind this one and `read_one` has already
        // read it, so reaching here at all proves this response was in
        // the slot we asked for. That is the same proof an echoed id
        // gives, arrived at differently - and without it the whole
        // endgame fan-out is dead weight against a non-echoing
        // backbone, spending a dispatch that can never become evidence.
        if !echoed && !w.fenced {
            // The dropped dup still spent the article's one hedge: it
            // dies here without a verdict, exactly like a shed or a
            // connection death (26 Aug #13), and leaving `dups` charged
            // bars every later stale/TTFB rescue for the article's
            // whole life. `uncharge_dup` handles the entry already
            // being gone. The do-not-merge half above stays: unproven
            // evidence never reaches the mask.
            shared.uncharge_dup(&w);
            return;
        }
        // A charged refusal that named the removal leaves its hint
        // beside the mask it is about to join. Unproven refusals
        // (dropped above) leave none, same as their tried_430 bit.
        if takedown {
            shared.note_takedown(&w.id, ctx.group_bits);
        }
        // M2c.4: a duplicate's 430 is real evidence, not a
        // discard - merge it into the article's
        // authoritative mask (the inflight entry while the
        // original is out reading, the queued copy if it
        // already requeued) and declare Missing the moment
        // the union goes unanimous, instead of waiting for
        // the original to walk the rest of the ladder.
        // STATED LIMIT, TODO 315. The INFLIGHT arm below still declares
        // Missing without consulting `Shared::take_recheck`: the hold is
        // per-article state living on the ORIGINAL's `Work`, which is on
        // another worker's stack while it reads, so there is nothing here
        // to charge or requeue. The original still walks its own
        // `handle_missing` and still takes its re-ask, so the article is
        // asked again - what is early is the VERDICT the consumer saw.
        // Closing that means moving the hold onto the inflight entry so
        // one helper owns every unanimous verdict, which is a change to
        // where the state lives rather than a guard - so it is left
        // named here instead of half-done. The QUEUED arm below is a
        // different question and IS answered: the hold is right there on
        // the queued `Work` to read.
        let live = shared.live_mask();
        let mut unanimous = false;
        // The mask the verdict was taken on, kept so the report can say
        // WHY it went terminal (27 Aug sweep finding 8): live-unanimous
        // is not the same claim as gone - see `Shared::missing_cause`.
        let mut verdict_mask = 0u32;
        {
            let mut m = shared.inflight.lock_ok();
            if let Some(inf) = m.get_mut(&w.id) {
                inf.tried_430 |= ctx.group_bits;
                unanimous = inf.tried_430 & live == live;
                verdict_mask = inf.tried_430;
            }
        }
        // The fold can open a ladder pick for other servers - wake
        // gated idle scanners (N6).
        shared.bump_inflight_gen();
        if !unanimous {
            // Tail queues are tiny (endgame ≤64) - a linear
            // stamp is cheap, and a miss (article mid-hand-
            // off) only costs one redundant attempt.
            let mut q = shared.queue.lock().await;
            if let Some(qi) = q.iter_mut().find(|x| x.id == w.id)
                // TODO 315: NOT onto a bit this article's late re-ask is
                // deliberately holding open. `handle_missing` clears the
                // re-asked group's bit precisely so the requeued item is
                // not live-unanimous while it waits, and stamping it
                // back here is the one write that undoes that: the item
                // goes terminal on evidence the hold was taken over,
                // reports a Missing the re-ask was bought to test, and
                // leaves its budget slot held by a `Work` nothing will
                // ever release. This dup is not the delayed ask - it was
                // already in flight when the hold was taken - so its
                // refusal is the same evidence the hold is doubting.
                // A dup from any OTHER group still stamps and is still
                // folded; unanimity simply cannot be reached while the
                // held group's own bit is down, which is the point.
                //
                // BOUNDED SINCE 30 Aug 2026, and this arm has to know it
                // or the bound does not take: `expire_hold` restores the
                // suppressed bit once the window at `RECHECK_430_HOLD`
                // is up, and after that this dup's refusal is ordinary
                // evidence about an article nothing is holding open any
                // more. The test is `recheck::holding` and NOT the bare
                // `recheck_430` read it replaced, because that read also
                // refused a dup about a hold whose re-ask had already
                // been ANSWERED - `recheck_430` stays set for the life
                // of the article, so a settled one could never be
                // terminalized from here at all.
                && {
                    // Milliseconds since `Shared::start`, which is what
                    // the hold is stamped in - NOT the module's
                    // `now_ms()`, which is wall clock and would read
                    // every hold as expired since the epoch.
                    let run_ms = shared.start.elapsed().as_millis() as u64;
                    recheck::expire_hold(qi, run_ms, shared.recheck_hold_ms);
                    !recheck::holding(qi, ctx.group_bits)
                }
            {
                qi.tried_430 |= ctx.group_bits;
                unanimous = qi.tried_430 & live == live;
                verdict_mask = qi.tried_430;
            }
        }
        if unanimous && shared.claim_done(&w.id, w.ord) {
            let td = shared.take_takedown(&w.id) != 0;
            let cause = shared.missing_cause(verdict_mask, td);
            let _ = out.send(FetchOutcome::Missing { id: w.id, cause }).await;
            shared.complete_one();
        }
        return;
    }
    // Fold in any 430s duplicate dispatches accumulated on
    // the inflight entry while this original was reading.
    if let Some(inf) = shared.inflight.lock_ok().remove(&w.id) {
        w.tried_430 |= inf.tried_430;
    }
    // The one retirement that removes its own entry instead of going
    // through `deregister_inflight`: the park's per-group count must
    // see it too (a dup was never counted).
    if !w.dup {
        shared.park.note_left(&w);
    }
    shared.bump_inflight_gen();
    // A miss whose refusal line carried no echoed id is positional
    // attribution only: if an upstream frontend dropped the previous
    // pipelined response, this bare "430 no such article" belongs to
    // the NEXT article, and folding it would emit a false terminal
    // Missing for a perfectly valid article on a single-server run.
    // First per group: remember, requeue uncharged, and require a
    // confirming repeat. Providers that never echo converge one
    // round-trip later.
    //
    // §129 3g: the repeat confirms nothing unless BOTH refusals were
    // read off aligned sockets, and the recheck landing on a re-aligned
    // session is not something this branch can assume - a desynced one
    // may simply stall instead of ever reading an id it can check, and
    // the recheck may land on a second desynced session. So the pass is
    // per (article, group) but NOT for the whole run: a session that
    // shows its misalignment voids the refusals it handed out
    // (`void_soft_430`), and this is where the article gets its pass
    // back. Without it the pass defeated exactly ONE desync event per
    // article for the lifetime of the run, and two events on one
    // article - which a high withheld-response rate supplies - produced
    // a terminal Missing for an article the server holds.
    if !echoed {
        // §129 3g: this provider's refusals cannot be checked, so from
        // here on its dispatches carry a fence and a dropped response
        // stops being invisible.
        shared.bare_refuser[ctx.idx].store(true, Ordering::Release);
        bare_refused.push_back(w.id.clone());
        if bare_refused.len() > BARE_LEDGER_MAX {
            bare_refused.pop_front();
        }
        let void = shared.take_soft_rearm(&w.id);
        if void != 0 && w.rearms < SOFT_REARM_CAP {
            w.rearms += 1;
            w.soft_430 &= !void;
        }
    }
    // The pass is only owed while the refusal is UNPROVEN. On a fenced
    // dispatch `read_one` has already read the fence's own answer out
    // of the slot behind this response and killed the session if it
    // was not there - so alignment is established before this line
    // runs, which is exactly what the confirming repeat was buying.
    // Charging such a refusal straight away costs no safety and saves
    // this backbone a whole extra hop per absent article: on a damaged
    // post that is half the ladder's questions. Only the bare refusal
    // that ARMS the fence (the first from a provider, before
    // `bare_refuser` is set) still takes the slow road, and a provider
    // that never answers a fence has it retired by `note_fence_dud`,
    // which puts every article here back on the double pass.
    // Every exit below either requeues this article or drives it
    // terminal, and neither is ours to do if something else already
    // owns the outcome: a dup that won the race, or a `give_up_covered`
    // / `cancel` that claimed the id while this refusal was in flight.
    // Requeuing a terminal id puts a zombie entry in front of
    // `next_work`, which has no `done` filter - so a real BODY is
    // issued, ~800 KB is fetched, `handle_body`'s `claim_done` then
    // fails and the whole thing is discarded by `charge_dup_loss`,
    // which can additionally push an innocent session into its
    // repeated-race redial. Both siblings in `runlife` ask exactly this
    // before reinserting; the inflight entry is already deregistered
    // above, so returning here strands nothing.
    if shared.done.lock_ok().contains(w.ord) {
        // TODO 315: this article is resolved and its Work is leaving
        // flight here without being requeued, so a late-re-ask slot it
        // was holding has to come back. Without this the budget leaks
        // one slot per held article that a dup finished first - and a
        // leaked budget does not fail loudly, it silently retires the
        // whole mechanism once `recheck_430_max` slots are gone.
        shared.release_recheck(&w);
        return;
    }
    if !echoed && !w.fenced && w.soft_430 & ctx.group_bits != ctx.group_bits {
        w.soft_430 |= ctx.group_bits;
        // This hold is one of the two the extractor has to hear about.
        // See `note_doubt`: only when folding THIS group's bit in would
        // have gone live-unanimous, which is the difference between "an
        // article a later server may still answer" and "an article that
        // is gone unless this repeat says otherwise".
        note_doubt(cfg, w.tried_430 | ctx.group_bits, shared.live_mask());
        // A wholly dead post takes this branch for EVERY article before
        // any of them can go terminal, so the whole first pass resolves
        // nothing and decodes nothing - indistinguishable from a wedged
        // pool to a watchdog reading only bytes and outstanding count.
        // That is the 31 Jul abort exactly, and this branch reopened it.
        shared.deferred.fetch_add(1, Ordering::Relaxed);
        // The recheck jumps the queue (behind promoted work) instead of
        // going to the back. At the back its verdict lands only as the
        // drain empties - on a long download that defers a terminal
        // Missing by the WHOLE download, and the M2c.5 speculative
        // prefetch never sees the damage while there is still a
        // download to overlap (the 7 Aug nightly red). Position costs
        // nothing on correctness: this same refusal armed the fence
        // above, and a fenced read proves alignment BEFORE any verdict
        // is charged, so the repeat really does converge one round trip
        // later wherever it is read.
        let mut q = shared.queue.lock().await;
        let at = q.iter().take_while(|x| x.promoted).count().min(q.len());
        if w.promoted {
            shared.promoted_pending.fetch_add(1, Ordering::AcqRel);
        }
        q.insert(at, w);
        return;
    }
    // 430 is authoritative for this server AND its mirror
    // group; route to untried LIVE servers before declaring
    // the article missing (dead servers can never answer -
    // counting them here deadlocked the run pre-fix).
    w.tried_430 |= ctx.group_bits;
    if takedown {
        shared.note_takedown(&w.id, ctx.group_bits);
    }
    let live = shared.live_mask();
    if w.tried_430 & live == live {
        // TODO 315: the refusal in hand is the LAST evidence this
        // article needs, and there is nobody left to ask - so before it
        // is spent, ask THIS backbone once more, later. The doubt is
        // not about attribution (an echoed id settles that, and
        // `soft_430` above is the pass that exists for the case where
        // nothing does); it is about whether the answer was TRUE. A
        // cold backend answers 430 for articles it holds, measured at
        // 231 of 250 refused articles served on the very next pass off
        // the same account nine minutes later - see
        // `PoolConfig::recheck_430`.
        //
        // The bit is cleared for the group being re-asked, so the
        // requeued item is not live-unanimous any more and `next_work`'s
        // own scan does not declare it Missing before the re-ask can
        // happen. Every other server's evidence stays, so the ladder
        // ordering is untouched. `recheck_430` remembers the hold was
        // spent, which is what makes this happen at most once.
        //
        // The MIDPOINT of the queue, where `soft_430` puts its repeat
        // at the FRONT: that pass only has to prove the socket was
        // aligned and converges one round trip later, and this one is
        // buying TIME. It went to the BACK until 29 Aug 2026, which is
        // not the long delay it reads as - the queue only shrinks, so
        // the back IS drain-end and the verdict landed with no download
        // left for the M2c.5 prefetch to overlap or for a parked chase
        // to be freed by. Two e2e tests caught it and no per-push job
        // runs them; the measurement is at `recheck::recheck_slot`.
        // Nothing is charged - not `attempts`, not a dup - because no
        // attempt failed here.
        //
        // TWO EXCLUSIONS, both about not making something else worse.
        // A PROMOTED article is the playhead: the branch below exists
        // because sending one to the queue back strands a player behind
        // gigabytes, and a delayed re-ask would do exactly that with a
        // better excuse. And a TAKEDOWN-flavoured refusal is not this
        // fault - the server said REMOVED, which a cold backend's "no
        // such article" never does (`crate::nntp::takedown_flavoured`,
        // and the M29 oracle trains harder on it for the same reason),
        // so re-asking
        // buys nothing and costs a dispatch on every article of a
        // DMCA'd post.
        if !w.promoted && !takedown && shared.take_recheck(&mut w, cfg, ctx.group_bits) {
            // The other one. `w.tried_430` already carries this group,
            // and the branch above proved it live-unanimous, so the
            // article is terminal but for the hold this line just took.
            note_doubt(cfg, w.tried_430, live);
            w.tried_430 &= !ctx.group_bits;
            // Counted like `soft_430`'s deferral for the same reason: a
            // caller's stall watchdog reads bytes and outstanding count,
            // and a pass that resolves nothing for a while is otherwise
            // indistinguishable from a wedged pool (the 31 Jul abort).
            shared.deferred.fetch_add(1, Ordering::Relaxed);
            // The MIDPOINT of the remaining queue, not its back: the
            // back is not a long delay, it is the end of the run, and
            // its verdict lands with no download left to overlap. The
            // measured cost of getting this wrong, and why
            // `recheck_430_max` cannot cover it, are at
            // `recheck::recheck_slot`.
            let mut q = shared.queue.lock().await;
            let at = recheck::recheck_slot(&q);
            q.insert(at, w);
            return;
        }
        shared.release_recheck(&w);
        if shared.claim_done(&w.id, w.ord) {
            let td = shared.take_takedown(&w.id) != 0;
            // Live-unanimous ends the article; whether that is GONE or a
            // fleet that shrank past it is `missing_cause`'s to say (27
            // Aug sweep finding 8).
            let cause = shared.missing_cause(w.tried_430, td);
            let _ = out.send(FetchOutcome::Missing { id: w.id, cause }).await;
            shared.complete_one();
        }
    } else if w.promoted {
        // A promoted (playhead) article 430'd here must
        // retry on another backbone NOW - at the queue
        // back it sits behind gigabytes while the player
        // starves (live wedge: DMCA-holed head articles
        // cycling 430 → back → re-promote → 430).
        let mut q = shared.queue.lock().await;
        let at = q.iter().take_while(|x| x.promoted).count().min(q.len());
        shared.promoted_pending.fetch_add(1, Ordering::AcqRel);
        q.insert(at, w);
    } else {
        shared.queue.lock().await.push_back(w);
    }
}

/// The flap-breaker claim at the top of a session: on a flapping
/// server, one worker (or min(observed cap, budget) workers with
/// cap-aware keepers, TODO 115) claims a keeper slot and the rest
/// retire for the run. Moved verbatim out of `session_loop` (TODO
/// 113). Returns false when this worker lost the claim and must bow
/// out - the parked connection, if any, has been quit.
pub(super) async fn claim_flap_keeper(
    cfg: &PoolConfig,
    ctx: ServerCtx,
    shared: &Arc<Shared>,
    am_keeper: &mut bool,
    preclaimed: &mut Option<Connection>,
) -> bool {
    // Flap breaker: this server's established sessions keep dying
    // while other servers are healthy. One worker claims the keeper
    // slot and keeps retrying - the operator's stated contract is
    // "retry, but never at the other downloads' expense" - and the
    // rest of the fleet retires for the run, so their churn (shed
    // pipelines, redials into a burned IP cap, backoff noise) stops
    // and the shared queue naturally routes everything to servers
    // that work.
    if cfg.flap_breaker && !*am_keeper && shared.is_flapping(ctx.idx) && shared.other_live(ctx.idx)
    {
        // TODO 115: the keeper count is 1 unless the provider has
        // SHOWN us an accept cap wider than that (dials bounced off
        // a capacity refusal while we held sessions) - then it is
        // min(observed cap, this server's connection budget), so a
        // cap of two keeps both slots the provider is willing to
        // serve instead of leaving one on the table.
        let target = shared.flap_keeper_target(ctx.idx, cfg);
        let claimed = shared.flap_keeper[ctx.idx]
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |k| {
                (k < target).then_some(k + 1)
            })
            .is_ok();
        if !claimed {
            if !shared.flap_noted[ctx.idx].swap(true, Ordering::AcqRel)
                && let Some(l) = &cfg.live
            {
                let kept = match target {
                    1 => "one retry connection".to_string(),
                    n => format!("{n} retry connections (the server's own cap)"),
                };
                l.note(
                    ctx.idx,
                    "cap",
                    format!(
                        "sessions flapping ({FLAP_DEATHS}+ drops in a minute) - \
                         reduced to {kept}; other servers carry on"
                    ),
                );
            }
            if let Some(c) = preclaimed.take() {
                c.quit().await;
            }
            return false;
        }
        *am_keeper = true;
    }
    true
}

/// The two "this worker is finished before it dials" exits at the top of
/// `session_loop`: every article is terminal, or the user aborted. Both
/// hand a connection claimed before the ramp and never used back to the
/// warm pool, because in both the session is DRAINED - which is the only
/// question the pool asks. They used to differ, and the abort arm below
/// records what that cost.
///
/// Returns true when the caller must return.
pub(super) async fn done_before_dial(
    cfg: &PoolConfig,
    server: &ServerConfig,
    shared: &Shared,
    idx: usize,
    preclaimed: &mut Option<Connection>,
) -> bool {
    if shared.pending.load(Ordering::Acquire) == 0 {
        // A worker that claimed a parked connection before the ramp and
        // then found the queue already empty is holding a DRAINED,
        // freshly validated session - `take` sent its DATE and read the
        // answer, and nothing has been written since. Dropping it here
        // closed it, so the pool SHRANK every time a fleet outran its
        // work: measured over six back-to-back jobs, three parked
        // connections eroded to two and the fourth job dialled again
        // despite a hit on every claim. That is the warm pool paying to
        // destroy exactly what it exists to keep, and it bites hardest
        // under load, which is when a fleet is most likely to have one
        // worker finish everything before its siblings start.
        if let Some(c) = preclaimed.take() {
            release_drained_conn(cfg, server, shared, idx, c).await;
        }
        return true; // every article is terminal
    }
    if shared.aborted.load(Ordering::Acquire) {
        // The same session as the arm above, reached one flag later, so
        // it gets the same answer: `take` sent its DATE and read the
        // answer, nothing has been written since, and a DRAINED session
        // is reusable whatever ended the run. Closing it here was the
        // erosion that arm names, charged to the seam that hits it most
        // - a defer or a job switch is an abort, and the whole point of
        // claiming before the ramp is that this worker never dials.
        // [`stand_down`] is the same decision at the session loop's own
        // abort exit, and carries the incident it comes from.
        if let Some(c) = preclaimed.take() {
            release_drained_conn(cfg, server, shared, idx, c).await;
        }
        return true; // user abort
    }
    false
}

/// The three gates a worker passes at the top of every `session_loop`
/// pass, before it goes anywhere near a dial: the permanent bow-out, the
/// live target's park, and the session-level pacing sleep. Lifted out of
/// the loop to keep `session_loop` inside its size-gate ceiling - the
/// behaviour, and the ORDER, are unchanged and load-bearing.
///
/// Returns false when this worker is done and the caller must return.
#[expect(clippy::too_many_arguments)]
pub(super) async fn pre_dial_gates(
    cfg: &PoolConfig,
    idx: usize,
    admit: &mut Option<Admitted>,
    // This worker's lease permit, held across sessions by `worker` and
    // borrowed here so the live-target park below can GIVE IT BACK
    // during a spill episode. `None` for a pool with no lease, which is
    // the CLI and every test that does not opt in.
    permit: &mut Option<crate::pool::handoff::Permit>,
    session_failures: u32,
    pending_backoff: &mut Option<Duration>,
    finished: &mut tokio::sync::watch::Receiver<bool>,
    shared: &Arc<Shared>,
) -> bool {
    // A session that can only ever fail bows out for good, exactly as
    // connect exhaustion does (see `MAX_SESSION_ATTEMPTS`) - this
    // worker's `alive` count comes down with it, so a multi-server job
    // steers to the healthy backbone and a single-server one seals a
    // truthful Failed. Checked before the backoff: a worker that is
    // leaving anyway must not sit out a 30 s sleep on the way out. The
    // fast-failure paths and (since A8) the read-stall arm touch the
    // counter, and any well-formed BODY response clears it, so a
    // connection that has been serving is never walked toward this by a
    // rough patch - only consecutive zero-work failures count.
    if session_failures >= MAX_SESSION_ATTEMPTS {
        return false;
    }
    // TODO 112 live target: a worker without an admission parks here,
    // holding no connection, until the target rises or another worker
    // returns its admission (F-22: admission is a count, so a retiring
    // worker's place is re-filled), or the run ends. The exit that
    // routed us here has already handed its session on - and unlike the
    // capacity yield it has NOT retired, so it can come back.
    //
    // "Handed on" and not "quit", since 26 Aug 2026: a shed for a
    // lowered live target now PARKS its drained session in the warm pool
    // rather than quitting it, precisely so that the raise this worker
    // is waiting for lands on a socket instead of a dial. So a worker
    // parked here costs the provider a warm-pool session for the
    // target's downswing, bounded by `max_idle` like every other park;
    // a shed for a spent prepaid block still quits, because nothing is
    // coming back for that one. The reasoning, and the live-daemon
    // measurement behind the split, are at the shed itself in
    // `session_loop`.
    if let Some(t) = &cfg.live_target
        && admit.is_none()
    {
        // TODO 313 item 2: while a spill episode is live, a HEAD's
        // parked worker gives its lease permit back for as long as it
        // is parked - and that is the whole of what turns a
        // `ConnTarget` walk-down into a socket the QUEUE can use.
        //
        // Without it the walk-down stops at this run's own accounting:
        // the worker parks holding no connection but still holding the
        // account's permit, so `HostLease` reads the fleet as fully
        // subscribed and a job started behind this one blocks in
        // `acquire` on a slot that is standing empty. (The initial park
        // in `runlife::worker` has no such problem - it happens BEFORE
        // the permit is taken. It is only the mid-run re-park, which is
        // the one a walk-down produces, that holds one.)
        //
        // Gated on the episode rather than done unconditionally, even
        // though a parked worker holding a permit is over-counting in
        // every case: outside a spill nothing is waiting on the lease
        // mid-run, so releasing would change no outcome and would put a
        // new re-acquire in the path of the TODO 112 walker and the
        // line-cap governor, both of which shed and raise on their own
        // schedule. One trigger, one behaviour.
        let gave_back = cfg
            .spill
            .as_ref()
            .is_some_and(|sp| sp.open_as(crate::pool::handoff::SpillRole::Head))
            && permit.take().is_some();
        match wait_for_slot(t, idx, finished, shared).await {
            Some(a) => *admit = Some(a),
            None => return false,
        }
        // Re-admitted: take a permit again before this worker goes
        // anywhere near a dial. It parks as this run's OWN waiter for
        // exactly as long as the lease counts it
        // (`Shared::own_lease_waiters`), so the head can never read its
        // own reclaim as a successor and shed to itself - and from the
        // SPILLED LANE's side this park is precisely the reclaim
        // signal, a `Download`-class waiter that `LeaseClass::Spill`
        // must stand behind.
        if gave_back && let Some(l) = &cfg.lease {
            let _parked = shared.park_on_lease(idx);
            tokio::select! {
                // As RECLAIM and not as this pool's own class: this is
                // the head asking for a socket it lent, which is the one
                // acquire a spilled lane must stand behind. See
                // `LeaseClass::Reclaim` for why an ordinary parked
                // download may not carry that meaning.
                p = l.acquire_as(crate::pool::handoff::LeaseClass::Reclaim) => {
                    *permit = Some(p)
                }
                _ = crate::pool::runlife::run_over(finished, shared) => return false,
            }
        }
    }
    // Session-level pacing (see `session_backoff_delay`). Armed by the
    // fast failure paths - protocol error, failed send, failed flush -
    // which otherwise reconnect with zero delay, and (A8) by the
    // read-stall arm: an expiry paces one attempt at the budget it
    // burned, but without the ladder a mute-after-AUTH server held its
    // whole fleet in a dial-and-expire loop at the TTFB floor for the
    // run. Deliberate reconnects (pipeline shed, promote shed) never
    // arm it. The session guard has
    // been dropped by the `continue` that got us here, so a worker
    // sleeping this off is not counted as connected. Abort sets
    // `finished`, so that arm covers it; a graceful pause does not, hence
    // the short slices - a drain must not wait out a 30 s backoff before
    // this worker retires.
    //
    // NOT `backoff_or_finish`, which looks identical and is not: it
    // treats a drain as "stop", while a drain here breaks the wait and
    // carries the worker ON into the loop to retire through the normal
    // path.
    if let Some(d) = pending_backoff.take() {
        // Deadline on the runtime's clock, not `std`'s: the slices below
        // are `tokio::time::sleep`, and mixing the two makes this a
        // busy-wait under a test clock (the sleeps return, the deadline
        // never moves). Identical in production, where the two clocks
        // are the same clock.
        let until = tokio::time::Instant::now() + d;
        loop {
            let left = until.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() || shared.draining.load(Ordering::Acquire) {
                break;
            }
            tokio::select! {
                _ = tokio::time::sleep(left.min(Duration::from_millis(250))) => {}
                // The run finished (or was aborted) while this worker was
                // sitting out.
                _ = finished.wait_for(|f| *f) => return false,
            }
        }
    }
    true
}

/// The session died mid-read: either an answer we could not use, or the
/// peer hanging up under us. Records who hung up, voids the soft-430
/// window if the error PROVES a response desync, counts the flap, and
/// requeues what was in flight. Consumes the connection (`quit` does),
/// and returns the `SessionEnds` cause so the caller can record it as
/// this worker's last end.
///
/// Split out of [`session_loop`] under TODO 106 - the 500-line function
/// ceiling. The body is unchanged; the caller still owns the retry
/// bookkeeping (`session_failures`, `pending_backoff`) because only it
/// can `continue 'session`.
async fn session_died_mid_read(
    cfg: &PoolConfig,
    ctx: ServerCtx,
    shared: &Arc<Shared>,
    out: &mpsc::Sender<FetchOutcome>,
    conn: Connection,
    inflight: &mut VecDeque<Work>,
    buf: PooledBuf<'_>,
    e: &crate::nntp::NntpError,
    bare_refused: &VecDeque<Arc<str>>,
    session_bytes: u64,
    session_responses: u32,
) -> usize {
    drop(buf); // returned to the pool here, not at scope end
    // WHO hung up (TODO 121 diagnostics): an I/O-flavoured
    // error OR a clean EOF (`Closed` - read_status maps
    // n==0 to it, and a between-responses FIN is the
    // commonest churn shape of all) is the peer closing
    // under us; anything else is an answer we could not
    // use. Counted here, at the death, for the same
    // reason note_flap is.
    let peer_closed = matches!(
        e,
        crate::nntp::NntpError::Io(_) | crate::nntp::NntpError::Closed
    );
    // §129 3g: THIS is the moment a response desync stops
    // being invisible. An id that is not the one we asked
    // for, or a status that cannot answer a BODY at all,
    // both mean the same thing - a response went missing
    // upstream and every read since has been answering the
    // slot behind it. The refusals this session handed out
    // were read off that misaligned socket, so the passes
    // they spent are void: the next bare refusal for those
    // articles is first evidence again, not a confirmation.
    // A peer hangup is NOT this shape: a socket that goes
    // away says nothing about how the responses before it
    // lined up, and re-arming on ordinary churn would pay
    // a dispatch per article on every flap. (The stall arm
    // below is the same event seen from the other end, and
    // voids the window for its own reasons.)
    if matches!(
        e,
        crate::nntp::NntpError::IdMismatch { .. } | crate::nntp::NntpError::Unexpected { .. }
    ) {
        shared.void_soft_430(bare_refused, ctx.group_bits);
    }
    let cause = if peer_closed { 0 } else { 1 };
    shared.note_session_end(ctx.idx, cause);
    conn.quit().await;
    if session_bytes > 0 {
        // Flap breaker: an ESTABLISHED session (it served bytes)
        // died - count it where it happens, not at some later
        // redial this worker may never win (a capped provider
        // bounces most re-entries, which hid the churn entirely).
        shared.note_flap(ctx.idx);
    }
    requeue_or_fail(
        shared,
        out,
        cfg,
        ctx,
        inflight,
        // The peer ended it, and the OS's own words for how ride in the
        // string beside the code.
        FailCode::Transport,
        &e.to_string(),
        session_responses == 0,
    )
    .await;
    cause
}

/// OUR read deadline ended the session, not the peer. Same shape as
/// [`session_died_mid_read`] but a different diagnosis, and it does not
/// quit the connection - the state is unusable, so it is simply dropped.
/// Returns the `SessionEnds` cause.
///
/// Split out of [`session_loop`] under TODO 106; the body is unchanged.
async fn session_stalled_mid_read(
    cfg: &PoolConfig,
    ctx: ServerCtx,
    shared: &Arc<Shared>,
    out: &mpsc::Sender<FetchOutcome>,
    inflight: &mut VecDeque<Work>,
    buf: PooledBuf<'_>,
    prebyte_expired: bool,
    bare_refused: &VecDeque<Arc<str>>,
    session_bytes: u64,
) -> usize {
    // Stalled mid-response; connection state unusable.
    // Body bytes of the CURRENT response count as flap
    // progress: `session_bytes` holds only COMPLETED
    // bodies, so a provider that repeatedly serves a
    // status plus most of a first body and then wedges
    // read as zero-work and never entered the keeper
    // clamp, however often it did it.
    let partial_bytes = buf.len() as u64;
    drop(buf); // returned to the pool here, not at scope end
    // OUR deadline ended this session, not the peer. Split
    // pre-byte from mid-flow: giving up before the first
    // byte is our budget choice, a mid-flow stop is a wedge.
    let cause = if prebyte_expired { 2 } else { 3 };
    shared.note_session_end(ctx.idx, cause);
    note_read_stall(
        shared,
        ctx.idx,
        session_bytes + partial_bytes,
        prebyte_expired,
        inflight.front_mut(),
    );
    // §129 3g: the OTHER shape a withheld response takes.
    // A session reading one slot early runs out of
    // answers - it is waiting for a response the server
    // already spent on the article behind - so a stall
    // with requests outstanding is the same event as the
    // id mismatch above, seen from the end of the
    // pipeline instead of the middle. It is weaker
    // evidence (a merely slow or muted provider stalls
    // too), but the reaction is cheap and bounded: the
    // refusals in the window get asked once more, at most
    // `SOFT_REARM_CAP` times each, and a healthy session
    // never enters this arm at all. Measured: without it
    // the sweep's 1-in-5 bare column stops at 2 false
    // Missing rather than 0, because the desynced
    // sessions in that leg mostly STALL - they never live
    // long enough to read an id they can check.
    shared.void_soft_430(bare_refused, ctx.group_bits);
    // The stall implicates the FRONT article - its own
    // response budget expired - so the charge stays
    // unconditional: a mute-on-one-article server must
    // still walk that article to a terminal verdict.
    requeue_or_fail(
        shared,
        out,
        cfg,
        ctx,
        inflight,
        // OUR deadline, not the peer's - its own code, for the reason
        // `FailCode::ReadStall` gives.
        FailCode::ReadStall,
        FailCode::ReadStall.reason(),
        true,
    )
    .await;
    cause
}

/// The abort exit: hand this worker's connection back the way the
/// SOCKET allows, whatever ended the run.
///
/// `drained` is the whole test, and it is the pool's own: a connection
/// with unread pipelined responses on it is reusable by nobody, so that
/// one closes. An abort with an empty pipeline does not have that
/// problem, and it used to close anyway - on the reasoning that "the
/// user is done with this server", which is what going OFFLINE means and
/// not what stopping a job means. Offline and shutdown shut the pool
/// itself (`set_accepting(false)` plus `clear`), so `give` closes for
/// them and no exit here has to guess which kind of abort it is looking
/// at.
///
/// What the guess cost, measured on the live daemon 25-26 Aug 2026: this
/// flag is also the defer watchdog's teeth and the job-switch seam, and
/// the workers those find on a server that has nothing fetchable are
/// idle BY DEFINITION - the population [`idle_turn`]'s keepalive probe
/// was written for. So every defer quit 9-13 authenticated sessions to
/// one provider and the next job dialled them again seconds later.
/// Against a per-account 40-session cap whose server holds torn-down
/// sessions for minutes before reaping them, that is a dial storm into a
/// wall the storm itself keeps up: "502 connection limit (40) reached"
/// for hours, across a daemon restart, with nothing else holding the
/// credentials.
///
/// It is also what the two neighbouring exits already do. A job that
/// ENDS parks and a graceful pause parks (both in [`idle_turn`]); only
/// the abort threw the fleet away, so completing a job and stopping one
/// left the account in different states for no stated reason.
///
/// PROVIDER-BLIND, deliberately. The pool does learn which providers cap
/// sessions - a capacity refusal whose text is a CONNECTION limit
/// records the count held at the bounce as the observed ceiling - but
/// making the seam wait for that evidence is a rule that only fires
/// after the damage, and the first job after a restart would storm
/// anyway - and the 25 Aug wall outlived a daemon restart. Keeping a
/// drained session is right for an uncapped provider too, for the reason
/// the warm pool exists at all, so there is nothing for the distinction
/// to buy.
///
/// It adds no holding mechanism and could not: what it changes is which
/// SOCKETS reach the pool, never how long the pool keeps one. A session
/// parked here ages out on `max_idle` and is trimmed by its server's
/// release policy exactly as one parked by a finished job is.
///
/// **`drained` is necessary and not sufficient**, since 27 Aug 2026, and
/// that is the one correction to everything above. Where the session
/// GOES once this has decided it is reusable is
/// [`release_drained_conn`], which quits a host whose prepaid block is
/// spent - and it has to be asked HERE and not only at the shed, because
/// the inner loop reads the abort flag BEFORE it reaches the shed's own
/// `over_budget` test. So a worker whose pipeline drains in the same
/// pass a sibling's bytes push the fleet over budget arrives here, and
/// until that date it parked on a host `release_shed_conn`'s rule
/// (`9b442b1ce`) already said must quit - one slot per racing worker,
/// held against a capped account until the 300 s idle reap. Nothing
/// above changes for a server with no block: `over_budget` is false for
/// every one of them.
pub(super) async fn stand_down(
    cfg: &PoolConfig,
    server: &ServerConfig,
    shared: &Shared,
    idx: usize,
    conn: Connection,
    drained: bool,
) {
    if drained {
        release_drained_conn(cfg, server, shared, idx, conn).await;
    } else {
        conn.quit().await;
    }
}

/// What an idle turn decided.
enum IdleTurn {
    /// Still wanted: look again shortly.
    Keep(Connection),
    /// The worker is done with this connection and must return (it has
    /// been parked or quit).
    Retire,
    /// The keepalive probe found the peer gone (FIN'd, reset, or
    /// black-holed past the validate bound). The session end is already
    /// tallied as `peer`; the connection is dropped, and the caller
    /// redials through the same failure path as a read-side death.
    Dead,
}

/// An idle turn at the reuse point: the pipeline is empty and the
/// queue had nothing for this worker. Hoisted out of `session_loop`
/// whole (size gate) when the hand-over arm joined the two that were
/// there; see [`IdleTurn`] for what each verdict means to the caller.
///
/// `quiet_since` is the last moment the socket was known alive - the
/// caller resets it on every pass that reaches the wire, and the probe
/// below resets it on success. Without the probe, a worker whose server
/// has nothing fetchable for the job (every remaining article missing
/// there) spins in the 25 ms arm for the life of the job and never
/// touches the socket, so the provider's idle timeout FINs it and
/// nobody notices: the socket sits in CLOSE_WAIT, the conn gauge still
/// reports it as a live connection, and the death only surfaces when
/// work finally arrives and the first write fails - which for a server
/// with 0% of the job never happens. Measured live, 25 Aug 2026: nine
/// CLOSE_WAIT sockets to a backbone with 100% of the job's articles
/// missing, stable for minutes, whyslow reporting conns 9 / reconnects
/// 0. The warm pool has pinged its parked connections on this exact
/// cadence all along ([`crate::warmpool::KEEPALIVE_EVERY`]); this is
/// the same discipline for the sockets workers hold.
async fn idle_turn(
    cfg: &PoolConfig,
    server: &ServerConfig,
    ctx: ServerCtx,
    shared: &Arc<Shared>,
    mut conn: Connection,
    quiet_since: &mut Instant,
) -> IdleTurn {
    if shared.pending.load(Ordering::Acquire) == 0 {
        release_drained_conn(cfg, server, shared, ctx.idx, conn).await;
        return IdleTurn::Retire; // truly drained
    }
    if shared.draining.load(Ordering::Acquire) {
        release_drained_conn(cfg, server, shared, ctx.idx, conn).await;
        return IdleTurn::Retire; // graceful pause: in-flight done, queue left for resume
    }
    // Keepalive probe, ahead of the throttle arm below on purpose: a
    // hold-parked fleet is "wanted back the moment the holds drain",
    // and a socket the provider idle-reaped during a long hold is not
    // coming back for anyone. DATE both proves the socket and resets
    // the provider's idle clock, so a healthy idle session stays held
    // instead of being torn down and redialled - which against a
    // per-account connection cap is a dial storm (the "502 connection
    // limit reached" wall behind the 25 Aug 2026 incident).
    if quiet_since.elapsed() >= crate::warmpool::KEEPALIVE_EVERY {
        let alive = matches!(
            tokio::time::timeout(crate::warmpool::VALIDATE_TIMEOUT, conn.date()).await,
            Ok(Ok(_))
        );
        if !alive {
            shared.note_session_end(ctx.idx, 0);
            return IdleTurn::Dead;
        }
        *quiet_since = Instant::now();
    }
    // Held-bytes backpressure (TODO 94 item E): the queue is not dry,
    // it is PARKED behind a chased group's engine, for seconds at a
    // time. Neither the idle-after-dry note nor a hand-over applies -
    // the connections are wanted back the moment the holds drain.
    if shared.park.is_throttling() {
        tokio::time::sleep(Duration::from_millis(25)).await;
        return IdleTurn::Keep(conn);
    }
    // Cross-job hand-over (`handoff`): idle past queue-dry with nothing
    // to fetch. Say so once per run, and if the next job's workers are
    // waiting on this host's lease, give them the socket - the same
    // reuse point and the same safety argument as the park above, one
    // job earlier. The permit goes with this worker's return (see
    // `worker`).
    shared.note_idle_after_dry(ctx.idx);
    // CLAIMED, not peeked: this arm is the one that acts on the answer,
    // and `want_handoff` alone let every idle worker on a server reach
    // the same conclusion at once. See `claim_handoff`.
    if shared.claim_handoff(ctx.idx) {
        shared.note_session_end(ctx.idx, 4);
        release_drained_conn(cfg, server, shared, ctx.idx, conn).await;
        return IdleTurn::Retire;
    }
    // Idle but articles are still in flight elsewhere and may requeue
    // (or become dup candidates) - re-check shortly.
    if std::env::var_os("NZBFAST_POOL_DEBUG").is_some() {
        shared.debug_dump_idle();
    }
    tokio::time::sleep(Duration::from_millis(25)).await;
    IdleTurn::Keep(conn)
}

/// What one window top-up decided.
enum TopUp {
    /// The window is as full as it is going to get - read responses.
    Filled,
    /// The write side died under us. The casualty is already requeued
    /// and the end is already counted; the carried value is the
    /// `SessionEnds` slot, so the caller records it and redials exactly
    /// as it does for the read-side deaths above.
    Redial(usize),
}

/// Fill the pipeline up to `win`, dispatching one BODY per slot.
///
/// Lifted out of `session_loop` whole (TODO 106) - it is the one
/// self-contained block left in the hottest function in the repo, and
/// the only reason it could not simply return was the failed-send
/// path's `continue 'session`, which [`TopUp::Redial`] now carries for
/// it. Everything the caller does after a session death - the failure
/// counter, the armed backoff - deliberately stayed at the call site,
/// where it is shared with the flush-failed arm.
async fn top_up_window(
    conn: &mut Connection,
    cfg: &PoolConfig,
    ctx: ServerCtx,
    shared: &Arc<Shared>,
    out: &mpsc::Sender<FetchOutcome>,
    inflight: &mut VecDeque<Work>,
    win: usize,
    over_target: bool,
    session_bytes: u64,
    session_responses: u32,
) -> TopUp {
    while inflight.len() < win {
        if shared.draining.load(Ordering::Acquire) {
            break;
        }
        // TODO 112: over the live target - admit nothing new,
        // so the pipeline drains toward the park above.
        if over_target {
            break;
        }
        // B3 wire-cap: over the global in-flight byte budget,
        // stop topping up - but never below ONE request in
        // flight, so every connection stays busy and the pool
        // can't deadlock (the response drain below is what
        // releases charges and reopens the cap).
        if !inflight.is_empty() && shared.wire_over_cap(cfg.inflight_cap) {
            shared.note_wire_cap();
            break;
        }
        let Some(mut w) = next_work(shared, ctx, out, Pipeline::of(inflight)).await else {
            break;
        };
        // B3 wire-cap: charge at dispatch, BEFORE the send can
        // fail. Every release is a `release_wire(inflight.len())`
        // over a worker's deque, so the only workable invariant is
        // "one charge per item in that deque" - and the failed-send
        // path below deliberately puts `w` into it. Charging after
        // the send left that one item uncharged while
        // requeue_or_fail released for it anyway: one flaky send
        // wrapped the global counter and collapsed every worker in
        // the pool to pipeline depth one.
        shared.charge_wire();
        // §129 3g: on a provider whose refusals arrive bare, the
        // BODY goes out with an alignment fence behind it. Both
        // are written unflushed into the same pipeline, so it
        // costs bytes rather than a round trip, and it gives the
        // reader something it can CHECK - which is the whole
        // difference between this provider and an id-echoing one.
        w.fenced = cfg.desync_fence
            && shared.bare_refuser[ctx.idx].load(Ordering::Acquire)
            && !shared.fence_off[ctx.idx].load(Ordering::Acquire);
        // TODO 96.4: a fan-out dup buys a verdict, not bytes, so under
        // `stat_probe` it goes out as STAT. Everything else about the
        // dispatch - the fence, the wire charge, the attribution - is
        // identical, which is the point: a STAT's refusal codes are a
        // BODY's, so nothing downstream of `handle_missing` can tell
        // the two apart.
        let sent = match if w.probe {
            conn.send_stat(&w.id).await
        } else {
            conn.send_body(&w.id).await
        } {
            Ok(()) if w.fenced => conn.send_fence().await,
            other => other,
        };
        if sent.is_err() {
            // Make the failed article the front-of-inflight casualty
            // so requeue_or_fail sees it (it was popped, never
            // registered in inflight). On a ZERO-response session it
            // is charged (attempts/tried_fail) - a server that RSTs
            // right after AUTH loops connect+AUTH forever on a
            // single-server job otherwise. After a completed
            // response (a body OR an authoritative 430/423) the
            // socket death is the session's fault, not this
            // article's, and it requeues uncharged. dup items are
            // still dropped by requeue_or_fail.
            inflight.push_front(w);
            // A failed send is the peer gone under us (RST/EPIPE)
            // - a session end like any read-side death, counted
            // so the churn census sees write-side exits too.
            shared.note_session_end(ctx.idx, 0);
            if session_bytes > 0 {
                // Flap breaker: an ESTABLISHED session (it served bytes)
                // died - count it where it happens, not at some later
                // redial this worker may never win (a capped provider
                // bounces most re-entries, which hid the churn entirely).
                shared.note_flap(ctx.idx);
            }
            requeue_or_fail(
                shared,
                out,
                cfg,
                ctx,
                inflight,
                FailCode::Transport,
                "send failed",
                session_responses == 0,
            )
            .await;
            return TopUp::Redial(0);
        }
        if let Some(l) = &cfg.live {
            l.servers[ctx.idx]
                .articles_tried
                .fetch_add(1, Ordering::Relaxed);
        }
        shared.register_inflight(&w, ctx.idx);
        inflight.push_back(w);
    }
    TopUp::Filled
}

/// Should this worker stop topping up its pipeline? Yes when the server
/// holds more admissions than the live target (TODO 112), and yes when
/// the prepaid block ran out mid-session (§96.5) - the budget gate at
/// the top of 'session then turns the redial into a bow-out. A pure
/// read; `shed_surplus` is the step that gives the admission back,
/// atomically (F-22), so exactly the surplus sheds and not every
/// worker that glimpsed the same over-count.
pub(super) fn surplus_here(
    cfg: &PoolConfig,
    idx: usize,
    shared: &Shared,
    admit: &Option<Admitted>,
) -> bool {
    shared.over_budget(idx)
        || cfg.live_target.as_ref().is_some_and(|t| {
            admit.as_ref().is_some_and(|a| !a.released)
                && shared.admitted[idx].load(Ordering::SeqCst) > t.get()
        })
}

/// Where a SHED connection goes: parked for the target's next upswing,
/// or quit for good because the block that paid for it is spent.
///
/// The shed's `inflight.is_empty()` guard is the reuse point's own safety
/// argument, so the session arriving here is drained and parkable - and it
/// was quit outright until 26 Aug 2026, which made the shed the last exit
/// in this pool that threw a provably reusable session away. Whether it
/// should is the one question `drained` alone does not settle,
/// because a shed carries a judgement a stop does not: the live target is
/// what this RUN may hold, so parking keeps an account slot occupied at
/// the moment somebody asked for fewer of them. The two reasons
/// [`surplus_here`] folds together get OPPOSITE answers, and both were
/// measured rather than reasoned about.
///
/// **A live-target reduction PARKS.** Nothing that lowers a `ConnTarget`
/// is evidence about the ACCOUNT: an observed session cap goes to
/// `Shared::note_cap_bounce` and moves the flap breaker's keeper count,
/// never this. What lowers it is the line-cap governor fitting a byte
/// budget and the TODO 112 walker finding a throughput knee - and the
/// raise that follows either is exactly what TODO 277 spawns parked slots
/// for. A `ConnTarget` above the SPAWNED fleet wakes nothing, so the seed
/// spawns the curve's ceiling and parks the surplus WORKERS in
/// [`pre_dial_gates`] precisely so a raise lands without a dial; a shed
/// that quit its socket made the same shed/raise cycle cost a dial, a TLS
/// handshake and an AUTHINFO every time, which is the churn that design
/// exists to avoid.
///
/// Measured 26 Aug 2026 on a long-lived daemon install running a
/// multi-provider account set: 13 runs across its two daemon logs, one of
/// 31,528 s and one of 8,192 s, every `[pool]` summary reporting `line cap
/// 25 (0 sheds)`, and not one in-run "using N of M" line in either
/// direction. That is not a quiet sample - `fleet_step`
/// returns early on `want <= fleet`, so the governor is monotone UP within
/// a run, and the TODO 112 walker ships off. So the population this arm
/// can reach in a default install is empty, and where it does fire it
/// fires once and holds one socket.
///
/// **A spent prepaid block QUITS**, and that is not symmetry for its own
/// sake. `Shared::over_budget` latches for the run, and the daemon's
/// runner rules a host whose block spend has reached its size out of the
/// NEXT job's pool outright, so a session parked here is a provider slot
/// held for a job that will never take it - pure cost until the warm
/// pool's idle bound reaps it. §96.5's own bow-out at the top of
/// `'session` already says as much: that worker leaves "before it can dial
/// (or keep) a session the account can no longer pay for". This only makes
/// the shed agree with it.
///
/// Pinned by `a_shed_for_a_lowered_target_parks_its_session_rather_than_quitting_it`
/// and `a_shed_for_a_spent_prepaid_block_quits_its_session`.
async fn release_shed_conn(
    cfg: &PoolConfig,
    server: &ServerConfig,
    shared: &Shared,
    idx: usize,
    conn: Connection,
) {
    // Re-read rather than taken from `surplus_here`: the budget latch only
    // ever goes one way, so a spent block seen there is spent here too,
    // and reading it at the decision keeps the two reasons from drifting.
    // The read itself is `release_drained_conn`'s, which is this rule
    // hoisted so that every drained exit asks it (27 Aug 2026, sweep
    // finding R3) - the shed keeps its own door because the LIVE-TARGET
    // half documented above it is the shed's alone and has nothing to
    // say at any other exit.
    release_drained_conn(cfg, server, shared, idx, conn).await;
}

/// The consuming half of [`surplus_here`]: the caller has drained its
/// pipeline and asks whether it is the one to bow out. What it then does
/// with the CONNECTION is [`release_shed_conn`] - since 26 Aug 2026 that
/// is a park on one of the two arms, so this no longer always means quit.
pub(super) fn shed_surplus(
    cfg: &PoolConfig,
    idx: usize,
    shared: &Shared,
    admit: &mut Option<Admitted>,
) -> bool {
    if shared.over_budget(idx) {
        return true;
    }
    let Some(t) = cfg.live_target.as_ref() else {
        return false;
    };
    let shed = admit.as_mut().is_some_and(|a| a.try_shed(t.get()));
    if shed {
        *admit = None;
    }
    shed
}

/// A parked connection first. `take` has already validated it with
/// a DATE round-trip, so it is interchangeable with a fresh
/// connect here and none of the error handling below has to know
/// the difference. Worth roughly five round-trips, a TLS
/// handshake, and - the part that actually dominates on a short
/// job - a TCP congestion window that is already open.
///
/// Split out of `session_loop` (TODO 106), body verbatim. The warm arm
/// yields `DialStep::Conn` and the dial arm is returned as it stands, so the
/// caller's three-way match is unchanged and every `continue`/`return` it
/// spells out stays at the call site where the loop label is in scope.
#[expect(clippy::too_many_arguments)]
async fn acquire_conn(
    spare: Option<Connection>,
    preclaimed: &mut Option<Connection>,
    server: &ServerConfig,
    cfg: &PoolConfig,
    ctx: ServerCtx,
    shared: &Arc<Shared>,
    connects: &Arc<AtomicU64>,
    reconnects: &Arc<AtomicU64>,
    finished: &mut tokio::sync::watch::Receiver<bool>,
    connect_failures: &mut u32,
    flap_bounces: &mut u32,
    cap_bounces: &mut u32,
    ever_connected: &mut bool,
    am_keeper: bool,
    last_end: &mut Option<usize>,
) -> DialStep {
    let warm = match spare.or_else(|| preclaimed.take()) {
        Some(c) => Some(c),
        None => match &cfg.warm {
            // Raced for the same reason as the dial below: the
            // claim's DATE validation is bounded at 8 s against
            // EXIT_GRACE's 5 s, so a mute peer here holds the whole
            // run open exactly as an unanswered SYN used to (§35).
            Some(w) => tokio::select! {
                c = w.take(server) => c,
                _ = run_over(finished, shared) => return DialStep::Quit,
            },
            None => None,
        },
    };
    match warm {
        Some(c) => {
            // "The outage is over the moment a session is GRANTED,
            // whatever the reason it started" - and one taken from
            // the warm pool is granted. Without these two the only
            // calls that stop the dashboard stamp and bank the
            // outage budget live on the DIAL path, so a server that
            // recovers purely through parked connections goes on
            // accruing downtime for as long as it serves.
            if let Some(live) = &cfg.live
                && let Some(sl) = live.servers.get(ctx.idx)
            {
                sl.note_up();
            }
            shared.auth[ctx.idx].mark_up();
            *connect_failures = 0;
            *ever_connected = true;
            shared.connected[ctx.idx].store(true, Ordering::Relaxed);
            DialStep::Conn(c)
        }
        None => {
            return dial_session(
                server,
                cfg,
                ctx,
                shared,
                connects,
                reconnects,
                finished,
                connect_failures,
                flap_bounces,
                cap_bounces,
                ever_connected,
                am_keeper,
                last_end,
            )
            .await;
        }
    }
}

pub(super) async fn session_loop(
    server: &ServerConfig,
    cfg: &PoolConfig,
    ctx: ServerCtx,
    shared: Arc<Shared>,
    out: mpsc::Sender<FetchOutcome>,
    connects: Arc<AtomicU64>,
    reconnects: Arc<AtomicU64>,
    // This worker's per-server ordinal (diagnostic; admission under the
    // live target is by count, see `Admitted`).
    _slot: u32,
    // The live-target admission `worker` acquired before the warm claim
    // (None without a live target). Held across sessions, re-acquired
    // only after a shed, dropped by every `return` so the next parked
    // worker is promoted in this one's place (F-22).
    mut admit: Option<Admitted>,
    // The account lease permit `worker` acquired, borrowed for this
    // worker's whole session life. Handed in rather than kept there so
    // that the live-target park inside [`pre_dial_gates`] can release
    // and re-take it during a spill episode (TODO 313 item 2); every
    // other path leaves it exactly where it was, and `worker` still
    // owns it and still drops it on every exit.
    permit: &mut Option<crate::pool::handoff::Permit>,
    // A parked connection already claimed (and validated) by `worker`
    // before the ramp; used for the first session instead of dialling.
    mut preclaimed: Option<Connection>,
) {
    let mut connect_failures: u32 = 0;
    // TODO 115: capacity bounces while holding a keeper slot pace their
    // retries on this counter, never on connect_failures - a keeper must
    // not walk toward connect exhaustion on bounces (see the keeper arm).
    let mut flap_bounces: u32 = 0;
    // The capacity-PROBE ladder's own step count, which is also how
    // `park_or_probe` tells the elected prober re-entering from its own
    // ladder (bounces > 0) from a worker arriving fresh. The keeper's
    // flap counter above must stay out of it: sharing one counter let a
    // keeper that had flapped and then exhausted its dial attempts walk
    // straight past the single-prober election.
    let mut cap_bounces: u32 = 0;
    // Consecutive sessions that connected and then died without doing any
    // useful work, and the delay they have armed for the next connect.
    let mut session_failures: u32 = 0;
    let mut pending_backoff: Option<Duration> = None;
    // Recycle experiment: consecutive articles of OURS a duplicate
    // dispatch finished first. Reset by any completion we win.
    let mut race_losses: u32 = 0;
    // Flap breaker: true once THIS worker claimed its server's keeper
    // slot - the keeper never bows out to its own clamp.
    let mut am_keeper = false;
    let mut ever_connected = false;
    // Why this worker's last session ended (SessionEnds slot order),
    // refreshed at every end site below, so the redial note can tell a
    // rotation we chose from a session genuinely lost.
    let mut last_end: Option<usize> = None;
    let mut finished = shared.finished.subscribe();
    let mut promote_gen = shared.promote_gen.subscribe();

    'session: loop {
        // §96.5: the prepaid block is spent - this worker leaves for
        // good, before it can dial (or keep) a session the account can
        // no longer pay for. Checked at the loop top so the in-session
        // drain below routes here: over budget the pipeline stops
        // topping up, in-flight responses complete and are counted,
        // the quit lands, and the redial becomes this bow-out. The
        // worker's retire brings `alive` down, so the routing masks
        // (level gates, the every-live-server-430'd terminal rule)
        // self-correct exactly as they do for a dead server.
        if shared.over_budget(ctx.idx) {
            shared.note_budget_spent(ctx.idx);
            if let Some(c) = preclaimed.take() {
                c.quit().await;
            }
            return;
        }
        if !pre_dial_gates(
            cfg,
            ctx.idx,
            &mut admit,
            permit,
            session_failures,
            &mut pending_backoff,
            &mut finished,
            &shared,
        )
        .await
        {
            return;
        }
        if done_before_dial(cfg, server, &shared, ctx.idx, &mut preclaimed).await {
            return;
        }

        if !claim_flap_keeper(cfg, ctx, &shared, &mut am_keeper, &mut preclaimed).await {
            return;
        }

        // Hot-spare experiment: spawn this server's filler once,
        // whichever worker gets here first (works on the single-runtime
        // and sharded paths alike), and claim a parked spare before
        // anything else - a worker arriving here after a session death
        // skips the dial entirely.
        if cfg.hot_spare && !shared.spare_filler_started[ctx.idx].swap(true, Ordering::AcqRel) {
            tokio::spawn(spare_filler(shared.clone(), server.clone(), ctx.idx));
        }
        let spare = if cfg.hot_spare {
            shared.spares[ctx.idx].lock_ok().take()
        } else {
            None
        };
        // Slope-recycle experiment: this session's own byte total and
        // birth, so its personal rate can be compared to the fleet's.
        let session_start = Instant::now();
        let mut session_bytes: u64 = 0;
        // Completed useful responses this session (a well-formed 222 OR
        // an authoritative 430/423). Session-death attribution keys on
        // THIS, not on bytes: a connection that validly answered "no
        // such article" and then died was a working session, and
        // charging its death to the innocent front article would let a
        // one-response-per-connection server walk a perfectly valid
        // article to Failed without ever serving it.
        let mut session_responses: u32 = 0;
        // §129 3g: the bare refusals this session has handed out, most
        // recent last. A response read off by one is invisible while the
        // refusals are bare, but the session PROVES the misalignment when
        // it finally reads an id it can check - and at that moment every
        // refusal in here is evidence collected from a misaligned socket.
        let mut bare_refused: VecDeque<Arc<str>> = VecDeque::new();
        // §129 3g: whether this session has already read a fence answer.
        // Only the first one can tell DATE-silence apart from a real
        // desync, because before it the socket is aligned by
        // construction.
        let mut fence_read_seen = false;
        let mut conn = match acquire_conn(
            spare,
            &mut preclaimed,
            server,
            cfg,
            ctx,
            &shared,
            &connects,
            &reconnects,
            &mut finished,
            &mut connect_failures,
            &mut flap_bounces,
            &mut cap_bounces,
            &mut ever_connected,
            am_keeper,
            &mut last_end,
        )
        .await
        {
            DialStep::Conn(c) => c,
            DialStep::Retry => continue 'session,
            DialStep::Quit => return,
        };

        // An authenticated session supersedes any earlier refusal note: a
        // capacity refusal (connection/IP cap) is a statement about THAT
        // moment, and once the server accepts a session again the stale
        // note would keep the dashboard warning and keep the idle-server
        // prefetch treating the host as dead. A permanent refusal never
        // reaches here - its workers all returned above.
        if let Some(live) = &cfg.live
            && let Some(sl) = live.servers.get(ctx.idx)
        {
            sl.refusal.lock_ok().take();
        }

        // Dashboard gauge: this worker holds a session until the next
        // 'session iteration or return drops the guard.
        let _gauge = ConnGauge::up(&cfg.live, ctx.idx);
        // Cap-estimation tally, same lifetime (TODO 115).
        let _sess = SessionTally::up(&shared, ctx.idx);

        // In-flight commands, oldest first (responses arrive in order).
        let mut inflight: VecDeque<Work> = VecDeque::with_capacity(cfg.window);

        // Last moment this session's socket was known alive: dial time,
        // then every pass that reaches the wire, then each successful
        // idle probe (see `idle_turn`). Per-session on purpose - a
        // redial starts a fresh clock.
        let mut quiet_since = Instant::now();

        loop {
            if shared.aborted.load(Ordering::Acquire) {
                shared.release_wire(inflight.len());
                stand_down(cfg, server, &shared, ctx.idx, conn, inflight.is_empty()).await;
                return; // user abort
            }
            // M11 stream mode: while a player is attached, run shallow
            // pipelines so a promoted seek article's BODY goes out within
            // ~one article of the promote, not after the whole window.
            let base_win = if shared.stream_active() {
                stream_window().min(cfg.window)
            } else {
                cfg.window
            };
            // M7b.2 depth steering and the TODO 208 item 3 endgame taper both
            // bound the TOP-UP only; the shed below keeps judging
            // against `base_win` (see steer_window / tail_window), so
            // neither can shed a pipeline or drop a connection.
            let win = shared
                .steer_window(ctx.idx, base_win)
                .min(shared.tail_window(base_win));
            // TODO 112 / §96.5: over the live target or over budget, stop
            // admitting work; once the pipeline drains, return the
            // connection and re-park (`shed_surplus`). A drain takes
            // precedence: a pause must finish what is in flight first.
            //
            // Where the connection GOES is `release_shed_conn` - the two
            // reasons `surplus_here` folds together get opposite answers,
            // and the measurement behind the split is on that function.
            let over_target = surplus_here(cfg, ctx.idx, &shared, &admit);
            if over_target
                && inflight.is_empty()
                && !shared.draining.load(Ordering::Acquire)
                && shed_surplus(cfg, ctx.idx, &shared, &mut admit)
            {
                shared.note_session_end(ctx.idx, 4);
                last_end = Some(4);
                release_shed_conn(cfg, server, &shared, ctx.idx, conn).await;
                continue 'session;
            }
            // A pipeline deeper than the live cap (stream mode engaged
            // mid-window) is abandoned outright: the sent BODYs can't be
            // unsent, but dropping the connection stops their responses
            // from serializing ahead of promoted work on this socket.
            // In-flight items requeue uncharged; the reconnect is cheap
            // next to the multi-second drain it replaces. Workers hit
            // this at their next response boundary, so the reconnects
            // stagger naturally. (Not during drain: a graceful pause
            // must complete - and journal - what's already in flight.)
            //
            // Measured and kept unconditional (chaos rig, Aug 2026): a
            // "keep the pipeline when it is entirely promoted work"
            // variant - the promote shed's immunity rule - protected a
            // degraded session's deep promoted pipeline too, and one
            // 40 KB/s connection then held its articles for 7.5 s each
            // while healthy conns sat idle: play start went 9.8 s ->
            // 31 s on the degraded-session scenario. The shed's own
            // cost is small (a dial round-trip plus the abandoned
            // in-flight bytes) and it is what hands a promoted run to
            // a FRESH session, which is exactly the recovery a sick
            // connection needs.
            if inflight.len() > base_win && !shared.draining.load(Ordering::Acquire) {
                shared.note_session_end(ctx.idx, 4);
                last_end = Some(4);
                shed_pipeline(&shared, &mut inflight).await;
                conn.quit().await;
                continue 'session;
            }
            // Top up the window - unless draining, when we admit nothing
            // new and just let the in-flight requests below complete.
            if let TopUp::Redial(cause) = top_up_window(
                &mut conn,
                cfg,
                ctx,
                &shared,
                &out,
                &mut inflight,
                win,
                over_target,
                session_bytes,
                session_responses,
            )
            .await
            {
                last_end = Some(cause);
                session_failures += 1;
                pending_backoff = Some(session_backoff_delay(cfg, session_failures));
                continue 'session;
            }
            if inflight.is_empty() {
                // THE reuse point. `inflight.is_empty()` is the whole
                // safety argument: no BODY is outstanding, so there are
                // no unread responses queued on this socket and the next
                // job can pick it up mid-conversation. Every other exit
                // from this loop abandons in-flight responses and closes.
                // TODO 313 item 7: this worker holds a live session
                // with nothing in flight - the connection the shipped
                // hedge can put on a stale article for free, and the
                // one whose ABSENCE is the surge dial's defining gate.
                // Held across the whole idle turn, guard-shaped because
                // `IdleTurn::Retire` leaves this function outright.
                let _idle = crate::pool::surge::IdleConn::hold(&shared);
                match idle_turn(cfg, server, ctx, &shared, conn, &mut quiet_since).await {
                    IdleTurn::Keep(c) => conn = c,
                    IdleTurn::Retire => return,
                    IdleTurn::Dead => {
                        // Nothing to requeue (in-flight is empty) and the
                        // end is already tallied; redial with the standard
                        // backoff so an idle-reaping provider is not dial
                        // stormed.
                        last_end = Some(0);
                        session_failures += 1;
                        pending_backoff = Some(session_backoff_delay(cfg, session_failures));
                        continue 'session;
                    }
                }
                continue;
            }
            quiet_since = Instant::now();
            if conn.flush().await.is_err() {
                // Write-side peer death, same as the failed send above.
                shared.note_session_end(ctx.idx, 0);
                last_end = Some(0);
                if session_bytes > 0 {
                    // Flap breaker: an ESTABLISHED session (it served bytes)
                    // died - count it where it happens, not at some later
                    // redial this worker may never win (a capped provider
                    // bounces most re-entries, which hid the churn entirely).
                    shared.note_flap(ctx.idx);
                }
                requeue_or_fail(
                    &shared,
                    &out,
                    cfg,
                    ctx,
                    &mut inflight,
                    FailCode::Transport,
                    "flush failed",
                    session_responses == 0,
                )
                .await;
                session_failures += 1;
                pending_backoff = Some(session_backoff_delay(cfg, session_failures));
                continue 'session;
            }

            let mut buf = crate::pool::PooledBuf::from_pool(cfg.buf_pool.as_deref());
            // TODO 96.4: which command the answer below belongs to. A
            // 223 and a 222 are both `Ok(Ok(true))`, and only this says
            // which one arrived.
            let probe_front = inflight.front().is_some_and(|w| w.probe);
            let step = read_one(
                &mut conn,
                &mut buf,
                cfg,
                ctx,
                &shared,
                &inflight,
                &mut finished,
                &mut promote_gen,
                &mut fence_read_seen,
            )
            .await;
            let Some(read) = step.read else {
                drop(buf); // back to the pool here, before the awaits below
                if step.shed_for_promote {
                    shared.note_session_end(ctx.idx, 4);
                    last_end = Some(4);
                    shed_pipeline(&shared, &mut inflight).await;
                    conn.quit().await; // internally bounded
                    continue 'session;
                }
                shared.release_wire(inflight.len());
                if !step.mute_suspect {
                    conn.quit().await; // internally bounded
                }
                return;
            };
            // Useful work: a well-formed BODY response (222, or an
            // authoritative 430/423 - both mean the session is healthy and
            // talking NNTP). THIS is what clears the session backoff, not
            // the connect: a connection that has served for hours and then
            // hits one transient error must not be paced as if it were a
            // broken account, and a session that can only ever fail must
            // not clear its counter just by connecting again.
            if matches!(&read, Ok(Ok(_))) {
                session_failures = 0;
                session_responses += 1;
                // §129 3g: this response carried a message-id we could
                // check against the article we asked for, so the socket
                // was aligned HERE - and a response desync is monotone
                // (every read after a dropped response answers the slot
                // behind), so every refusal this session handed out
                // earlier came off an aligned socket too. None of them is
                // suspect any more. What accumulates after this point
                // is exactly the window a later proof of desync voids.
                if step.id_echoed {
                    bare_refused.clear();
                }
            }
            match read {
                Ok(Ok(true)) if probe_front => {
                    handle_probe_hit(ctx, &shared, &mut inflight, buf);
                }
                Ok(Ok(true)) => {
                    match handle_body(
                        cfg,
                        ctx,
                        &shared,
                        &out,
                        &mut inflight,
                        buf,
                        &mut race_losses,
                        &mut session_bytes,
                        session_start,
                    )
                    .await
                    {
                        BodyStep::Proceed => {}
                        BodyStep::Recycle => {
                            // Deliberate hangup (slow-session recycle):
                            // ours, and the census must say so.
                            shared.note_session_end(ctx.idx, 4);
                            last_end = Some(4);
                            conn.quit().await; // internally bounded
                            continue 'session;
                        }
                    }
                }
                Ok(Ok(false)) => {
                    handle_missing(
                        cfg,
                        ctx,
                        &shared,
                        &out,
                        &mut inflight,
                        buf,
                        step.id_echoed,
                        step.takedown,
                        &mut bare_refused,
                    )
                    .await;
                }
                Ok(Err(e)) => {
                    last_end = Some(
                        session_died_mid_read(
                            cfg,
                            ctx,
                            &shared,
                            &out,
                            conn,
                            &mut inflight,
                            buf,
                            &e,
                            &bare_refused,
                            session_bytes,
                            session_responses,
                        )
                        .await,
                    );
                    session_failures += 1;
                    pending_backoff = Some(session_backoff_delay(cfg, session_failures));
                    continue 'session;
                }
                Err(_) => {
                    last_end = Some(
                        session_stalled_mid_read(
                            cfg,
                            ctx,
                            &shared,
                            &out,
                            &mut inflight,
                            buf,
                            step.prebyte_expired,
                            &bare_refused,
                            session_bytes,
                        )
                        .await,
                    );
                    // A8: the stall arm arms the same backoff as the
                    // protocol-death arm above. The expiry itself paces
                    // one attempt (the budget had to run out first),
                    // but it never grew: a server that accepts
                    // TCP+TLS+AUTH and then goes mute produced an
                    // unbounded dial-and-expire loop at the TTFB floor
                    // for the whole run - exactly the traffic shape
                    // `session_backoff_delay` documents providers
                    // banning for. The useful-work reset plus the
                    // immediate first retry keep a transient stall on
                    // a serving session at zero extra delay, and a
                    // can-only-stall server now also bows out at
                    // MAX_SESSION_ATTEMPTS like any other broken one.
                    session_failures += 1;
                    pending_backoff = Some(session_backoff_delay(cfg, session_failures));
                    continue 'session;
                }
            }
        }
    }
}
