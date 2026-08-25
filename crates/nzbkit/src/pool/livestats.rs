//! What the pool tells the outside world while it runs: the per-server
//! gauges the dashboard reads, the timestamped event ring a throughput
//! dip is attributed from, and the two refusal records that say why a
//! provider is contributing nothing.
//!
//! Moved out of pool.rs whole (TODO 106 size-gate split) because it is
//! one subject and none of it is on the fetch path - workers only ever
//! write to it. Re-exported from `pool`, so every `pool::LiveStats` /
//! `pool::ServerLive` / `pool::now_ms` spelling is unchanged.

use super::*;

/// Live per-server gauges, updated by workers with relaxed atomics and
/// readable at any moment (the dashboard's connection-pool view).
pub struct LiveStats {
    pub servers: Vec<ServerLive>,
    /// A capped ring of timestamped pool events, so a throughput dip can
    /// be ATTRIBUTED after the fact instead of guessed at.
    ///
    /// The gauges above are levels: they say what is true now, and a
    /// counter that has been climbing all run cannot tell you that
    /// something happened at 22:59. A dip is an event at a moment, and
    /// until this existed the daemon recorded no moments at all - the
    /// pool counted reconnects into a `PoolStats` field that only the
    /// CLI ever read, and the capacity warning fired `if first`, so the
    /// second and third bounce of a run were silent by construction.
    /// One real dip on a 59 GB job had NOTHING anywhere to explain it.
    ///
    /// Capped and timestamped rather than logged: the log is the wrong
    /// shape (a flapping provider floods it, and nothing aligns it with
    /// the graph), while a bounded ring the UI can overlay on the
    /// throughput trace answers the only question worth asking - what
    /// else was happening at the moment the line fell over.
    pub events: std::sync::Mutex<std::collections::VecDeque<PoolEvent>>,
    /// Run-level racing gauges (M7b.2): dup spend and the hygiene-cap
    /// state, for `report_diagnostics`' consumers and the "Why is this
    /// slow?" panel. See `steer::RaceLive`.
    pub race: steer::RaceLive,
}

/// One thing that happened to the pool, at a moment.
#[derive(Debug, Clone)]
pub struct PoolEvent {
    /// Unix milliseconds. The dashboard's throughput samples carry their
    /// own wall-clock, so this is what lets the two be laid on top of
    /// each other; a monotonic instant could not cross the API.
    pub at_ms: u64,
    pub host: String,
    /// `reconnect` | `rotate` | `cap` | `blocked` | `retired` |
    /// `block` | `missing` | `racing` | `timeout` | `tail` | `drained` - see
    /// [`LiveStats::note`]. The dashboard groups these into severity
    /// classes (fault / tuning / recovery / phase), so a new kind must
    /// be added to its map or it draws in the fallback colour.
    ///
    /// `rotate` vs `reconnect` is the load-bearing split: a session WE
    /// ended on purpose (pre-byte budget, live-target park, promote
    /// shed, slow-session recycle) is the tuner doing its job, and
    /// painting it as a fault taught a flawless 3.3 Gbps run to read
    /// as a failing-connections incident (38 red dots, 7 Aug 2026).
    pub kind: &'static str,
    /// Free text for the user, already specific: the provider's own
    /// refusal line, or the reason a session ended.
    pub detail: String,
}

/// How many events are kept. At the rate a healthy run generates them
/// this is hours; at the rate a sick one does it is the last few
/// minutes, which is exactly the window someone stares at a dip in.
/// Public because a caller that filters by TIME has to ask for the
/// whole ring: `recent_events` takes a COUNT, so any smaller number
/// drops the oldest events in the window before the time filter ever
/// sees them.
pub const EVENT_RING: usize = 256;

/// How long a worker must wait on the write side before it is worth
/// marking. A full channel is the pipeline working as designed - bodies
/// arrive faster than they decode all the time - so the threshold is set
/// where a pause stops being normal and starts being something a person
/// would notice in the graph.
pub(super) const BLOCKED_NOTE_MS: u64 = 500;

/// Windowed burst notes (missing-article bursts, duplicate racing): at
/// most one marker per server (or per run, for racing) per window,
/// emitted when a window closes with at least the threshold inside it.
/// A marker can land up to one window after the burst began, which is
/// invisible at chart scale - what matters is that a storm of 430s or
/// dups can never flood the ring the way one event per response would,
/// exactly the discipline `BLOCKED_NOTE_MS` set.
pub(super) const BURST_WINDOW_MS: u64 = 10_000;

/// 430/423 responses from one server inside one window that earn a
/// missing-articles marker. Scattered misses are normal (that is what
/// the retry ladder is for); a burst this size is a take-down or a
/// backfill hole and it bends the graph.
pub(super) const MISSING_BURST: u64 = 25;

/// Duplicate + hedge dispatches inside one window that mark a racing
/// spike. The tail of every job issues a handful; a sustained spike
/// means the pool is fighting slow articles hard enough to show.
pub(super) const RACE_BURST: u64 = 12;

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// `Default` so the field list lives in exactly one place: this struct
/// has grown past twenty gauges and every test rig that built one by
/// literal had to be edited whenever an unrelated counter was added.
#[derive(Default)]
pub struct ServerLive {
    pub host: String,
    /// Connection budget: the number of workers the run intends to use
    /// on this server. Atomic because the live tuner (TODO 112) moves
    /// its [`ConnTarget`] mid-run and this gauge must follow; without a
    /// tuner it holds the spawn count for the whole run.
    pub budget: AtomicUsize,
    /// Workers currently holding an open NNTP session.
    pub connected: AtomicUsize,
    /// Raw bytes fetched by this server this run.
    pub bytes: AtomicU64,
    /// Article dispatches sent to this server this run (reliability
    /// denominator - dups and retries each count as a try).
    pub articles_tried: AtomicU64,
    /// 430/423 "no such article" responses from this server this run
    /// (reliability numerator: completion = 1 - missing/tried).
    pub articles_missing: AtomicU64,
    /// §35: the provider's own words when it refused to authenticate,
    /// and whether that refusal is permanent.
    ///
    /// Without this a user with one expired or capped provider pays for
    /// it on every download - the server contributes nothing - and has
    /// nothing anywhere in the UI saying why. The pool already knows;
    /// this carries it out to the dashboard verbatim, because the
    /// provider's own sentence ("max simultaneous IP addresses reached")
    /// tells the user what to do and our paraphrase would not.
    pub refusal: std::sync::Mutex<Option<Refusal>>,
    /// Sessions this server lost and redialled MID-RUN (the first
    /// connect is not one). The pool has always counted these into
    /// `PoolStats::reconnects`, but only the one-shot CLI ever read that
    /// - on the daemon path a worker whose socket died and came back was
    /// invisible, which is the single most likely cause of a dip that
    /// leaves the job itself undamaged.
    pub reconnects: AtomicU64,
    /// Milliseconds this server's workers spent parked because the
    /// fetch→decode channel was FULL - i.e. waiting on everything
    /// downstream (decode, verify, the disk), not on the network.
    ///
    /// This is the half that makes a dip diagnosable rather than merely
    /// visible. Both causes look identical on the throughput graph, and
    /// they have opposite remedies: if the line fell while this was
    /// climbing, the network was fine and the write side could not keep
    /// up (an external enclosure hiccuping, a slow volume); if it fell
    /// while `reconnects` moved instead, it was the provider. Measuring
    /// only one of them would have let every dip be blamed on the one we
    /// happened to instrument.
    pub blocked_ms: AtomicU64,
    /// Unix ms of the last `blocked` event noted for this server, so a
    /// genuinely stalled disk marks the graph once a second instead of
    /// once per article. Without it a bad enough stall would flush the
    /// whole ring with its own events and erase the reconnects sitting
    /// beside them - the instrumentation would destroy the comparison it
    /// exists to make.
    pub(crate) last_blocked_note: AtomicU64,
    /// Missing-article burst window: when the current window opened
    /// (unix ms, 0 = not yet opened) and what `articles_missing` read at
    /// that moment. See [`LiveStats::note_missing_burst`].
    pub(crate) missing_note_at: AtomicU64,
    pub(crate) missing_at_note: AtomicU64,
    /// Unix ms of the last adaptive-timeout marker, same once-a-second
    /// discipline as `last_blocked_note` - a provider gone slow expires
    /// budgets on every worker at once.
    pub(crate) last_timeout_note: AtomicU64,
    /// Session-end causes; see [`SessionEnds`]. Same counters the CLI
    /// census prints, kept live for the dashboard.
    pub(crate) ends_peer: AtomicU64,
    pub(crate) ends_protocol: AtomicU64,
    pub(crate) ends_prebyte: AtomicU64,
    pub(crate) ends_stall: AtomicU64,
    pub(crate) ends_ours: AtomicU64,
    /// M7b.2 PUBLISHED CONTRACT for the live connection tuner (steering
    /// design §4.3; full semantics in the pool `steer` module doc):
    /// windowed delivered rate in B/s as of the last fold (~10 s
    /// half-life, 0 until the first body - read against `srv_rate_at`,
    /// the unix-ms fold stamp), the per-server dispatch-to-done EWMA,
    /// and the `steered` demand bit (true while depth-clamped or
    /// frontier-passed: a rate drop with it set is our own steering,
    /// not a provider knee). Demand-inclusive, fed only from real
    /// delivered bodies - do not rename or filter.
    pub(crate) srv_rate: AtomicU64,
    pub(crate) srv_rate_at: AtomicU64,
    /// `pub`, unlike its two neighbours: the daemon's "Why is this
    /// slow?" payload publishes it per provider (`whyslow.rs`), so it
    /// crosses the crate boundary. It stayed crate-private for as long
    /// as it had no reader at all.
    pub srv_art_ms: AtomicU64,
    pub steered: AtomicBool,
    /// Unix ms when this server LAST stopped granting sessions, 0 while
    /// it holds one. Set by the first dial that fails or is refused,
    /// cleared by the first that succeeds, so it reads as "down since".
    ///
    /// `connected == 0` already says a server has nothing open right
    /// now, and it says it about a worker mid-redial too - a level with
    /// no duration and no cause. This is the pair that makes an outage
    /// REPORTABLE while the job is still running: the moment it began,
    /// and (with `down_reason`) whose fault it is. Without it the only
    /// place that ever named a wholly-dead provider was the diagnostics
    /// block of a job that FINISHED, which is exactly the block a job
    /// wedged on that provider never reaches (soak, 12 Aug 2026).
    pub down_since: AtomicU64,
    /// Why, in the provider's or the OS's own words. See [`DownReason`].
    pub down_reason: std::sync::Mutex<Option<DownReason>>,
    /// The most sessions this provider was serving US at the instant it
    /// refused another one - the connection ceiling it actually grants,
    /// as opposed to the one the account is sold with. 0 = it has never
    /// refused us, so the ceiling is unobserved and unknown.
    ///
    /// Giganews granted 38 against a Diamond account provisioned for
    /// 100 for a full day (18 Aug 2026) and the only place that number
    /// existed was daemon.log: the dashboard row read "using 0 of 100",
    /// which is the configured count and the live count and neither of
    /// the two numbers the user needed. Sampled ONLY on a
    /// CAPACITY-classified auth refusal ([`crate::nntp::AuthRefusal`]),
    /// never inferred from `connected < budget` - every idle provider
    /// satisfies that, and painting idle as refused is the 38-red-dots
    /// mistake of 7 Aug in a different costume.
    ///
    /// High-water across bounces, for the same reason
    /// [`Shared::flap_cap_seen`] takes one: a bounce can land while the
    /// server still holds ghosts of sessions it just dropped, which
    /// UNDER-counts the true ceiling; it can never land while the
    /// server is serving MORE than the ceiling.
    pub granted_hi: AtomicUsize,
    /// What we were ASKING for at the moment of the refusal - `budget`
    /// sampled there, high-water across bounces.
    ///
    /// Not the live `budget`, and that is the whole point of storing
    /// it: the pool's response to a cap is to yield slots, so by the
    /// time anyone reads the row the live budget has fallen toward the
    /// granted count and "asked 38, granted 38" would say nothing. This
    /// is the number that was refused.
    pub capped_at: AtomicUsize,
    /// Unix ms of the FIRST capacity refusal from this server this run;
    /// 0 while it has never capped us. The gate for the whole display:
    /// a row says nothing about caps until a real refusal has been
    /// heard from that host.
    pub capped_since: AtomicU64,
}

/// Why a server is granting no sessions right now.
#[derive(Debug, Clone)]
pub struct DownReason {
    /// `unreachable` (the dial itself failed - DNS, refused, TLS,
    /// timeout), `refused` (it rejected the account for good) or
    /// `capacity` (it is at a connection or IP cap and may clear).
    /// A stable token, not prose: the dashboard maps it to a phrase in
    /// the user's language and the detail below carries the words.
    pub kind: &'static str,
    /// The failing server's own sentence, verbatim.
    pub detail: String,
}

impl ServerLive {
    /// First failed dial of an outage wins the clock; later ones only
    /// refresh the reason. Idempotent per episode, so the whole fleet
    /// bouncing off one cap still reports one start time.
    pub fn note_down(&self, kind: &'static str, detail: impl Into<String>) {
        let _ = self
            .down_since
            .compare_exchange(0, now_ms(), Ordering::Relaxed, Ordering::Relaxed);
        if let Ok(mut r) = self.down_reason.lock() {
            *r = Some(DownReason {
                kind,
                detail: detail.into(),
            });
        }
    }

    /// A session was granted: the episode is over.
    pub fn note_up(&self) {
        self.down_since.store(0, Ordering::Relaxed);
        if let Ok(mut r) = self.down_reason.lock() {
            *r = None;
        }
    }

    /// A capacity refusal just bounced a dial: record the ceiling this
    /// provider is actually willing to serve, and the ask it refused.
    ///
    /// `held` is the sessions we were holding at that instant (from
    /// [`Shared::note_cap_bounce`], which prices the same bounce for
    /// the flap clamp). Both counters are high-water and the stamp is
    /// first-write-wins, so the whole fleet bouncing off one cap
    /// reports one episode with one ceiling rather than a race.
    pub fn note_cap(&self, held: usize) {
        self.granted_hi.fetch_max(held, Ordering::AcqRel);
        self.capped_at
            .fetch_max(self.budget.load(Ordering::Relaxed), Ordering::AcqRel);
        let _ =
            self.capped_since
                .compare_exchange(0, now_ms(), Ordering::Relaxed, Ordering::Relaxed);
    }

    /// A live fleet just held `now` sessions. If that is above a cap we
    /// recorded earlier, the cap is disproven and is retired.
    ///
    /// Only ever called with a count we actually achieved, so it cannot
    /// fire for a provider that is merely idle below its ceiling.
    pub fn retire_cap_if_exceeded(&self, now: usize) {
        if self.capped_at.load(Ordering::Acquire) == 0 {
            return;
        }
        if now <= self.granted_hi.load(Ordering::Acquire) {
            return;
        }
        self.granted_hi.store(now, Ordering::Release);
        self.capped_at.store(0, Ordering::Release);
        self.capped_since.store(0, Ordering::Release);
    }

    /// How long this server has been granting nothing, in seconds, or
    /// `None` while it is up. Reading the level and the stamp together
    /// here keeps every consumer's rule the same.
    pub fn down_secs(&self) -> Option<u64> {
        let at = self.down_since.load(Ordering::Relaxed);
        (at > 0).then(|| now_ms().saturating_sub(at) / 1000)
    }
}

/// A server's refusal to authenticate, as shown to the user.
#[derive(Debug, Clone)]
pub struct Refusal {
    /// True when retrying cannot help (bad credential), false when the
    /// server is simply at a connection or IP cap right now.
    pub permanent: bool,
    /// A capacity refusal about WHERE the account is used from, not how
    /// many sockets it grants. "Lower your connection count" is not the
    /// remedy for it, and the sessions held when it arrived are not a
    /// ceiling (Codex sweep 5, M9).
    pub source_ips: bool,
    /// The server's status line, verbatim.
    pub line: String,
}

impl LiveStats {
    pub fn for_servers(servers: &[(ServerConfig, PoolConfig)]) -> Arc<LiveStats> {
        Arc::new(LiveStats {
            servers: servers
                .iter()
                .map(|(s, cfg)| ServerLive {
                    host: s.host.clone(),
                    // With a live target in force the number in use is
                    // the target, not the spawn count - slots above it
                    // park immediately. `PoolConfig::dialled` is that
                    // rule; it was inlined here first and is now shared
                    // with the launch banner, which needs the same
                    // number for the same reason.
                    budget: AtomicUsize::new(cfg.dialled()),
                    connected: AtomicUsize::new(0),
                    refusal: std::sync::Mutex::new(None),
                    bytes: AtomicU64::new(0),
                    articles_tried: AtomicU64::new(0),
                    articles_missing: AtomicU64::new(0),
                    reconnects: AtomicU64::new(0),
                    ends_peer: AtomicU64::new(0),
                    ends_protocol: AtomicU64::new(0),
                    ends_prebyte: AtomicU64::new(0),
                    ends_stall: AtomicU64::new(0),
                    ends_ours: AtomicU64::new(0),
                    blocked_ms: AtomicU64::new(0),
                    last_blocked_note: AtomicU64::new(0),
                    missing_note_at: AtomicU64::new(0),
                    missing_at_note: AtomicU64::new(0),
                    last_timeout_note: AtomicU64::new(0),
                    srv_rate: AtomicU64::new(0),
                    srv_rate_at: AtomicU64::new(0),
                    srv_art_ms: AtomicU64::new(0),
                    steered: AtomicBool::new(false),
                    down_since: AtomicU64::new(0),
                    down_reason: std::sync::Mutex::new(None),
                    granted_hi: AtomicUsize::new(0),
                    capped_at: AtomicUsize::new(0),
                    capped_since: AtomicU64::new(0),
                })
                .collect(),
            events: std::sync::Mutex::new(std::collections::VecDeque::new()),
            race: Default::default(),
        })
    }

    /// Record one event against a server, oldest dropped at the cap.
    ///
    /// Deliberately infallible and deliberately quiet: instrumentation
    /// that can fail, block, or log is instrumentation that changes the
    /// thing it measures. A poisoned ring is not worth a panic in a
    /// download worker, so it is simply skipped.
    pub fn note(&self, idx: usize, kind: &'static str, detail: impl Into<String>) {
        let Some(host) = self.servers.get(idx).map(|s| s.host.clone()) else {
            return;
        };
        let Ok(mut ring) = self.events.lock() else {
            return;
        };
        if ring.len() >= EVENT_RING {
            ring.pop_front();
        }
        ring.push_back(PoolEvent {
            at_ms: now_ms(),
            host,
            kind,
            detail: detail.into(),
        });
    }

    /// Record an event that belongs to the RUN, not to one server -
    /// phase boundaries (queue dry, drained) and fleet-wide spikes
    /// (duplicate racing). Same ring, empty host; the dashboard shows
    /// these without a server name.
    pub fn note_run(&self, kind: &'static str, detail: impl Into<String>) {
        let Ok(mut ring) = self.events.lock() else {
            return;
        };
        if ring.len() >= EVENT_RING {
            ring.pop_front();
        }
        ring.push_back(PoolEvent {
            at_ms: now_ms(),
            host: String::new(),
            kind,
            detail: detail.into(),
        });
    }

    /// Called on every 430/423 this server answers, AFTER
    /// `articles_missing` was bumped. Emits at most one `missing` marker
    /// per [`BURST_WINDOW_MS`] per server, and only for a window that
    /// held at least [`MISSING_BURST`] misses - scattered misses are the
    /// retry ladder's normal diet and must not mark the graph.
    pub fn note_missing_burst(&self, idx: usize) {
        let Some(s) = self.servers.get(idx) else {
            return;
        };
        let now = now_ms();
        let count = s.articles_missing.load(Ordering::Relaxed);
        let opened = s.missing_note_at.load(Ordering::Relaxed);
        if opened == 0 {
            // First miss of the run opens the first window, no marker.
            if s.missing_note_at
                .compare_exchange(0, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                s.missing_at_note
                    .store(count.saturating_sub(1), Ordering::Relaxed);
            }
            return;
        }
        if now.saturating_sub(opened) < BURST_WINDOW_MS {
            return;
        }
        // Window closed; one racer re-anchors it and judges the burst.
        if s.missing_note_at
            .compare_exchange(opened, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let since = count.saturating_sub(s.missing_at_note.swap(count, Ordering::Relaxed));
        if since >= MISSING_BURST {
            self.note(
                idx,
                "missing",
                format!(
                    "{since} articles missing from this server in the last \
                     {} seconds",
                    BURST_WINDOW_MS / 1000
                ),
            );
        }
    }

    /// Events newest first, for the API.
    pub fn recent_events(&self, limit: usize) -> Vec<PoolEvent> {
        self.events
            .lock()
            .map(|r| r.iter().rev().take(limit).cloned().collect())
            .unwrap_or_default()
    }
}
