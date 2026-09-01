//! Managed connection pool with pipelining (design: Phase 2b).
//!
//! Design inputs, all paid for empirically:
//! - Pipelining wins +170% on fibre - keep `window` commands in flight.
//! - Providers punish connect bursts → connections spawn with a ramp delay
//!   and are REUSED for the whole run, never churned.
//! - Providers stall reads mid-article under load → per-response timeout;
//!   a stalled/dead connection requeues its in-flight articles and the
//!   worker reconnects with backoff.
//! - Sessions linger server-side after abrupt closes → always QUIT.
//! - Retry taxonomy from the NNTP response codes: transport failures retry (bounded); a 430
//!   "no such article" is authoritative for this server - no retry.

use crate::sync::MutexExt;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

use tokio::sync::{Mutex, mpsc};

use crate::config::ServerConfig;
use crate::fail::FailCode;
use crate::nntp::Connection;

/// Live per-server connection target (TODO 112): how many of a server's
/// spawned workers may hold a session RIGHT NOW.
///
/// The fleet is still built at `PoolConfig::connections` - that number
/// is the ceiling, the account fact the user typed - but every worker
/// knows its slot ordinal and parks, holding no connection, while its
/// ordinal sits at or above this target. An outside controller (the
/// live tuner) can therefore move the number in use up and down mid-run
/// without the pool respawning anything: lowering the target drains the
/// highest slots at their next response boundary; raising it wakes
/// them. Nothing here ever writes a settings value - the target is
/// state, not configuration.
///
/// Distinct from the capacity yield (481/502), which is the PROVIDER
/// shrinking the fleet and is one-way for the run: a yielded worker has
/// returned and cannot be woken. This is the controller's dial, and it
/// moves both directions.
#[derive(Debug)]
pub struct ConnTarget {
    tx: tokio::sync::watch::Sender<usize>,
}

impl ConnTarget {
    pub fn new(target: usize) -> Arc<Self> {
        Arc::new(Self {
            tx: tokio::sync::watch::channel(target.max(1)).0,
        })
    }

    pub fn get(&self) -> usize {
        *self.tx.borrow()
    }

    /// Move the live target. Clamped to at least one connection: a
    /// target of 0 would park the whole fleet with the queue still
    /// pending, which is the `connections: 0` hang this file already
    /// refuses at spawn. Slots above the spawned fleet size are simply
    /// not there to wake, so the fleet size is the natural ceiling.
    /// That ceiling is why a fleet meant to GROW must be spawned wide
    /// and parked (TODO 277): a `set` above the spawn count returns
    /// exactly as one below it does and nothing dials, so `get::fleet`
    /// spawns the line-cap curve's CEILING and parks the surplus.
    pub fn set(&self, target: usize) {
        self.tx.send_if_modified(|t| {
            let n = target.max(1);
            if *t == n {
                false
            } else {
                *t = n;
                true
            }
        });
    }

    /// Read-decide-write in ONE step: `f` sees the current target and
    /// returns the new one (or None to leave it), and runs under the
    /// channel's write lock so no concurrent `set` can slip between
    /// the read and the write (F-24). Floored at 1 exactly like `set`.
    /// Returns whether the target moved.
    pub fn update(&self, f: impl FnOnce(usize) -> Option<usize>) -> bool {
        self.tx.send_if_modified(|t| match f(*t) {
            Some(n) if n.max(1) != *t => {
                *t = n.max(1);
                true
            }
            _ => false,
        })
    }

    fn subscribe(&self) -> tokio::sync::watch::Receiver<usize> {
        self.tx.subscribe()
    }
}

// Every knob the pool has, its neutral default and the shipped profile
// are a child module (TODO 106 size-gate split): 543 lines of pure
// configuration with no behaviour in them. The re-export keeps
// `pool::PoolConfig` spelled exactly as it always was.
mod config;
pub use config::PoolConfig;

/// Decrements the connected gauge when a session ends, however it ends.
struct ConnGauge {
    live: Option<Arc<LiveStats>>,
    idx: usize,
}

impl ConnGauge {
    fn up(live: &Option<Arc<LiveStats>>, idx: usize) -> ConnGauge {
        if let Some(l) = live {
            let now = l.servers[idx].connected.fetch_add(1, Ordering::Relaxed) + 1;
            // Holding MORE sessions than a recorded ceiling is direct
            // proof that ceiling is no longer one. Session memory is
            // meant to outlive a job so the next one does not spend its
            // first seconds rediscovering a cap - but nothing retired it
            // on contradiction, so after a plan upgrade a row could read
            // "using 100 of 38" and still claim "capped at 38" until the
            // daemon restarted (Codex sweep 5, L6). Deliberately keyed
            // on connections we actually GOT: an idle provider sitting
            // below its cap says nothing either way.
            l.servers[idx].retire_cap_if_exceeded(now);
            // High-water mark of the same number, which is what the
            // word GRANTED means to every caller that reads it (see
            // `ServerLive::connected_peak`). Recorded HERE, at the one
            // place the concurrency can rise, so the answer is exact:
            // `sysbench` used to approximate it with a 100 ms sampler,
            // which cannot see a fleet that does not outlive a tick.
            // One `fetch_max` per SESSION ESTABLISHMENT - not per
            // article - on the cache line the `fetch_add` above just
            // touched.
            l.servers[idx]
                .connected_peak
                .fetch_max(now, std::sync::atomic::Ordering::AcqRel);
        }
        ConnGauge {
            live: live.clone(),
            idx,
        }
    }
}

impl Drop for ConnGauge {
    fn drop(&mut self) {
        if let Some(l) = &self.live {
            l.servers[self.idx]
                .connected
                .fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Counts an established session in `Shared::sessions` for exactly as
/// long as the worker holds it, however the session ends. The count
/// exists so a capacity bounce can be priced in sessions actually held
/// (see [`Shared::note_cap_bounce`]) - the dashboard gauge above can't
/// serve that role because `cfg.live` is optional.
struct SessionTally<'a> {
    shared: &'a Shared,
    idx: usize,
}

impl<'a> SessionTally<'a> {
    fn up(shared: &'a Shared, idx: usize) -> Self {
        shared.sessions[idx].fetch_add(1, Ordering::AcqRel);
        SessionTally { shared, idx }
    }
}

impl Drop for SessionTally<'_> {
    fn drop(&mut self) {
        // `ConnDark`'s clock is stamped HERE and at no other site, which
        // is a decision rather than an omission: a matching stamp as the
        // session STARTS is dead weight, because `Shared::serving_at`
        // reads the live count first and a held session already answers
        // it - so the start stamp is a second guard that makes both
        // unfalsifiable, and it survived a mutation that deleted it.
        //
        // BEFORE the count drops, though, and that order is load-
        // bearing: `serving_at` reads the count and then the deadline,
        // so a reader landing between the two would otherwise see a
        // server with no session and a deadline older than the session
        // it just finished holding.
        self.shared
            .conn_dark
            .note_session(self.idx, self.shared.run_ms());
        self.shared.sessions[self.idx].fetch_sub(1, Ordering::AcqRel);
    }
}

/// One article to fetch, with the routing metadata the pool needs up
/// front. `age_days` drives per-server retention exclusion (M14e):
/// a server with `retention_days: N` never sees requests for articles
/// older than N days.
#[derive(Debug, Clone)]
pub struct ArticleReq {
    /// R9: the bracketed message-id, interned. The queue item, the
    /// in-flight and steer maps and the outcome all share THIS
    /// allocation, so an id is heap-copied once per run instead of the
    /// six to nine times it used to be. `Arc<str>` rather than an arena
    /// index because ids escape the run (see [`FetchOutcome`]), and
    /// `HashMap<Arc<str>, _>` still answers `&str` lookups through
    /// `Borrow`, so borrow-only readers kept their signatures.
    pub id: Arc<str>,
    /// Article age in days (from the NZB `<file date>`); 0 = fresh/unknown.
    pub age_days: u32,
    /// Expected yEnc part number (the NZB `<segment number>`); 0 =
    /// unknown. Only the CRC-retry gate reads it: a body whose decoded
    /// part disagrees with the segment it was requested for is a valid
    /// article for the WRONG id (split-brain server) - its own pcrc32
    /// passes, so identity is the only check that can catch it.
    pub part: u32,
    /// The NZB file (slot index) this segment belongs to; `u32::MAX` =
    /// unscoped (a side fetch, a probe). Only the part-mismatch gate
    /// reads it: two backbones agreeing a file's numbering is
    /// synthesized stand THAT file's gate down alone (F-09), and the
    /// sentinel is not a file, so it can neither earn a stand-down nor
    /// inherit one. `pool::queue`'s `PartLatch` carries both whys.
    pub file: u32,
}

impl ArticleReq {
    /// A request with no age information - never retention-excluded.
    /// Takes anything an `Arc<str>` can be built from, so a caller that
    /// already holds an interned handle passes it by refcount bump and
    /// one that has just formatted a `String` pays the one copy here.
    pub fn fresh(id: impl Into<Arc<str>>) -> ArticleReq {
        ArticleReq {
            id: id.into(),
            age_days: 0,
            part: 0,
            file: u32::MAX,
        }
    }
}

/// Bitmask of servers whose retention window (`retention_days`, 0 =
/// unlimited) cannot cover an article `age_days` old. Seeded into a Work
/// item's `tried_430` at queue-build time so all downstream routing -
/// fill gates, dup dispatch, terminal-missing accounting - treats
/// "outside retention" exactly like "430'd here".
pub fn retention_mask(retention_days: &[u32], age_days: u32) -> u32 {
    let mut mask = 0u32;
    for (si, &days) in retention_days.iter().enumerate() {
        if days > 0 && age_days > days {
            mask |= server_bit(si);
        }
    }
    mask
}

/// Why the pool declared an article Missing. The distinction is what the
/// failure summary hangs its diagnosis on: `Retention` means WE never
/// asked anyone (a configured `retention_days` ruled every server out),
/// which is a settings problem, not a takedown - folding it into the
/// generic "missing segments" sent users hunting propagation ghosts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingCause {
    /// Every server that could have been asked WAS asked, and every one
    /// of them answered 430/423 - unanimous over the servers that had a
    /// working connection at some point in the run, not merely over
    /// whoever still had a worker at the moment the verdict was taken.
    /// `Shared::participation_mask` is the internal name of that set,
    /// and `MissingCause::Unasked` is what a verdict short of it says.
    ///
    /// `takedown`: at least one of those refusals said the article was
    /// REMOVED rather than not found ([`crate::nntp::takedown_flavoured`]
    /// - Giganews's 451, or refusal text naming a removal). A hint for
    /// the failure summary and the availability oracle, never part of
    /// the verdict: the unanimity contract is identical either way.
    Gone { takedown: bool },
    /// The article's age exceeds every configured server's
    /// `retention_days` - no server was ever asked.
    Retention,
    /// Every server that still had a worker refused it - but `dark`
    /// server(s) that had been serving this run went out before the
    /// article reached them, so the refusals are NOT unanimous over the
    /// servers that could have answered. It is terminal (nobody left can
    /// fetch it, and waiting rotates it forever) because OUR FLEET SHRANK,
    /// not because the post is gone. `FailCode::FleetExhausted` says that
    /// of a run which lost EVERY server; this is the partial case, worded
    /// alike on purpose.
    ///
    /// Read it the way [`crate::fail::FailCode`] asks its own readers to:
    /// a consumer that treats this as evidence ABOUT THE POST repeats the
    /// mistake. `takedown` carries the same hint `Gone` does and is still
    /// worth having - a refusal naming a removal said something about the
    /// post, whichever other server went dark.
    Unasked { takedown: bool, dark: u32 },
}

/// The decode consumer's per-article verdict, reported back through
/// [`QueueControl::note_decoded`] (TODO 114 consumer steer). The
/// consumer reports only what its own decode saw; the expected part
/// number stays in the pool (`Work::part`, via the stashed [`queue::Handed`]
/// copy), which does the split-brain identity comparison itself.
#[derive(Debug, Clone, Copy)]
pub enum DecodeReport<'a> {
    /// Decode succeeded; `part` is the body's declared yEnc part
    /// number (None when it declared none).
    Clean { part: Option<u32> },
    /// yEnc decode / pcrc32 failed.
    Bad { why: &'a str },
}

/// What [`QueueControl::note_decoded`] decided about a reported body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeAck {
    /// The consumer owns the outcome exactly as before this seam
    /// existed - process (or account) the body as usual.
    Owned,
    /// The pool took the article back and requeued it to a different
    /// server. Drop the body silently: no write, no counters, no
    /// slot bookkeeping - the refetched copy delivers the outcome.
    Steered,
}

/// Terminal outcome for one article.
#[derive(Debug)]
pub enum FetchOutcome {
    /// Raw dot-stuffed body, ready for `yenc::decode`.
    Done { id: Arc<str>, raw: Vec<u8> },
    /// No server can produce the article; `cause` says why.
    Missing { id: Arc<str>, cause: MissingCause },
    /// The pool gave up on the article without a body. `code` is the
    /// typed reason - not every one of them is a transport failure of
    /// the LINK, and a consumer that reads them all as evidence about
    /// the post repeats the mistake `FailCode`'s header describes.
    ///
    /// `error` is the same sentence it always was: the log, SAB-compat
    /// and `anyhow` surface, carrying the OS's own words in the OS's
    /// own language. The two travel together and neither replaces the
    /// other - TODO 307 item 1 added the code BESIDE the string
    /// precisely so no reader has to parse the string to learn which
    /// kind of failure it was.
    Failed {
        id: Arc<str>,
        code: FailCode,
        error: String,
    },
}

// TODO 106 size-gate split (28 Aug 2026): PoolStats and SessionEnds -
// the caller-visible per-server run statistics - live in
// pool/stats.rs; the re-export keeps every `pool::PoolStats` /
// `pool::SessionEnds` spelling unchanged.
mod stats;
pub use stats::{PoolStats, SessionEnds};

// TODO 106 size-gate split: the live gauges, the event ring and the
// refusal records - everything the pool REPORTS rather than does - came
// out whole to pool/livestats.rs. The glob re-export keeps every
// `pool::LiveStats` / `pool::ServerLive` / `pool::now_ms` spelling
// unchanged, and puts the private note thresholds back in scope for
// pool's other descendants exactly as they were.
mod bufpool;
pub use bufpool::{BufPool, PooledBuf};
mod livestats;
pub use livestats::*;

// M11 seek re-prioritization: QueueControl and its impl live in
// pool/queue.rs (TODO 106 size-gate split); the re-export keeps
// every `pool::QueueControl` spelling unchanged.
mod done_bits;
use done_bits::DoneBits;

mod queue;
pub use queue::{QueueControl, Walker};

/// §129 3g: bare refusals one session remembers having handed out, so a
/// later proof that the session was desynced can void the passes they
/// spent. A desync is proven within a few responses (the first misaligned
/// hit fails its echoed id), so this only ever has to hold the recent
/// tail - and on a wholly-dead post it would otherwise grow to the whole
/// job.
const BARE_LEDGER_MAX: usize = 512;
/// Ceiling on the pool-wide re-arm map ([`Shared::soft_rearm`]).
const SOFT_REARM_MAX: usize = 8192;
/// §129 3g: how many times one article's bare-refusal pass may be given
/// back. This is what makes the re-arm terminate: a server that stalls
/// or desyncs every session would otherwise hand every article its pass
/// back forever and no post would ever resolve as missing (measured -
/// the first cut of this fix hung the 1-in-5 leg outright).
///
/// It has to clear the DEMAND, not merely be finite. Each re-arm
/// answers one desync event that landed on that article, so what an
/// article needs is the number of faulty sessions that touch it - and
/// a cap under that is a false Missing waiting for the right run. A cap
/// of 3 looked fine until it was measured: the sweep's 1-in-7 leg ran
/// articles into it 16 times over three rounds, five of them articles
/// the server HELD, and a contended box turned one of those into
/// exactly the data loss this item is about. Measured demand peaks at
/// 10 at the worst rate the sweep asserts (1-in-5, where one response
/// in five is withheld), so 24 is headroom over the demand rather than
/// a number that sounded safe.
///
/// It costs nothing on a provider that is merely empty: no re-arm can
/// happen without a desync signature, so the ceiling for a
/// healthy-but-absent post is the two dispatches it always was.
const SOFT_REARM_CAP: u8 = 24;

/// Ceiling on the SAME-server re-asks of a corrupt body that a run may
/// waste, sized in articles.
///
/// [`QueueControl::note_decoded`]'s steer sends a corrupt body back to a
/// DIFFERENT server. Where the fleet has no eligible peer - which is
/// every single-server install, and any fleet whose only other server is
/// a fill tier or the same backbone - it re-asks the deliverer itself,
/// and this is what bounds that. A same-server re-ask is worth making
/// because the two commonest corruptions are not the same fault: a
/// damaged article in the spool answers the same bad bytes forever, and
/// a broken cache node behind a load balancer answers a FRACTION of
/// requests badly, so the second ask usually lands somewhere healthy.
///
/// It counts WASTE and not re-asks, which is the whole design. A unit is
/// spent when a same-server re-ask goes out and REFUNDED the moment that
/// article comes back with its CRC intact ([`Shared::settle_reask`]), so
/// the broken cache node above never runs out however long the job is,
/// and the damaged-spool article stops being asked after this many. A
/// flat per-run quota cannot be both large enough to rescue a real job
/// and small enough to refuse a corrupt storm; a waste quota is bounded
/// on the useless side ONLY.
///
/// A unit is charged while its re-ask is IN FLIGHT, so this also bounds
/// how many re-asks may be outstanding at one moment, and a burst of
/// concurrent corrupt bodies wider than the budget has some of them
/// refused. That is deliberate rather than a corner: a fleet holding
/// more than this many bad bodies at once IS the corrupt storm, and
/// refusing to keep paying is the direction to fail in. It does mean the
/// rescue rate under a burst depends on arrival order, which is why the
/// rig legs that assert EXACT counts run a serial pipeline (`lone_cfg`
/// in `integration::steer_rig`).
///
/// 32 articles is ~25 MB at this repo's ~800 KB working article, inside
/// the noise of any job large enough to carry a recovery set. Scaled
/// DOWN on small jobs (see [`Shared::new`]): a nine-article post must
/// not be able to pay 32 wasted fetches for nine articles of payload.
/// Both numbers are first cuts with that reasoning behind them and no
/// wire measurement under them; what IS measured is the mechanism, at
/// `pool::steer_seam_tests`.
const REASK_WASTE_CAP: usize = 32;

/// Divisor for the small-job scaling of [`REASK_WASTE_CAP`]: waste is
/// capped at an eighth of the run's articles, so the ceiling binds only
/// from 256 articles up and a short post pays proportionally.
const REASK_WASTE_DIV: usize = 8;

struct Work {
    /// The interned id from [`ArticleReq`] (R9), MOVED in at queue
    /// construction: a requeue, a hedge dup, a `handed` stash and the
    /// outcome all hold that same allocation.
    id: Arc<str>,
    attempts: u8,
    /// M11: promoted to the queue front by a streaming seek. Shed
    /// pipelines re-insert their abandoned items BEHIND the promoted run,
    /// never ahead of it.
    promoted: bool,
    /// Bitmask of servers that 430'd this article. An article is Missing
    /// only when every configured server has - different backbones have
    /// different retention/takedown profiles, so posts often complete from
    /// the union ("cross-server piecing").
    tried_430: u32,
    /// Bitmask of servers whose transport failed while this article was
    /// the charged one (front of a dead connection). Steering only, not
    /// authoritative: another live eligible server gets first claim on
    /// the retry; with none left the failing server may retry it itself
    /// (still bounded by `attempts`). Without this, a server that
    /// deterministically kills the article's connection can burn the
    /// whole retry budget before a healthy server ever sees the requeue.
    ///
    /// Since 31 Aug 2026 the CORRUPT-body seam reaches that same rule:
    /// `note_decoded` folds the deliverer's group in here and requeues
    /// even with no eligible peer, so `next_work` hands the article back
    /// to the server that damaged it. Two readers of one sentence now,
    /// which is why it is spelled out rather than left to the code -
    /// narrowing it would silently retire the peerless re-ask as well as
    /// the transport one. See [`REASK_WASTE_CAP`].
    tried_fail: u32,
    /// Tail duplicate: a second dispatch of an article already in flight
    /// on a slower server. First completion wins; a dup's own failures
    /// are silently discarded (the original still owns the outcome).
    dup: bool,
    /// TODO 121.1: attempts of THIS article that expired before a
    /// status byte arrived. Rides the requeue so the next attempt's
    /// pre-byte budget escalates per [`article_prebyte_budget`] -
    /// per-server training alone re-floors between retries.
    prebyte_expiries: u8,
    /// Server groups whose 430/423 arrived WITHOUT an echoed
    /// message-id. Positional attribution can misfile such a miss (a
    /// frontend that dropped the previous pipelined response leaves
    /// the next bare "430 no such article" landing on the wrong front
    /// article), so the first per group is suspect - requeued
    /// uncharged for one confirming retry - and only a repeat from
    /// the same group folds into `tried_430`. §129 3g: the bit is not
    /// permanent. A session that shows it was reading responses off by
    /// one voids the refusals it handed out ([`Shared::void_soft_430`]),
    /// which clears its bits here again.
    soft_430: u32,
    /// TODO 315: server groups whose LAST-EVIDENCE refusal this article
    /// has already spent its one late re-ask on - held at most once per
    /// group, which is what makes the pass terminate. A field of its
    /// own and NOT a second meaning for `soft_430`, which doubts a
    /// different thing; see [`Shared::take_recheck`] for both.
    recheck_430: u32,
    /// TODO 315: ms since [`Shared::start`] at which this article's late
    /// re-ask hold was taken; 0 when it has never held one. The only
    /// thing that can date a hold, and therefore the only thing that can
    /// end one - what that bought, and what it cost when nothing did, is
    /// at [`recheck::RECHECK_430_HOLD`]. A `u32` of milliseconds and not
    /// an `Instant`: it rides every queued `Work` (a big job queues
    /// ~100k), it fits the padding beside the four `u32` masks above,
    /// and 49 days of run time is not a bound anything here reaches.
    recheck_at: u32,
    /// §129 3g: this dispatch carried an alignment fence, so its
    /// response is followed by the fence's own and the reader must
    /// consume that too. Set at dispatch from the server's
    /// `bare_refuser` flag, which can arm mid-session - so it is per
    /// ITEM, not per session.
    fenced: bool,
    /// §129 3g: how many times this article's `soft_430` pass has been
    /// GIVEN BACK by [`Shared::void_soft_430`] - capped at
    /// [`SOFT_REARM_CAP`] so a provider that desyncs on every session
    /// cannot keep an article out of a terminal verdict for ever.
    rearms: u8,
    /// This dispatch is a VERDICT PROBE, not payload: the article has
    /// already been refused somewhere and this hop exists only to walk
    /// it toward (or away from) a unanimous Missing. Set per dispatch -
    /// a queued item earns it by carrying `tried_430`/`soft_430` bits,
    /// a ladder fan-out dup is born with it - and read by
    /// [`Pipeline::payload`], because the endgame gates that used to
    /// ask "is this worker idle" only ever meant "is a BODY holding
    /// this socket". A refusal is one small line, so a probe queued
    /// behind other probes costs nothing, and refusing to pipeline
    /// them capped verdict throughput at one article per connection
    /// per round trip - the measured zero-throughput stall before
    /// repair on a damaged post.
    ladder: bool,
    /// TODO 96.4: dispatch this as a STAT, not a BODY. Set only on
    /// ladder fan-out dups beyond the FIRST one for an article, and
    /// only under [`PoolConfig::stat_probe`]: the first racer may still
    /// deliver the article in one round trip, and every racer after it
    /// could only ever deliver a copy of what that one brings. A STAT
    /// answers the verdict question those racers exist to ask -
    /// identical refusal codes, so `handle_missing` cannot tell the
    /// difference - without buying an article to throw away.
    probe: bool,
    /// Article age in days from [`ArticleReq`]; 0 = fresh/unknown. Read
    /// by the M29 oracle when this item's outcome lands. Rides the Work
    /// (and [`Inflight`], for hedge dups born without a queued original)
    /// instead of a pool-wide id-keyed map - the map's ~110 B/entry was
    /// the A2 perf-audit cost, and a dup seeded from the inflight entry
    /// still charges the TRUE age, never a zero.
    age_days: u32,
    /// Expected yEnc part number from [`ArticleReq`]; 0 = undeclared.
    /// Read by the split-brain part-mismatch gate in
    /// [`QueueControl::note_decoded`] via the stashed [`queue::Handed`]
    /// copy - rebuilt from whatever Work DELIVERED, so dups must carry
    /// it too or a dup-delivered wrong-part body would sail through.
    part: u32,
    /// [`ArticleReq::file`], the part gate's stand-down scope (F-09).
    file: u32,
    /// C4: this article's completion ordinal - its accepted-request
    /// index at queue construction, the bit `Shared::done` arbitrates
    /// on. Rides the Work (and [`Inflight`], so both hedge dup
    /// constructors seed their fresh Work from the entry) exactly as
    /// `age_days`/`part` do: a dup-delivered body must claim the SAME
    /// bit as its original or one article could emit two outcomes.
    ord: u32,
}

/// What a worker currently has on the wire, split by kind. The two
/// numbers gate different things: speculation (racing an article
/// someone else may yet deliver) is spent only by a worker with
/// NOTHING outstanding, while a 430-ladder probe only has to keep
/// clear of payload - a body holds the socket for its whole transfer,
/// a refusal for one line.
#[derive(Clone, Copy, Default)]
struct Pipeline {
    /// Everything in flight on this connection.
    used: usize,
    /// Of those, the ones fetching a body we expect to arrive.
    payload: usize,
}

impl Pipeline {
    /// The pipeline a worker's in-flight deque describes.
    fn of(inflight: &VecDeque<Work>) -> Pipeline {
        Pipeline {
            used: inflight.len(),
            payload: inflight.iter().filter(|w| !w.ladder).count(),
        }
    }

    /// Test/callsite shorthand for a worker holding `n` payload bodies.
    #[cfg(test)]
    fn payload(n: usize) -> Pipeline {
        Pipeline {
            used: n,
            payload: n,
        }
    }

    /// Test shorthand for a worker holding `n` ladder probes and
    /// nothing else.
    #[cfg(test)]
    fn probes(n: usize) -> Pipeline {
        Pipeline {
            used: n,
            payload: 0,
        }
    }
}

/// One article currently being fetched by some worker.
struct Inflight {
    server: usize,
    dispatched: Instant,
    dups: u8,
    /// Servers that already 430'd this article - seeded from the Work
    /// item at dispatch, and UPDATED by duplicate dispatches' 430s
    /// (M2c.4): the entry is the authoritative union while the article
    /// is in flight, so the endgame fan-out can reach a unanimous
    /// verdict without waiting for the ladder.
    tried_430: u32,
    /// Servers a duplicate dispatch has already been issued to (mirror
    /// group bits) - the endgame fan-out races each backbone at most
    /// once.
    dup_servers: u32,
    /// TODO 96.4: server groups whose STAT probe answered 223. Only a
    /// `stat_probe` fan-out ever writes here, and one bit is enough to
    /// end the ladder: an article some backbone HOLDS can never reach a
    /// unanimous Missing, so every further probe is a question whose
    /// answer is already known.
    found: u32,
    /// Servers whose transport - or, TODO 114, whose delivered BODY -
    /// already failed this article, seeded from the Work item at
    /// dispatch. Dup pickers skip these: racing an article back to a
    /// server that already failed it is wasted work at best, and for
    /// a CRC-steered refetch it is the misfire that loses the race to
    /// the same corrupt copy the steer just rejected (the corrupt dup
    /// claims first and the clean refetch is discarded as the loser).
    tried_fail: u32,
    /// Pre-byte silence (TODO 115): the owner's read sat in pre-byte
    /// silence past the suspicion bound. `pick_suspect_dup` races
    /// suspect articles immediately - same server included - instead
    /// of waiting out the full adaptive budget.
    ///
    /// TODO 202 §17: it is ALSO the line gate's per-article escape
    /// (`Shared::not_using_the_line`), which is why the marker is armed
    /// on the whole adaptive path rather than only under the dark
    /// `ttfb_hedge` - see `session::read_one`. Set once and never
    /// cleared: the entry dies with the read, so the only window in
    /// which it can be stale is between the status line arriving and
    /// that body completing, and a race issued there is exactly the one
    /// the pool issued before the gate existed.
    suspect: bool,
    /// The original's [`Work::age_days`], seeded at registration so a
    /// hedge dup - built fresh from this entry, no queued Work in hand -
    /// still carries the true age to the oracle.
    age_days: u32,
    /// The original's [`Work::part`], seeded at registration for the
    /// same reason: a dup-delivered body must still face the
    /// part-mismatch gate.
    part: u32,
    /// The original's [`Work::file`], for the same reason.
    file: u32,
    /// The original's [`Work::ord`], seeded at registration so a hedge
    /// dup claims the original's completion bit - and so the hedge
    /// scans and the census can ask `done` about an in-flight entry
    /// without an id lookup.
    ord: u32,
}

/// State shared by every worker of one fetch run.
///
/// Tail behavior (measured on a high-RTT link): when the queue
/// runs dry but articles are still in flight on servers observed to be
/// much slower, idle workers re-dispatch those articles instead of
/// waiting out the stragglers. `done` arbitrates so exactly one outcome
/// is emitted (and `pending` decremented once) per article.
/// Capacity-episode lifecycle (issue #16), broadcast to parked
/// yielders: Idle = nothing to wait for, Probing = one prober is
/// riding the bounce ladder, Reopened = a session was granted again
/// (parked workers redial), Dead = the prober exhausted its horizon
/// (parked workers exit so the run can reach a truthful terminal).
/// Hard connect outages (wifi drop, VPN reconnect, router reboot)
/// ride the SAME lifecycle via `park_or_probe`: a server that refuses
/// the dial outright is as plausibly transient as one bouncing on a
/// ghost capacity lease.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
enum CapEpisode {
    #[default]
    Idle,
    Probing,
    Reopened,
    Dead,
}

/// One server's authentication standing, shared by all its workers.
struct AuthState {
    /// Set once when the server refuses permanently (bad credentials, a
    /// disabled account). Every worker for this server stops trying:
    /// retrying cannot fix it, and the operator needs to see it, not a
    /// wall of backoff.
    rejected: AtomicBool,
    /// Set when the server refused for CAPACITY reasons. Workers still
    /// retry, but they stand down one at a time rather than all racing
    /// to re-provoke the same cap.
    capacity_capped: AtomicBool,
    /// Workers that have voluntarily given up a slot to a capacity
    /// refusal. This IS the reduced connection count: asking for fewer
    /// sessions is the only response a simultaneous-connection cap
    /// actually accepts.
    yielded: AtomicUsize,
    /// Exactly ONE worker holds the long capacity-probe role (issue
    /// #16). `claim_yield` alone cannot elect a single survivor: early
    /// yielders exit and shrink `alive` while later workers are still
    /// claiming, so several can each read "I am the last" and all ride
    /// the probe ladder at once - harmless when the ladder was five
    /// bounces, a small dial storm now that it is seventy-five.
    cap_prober: AtomicBool,
    /// See [`CapEpisode`]. Yielders park on this instead of dying, so
    /// a cap that clears mid-run gets its fleet back instead of one
    /// prober crawling the rest of the job alone. The u64 is a publish
    /// generation: the watch never returns to Idle, so without it a
    /// LATER episode's parkers would consume the previous episode's
    /// leftover `Reopened` on entry, skip the prober election, and a
    /// permanent outage could never reach `Dead` (each worker bounced
    /// off the stale value forever instead of parking).
    episode: tokio::sync::watch::Sender<(CapEpisode, u64)>,
    /// The server's own words, kept for the log and the dashboard.
    reason: std::sync::Mutex<Option<String>>,
    /// Unix ms the CURRENT outage began, 0 while the server is granting
    /// sessions. Paired with `down_ms_total` below.
    down_since: AtomicU64,
    /// Wall-clock ms this server has spent granting NO session during
    /// this run, summed ACROSS episodes.
    ///
    /// `connect_failures` and `cap_bounces` are consecutive counters and
    /// a single granted session zeroes both ([`session::dial_session`]'s
    /// success arm), which is right for a blip and wrong for a cap: an
    /// account whose provider frees one slot every few minutes renews
    /// the ~10 minute `CAP_PROBE_BOUNCES` horizon forever, so the run
    /// never reaches a terminal and the job sits at zero bytes for as
    /// long as the user lets it (soak, 11->12 Aug 2026: 25 minutes on a
    /// capped Giganews account, and only a rig watchdog ended it).
    ///
    /// This accumulator is the one clock a reopen does not rewind. It
    /// only ever bites the flapping case: against a server that is
    /// simply DOWN the consecutive horizon still expires first.
    down_ms_total: AtomicU64,
    /// Dial pacing for a server that has STATED a connection cap: the
    /// single-canary permit, and the ticket counter the connect
    /// ladders' de-synchronising spread draws from. See
    /// [`dialgate::DialGate`], whose header carries the 29 Aug 2026
    /// measurement it was written against.
    dial: dialgate::DialGate,
}

impl Default for AuthState {
    fn default() -> Self {
        AuthState {
            rejected: Default::default(),
            capacity_capped: Default::default(),
            yielded: Default::default(),
            cap_prober: Default::default(),
            episode: tokio::sync::watch::channel((CapEpisode::Idle, 0)).0,
            reason: Default::default(),
            down_since: Default::default(),
            down_ms_total: Default::default(),
            dial: Default::default(),
        }
    }
}

impl AuthState {
    /// Record a refusal. Returns true if this worker is the FIRST to see
    /// it, which is the one that gets to log it.
    fn note(&self, kind: crate::nntp::AuthRefusal, line: &str) -> bool {
        let flag = match kind {
            crate::nntp::AuthRefusal::Permanent => &self.rejected,
            crate::nntp::AuthRefusal::Capacity => &self.capacity_capped,
        };
        let first = !flag.swap(true, Ordering::SeqCst);
        if first {
            *self.reason.lock_ok() = Some(line.to_string());
        }
        first
    }

    /// This server just failed to grant a session. The FIRST failure of
    /// an episode starts its clock; later ones are already counted.
    ///
    /// `held` is the number of sessions the server is serving RIGHT NOW
    /// ([`Shared::sessions`]), and a non-zero one means this refusal was
    /// not an outage at all. That distinction is the whole safety of the
    /// budget: asking a provider for more connections than the plan
    /// grants is the NORMAL case (we ask 30, the account allows 20), so
    /// the surplus workers bounce off a capacity refusal for the entire
    /// job. Counting those as downtime would accumulate fifteen minutes
    /// of "outage" on a server that never stopped serving, and retire a
    /// perfectly healthy provider mid-job.
    fn mark_down(&self, held: usize) {
        if held > 0 {
            return;
        }
        let _ = self
            .down_since
            .compare_exchange(0, now_ms(), Ordering::Relaxed, Ordering::Relaxed);
    }

    /// A session was granted: bank the episode and stop the clock.
    fn mark_up(&self) {
        let at = self.down_since.swap(0, Ordering::Relaxed);
        if at > 0 {
            self.down_ms_total
                .fetch_add(now_ms().saturating_sub(at), Ordering::Relaxed);
        }
    }

    /// Total ms with no usable session this run, banked episodes plus
    /// the open one.
    fn down_ms(&self) -> u64 {
        let open = match self.down_since.load(Ordering::Relaxed) {
            0 => 0,
            at => now_ms().saturating_sub(at),
        };
        self.down_ms_total.load(Ordering::Relaxed) + open
    }

    /// Publish an episode event under a fresh generation, so parkers
    /// can tell it apart from a previous episode's leftover value.
    fn publish_episode(&self, ep: CapEpisode) {
        self.episode.send_modify(|v| *v = (ep, v.1 + 1));
    }

    /// Try to give up this worker's slot to a capacity refusal. True when
    /// the slot was yielded and the caller must leave the fleet.
    ///
    /// The survivor has to be decided against workers STILL HERE, not
    /// against the configured connection count: a worker can also leave
    /// via the connect ladder or the session bow-out, and neither passes
    /// through this counter. Counting yields against the static config
    /// meant that once anyone had left by another door the target could
    /// never be reached, so every remaining worker yielded and the server
    /// was left with nobody - failing the whole job on exactly the
    /// transient refusal this path exists to survive.
    ///
    /// `alive` counts the calling worker too, and every exit path
    /// decrements it, so a claim is only safe while it leaves someone
    /// behind. fetch_update serialises two simultaneous refusals so they
    /// cannot both conclude they are not the last one out.
    ///
    /// The caller's `alive` decrement lands after this returns (the
    /// worker unwinds to `life.retire()`), so `yielded` holds the claims
    /// that have not shown up in `alive` yet. Counting both makes the
    /// rule conservative: a full fleet stands down to about half rather
    /// than to a single survivor. That is deliberate. Reading `alive`
    /// alone would reduce to exactly one, but leaves a window where two
    /// simultaneous refusals both see two workers left and both go,
    /// which is the zero-worker failure this exists to prevent. Half a
    /// fleet still stops the hammering and still asks the provider for
    /// fewer sessions, which is what a simultaneous-connection cap
    /// actually wants; a stranded server is unrecoverable for the run.
    fn claim_yield(&self, alive: &AtomicUsize) -> bool {
        self.yielded
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |y| {
                (alive.load(Ordering::SeqCst) > y + 1).then_some(y + 1)
            })
            .is_ok()
    }

    fn is_rejected(&self) -> bool {
        self.rejected.load(Ordering::Acquire)
    }

    // Not #[expect]: the unit tests call it, so the expectation is
    // unfulfilled under cfg(test).
    #[allow(dead_code)] // diagnostic accessor, kept for pool-debug dumps
    fn reason(&self) -> Option<String> {
        self.reason.lock_ok().clone()
    }
}

struct Shared {
    queue: Mutex<VecDeque<Work>>,
    /// Articles not yet terminal (Done/Missing/Failed). Workers may only
    /// exit when this hits zero - a queue that looks empty can still
    /// receive requeues from other workers' in-flight failures/430s.
    pending: AtomicUsize,
    /// Articles whose outcome has been emitted, one bit per
    /// [`Work::ord`] (C4: the id-keyed set cost ~110 B per completion;
    /// this is one bit, and the count rides along exactly).
    done: std::sync::Mutex<DoneBits>,
    /// Articles currently in flight, keyed by message-id.
    inflight: std::sync::Mutex<HashMap<Arc<str>, Inflight>>,
    /// Held-bytes backpressure (TODO 94 item E): files whose pending
    /// articles `next_work` steps past, see [`park::FilePark`].
    park: park::FilePark,
    /// Per-server raw byte counters (also the caller-visible stats).
    bytes: Vec<Arc<AtomicU64>>,
    /// Per-server session-end tally by cause, in [`SessionEnds`] field
    /// order: peer, protocol, prebyte, stall, ours. Counted where the
    /// session actually ends, so a redial that never wins cannot hide
    /// the cause (the same reasoning as `note_flap`).
    ends: Vec<[AtomicU64; 5]>,
    /// Per-server tally of authoritative 430/423 wire answers, split by
    /// whether the attribution was PROVEN (slot 0: the refusal echoed a
    /// message-id, or arrived fenced) or POSITIONAL (slot 1: a bare
    /// refusal, filed against the pipeline front by position alone).
    /// The split is the one number that separates "the provider said
    /// this article is gone" from "a desynced socket's refusal was
    /// filed on the wrong article" after the fact: a run whose losses
    /// are all bare, on a session population that also shows protocol
    /// desyncs, is a misattribution suspect, while echoed refusals
    /// cannot misfile (a mismatched echo kills the session before any
    /// verdict is recorded). Counted where the answer lands
    /// ([`session::handle_missing`]), dups included, exactly like the
    /// M29 oracle's miss - this counts WIRE ANSWERS, not verdicts.
    /// Motivated by the 28 Aug 2026 g25L leg: 952 segments went
    /// terminally missing on a slow cold route whose sessions also
    /// died 89 times on protocol desync, and nothing in the leg log
    /// could say which kind of 430 the verdicts rested on
    /// (research/SLOW-SOCKET-430-CAUSAL-READ-2026-08-28.md).
    miss_answers: Vec<[AtomicU64; 2]>,
    /// Per-server write-side wait (see [`PoolStats::blocked_ms`]). Kept
    /// on Shared as well as LiveStats because the CLI runs without a
    /// live-stats sink and still needs to tell a network dip from a
    /// disk one.
    blocked_ms: Vec<AtomicU64>,
    /// Per-server time-to-status EWMA in ms (adaptive timeout path,
    /// TODO 96.1). 0 = unmeasured, which budgets at the clamp ceiling.
    ttfb_ms: Vec<AtomicU64>,
    /// Ids the CRC-retry gate has already requeued once. Bounds the
    /// experiment to a single decode-seam retry per article - the
    /// second bad copy is delivered as-is and PAR2 owns it, exactly as
    /// with the knob off. One budget for both destinations: a peer when
    /// one is eligible, otherwise the deliverer itself under
    /// [`REASK_WASTE_CAP`]. Sharing it is what keeps the same-server
    /// re-ask strictly ADDITIVE - an article the steer could place is
    /// placed exactly as it was before, and only one the steer had to
    /// own gets the new ask.
    crc_retried: std::sync::Mutex<HashSet<Arc<str>>>,
    /// Units of same-server re-ask WASTE left this run. See
    /// [`REASK_WASTE_CAP`] for what a unit is and why it comes back.
    reask_waste: AtomicUsize,
    /// Ids out on a budget-spending same-server re-ask right now, so the
    /// refund can find the unit again. Empty on every run that never met
    /// a corrupt body, and the counter beside it keeps the CLEAN decode
    /// path off this lock - the same arrangement `soft_rearm` above uses,
    /// and for the same reason: this is asked once per delivered article.
    reask_out: std::sync::Mutex<HashSet<Arc<str>>>,
    reask_out_n: AtomicUsize,
    /// Synthesized-numbering latch for the part gate (see its doc).
    part_latch: queue::PartLatch,
    /// §129 3g: bare-refusal passes to RE-ARM, keyed by message-id, the
    /// value being the server-group bits to clear from `Work::soft_430`.
    /// Filled when a session shows it was reading responses off by one -
    /// an id mismatch, a status that cannot answer a BODY, or a read
    /// that stalled with requests outstanding - and drained by the next
    /// bare refusal for that article. Empty on every healthy run, and
    /// the counter beside it keeps the hot path off this lock.
    soft_rearm: std::sync::Mutex<HashMap<Arc<str>, u32>>,
    soft_rearm_n: AtomicUsize,
    /// TODO 315: how many articles hold a late re-ask right now. A
    /// COUNT, not a set, and a CONCURRENCY limit, not a quota - see
    /// [`Shared::take_recheck`].
    recheck_held: AtomicUsize,
    /// TODO 315: [`PoolConfig::recheck_430_hold`] in ms, MAX-folded
    /// across the fleet; 0 = unbounded (the pre-30-Aug shape). Here
    /// rather than read at the site because the site that enforces it
    /// is `next_work`'s queue scan, which is handed no `PoolConfig` at
    /// all. MAX-folded like the gauge's `pct`: the most generous window
    /// any member asked for is the only reading that cannot shorten a
    /// hold somebody deliberately lengthened.
    recheck_hold_ms: u64,
    /// TODO 315: holds this run whose window ran out before their group
    /// answered - the bounded outcome, and its only trace, so one warns.
    recheck_expired: AtomicU64,
    /// Per-server darkness clock: when each server stops counting as
    /// able to serve for want of a session. See [`gates::ConnDark`].
    conn_dark: ConnDark,
    /// Takedown-flavoured refusal evidence by message-id: server-group
    /// bits whose CHARGED refusal said "removed" rather than "not
    /// found" (see [`crate::nntp::takedown_flavoured`]). A HINT and
    /// never a gate - it changes no routing, no unanimity and no
    /// verdict; a terminal Gone drains its entry to flavour the
    /// outcome for the failure summary. Empty on every run that never
    /// sees one, and the counter beside it keeps the terminal path off
    /// the lock.
    takedown: std::sync::Mutex<HashMap<Arc<str>, u32>>,
    takedown_n: AtomicUsize,
    /// M5: servers that burned their WHOLE retry budget on one article,
    /// keyed by message-id, the value being their server bits. Routing
    /// only, never evidence - pool/gates.rs holds the reasoning and
    /// everything that reads it. Empty on every healthy run, and the
    /// counter beside it keeps the queue scan off this lock.
    spent: std::sync::Mutex<HashMap<Arc<str>, u32>>,
    spent_n: AtomicUsize,
    /// TODO 114 consumer steer: Done outcomes handed to the consumer
    /// whose `complete_one` is DEFERRED until the consumer's decode
    /// verdict arrives via [`QueueControl::note_decoded`]. The stashed
    /// Work (plus the deliverer's identity) is what a bad-body verdict
    /// requeues; a clean verdict just finalizes. Keeping these ids in
    /// `pending` is what keeps the fleet alive to serve a steer even
    /// when the damaged body was the last article on the wire. Bounded
    /// by the outcome channel depth plus the consumers' in-hand
    /// batches. Empty unless `PoolConfig::crc_steer` is on.
    handed: std::sync::Mutex<HashMap<Arc<str>, queue::Handed>>,
    /// TODO 114 consumer steer: requeued-after-claim Work waiting to
    /// re-enter the queue. The verdict thread must NOT take the tokio
    /// queue mutex - it is FIFO-fair and worker-hot, and during a
    /// steer burst a bounded try_lock lost to the worker scans for
    /// long enough to own real damage (measured: up to a third of a
    /// storm's steers at a 200 ms budget). Workers drain this into
    /// the queue at the top of their own `next_work` lock hold. An
    /// item here counts as live in `any_live` (the top-up is usually
    /// ms away, but workers all blocked in long pipelined reads can
    /// hold it back past the dead-span verdict's grace+votes);
    /// `seal_run` drains it so an exhausted fleet still accounts
    /// every steered article.
    steer_inbox: std::sync::Mutex<Vec<Work>>,
    /// Ids whose body ARRIVED and is mid-handoff to the consumer: from
    /// claim to the outcome channel accepting it, the body is out of
    /// `inflight` and out of the queue - invisible to both `any_live`
    /// checks - and a full channel can park that send for many seconds
    /// under disk backpressure (the `blocked_ms` gauge measures exactly
    /// this window). The /stream dead-span verdict must never condemn
    /// such a span (it would serve zeros for bytes that already
    /// arrived), so `any_live` counts these as live. Entries leave
    /// when the body is SETTLED: under `crc_steer` at the consumer's
    /// `note_decoded` verdict, under `arrival_ack` at the consumer's
    /// `note_settled` after decode+write (TODO 121.4 - the channel
    /// buffer and the consumer's in-hand batch were the residual
    /// blind window, and ~6 s of disk backpressure could outlast the
    /// verdict's grace-plus-votes threshold), and otherwise when the
    /// channel accepts the body.
    done_ok: std::sync::Mutex<HashSet<Arc<str>>>,
    start: Instant,
    /// Monotonic count of DELIBERATE non-terminal progress. The
    /// caller's deadlock watchdog treats a run as wedged when decoded
    /// bytes AND outstanding articles both sit frozen; two kinds of
    /// healthy work move neither: a path that consumes a response and
    /// requeues instead of emitting Hit/Missing/Failed (31 Jul's
    /// dead-post abort, returning through the `soft_430` confirming
    /// repeat), and the outage prober's paced bounce ladder (whose
    /// ~10 min horizon the 180 s watchdog was aborting straight
    /// through). Anything that defers a verdict or paces a recovery
    /// must tick here, and the watchdog counts it as life.
    deferred: AtomicU64,
    /// Diagnostics: dup dispatches issued, and when the queue first ran dry
    /// with work still pending (start of the tail phase).
    dups_issued: AtomicU64,
    tail_started: std::sync::Mutex<Option<Instant>>,
    /// Cross-job hand-over (`handoff`): per-server seats at the leases a
    /// successor's workers wait on, and this run's idle latch.
    leases: Vec<Option<handoff::LeaseSeat>>,
    handoff: Option<Arc<handoff::HandoffSignal>>,
    /// Flips to true the moment every article is terminal. Workers blocked
    /// mid-read on slow connections select on this - without it, a tail
    /// duplicate's win is worthless because the pool still waits for the
    /// slow original to finish streaming (the 15 s zero-throughput tail
    /// observed on Miami).
    finished: tokio::sync::watch::Sender<bool>,
    /// Hard-stop signal (user abort): workers exit at their next loop
    /// check; the finished watch wakes any blocked read. Never zero
    /// `pending` for this - in-flight completions would wrap it.
    aborted: AtomicBool,
    /// Graceful-pause signal: workers stop admitting NEW articles but
    /// finish (and journal) whatever is already in flight, then return.
    /// Unstarted queue items are left for a resume - nothing in flight is
    /// thrown away, unlike `aborted`.
    draining: AtomicBool,
    /// When the last article went terminal (vs when the pool returned).
    drained_at: std::sync::Mutex<Option<Instant>>,
    /// Serializes the drained verdict against a revive. `complete_one`'s
    /// fetch_sub landing `pending` on zero and its `finished.send` are
    /// two steps; [`QueueControl::requeue`]'s raise-then-check-finished
    /// could land whole inside that gap - the raise too late to stop the
    /// zero-crossing, the check too early to see the send - and the
    /// requeued articles then sat in a queue every worker had already
    /// left (or were swept up as failures by `seal_run`), with the
    /// caller told they would be fetched. Every zero-crossing send now
    /// re-reads `pending` under this lock ([`Shared::finish_if_drained`])
    /// and requeue raises+checks under the same lock, so exactly one
    /// side wins: the send happens and requeue sees it and rolls back,
    /// or the raise happens and the send stays unfired. Leaf lock, cold
    /// path (taken once per run end plus once per requeue call).
    finish_gate: std::sync::Mutex<()>,
    /// Test seam: trips `complete_one` between the fetch_sub that lands
    /// `pending` on zero and the gated finished-send decision - the
    /// exact window a concurrent `requeue` must win. Two-stage shape as
    /// daemon_park::IDLE_CAS_BARRIER (first: the crossing has happened
    /// and the verdict has not; second: the test has run its interleaved
    /// work and releases it). Per-instance, not a static - lib tests in
    /// one process must not trip each other's pools.
    #[cfg(test)]
    drain_send_barrier:
        std::sync::Mutex<Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>>,
    /// Test seam: trips [`QueueControl::requeue`] between dropping
    /// `finish_gate` and taking the queue lock - the window in which the
    /// last worker can retire (`WorkerLife::retire` touches no gate) and
    /// both terminal seals can drain a queue the requeue has not written
    /// to yet. Same two-stage shape and per-instance rationale as
    /// `drain_send_barrier` above.
    #[cfg(test)]
    requeue_gate_barrier:
        std::sync::Mutex<Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>>,
    /// Work items removed by [`QueueControl::cancel`], kept whole (retry
    /// budget, retention seed) so [`QueueControl::requeue`] can resurrect
    /// them exactly as they were - the in-stream PAR2 sniff un-defers a
    /// slot when activation reveals it was set-covered payload after all.
    cancelled: std::sync::Mutex<HashMap<Arc<str>, Work>>,
    /// Tail duplicates that won their race (emitted the outcome).
    dup_wins: AtomicU64,
    /// The consumer acks decode+write via `note_settled` (see
    /// [`PoolConfig::arrival_ack`]), uniform like `tail_fanout`. Under
    /// it a clean `note_decoded` verdict must NOT drop the `done_ok`
    /// liveness entry - the body is decoded but not yet on disk, and
    /// the write can outlast the dead-span verdict.
    arrival_ack: bool,
    /// Opt-in tail fan-out (see [`PoolConfig::tail_fanout`] and
    /// `pick_dup`): in the endgame, idle primaries race healthy
    /// in-flight articles too. Uniform across servers - the daemon sets
    /// every server's config from one env knob.
    tail_fanout: bool,
    /// Hedge experiment (see [`PoolConfig::hedge`]), uniform like
    /// `tail_fanout`.
    hedge: bool,
    /// The line gate's per-article escape is armed (see
    /// [`PoolConfig::race_escape`]). Fleet-wide like the gate itself,
    /// so the `any` fold is the bool analogue of the gate's `max`.
    race_escape: bool,
    /// TTFB-suspicion hedge (see [`PoolConfig::ttfb_hedge`]), uniform.
    ttfb_hedge: bool,
    /// TTFB-suspicion fast path: true while some in-flight article MAY
    /// be suspect and unraced, so the per-top-up check in `next_work`
    /// costs one atomic load until a suspicion actually fires. Set by
    /// `mark_suspect`, cleared by a `pick_suspect_dup` scan that comes
    /// up empty.
    suspect_pending: AtomicBool,
    /// Early fan-out (see [`PoolConfig::tail_fanout_early`]), uniform.
    tail_fanout_early: bool,
    /// TODO 208 item 3: the endgame depth taper is armed for this run.
    tail_taper: bool,
    /// The shallowest pipeline depth the taper actually handed out, or
    /// `usize::MAX` if it never bit. Printed on the `[pool]` line so a
    /// leg can PROVE the arm took instead of inferring it from the
    /// drain it is trying to measure - the trap §202's A/B hit, where
    /// only the gauge's own `saturated 0%` distinguished a real off-arm
    /// from an env var that never arrived. Written only while the taper
    /// is biting (a tail-only event), so the steady state pays one
    /// comparison against a value it already has.
    taper_min: AtomicUsize,
    /// Dispatch-to-done article time EWMA in ms, trained by the 222
    /// Done path only (430s answer with no body and requeues never
    /// completed - both would drag the average away from what a
    /// straggler actually costs). 0 = untrained. Includes time spent
    /// queued behind pipeline-mates, deliberately: that IS the time an
    /// article blocks its slot.
    art_ms: AtomicU64,
    /// TODO 208.2: delivered body size EWMA in bytes (same 1/8 fold,
    /// fed beside `srv_rate`), for the share-aware stall bound. 0 =
    /// untrained, which keeps the flat bound.
    body_bytes_ewma: AtomicU64,
    /// Dup dispatches issued on staleness alone (the hedge), for the
    /// issue-rate cap and the diagnostics line.
    hedges_issued: AtomicU64,
    /// Dup dispatches issued on TTFB suspicion (`pick_suspect_dup`),
    /// against its OWN issue-rate cap. §17c: until 21 Aug 2026 both
    /// hedges spent one counter against one threshold, so enabling the
    /// TTFB rescue would have drawn down the straggler budget with no
    /// ledger able to say which mechanism spent it. Same formula, two
    /// purses.
    ttfb_hedges_issued: AtomicU64,
    /// The run's shared event ring (every server's `PoolConfig` carries
    /// the same `Arc`). Held here too so moments that belong to the RUN
    /// rather than to one worker - the tail latch, the drain, a racing
    /// spike - can mark the graph from `Shared` methods. None on the
    /// bare CLI paths that build no live view.
    live: Option<Arc<LiveStats>>,
    /// Racing-burst window (see [`Shared::note_race_burst`]): when the
    /// current window opened (unix ms, 0 = none yet) and what
    /// dups+hedges read at that moment.
    race_note_at: AtomicU64,
    races_at_note: AtomicU64,
    /// Unix ms of the last wire-cap marker: the cap check runs on every
    /// pipeline top-up, so an engaged cap on a big fleet would flood the
    /// ring thousands of times over without this gate.
    wire_note_at: AtomicU64,
    /// Hot-spare experiment: one parked, authenticated connection per
    /// server, claimed by any worker whose session dies. Filled by a
    /// per-server background task (spawned lazily by the first worker,
    /// so both the single-runtime and sharded paths get one).
    spares: Vec<std::sync::Mutex<Option<Connection>>>,
    /// One filler per server, whichever worker gets there first.
    spare_filler_started: Vec<AtomicBool>,
    /// Flap breaker: per-server timestamps of established-session
    /// deaths (recorded at the successful REDIAL, which is when the
    /// worker knows the old session both worked and died).
    flap_deaths: Vec<std::sync::Mutex<VecDeque<Instant>>>,
    /// Per server: keeper slots claimed by the workers that keep a
    /// flapping server's light on; everyone else bows out for the run.
    /// The target is 1 (the shipped clamp) unless `flap_cap_keepers`
    /// widens it to the observed accept cap - see
    /// [`Shared::flap_keeper_target`].
    flap_keeper: Vec<AtomicUsize>,
    /// Per server: established sessions held RIGHT NOW by this run's
    /// workers. Sampled at the moment a dial bounces off a capacity
    /// refusal to estimate the provider's accept cap (`flap_cap_seen`).
    sessions: Vec<AtomicUsize>,
    /// Per server: high-water of `sessions` sampled at capacity-refusal
    /// bounces - the largest number of our own sessions the provider
    /// was serving while refusing one more. 0 = never bounced, cap
    /// unknown. Max across bounces, because a bounce can also land
    /// while the server still holds ghosts of sessions it just dropped
    /// (undercounting the true cap); it can never land while it serves
    /// MORE than the cap.
    flap_cap_seen: Vec<AtomicUsize>,
    /// The clamp is narrated once, not once per bowing worker.
    flap_noted: Vec<AtomicBool>,
    /// §129 3g: this server has answered at least one 430/423 with no
    /// message-id on the line, so positional attribution of its
    /// refusals is unverifiable and every later dispatch to it carries
    /// an alignment fence ([`Connection::send_fence`]). Sticky for the
    /// run and per SERVER, not per session: a session's own first bare
    /// refusal is the one that would otherwise be misattributed, so
    /// arming has to outlive the session that learned it.
    bare_refuser: Vec<AtomicBool>,
    /// §129 3g: this server has answered a fence at least once, so its
    /// fences are known to work and a later fence that goes unanswered
    /// is the fault talking, not the provider.
    fence_ok: Vec<AtomicBool>,
    /// §129 3g: fence reads that came to nothing on a server that has
    /// never answered one - the read expired, or (only on a session's
    /// FIRST fenced read, where a fresh socket is aligned by
    /// construction) the fence slot held a BODY-shaped answer, which is
    /// what DATE-silence looks like at pipeline depth above one.
    /// DATE is mandatory in RFC 3977 and the warm pool
    /// already validates parked connections with it, but a provider
    /// that quietly ignores it would otherwise have every session cut
    /// on a fence that was never coming - a broken download in defence
    /// of a fault this provider may not even have. Two of these and
    /// fencing retires for that server, back to the behavior that
    /// shipped before this item.
    fence_dud: Vec<AtomicUsize>,
    /// §129 3g: fencing has retired for this server. Latched and never
    /// cleared, because the alternative - clearing `bare_refuser` - is
    /// undone by the next bare refusal `handle_missing` sees, so
    /// retirement would last exactly one refusal and the live note
    /// would re-emit every cycle. `bare_refuser` must stay armed
    /// regardless: the suspect/soft-430 attribution logic still needs
    /// to know this server's refusals arrive unverifiable.
    fence_off: Vec<AtomicBool>,
    /// M14e tiers: per-server level and live-worker counts. A fill
    /// server's gate only counts LIVE lower-level servers, so a dead
    /// primary (all its workers bowed out) never wedges the queue.
    levels: Vec<u32>,
    alive: Vec<AtomicUsize>,
    /// Per-server count of workers that have CLAIMED a cross-job
    /// hand-over and are on their way out ([`Shared::claim_handoff`]).
    /// Monotone for the run except when a claim's leftover reservation
    /// fails and the claim is handed straight back - otherwise never
    /// released, the same conservative trade `ServerState::claim_yield`
    /// makes, and for the same reason.
    handoff_out: Vec<AtomicUsize>,
    /// Per-server count of `alive` decrements already taken by a
    /// granted hand-over claim (the finding-25 reservation in
    /// [`Shared::claim_handoff`]), still owed to `WorkerLife`'s exit
    /// arithmetic - which consumes one instead of decrementing `alive`
    /// a second time for the same departure.
    handoff_retired: Vec<AtomicUsize>,
    /// Per-server count of workers holding a live-target admission
    /// (see [`Admitted`]); `admit_wake` is pinged whenever one is
    /// returned so a parked worker can take it.
    admitted: Vec<AtomicUsize>,
    admit_wake: Vec<tokio::sync::Notify>,
    /// Per-server: latched true the first time any worker holds a usable
    /// connection (fresh dial or warm-pool). Read into
    /// `PoolStats::ever_connected` when the run returns.
    connected: Vec<AtomicBool>,
    /// Per-server: latched when a server that HAD connected loses its last
    /// worker while the run still has work pending. Read into
    /// [`PoolStats::left_mid_run`], which says why it is needed.
    left_mid_run: Vec<AtomicBool>,
    /// §15e per-SERVER auth state, one slot per server index.
    ///
    /// A refusal to authenticate is a property of the server, not of the
    /// worker that happened to discover it, but every worker used to
    /// rediscover it independently: with 8 connections that is 8 workers
    /// x `max_connect_attempts`, each behind its own growing backoff, all
    /// hammering an account that has already said no. For a Giganews
    /// `481 max simultaneous IP addresses reached` that is precisely the
    /// wrong response - the refusal IS about connection count, and behind
    /// a load-balancing multi-WAN router each retry can present a fresh
    /// WAN IP and re-exhaust the very cap it is failing on.
    ///
    /// So the first worker to hear it records it here and the rest read
    /// it instead of re-provoking it.
    auth: Vec<AuthState>,
    /// Live workers across EVERY server (and, on the sharded path, every
    /// shard runtime). `alive` answers "can this server still serve?";
    /// this answers "is anyone at all still able to finish the run?" -
    /// the question the terminal-state invariant turns on. The last
    /// worker out owns [`seal_run`]; see it for why that matters.
    workers_live: AtomicUsize,
    /// Of those, how many are parked in `admit::wait_for_slot` right
    /// now - alive, holding no admission and so no connection (TODO
    /// 277). Per server, then summed: `stall_bound_at` samples the
    /// total before every socket wait and must not fold a Vec there.
    /// [`Shared::workers_dialling`] is why both exist.
    parked: Vec<AtomicUsize>,
    parked_total: AtomicUsize,
    /// How many workers this run has EVER had. `workers_live == 0` is
    /// ambiguous on its own - it is equally "the fleet is exhausted" and
    /// "the fleet has not been born yet" - and a guard that cannot tell
    /// them apart drops work racing fleet birth (Fable sweep 15 Aug,
    /// TODO 170). Paired with `workers_live`, this disambiguates: born
    /// and none live is a dead fleet, never born is a fleet still
    /// arriving.
    workers_born: AtomicUsize,
    /// M11 stream mode: deadline (ms since `start`, 0 = never engaged)
    /// until which a live /stream reader is considered attached. While
    /// active, workers cap their pipeline to `stream_window()` so a
    /// promoted seek article is never queued behind a deep in-flight
    /// backlog. Refreshed on every reader touch; the linger stops VLC's
    /// per-seek request churn (close + reopen) from flapping the mode.
    stream_until: AtomicU64,
    /// Bumped by every promote() that moves work. Workers blocked mid-read
    /// on a NON-promoted article select on this and abandon the read
    /// (reconnect + uncharged requeue): measured on the real line, a
    /// promoted 32 MB window otherwise lands at the seeking conn's
    /// fair-share (~1/130th of the line) because 100+ busy connections
    /// keep streaming frontier bytes - the whole wave took 4-6 s and a
    /// VLC seek needed several waves. Shedding the fleet on promote
    /// re-dedicates the line to the seek window within ~a reconnect.
    promote_gen: tokio::sync::watch::Sender<u64>,
    /// Approximate count of promoted items still in the pending queue
    /// (set by promote, decremented as workers pop them). Gates the
    /// promote-shed so a stale generation bump can't cause storms.
    promoted_pending: AtomicUsize,
    /// The LAST promote's full id set. The shed immunity check needs it:
    /// an article dispatched BEFORE the promote never carries the
    /// `promoted` flag, yet if its id is in the promoted span, abandoning
    /// it just refetches the same bytes after a reconnect (at play-start
    /// the whole fleet is fetching exactly the head/tail articles the
    /// first promote names - shedding them delayed the volume headers the
    /// extractor needs to classify, live-caught by the ordering e2e).
    promoted_ids: std::sync::Mutex<HashSet<Arc<str>>>,
    /// Per-server: ms-since-start of the last FRUITLESS full-queue scan
    /// (u64::MAX = never). `next_work`'s scan pops and re-pushes every
    /// item a server can't take - O(queue) under the shared queue lock.
    /// On a mostly-taken-down 12k-segment post (live, 2026-07-20) five
    /// servers that had 430'd everything re-scanned the whole queue every
    /// 25 ms per worker, starving the one server that could still serve:
    /// ~5 MB/s crawling to a flat 0.0 that read as a permanent stall.
    /// A server whose scan just came up empty doesn't rescan within
    /// [`SCAN_RETRY_MS`]; new work only appears via queue mutations, so
    /// the worst case is a one-tick delay picking it up.
    scan_futile: Vec<AtomicU64>,
    /// N6 endgame idle-spin gate: generation counter over the inflight
    /// map, bumped ([`Self::bump_inflight_gen`], hedge module) by every
    /// mutation that can create or advance a `pick_dup` candidate. The
    /// full rationale sits on the gate itself at the top of `pick_dup`.
    inflight_gen: AtomicU64,
    /// Per-server: ms-since-start of the last fruitless idle `pick_dup`
    /// walk (u64::MAX = never) and the generation that walk snapshotted.
    dup_futile: Vec<AtomicU64>,
    dup_futile_gen: Vec<AtomicU64>,
    /// B3 wire-cap: estimated bytes of BODY responses currently owed to
    /// this pool's pipelines, GLOBAL across servers - the budget-exempt
    /// wire-side memory (pooled ~800 KB bodies + per-conn BufReader).
    /// Charged [`EST_BODY_BYTES`] per dispatched BODY (dups included -
    /// their responses are just as real), released when the item leaves
    /// a worker's pipeline, however it leaves. A fixed estimate keeps
    /// charge/release trivially symmetric; actual sizes only skew the
    /// throttle point, never the balance.
    inflight_body_bytes: AtomicU64,
    /// Per-server windowed throughput signal (M7b.2 steering, see the
    /// `steer` module): a delivered-byte accumulator decayed with a
    /// ~10 s half-life, and the ms-since-start stamp of its last fold
    /// (u64::MAX = never fed - untrained). Fed ONLY beside the
    /// `bytes[]` bump on the 222 body path, so probe or synthetic
    /// traffic can never train it.
    srv_rate_val: Vec<AtomicU64>,
    srv_rate_at: Vec<AtomicU64>,
    /// Per-server dispatch-to-done EWMA in ms, the by-owner twin of
    /// `art_ms` (same fold, same Done-only feeding). 0 = untrained;
    /// the global stays the fleet-wide fallback and clamp source.
    srv_art_ms: Vec<AtomicU64>,
    /// Ms-since-start of the last article-time gauge line (see
    /// [`Shared::note_art_gauges`]); 0 = none emitted yet. The gauge is
    /// sampled on every completion, so without this the log would carry
    /// one line per article - the same once-a-window discipline
    /// `last_blocked_note` keeps for the event ring.
    art_note_at: AtomicU64,
    /// M7b.2 depth steering armed (OR-fold of `PoolConfig::steer_depth`,
    /// like `tail_fanout`).
    steer_depth: bool,
    /// Per-server hysteresis state for the depth clamp (see
    /// `steer_window` in the steer module). Mirrored into
    /// `ServerLive::steered` for the tuner.
    steer_clamped: Vec<AtomicBool>,
    /// M7b.2 envelope racing armed (OR-fold, like `tail_fanout`).
    race_envelope: bool,
    /// TODO 202: the fleet-level line gauge and racing ledger.
    sat: saturation::Saturation,
    /// TODO 208 item 1: the in-run line-aware shed (`pool::linecap`).
    line_cap: linecap::LineCap,
    /// §5.7 block-account mask: servers whose bytes are never spent
    /// speculatively, whatever their level.
    block_bits: u32,
    /// TODO 96.4 STAT verdict probes armed (OR-fold, like `tail_fanout`).
    stat_probe: bool,
    /// §96.5 per-server remaining-block budgets in bytes (0 = no
    /// budget). When a server's own `bytes` counter crosses its entry,
    /// its workers drain their pipelines and bow out for good - the
    /// mid-run half of the prepaid-block cap, whose job-boundary half
    /// is the daemon's exhausted-host exclusion.
    budget_bytes: Vec<u64>,
    /// One-shot latch per server: the "block spent" event has been
    /// emitted, and `note_server_dark` must not relabel the exit as a
    /// connection failure.
    budget_noted: Vec<AtomicBool>,
    /// Fleet-wide bytes of LOSING dup copies - the hygiene cap's
    /// counter (design 5.2; fleet-wide deliberately, the 3d/3c trap:
    /// per-server counters read zero for cross-server quantities).
    dup_bytes_lost: AtomicU64,
}

/// B3 wire-cap charge per dispatched BODY - the same ~800 KB working
/// estimate the buffer pool and channel depth are sized around.
const EST_BODY_BYTES: u64 = 800 * 1024;

/// How long stream mode outlives the last reader touch. Long enough to
/// span player pauses and per-seek reconnects; short enough that a closed
/// player gives the pool its deep pipelines back.
const STREAM_LINGER: Duration = Duration::from_secs(60);

/// A promote only sheds an in-flight read older than this. Younger reads
/// complete faster than the reconnect would (quit + TLS + BODY ≈ 300 ms)
/// - abandoning them buys nothing and, at play-start, aborts the volume
/// header probes racing the first promote (their displacement behind a
/// 40 MB promoted run stalls extractor classification - caught by the
/// ordering e2e). A read that has already sat this long on a contended
/// line is mid-transfer at ~1/130th fair share, exactly the case where
/// the reconnect wins.
const PROMOTE_SHED_MIN_AGE: Duration = Duration::from_millis(400);

// Timeout/backoff arithmetic lives in `pacing` (split under the size
// gate); the glob keeps every call site and test spelling unchanged.

// TODO 106: one worker's session lifecycle - dial, pipeline, read, and
// every way a session ends - came out whole to pool/session.rs. Imported
// rather than re-exported: these are pool internals, and the glob is what
// keeps `super::handle_body`-style paths working for the test children.
// TODO 106: the run's end game - the worker task, the spare filler, and
// every way a run is sealed or a work item requeued - came out whole to
// pool/runlife.rs. Free functions, so the glob puts them back in scope
// for pool and its descendants exactly as the private ones were.
mod runlife;
use runlife::*;

mod admit;
use admit::*;

mod ratelimit;
pub use ratelimit::RateLimit;

// pool/gates.rs. Inherent methods on `Shared` plus the two server-bit
// helpers; the glob puts the free functions back in scope for pool and
// its descendants exactly as the private ones were, and `pub(super)`
// does the same for the methods.
mod gates;
mod recheck;
use gates::*;
use recheck::{RECHECK_430_HOLD, RECHECK_430_MAX};

mod session;
use session::*;

// TODO 106: the park-and-probe tail - what a worker does while a server
// is not granting sessions - came out of session.rs whole. A glob, as
// `session`'s own is, so its callers there are unchanged.
mod parkprobe;
use parkprobe::*;

mod pacing;
use pacing::*;

// The stated-cap dial gate and the connect-ladder spread (29 Aug 2026).
// No glob: the dial path reaches it through `AuthState::dial`, and the
// two free functions are named where they are used, so a reader of a
// backoff line can see which module decides its delay.
mod dialgate;

// TODO 106: the tail dup race and the B3 in-flight wire budget came out
// whole to pool/hedge.rs. Inherent `impl Shared` methods, so no glob is
// needed - the child's `pub(super)` puts them back in scope for pool and
// every one of its descendants exactly as the private ones were.
pub mod handoff;
mod hedge;

// TODO 106: the per-server observation ledger - the §96.5 block latch,
// the TTFB EWMA, the session-end and 430-attribution tallies, the flap
// breaker and the cap-bounce clamp - came out whole to
// pool/serverledger.rs. Inherent `impl Shared` methods, so no glob is
// needed: the child's `pub(super)` puts them back in scope for pool and
// every one of its descendants exactly as the private ones were.
mod serverledger;

// TODO 106: work selection - the per-worker routing identity and the
// pick itself - came out whole to pool/nextwork.rs. A glob, as
// `session`'s own is, so its callers there and in the test modules are
// unchanged; `MAX_SERVERS` is re-exported because `crate::config` names
// it as `crate::pool::MAX_SERVERS`.
mod nextwork;
pub use nextwork::MAX_SERVERS;
use nextwork::*;

// TODO 94 item E: held-bytes backpressure - the per-file park the
// extractor raises near its holds cap, consulted by `next_work`.
mod park;

// TODO 202: line-speed-aware racing - the fleet-level saturation gate
// the speculative pickers consult - plus the racing ledger (`[pool]`
// summary line, burst marker) that pool.rs used to carry.
mod saturation;

// TODO 208 item 1: the line-aware fleet cap - the pure rule the seed in
// nzbfast::get::fleet applies, and the in-run shed that walks live
// targets down to it once the §202 gauge has read the line.
pub mod linecap;

// Windowed per-server speed signals for steering and racing (M7b.2) -
// see the module doc. Inherent `impl Shared` methods, so no glob needed;
// pub for `RaceLive`, the run-level racing gauges LiveStats carries.
pub(crate) mod steer;

/// Tail fan-out (opt-in, `PoolConfig::tail_fanout`): an idle primary only
/// races a HEALTHY in-flight article once it has been on the wire this
/// long. Same reasoning as `PROMOTE_SHED_MIN_AGE`: a read younger than
/// this finishes faster than the duplicate's dispatch round-trip on any
/// healthy line, so racing it buys nothing and doubles its bytes. A tail
/// article still outstanding past this floor is exactly the straggler
/// the fan-out exists for.
const TAIL_FANOUT_MIN_AGE: Duration = Duration::from_millis(500);

/// Hedge experiment: the flat staleness bound the adaptive one clamps
/// to (and the bound used whenever hedging is off or untrained).
const HEDGE_STALE_MAX: Duration = Duration::from_secs(8);

/// Recycle experiment: consecutive dup-race losses before a connection
/// concludes it is the slow one and redials. One loss can be bad luck
/// (the endgame fan-out races healthy articles on purpose); two in a
/// row with no win between them is a pattern.
const RECYCLE_RACE_LOSSES: u32 = 2;

/// Flap breaker: established-session deaths within [`FLAP_WINDOW`]
/// before a server is clamped to one keeper connection. Six deaths in a
/// minute is a pattern no healthy provider produces; a single bounce or
/// an idle-timeout reap never reaches it.
const FLAP_DEATHS: usize = 6;
const FLAP_WINDOW: Duration = Duration::from_secs(60);

/// Per-connection pipeline depth while stream mode is active. Depth 1
/// means a promoted article waits at most one article's transfer before
/// its BODY goes out - the measured backlog floor behind the M11 seek
/// latency (window 4 × ~120 conns ≈ 360 MB of unpreemptable responses).
/// Line rate ≫ any media bitrate, so the pipelining throughput cost is
/// acceptable for the duration of a stream. `NZBFAST_STREAM_WINDOW`
/// overrides for live A/B tuning.
fn stream_window() -> usize {
    static W: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *W.get_or_init(|| {
        std::env::var("NZBFAST_STREAM_WINDOW")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|&w| w >= 1)
            .unwrap_or(1)
    })
}

/// How long a server sits out queue scans after one came up empty.
const SCAN_RETRY_MS: u64 = 100;

/// Consecutive useless sessions - connected, then failed without one
/// well-formed BODY response - before a worker bows out of this server
/// for good. The session-level twin of `max_connect_attempts`.
///
/// The pacing above is otherwise open-ended: a server that connects fine
/// and can never serve a body - a broken or exhausted account - is retried
/// at the 30 s cap forever, one paced retry per article per attempt, and
/// nothing in the loop ever concludes "this server is useless to me". On a
/// large single-server job that stretches the tail (or the whole job) from
/// minutes into hours while making no progress at all.
///
/// Bowing out is the SAME exit connect exhaustion takes - return, drop the
/// worker's `alive` count - so the rest follows from machinery that is
/// already there and already tested: `live_mask` stops counting a server
/// with no workers left, so a multi-server job routes to the healthy
/// backbone, and a single-server job reaches a truthful terminal Failed
/// through `seal_run` instead of stalling silently.
///
/// Sized against the article retry ladder rather than the clock. One
/// article whose response this client can only read as a protocol error
/// (a provider answering a takedown with a non-BODY status, say) burns
/// `article_retries + 1` sessions on its way to terminal - four at the
/// default - and a healthy server must survive a few of those back to
/// back. Twelve leaves room for three such ladders and still bows out
/// after ~4 minutes of default pacing.
const MAX_SESSION_ATTEMPTS: u32 = 12;

/// How many consecutive capacity bounces the LAST prober rides before
/// bowing out (issue #16). Its ladder caps at 2^2 x connect_backoff
/// (~8 s) - a ghost lease can expire at any moment and a 32 s nap
/// past the reopening is wall time a user watches at 0 MB/s - so 75
/// bounces is roughly ten minutes of probing at one paced dial per
/// 8 s, enough for any realistic ghost-session lease and cheap
/// against an account that is genuinely full for good.
const CAP_PROBE_BOUNCES: u32 = 75;

/// Shipped default for [`PoolConfig::outage_budget`]: 15 minutes of
/// accumulated no-session time per server per run.
///
/// Set ABOVE the ~10 minute consecutive horizon on purpose, so the two
/// never race. A server that is simply down still dies on the bounce
/// ladder exactly as before, at the same moment, with the same
/// diagnostics; this budget only reaches a server that keeps coming back
/// just long enough to rewind that ladder. Below the horizon it would
/// instead shorten every ordinary total outage, which is a behaviour
/// change nobody asked for.
const OUTAGE_BUDGET: Duration = Duration::from_secs(15 * 60);

/// [`OUTAGE_BUDGET`] in whole minutes, which is the unit the daemon
/// setting and the dashboard use. Exported so the shipped default lives
/// in exactly one place - a constant here and a literal in the settings
/// seed would drift the first time either moved.
pub fn default_outage_mins() -> u64 {
    OUTAGE_BUDGET.as_secs() / 60
}

/// M2c.4: at or below this many non-terminal articles the pool is in
/// its ENDGAME - remaining 430-laddering articles are raced across all
/// untried backbones at once instead of hop-by-hop (see `pick_dup`).
/// Small enough that the duplicate traffic is a handful of ~800 KB
/// bodies at worst, large enough to cover realistic damage tails.
const ENDGAME_MAX: usize = 64;

impl Shared {
    /// Refresh the stream-mode deadline: a reader touched the hub now.
    fn note_stream(&self) {
        let now = self.start.elapsed().as_millis() as u64;
        self.stream_until
            .store(now + STREAM_LINGER.as_millis() as u64, Ordering::Release);
    }

    /// Is a /stream reader considered attached (touched within the linger)?
    fn stream_active(&self) -> bool {
        let until = self.stream_until.load(Ordering::Acquire);
        until != 0 && (self.start.elapsed().as_millis() as u64) < until
    }

    /// Build the queue, seeding each Work's `tried_430` with the servers
    /// whose retention can't cover it. Articles outside EVERY server's
    /// retention never enter the queue (no worker could pop them - they'd
    /// rotate forever); they're returned for an immediate Missing report.
    fn new(
        reqs: Vec<ArticleReq>,
        servers: &[(ServerConfig, PoolConfig)],
    ) -> (Arc<Shared>, Vec<Arc<str>>) {
        let n_servers = servers.len();
        // F-13: every routing decision is a u32 bitmask and `server_bit`
        // is 0 past the cap, so two servers past it would be invisible
        // to each other's 430s, tiers and dup guards. The config loader
        // already refuses this (`TooManyServers`); the library entries
        // must not silently accept what the loader does not.
        assert!(
            n_servers <= MAX_SERVERS,
            "pool: {n_servers} servers exceeds MAX_SERVERS ({MAX_SERVERS}); \
             routing bitmasks cannot distinguish them"
        );
        let retentions: Vec<u32> = servers.iter().map(|(s, _)| s.retention_days).collect();
        let all = servers_mask(n_servers);
        let mut queue: VecDeque<Work> = VecDeque::with_capacity(reqs.len());
        let mut unservable: Vec<Arc<str>> = Vec::new();
        // A repeated id charges `pending` per occurrence but `claim_done`
        // credits once - the run would never turn terminal and every worker
        // would idle-loop forever. Malformed NZBs do repeat <segment> ids,
        // and this guards every pool entry point regardless of what the
        // caller built: each id is requested exactly once (the FIRST
        // occurrence, as ever). A borrowed-id prepass marks the keepers
        // so the dedup set never clones a String and dies before the
        // queue is built.
        let keep: Vec<bool> = {
            let mut seen: HashSet<&str> = HashSet::with_capacity(reqs.len());
            reqs.iter().map(|r| seen.insert(&*r.id)).collect()
        };
        let dups = keep.iter().filter(|&&k| !k).count();
        for (r, keep) in reqs.into_iter().zip(keep) {
            if !keep {
                continue;
            }
            let seed = retention_mask(&retentions, r.age_days);
            if seed & all == all {
                unservable.push(r.id);
            } else {
                // C4: the ordinal is the accepted-request index - the
                // borrowed-id prepass above already fixed
                // first-occurrence order, so this is stable per run.
                queue.push_back(Work {
                    ord: queue.len() as u32,
                    id: r.id,
                    attempts: 0,
                    promoted: false,
                    tried_430: seed,
                    tried_fail: 0,
                    dup: false,
                    prebyte_expiries: 0,
                    soft_430: 0,
                    recheck_430: 0,
                    recheck_at: 0,
                    fenced: false,
                    rearms: 0,
                    ladder: false,
                    probe: false,
                    age_days: r.age_days,
                    part: r.part,
                    file: r.file,
                });
            }
        }
        if dups > 0 {
            info!(
                target: "pool",
                "dropped {dups} duplicate article request(s) - each id is fetched once"
            );
        }
        // Same-server re-ask waste budget, sized off this run's article
        // count while it is still in hand (see [`REASK_WASTE_CAP`]).
        // Never zero: one wasted re-ask is what it costs to learn that
        // this server's copy is the damaged one, and a job too small to
        // afford that is too small to have a recovery set either.
        let reask_budget = (queue.len() / REASK_WASTE_DIV).clamp(1, REASK_WASTE_CAP);
        let pending = AtomicUsize::new(queue.len());
        let done = std::sync::Mutex::new(DoneBits::new(queue.len()));
        let shared = Arc::new(Shared {
            queue: Mutex::new(queue),
            pending,
            done,
            inflight: std::sync::Mutex::new(HashMap::new()),
            park: park::FilePark::new(),
            bytes: (0..n_servers)
                .map(|_| Arc::new(AtomicU64::new(0)))
                .collect(),
            ttfb_ms: (0..n_servers).map(|_| AtomicU64::new(0)).collect(),
            ends: (0..n_servers)
                .map(|_| std::array::from_fn(|_| AtomicU64::new(0)))
                .collect(),
            miss_answers: (0..n_servers)
                .map(|_| std::array::from_fn(|_| AtomicU64::new(0)))
                .collect(),
            blocked_ms: (0..n_servers).map(|_| AtomicU64::new(0)).collect(),
            crc_retried: std::sync::Mutex::new(HashSet::new()),
            reask_waste: AtomicUsize::new(reask_budget),
            reask_out: std::sync::Mutex::new(HashSet::new()),
            reask_out_n: AtomicUsize::new(0),
            part_latch: queue::PartLatch::default(),
            soft_rearm: std::sync::Mutex::new(HashMap::new()),
            soft_rearm_n: AtomicUsize::new(0),
            recheck_held: AtomicUsize::new(0),
            recheck_hold_ms: recheck::hold_ms(servers),
            recheck_expired: AtomicU64::new(0),
            conn_dark: ConnDark::new(servers),
            takedown: std::sync::Mutex::new(HashMap::new()),
            takedown_n: AtomicUsize::new(0),
            spent: std::sync::Mutex::new(HashMap::new()),
            spent_n: AtomicUsize::new(0),
            handed: std::sync::Mutex::new(HashMap::new()),
            steer_inbox: std::sync::Mutex::new(Vec::new()),
            done_ok: std::sync::Mutex::new(HashSet::new()),
            start: Instant::now(),
            deferred: AtomicU64::new(0),
            dups_issued: AtomicU64::new(0),
            tail_started: std::sync::Mutex::new(None),
            leases: handoff::LeaseSeat::seats(servers),
            handoff: servers.iter().find_map(|(_, c)| c.handoff.clone()),
            finished: tokio::sync::watch::Sender::new(false),
            aborted: AtomicBool::new(false),
            draining: AtomicBool::new(false),
            drained_at: std::sync::Mutex::new(None),
            finish_gate: std::sync::Mutex::new(()),
            #[cfg(test)]
            drain_send_barrier: std::sync::Mutex::new(None),
            #[cfg(test)]
            requeue_gate_barrier: std::sync::Mutex::new(None),
            cancelled: std::sync::Mutex::new(HashMap::new()),
            dup_wins: AtomicU64::new(0),
            arrival_ack: servers.iter().any(|(_, c)| c.arrival_ack),
            tail_fanout: servers.iter().any(|(_, c)| c.tail_fanout),
            tail_fanout_early: servers.iter().any(|(_, c)| c.tail_fanout_early),
            tail_taper: servers.iter().any(|(_, c)| c.tail_taper),
            taper_min: AtomicUsize::new(usize::MAX),
            hedge: servers.iter().any(|(_, c)| c.hedge),
            ttfb_hedge: servers
                .iter()
                .any(|(_, c)| c.ttfb_hedge && c.adaptive_timeout),
            suspect_pending: AtomicBool::new(false),
            art_ms: AtomicU64::new(0),
            body_bytes_ewma: AtomicU64::new(0),
            hedges_issued: AtomicU64::new(0),
            ttfb_hedges_issued: AtomicU64::new(0),
            live: servers.iter().find_map(|(_, c)| c.live.clone()),
            race_note_at: AtomicU64::new(0),
            races_at_note: AtomicU64::new(0),
            wire_note_at: AtomicU64::new(0),
            spares: (0..n_servers)
                .map(|_| std::sync::Mutex::new(None))
                .collect(),
            spare_filler_started: (0..n_servers).map(|_| AtomicBool::new(false)).collect(),
            flap_deaths: (0..n_servers)
                .map(|_| std::sync::Mutex::new(VecDeque::new()))
                .collect(),
            flap_keeper: (0..n_servers).map(|_| AtomicUsize::new(0)).collect(),
            sessions: (0..n_servers).map(|_| AtomicUsize::new(0)).collect(),
            flap_cap_seen: (0..n_servers).map(|_| AtomicUsize::new(0)).collect(),
            flap_noted: (0..n_servers).map(|_| AtomicBool::new(false)).collect(),
            bare_refuser: (0..n_servers).map(|_| AtomicBool::new(false)).collect(),
            fence_ok: (0..n_servers).map(|_| AtomicBool::new(false)).collect(),
            fence_dud: (0..n_servers).map(|_| AtomicUsize::new(0)).collect(),
            fence_off: (0..n_servers).map(|_| AtomicBool::new(false)).collect(),
            levels: servers.iter().map(|(s, _)| s.level).collect(),
            alive: (0..n_servers).map(|_| AtomicUsize::new(0)).collect(),
            handoff_out: (0..n_servers).map(|_| AtomicUsize::new(0)).collect(),
            handoff_retired: (0..n_servers).map(|_| AtomicUsize::new(0)).collect(),
            admitted: (0..n_servers).map(|_| AtomicUsize::new(0)).collect(),
            admit_wake: (0..n_servers).map(|_| tokio::sync::Notify::new()).collect(),
            connected: (0..n_servers).map(|_| AtomicBool::new(false)).collect(),
            left_mid_run: (0..n_servers).map(|_| AtomicBool::new(false)).collect(),
            auth: (0..n_servers).map(|_| AuthState::default()).collect(),
            workers_live: AtomicUsize::new(0),
            parked: (0..n_servers).map(|_| AtomicUsize::new(0)).collect(),
            parked_total: AtomicUsize::new(0),
            workers_born: AtomicUsize::new(0),
            stream_until: AtomicU64::new(0),
            promote_gen: tokio::sync::watch::Sender::new(0),
            promoted_pending: AtomicUsize::new(0),
            promoted_ids: std::sync::Mutex::new(HashSet::new()),
            scan_futile: (0..n_servers).map(|_| AtomicU64::new(u64::MAX)).collect(),
            inflight_gen: AtomicU64::new(0),
            dup_futile: (0..n_servers).map(|_| AtomicU64::new(u64::MAX)).collect(),
            dup_futile_gen: (0..n_servers).map(|_| AtomicU64::new(0)).collect(),
            inflight_body_bytes: AtomicU64::new(0),
            srv_rate_val: (0..n_servers).map(|_| AtomicU64::new(0)).collect(),
            srv_rate_at: (0..n_servers).map(|_| AtomicU64::new(u64::MAX)).collect(),
            srv_art_ms: (0..n_servers).map(|_| AtomicU64::new(0)).collect(),
            art_note_at: AtomicU64::new(0),
            steer_depth: servers.iter().any(|(_, c)| c.steer_depth),
            steer_clamped: (0..n_servers).map(|_| AtomicBool::new(false)).collect(),
            race_envelope: servers.iter().any(|(_, c)| c.race_envelope),
            sat: saturation::Saturation::new(servers),
            race_escape: servers.iter().any(|(_, c)| c.race_escape),
            line_cap: linecap::LineCap::new(servers),
            block_bits: steer::block_bits(servers),
            budget_bytes: servers
                .iter()
                .map(|(_, c)| c.budget_bytes.unwrap_or(0))
                .collect(),
            budget_noted: (0..n_servers).map(|_| AtomicBool::new(false)).collect(),
            dup_bytes_lost: AtomicU64::new(0),
            stat_probe: servers.iter().any(|(_, c)| c.stat_probe),
        });
        (shared, unservable)
    }

    /// NZBFAST_POOL_DEBUG=1: dump unresolved queue/inflight state from a
    /// worker's idle branch, at most once per 5 s. Diagnostic only.
    fn debug_dump_idle(&self) {
        static LAST: AtomicU64 = AtomicU64::new(0);
        let now = self.start.elapsed().as_secs();
        let last = LAST.load(Ordering::Relaxed);
        if now < last + 5
            || LAST
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        let alive: Vec<usize> = self
            .alive
            .iter()
            .map(|a| a.load(Ordering::Relaxed))
            .collect();
        // `sessions` and `live` beside `alive` since 30 Aug 2026: the
        // incident behind `gates::CONN_DARK` read `alive=[9, 17, 17]`
        // with 399 articles pinned, and nothing said thirty-four of
        // those workers held no socket.
        let sessions: Vec<usize> = self
            .sessions
            .iter()
            .map(|a| a.load(Ordering::Relaxed))
            .collect();
        info!(
            target: "pool-debug",
            "t={now}s pending={} alive={alive:?} sessions={sessions:?} live={:06b}",
            self.pending.load(Ordering::Relaxed),
            self.live_mask(),
        );
        if let Ok(q) = self.queue.try_lock() {
            info!(target: "pool-debug", "queue={} item(s)", q.len());
            for w in q.iter().take(30) {
                info!(
                    target: "pool-debug",
                    "  q {} tried_430={:06b} tried_fail={:06b} attempts={} dup={}",
                    w.id, w.tried_430, w.tried_fail, w.attempts, w.dup
                );
            }
        } else {
            info!(target: "pool-debug", "queue lock busy");
        }
        let inf = self.inflight.lock_ok();
        info!(target: "pool-debug", "inflight={} entr(ies)", inf.len());
        for (id, i) in inf.iter().take(30) {
            info!(
                target: "pool-debug",
                "  inflight {} srv={} age={:.1}s dups={} tried_430={:06b}",
                id,
                i.server,
                i.dispatched.elapsed().as_secs_f64(),
                i.dups,
                i.tried_430
            );
        }
    }

    /// Mark one article terminal; wakes every worker when the last lands.
    fn complete_one(&self) {
        if self.pending.fetch_sub(1, Ordering::AcqRel) == 1 {
            #[cfg(test)]
            {
                let pair = self.drain_send_barrier.lock_ok().clone();
                if let Some((entered, released)) = pair {
                    entered.wait();
                    released.wait();
                }
            }
            self.finish_if_drained();
        }
    }

    /// A decrement just landed `pending` on zero: decide, under
    /// `finish_gate`, whether the run really drained. A concurrent
    /// [`QueueControl::requeue`] raises `pending` under the same gate
    /// before it checks `finished`, so the re-read here and requeue's
    /// check cannot both come up in the revived-but-finished state that
    /// left work behind: whichever takes the gate second sees the other
    /// side's write. Staying silent on a revived count is correct - the
    /// requeue owns the articles now, and THEIR last completion (or its
    /// own rollback) reaches this same decision again.
    fn finish_if_drained(&self) {
        let _gate = self.finish_gate.lock_ok();
        if self.pending.load(Ordering::Acquire) == 0 {
            self.mark_drained();
            let _ = self.finished.send(true);
        }
    }

    /// The last article just went terminal: latch the moment and mark
    /// the graph. This is the marker that stops the natural end-of-job
    /// throughput fall from reading as a fault - the line drops to zero
    /// here because there is nothing left to fetch, not because
    /// anything broke.
    fn mark_drained(&self) {
        *self.drained_at.lock_ok() = Some(Instant::now());
        if let Some(l) = &self.live {
            l.note_run(
                "drained",
                "all article data is in - nothing left to download",
            );
        }
    }

    /// First-emitter check: true exactly once per article. `ord` is
    /// the article's [`Work::ord`] (C4 - the bit arbitrated on); the
    /// id is still taken for the spent-map cleanup, which stays
    /// message-id keyed.
    fn claim_done(&self, id: &str, ord: u32) -> bool {
        // A terminal article has no ladder left to route, so drop its
        // spent bits with it - the map is keyed by message-id and would
        // otherwise carry every rescued article to the end of the run.
        if self.spent_n.load(Ordering::Acquire) > 0 {
            let mut m = self.spent.lock_ok();
            if m.remove(id).is_some() {
                self.spent_n.store(m.len(), Ordering::Release);
            }
        }
        self.done.lock_ok().claim(ord)
    }

    /// §129 3g: a session has just shown it was reading responses off by
    /// one, so every bare refusal in its ledger is positional evidence
    /// collected from a misaligned socket - void the passes those
    /// refusals spent, so the next refusal for those articles is first
    /// evidence again rather than a confirmation.
    ///
    /// `ids` is the window since that session last read an id it could
    /// check, not its whole history: a desync is monotone, so anything
    /// before a checked id came off an aligned socket. Callers decide
    /// what counts as showing it - an id mismatch or an unusable status
    /// is proof, a stall with requests outstanding is the same event
    /// seen from the end of the pipeline.
    ///
    /// The ledger is capped, and so is this map: the cost of a re-arm is
    /// at most one extra dispatch per article, but an unbounded map on a
    /// 50,000-article job is a leak.
    fn void_soft_430(&self, ids: &VecDeque<Arc<str>>, group_bits: u32) {
        if ids.is_empty() {
            return;
        }
        let mut m = self.soft_rearm.lock_ok();
        for id in ids {
            if m.len() >= SOFT_REARM_MAX && !m.contains_key(id) {
                break;
            }
            *m.entry(id.clone()).or_insert(0) |= group_bits;
        }
        self.soft_rearm_n.store(m.len(), Ordering::Release);
    }

    /// §129 3g: a fence went unanswered. Harmless when this server has
    /// answered one before - that is the withheld-response fault itself,
    /// seen from the end of the pipeline. But a provider that ignores
    /// DATE outright would fail EVERY fence, so if we have never seen
    /// one answered, the second dud retires fencing for this server and
    /// says so once.
    fn note_fence_dud(&self, idx: usize, cfg: &PoolConfig) {
        if self.fence_ok[idx].load(Ordering::Acquire) {
            return;
        }
        if self.fence_dud[idx].fetch_add(1, Ordering::AcqRel) + 1 < 2 {
            return;
        }
        // Latch the retirement, not `bare_refuser`: the suspect logic
        // in `handle_missing` re-arms that on the very next bare 430,
        // so clearing it retires nothing and re-notes forever.
        if !self.fence_off[idx].swap(true, Ordering::AcqRel)
            && let Some(l) = &cfg.live
        {
            l.note(
                idx,
                "fence-off",
                "this provider does not answer DATE, so its responses cannot be checked for alignment - continuing without the check",
            );
        }
    }

    /// Spend one unit of the same-server re-ask budget for `id`, or
    /// answer false when the run has wasted its allowance already.
    ///
    /// The id is remembered so [`Self::settle_reask`] can hand the unit
    /// back if the second copy is good. Asked only on the path that has
    /// already decided to re-ask, so the lock here is off the hot path
    /// by construction.
    fn take_reask(&self, id: &Arc<str>) -> bool {
        if self
            .reask_waste
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_sub(1))
            .is_err()
        {
            return false;
        }
        let mut out = self.reask_out.lock_ok();
        out.insert(id.clone());
        self.reask_out_n.store(out.len(), Ordering::Release);
        true
    }

    /// Settle a same-server re-ask: `crc_ok` says whether the body that
    /// just came back for `id` passed its own CRC.
    ///
    /// A pass refunds the unit - the re-ask did its job, so it was not
    /// waste and the budget must not shrink for it. A second bad copy
    /// keeps the unit spent, which is the only thing that ever exhausts
    /// the budget. Ids this run never re-asked cost one relaxed load.
    fn settle_reask(&self, id: &str, crc_ok: bool) {
        if self.reask_out_n.load(Ordering::Acquire) == 0 {
            return;
        }
        let mut out = self.reask_out.lock_ok();
        let was_reasked = out.remove(id);
        self.reask_out_n.store(out.len(), Ordering::Release);
        drop(out);
        if was_reasked && crc_ok {
            self.reask_waste.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// §129 3g: the group bits whose bare-refusal pass this article must
    /// get back, consumed on read. Lock-free when nothing is pending,
    /// which is every run that never met a desynced session.
    fn take_soft_rearm(&self, id: &str) -> u32 {
        if self.soft_rearm_n.load(Ordering::Acquire) == 0 {
            return 0;
        }
        let mut m = self.soft_rearm.lock_ok();
        let bits = m.remove(id).unwrap_or(0);
        self.soft_rearm_n.store(m.len(), Ordering::Release);
        bits
    }

    /// Record a CHARGED takedown-flavoured refusal for this article
    /// (see the `takedown` field doc). Same fold discipline as
    /// `tried_430`: the whole mirror group's bits, because the evidence
    /// is about the backbone, not the reseller.
    fn note_takedown(&self, id: &Arc<str>, group_bits: u32) {
        let mut m = self.takedown.lock_ok();
        *m.entry(id.clone()).or_insert(0) |= group_bits;
        self.takedown_n.store(m.len(), Ordering::Release);
    }

    /// Drain an article's takedown evidence at its terminal verdict.
    /// Lock-free when nothing was ever flagged, which is every run on
    /// backbones that never name the removal.
    fn take_takedown(&self, id: &str) -> u32 {
        if self.takedown_n.load(Ordering::Acquire) == 0 {
            return 0;
        }
        let mut m = self.takedown.lock_ok();
        let bits = m.remove(id).unwrap_or(0);
        self.takedown_n.store(m.len(), Ordering::Release);
        bits
    }

    /// Post-handoff terminal bookkeeping for a Done delivery. Legacy
    /// (no consumer verdicts): the channel owns the body now, and a
    /// lingering `done_ok` entry would keep ±slack neighbors "live"
    /// forever - clear it and complete. Steer mode: a DELIVERED body
    /// keeps both its `done_ok` and `handed` entries until the
    /// consumer's `note_decoded` verdict; an undelivered one (channel
    /// closed - the consumer is gone) can never be acked, so it
    /// finalizes here.
    fn settle_handoff(&self, steer: bool, ack: bool, delivered: bool, arrived: &str) {
        if steer && delivered {
            return;
        }
        if steer {
            self.handed.lock_ok().remove(arrived);
        }
        // TODO 121.4: an acking consumer owns the done_ok removal
        // (note_settled after decode+write), so the entry keeps the
        // article "live" through the channel buffer and the consumer's
        // in-hand batch - the two windows a handoff-side removal left
        // dark. An undelivered body (channel closed) has no consumer
        // left to ack it and settles here as before.
        if !(ack && delivered) {
            self.done_ok.lock_ok().remove(arrived);
        }
        self.complete_one();
    }

    // The inflight-entry lifecycle (register_inflight / note_found /
    // deregister_inflight / deregister_inflight_done) lives with the
    // dup race that reads the map: pool/hedge.rs.
}

/// Fetch every article in `reqs`, streaming outcomes to `out` as they land.
/// Resolves when all work is terminal. Consumers decode/write concurrently -
/// that's the overlap that makes the zero-copy pipeline work.
pub async fn fetch_all(
    server: &ServerConfig,
    cfg: &PoolConfig,
    reqs: Vec<ArticleReq>,
    out: mpsc::Sender<FetchOutcome>,
) -> PoolStats {
    fetch_all_multi(&[(server.clone(), cfg.clone())], reqs, out)
        .await
        .pop()
        .unwrap_or_default()
}

/// Multi-server variant: all servers' workers pull from ONE shared queue, so
/// faster providers naturally take more of the work - this is both the soak
/// mode (aggregate several accounts past any single provider's cap) and the
/// foundation for Phase 3 tiers. Returns per-server stats, same order as
/// `servers`.
///
/// Note: a 430 Missing is currently terminal even in multi-server mode
/// (fine for soak benches on fresh articles); per-server retry of missing
/// articles is Phase 3a's failedServers ledger.
///
/// # Panics
///
/// If `servers` holds more than [`MAX_SERVERS`] entries - the routing
/// bitmasks cannot distinguish them (F-13).
pub async fn fetch_all_multi(
    servers: &[(ServerConfig, PoolConfig)],
    reqs: Vec<ArticleReq>,
    out: mpsc::Sender<FetchOutcome>,
) -> Vec<PoolStats> {
    fetch_all_multi_ctl(servers, reqs, out, None).await
}

/// `fetch_all_multi` with an optional queue-reorder handle (M11 seeks).
///
/// # Panics
///
/// If `servers` holds more than [`MAX_SERVERS`] entries - the routing
/// bitmasks cannot distinguish them (F-13).
pub async fn fetch_all_multi_ctl(
    servers: &[(ServerConfig, PoolConfig)],
    reqs: Vec<ArticleReq>,
    out: mpsc::Sender<FetchOutcome>,
    ctl: Option<&QueueControl>,
) -> Vec<PoolStats> {
    // A zero here is not a configuration, it is a hang.
    //
    // `connections: 0` spawns no workers at all, so the run returns with
    // every article still non-terminal and no outcome emitted for any of
    // them. `window: 0` is worse: workers start, but the top-up loop can
    // never admit an article, so each one sleeps forever with pending > 0
    // and `finished` never fires - so the join deadline never arms
    // either. Both are reachable straight from the CLI (`get --window 0`)
    // and neither reports anything to the user.
    //
    // Clamped here rather than at each of the several CLI call sites, so
    // the daemon and every other caller of the public pool API get the
    // same floor - and ONCE, ahead of everything, as `fetch_all_sharded`
    // does, because the dealer below reads `connections` too.
    let mut servers = servers.to_vec();
    for (_, cfg) in servers.iter_mut() {
        cfg.connections = cfg.connections.max(1);
        cfg.window = cfg.window.max(1);
    }
    let servers = &servers[..];
    let (shared, unservable) = Shared::new(reqs, servers);
    if let Some(c) = ctl {
        c.attach(&shared);
    }
    // Outside every server's retention: Missing without a single request.
    for id in unservable {
        let _ = out
            .send(FetchOutcome::Missing {
                id,
                cause: MissingCause::Retention,
            })
            .await;
    }

    let mut workers = Vec::new();
    let counters: Vec<_> = (0..servers.len())
        .map(|si| {
            let z = || Arc::new(AtomicU64::new(0));
            (shared.bytes[si].clone(), z(), z())
        })
        .collect();
    // Hold one reference on the run-wide live count for as long as we are
    // still creating workers. Spawned tasks run on other runtime threads
    // immediately, so without this the first worker of a dead server can
    // fail its connect, find itself alone in the count, and seal the run
    // before its siblings have been born.
    shared.workers_live.fetch_add(1, Ordering::AcqRel);
    // Deal the WHOLE fleet before spawning any of it, through the same
    // `deal_shard_plans` the sharded path uses (one shard is one plan,
    // in configured order): every `WorkerLife` is born before it
    // returns, so `alive` - and with it `live_mask` and `required_mask`
    // - counts the complete fleet from the first instruction any worker
    // runs. Birthing inside the spawn pass, as this path used to while
    // claiming to pin the invariant "by counting from spawn", let
    // server 0's workers route against a fleet that did not exist yet.
    // The measurement, and what it cost, are on
    // `every_worker_life_is_born_by_the_one_dealer`, which refuses a
    // second birth site.
    for (si, slot, life) in deal_shard_plans(&shared, servers, 1).into_iter().flatten() {
        let (server, cfg) = servers[si].clone();
        let shared = shared.clone();
        let out = out.clone();
        let ctx = ctx_for(servers, si);
        let connects = counters[si].1.clone();
        let reconnects = counters[si].2.clone();
        let ramp = cfg.ramp_delay * slot;
        workers.push(tokio::spawn(async move {
            worker(
                &server, &cfg, ctx, shared, out, connects, reconnects, life, ramp, slot,
            )
            .await;
        }));
    }
    // The fleet is complete; from here the workers own the live count.
    shared.workers_live.fetch_sub(1, Ordering::AcqRel);
    // `out` moves into join_fleet, which drops it once the run is sealed:
    // the channel must not close until every article has its outcome.
    join_fleet(&shared, out, workers).await;
    shared.report_diagnostics();

    stats::run_stats(&shared, &counters)
}

/// How long a worker may outlive the run's terminal state before its join
/// is abandoned. Once every article is terminal (or the run is aborted),
/// workers only have goodbyes left - sub-second on a healthy connection.
const EXIT_GRACE: Duration = Duration::from_secs(5);

/// Join every worker, but never let a straggler outlive a finished run.
/// A worker parked on an await with no timeout - a mute peer mid-QUIT, a
/// half-open TCP connection, a TLS handshake that never answers - would
/// otherwise hang the whole fetch AFTER its bytes are complete (seen live
/// on a 190 GB job: one provider ACKed QUIT, sent no goodbye, and the run
/// never returned). Once `finished` fires, stragglers get `EXIT_GRACE`,
/// then are aborted; dropping the task closes its connection, which is
/// exactly what QUIT was for. Runs that never reach terminal state keep
/// the old unbounded join - the deadlock there is someone else's bug.
///
/// This is also where the run's terminal-state postcondition is enforced.
/// A worker seals the run when it is the last to retire, but a worker that
/// PANICKED never retired, and one abandoned at the grace deadline never
/// finished its pipeline - either can drop the live count to zero with no
/// one left holding an outcome sender. `join_fleet` still holds one, so it
/// gets the last word: seal whatever is outstanding, then report if the
/// invariant somehow still does not hold.
///
/// A panicking worker is a bug in this pool, and it used to be invisible:
/// `JoinError` was discarded and its pipeline's articles simply went
/// quiet. It is now logged with its payload and folded into the sealed
/// articles' error text, so it surfaces in the job's own failure record
/// rather than only in a log nobody reads. We do NOT resume the unwind -
/// this runs inside a daemon serving other jobs, and turning one worker's
/// bug into a whole-download abort trades a reported failure for an
/// unreported one.
async fn join_fleet(
    shared: &Arc<Shared>,
    out: mpsc::Sender<FetchOutcome>,
    workers: Vec<tokio::task::JoinHandle<()>>,
) {
    let mut finished = shared.finished.subscribe();
    let deadline = async move {
        let _ = finished.wait_for(|f| *f).await;
        tokio::time::sleep(EXIT_GRACE).await;
    };
    tokio::pin!(deadline);
    let mut expired = false;
    let mut panics = 0usize;
    let mut note_panic = |r: Result<(), tokio::task::JoinError>| {
        if let Err(e) = r
            && e.is_panic()
        {
            panics += 1;
            error!(target: "pool", "worker panicked - its articles are sealed Failed below: {e}");
        }
    };
    for mut w in workers {
        if !expired {
            let joined = tokio::select! {
                r = &mut w => Some(r),
                _ = &mut deadline => {
                    expired = true;
                    warn!(
                        target: "pool",
                        "worker still parked {}s after the run went terminal \
                         (wedged connection?) - abandoning its goodbye",
                        EXIT_GRACE.as_secs()
                    );
                    None
                }
            };
            if let Some(r) = joined {
                note_panic(r);
                continue;
            }
        }
        w.abort();
        // A cancelled task is not a panic - only report real ones.
        note_panic(w.await);
    }
    // TODO 307 item 1: a code rather than a sentence. `seal_run` derives
    // the wording from it, so the article's typed reason and the text
    // sent beside it cannot part company.
    let code = if panics > 0 {
        FailCode::WorkerPanic
    } else {
        FailCode::FleetExhausted
    };
    seal_run(shared, &out, code).await;
    let left = shared.pending.load(Ordering::Acquire);
    if left > 0
        && shared.workers_live.load(Ordering::Acquire) == 0
        && !shared.aborted.load(Ordering::Acquire)
        && !shared.draining.load(Ordering::Acquire)
    {
        // Neither the queue nor the inflight map named these, so the pool
        // cannot report them itself. Loud, because it means an article
        // went missing from this module's own bookkeeping. Gated on being
        // the run-wide last owner (workers_live == 0, the same condition
        // seal_run uses): on the sharded path an early shard joins its
        // fleet while other shards still legitimately own pending work.
        error!(
            target: "pool",
            "BUG: fleet joined with {left} article(s) non-terminal and unaccounted \
             for - the caller will see slots with no outcome"
        );
    }
}

/// Deal every configured connection round-robin across `shards.max(1)`
/// plans as (server index, per-server ramp step, pre-born life),
/// birthing each [`WorkerLife`] on the spot. THE ONE BIRTH SITE, for
/// both entry paths: the whole fleet is counted in `alive` and
/// `workers_live` before this returns, so no worker - shard thread or
/// spawned task - can route against a fleet that is still being built.
/// `fetch_all_multi_ctl` passes one shard, which is one plan holding
/// every worker. A plan dropped unspawned (a shard runtime that failed
/// to build) releases its lives through `Drop`, exactly like its
/// workers dying.
fn deal_shard_plans(
    shared: &Arc<Shared>,
    servers: &[(ServerConfig, PoolConfig)],
    shards: usize,
) -> Vec<Vec<(usize, u32, WorkerLife)>> {
    let n_shards = shards.max(1);
    let mut plans: Vec<Vec<(usize, u32, WorkerLife)>> = (0..n_shards).map(|_| Vec::new()).collect();
    let mut next_shard = 0usize;
    for (si, (_, cfg)) in servers.iter().enumerate() {
        for ci in 0..cfg.connections {
            plans[next_shard % n_shards].push((si, ci as u32, WorkerLife::birth(shared, si)));
            next_shard += 1;
        }
    }
    plans
}

/// Sharded variant: split all servers' connections across `shards`
/// independent tokio runtimes (each on its own OS threads with its OWN
/// kqueue/epoll I/O driver), all pulling one shared queue. This is the fix
/// for the single-I/O-driver per-process throughput ceiling (measured:
/// 4.1 Gbps per process at 9% CPU). Blocking call - run it via
/// `tokio::task::spawn_blocking` from async contexts.
///
/// # Panics
///
/// If `servers` holds more than [`MAX_SERVERS`] entries - the routing
/// bitmasks cannot distinguish them (F-13).
pub fn fetch_all_sharded(
    servers: Vec<(ServerConfig, PoolConfig)>,
    reqs: Vec<ArticleReq>,
    out: mpsc::Sender<FetchOutcome>,
    shards: usize,
    ctl: Option<&QueueControl>,
) -> Vec<PoolStats> {
    // The same floor fetch_all_multi_ctl applies, for the same reason: a
    // zero here is not a configuration, it is a hang. This path is the
    // daemon's production one, so it needs the clamp at least as much.
    let mut servers = servers;
    for (_, cfg) in servers.iter_mut() {
        cfg.connections = cfg.connections.max(1);
        cfg.window = cfg.window.max(1);
    }
    let (shared, unservable) = Shared::new(reqs, &servers);
    // Same pause/abort/state-dump hookup as fetch_all_multi_ctl: the ctl
    // attaches to Shared, which every shard's workers already poll - so
    // the daemon keeps its whole control surface on the sharded path.
    if let Some(c) = ctl {
        c.attach(&shared);
    }
    // Outside every server's retention: Missing without a single request.
    // (Blocking send is fine - this whole function is documented blocking.)
    for id in unservable {
        let _ = out.blocking_send(FetchOutcome::Missing {
            id,
            cause: MissingCause::Retention,
        });
    }

    let counters: Vec<_> = servers
        .iter()
        .enumerate()
        .map(|(si, _)| {
            (
                shared.bytes[si].clone(),
                Arc::new(AtomicU64::new(0)),
                Arc::new(AtomicU64::new(0)),
            )
        })
        .collect();

    // Deal the fleet BEFORE any shard thread starts - every worker's
    // life is born inside deal_shard_plans, so `alive` (which feeds
    // `live_mask`/`required_mask`) and `workers_live` count the complete
    // fleet from here. Shard threads come up in whatever order the OS
    // schedules them: birthing inside each shard let an early shard read
    // a partial fleet - a 430 there became a premature unanimous
    // Missing, and a fill server could take queued work against
    // required_mask == 0. Same invariant the single-runtime path pins by
    // counting from spawn. The pre-born lives also make a spawn gate
    // unnecessary: an early-dying shard cannot seal a run whose other
    // shards are still being built, because those shards' workers are
    // already in the live count.
    let plans = deal_shard_plans(&shared, &servers, shards);

    let servers = Arc::new(servers);
    let counters = Arc::new(counters);
    let mut threads = Vec::new();
    for (i, plan) in plans.into_iter().enumerate() {
        let servers = servers.clone();
        let counters = counters.clone();
        let shared = shared.clone();
        let out = out.clone();
        // Test seam (F-15): a denied ordinal answers as the OS does on
        // thread exhaustion, so the Err arm below is reachable in-tree.
        #[cfg(test)]
        let denied = SHARD_SPAWN_DENY.with(|d| d.get()) & (1u64 << i.min(63)) != 0;
        #[cfg(not(test))]
        let denied = false;
        let builder =
            (!denied).then(|| std::thread::Builder::new().name(format!("nzbfast-shard-{i}")));
        let spawned = match builder {
            None => Err(std::io::Error::other("injected shard-thread spawn refusal")),
            Some(b) => b.spawn(move || {
                let rt = match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        // This shard never spawned its workers; returning
                        // drops `plan`, whose pre-born lives release their
                        // head-counts through `Drop` exactly as if the
                        // workers had died. Panicking here instead leaked
                        // the counts and made every surviving shard believe
                        // work could still finish, suppressing terminal
                        // outcomes.
                        warn!(target: "pool", "shard runtime: {e}");
                        return;
                    }
                };
                rt.block_on(async move {
                    let mut tasks = Vec::new();
                    for (si, ramp_step, life) in plan {
                        let ctx = ctx_for(&servers, si);
                        let (server, cfg) = servers[si].clone();
                        let (_, connects, reconnects) = counters[si].clone();
                        let shared = shared.clone();
                        let out = out.clone();
                        // `ramp_step` is the per-server worker ordinal, so it
                        // doubles as the live-target slot.
                        let ramp = cfg.ramp_delay * ramp_step;
                        tasks.push(tokio::spawn(async move {
                            worker(
                                &server, &cfg, ctx, shared, out, connects, reconnects, life, ramp,
                                ramp_step,
                            )
                            .await;
                        }));
                    }
                    // Each shard joins its own tasks; `seal_run` is gated on
                    // the run-wide live count, so only the shard whose workers
                    // are genuinely the last ones out seals anything.
                    join_fleet(&shared, out, tasks).await;
                });
            }),
        };
        match spawned {
            Ok(t) => threads.push(t),
            // Same symmetry as the runtime-build failure inside the
            // closure (F-15): the unspawned closure is dropped here and
            // takes `plan` with it, so its pre-born lives release their
            // head-counts and the other shards can still seal. A panic
            // from `thread::spawn` leaked them.
            Err(e) => warn!(target: "pool", "shard thread {i}: {e}"),
        }
    }
    for t in threads {
        let _ = t.join();
    }
    // If every shard failed before it could enter an async `join_fleet`,
    // there is nobody left to run the async terminal seal. All shard
    // threads are joined here, so the queue and inflight maps are
    // uncontended and can be sealed on this documented blocking path.
    // Every shard runtime is joined with work still queued, so nothing
    // is left that could fetch these articles - the same fact
    // `seal_run`'s own wind-down reports, reached from the sharded path.
    seal_run_blocking(&shared, &out, FailCode::FleetExhausted);
    drop(out);
    shared.report_diagnostics();

    stats::run_stats(&shared, &counters)
}

#[cfg(test)]
mod inline_tests;

#[cfg(test)]
mod event_ring_tests;

#[cfg(test)]
mod ratelimit_tests;

#[cfg(test)]
mod dup_meta_tests;

#[cfg(test)]
mod interning_tests;
#[cfg(test)]
mod queue_tests;

#[cfg(test)]
mod giveup_tests;

#[cfg(test)]
mod unit_tests;

#[cfg(test)]
mod seal_tests;

#[cfg(test)]
mod steer_seam_tests;

#[cfg(test)]
mod rig_tests;

#[cfg(test)]
mod fault_rigs;

#[cfg(test)]
mod tail_rigs;
