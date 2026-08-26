//! Mock NNTP server for the chaos suite (design: M4): a minimal in-memory
//! NNTP test server. Serves yEnc articles from memory over plain TCP with
//! injectable failure modes: missing articles (430), corrupt payloads,
//! truncated bodies, mid-response stalls, and periodic connection drops.
//!
//! Runs on a real socket so the full client stack - TLS-less connect,
//! AUTHINFO, pipelining, timeouts, reconnects - is exercised end to end.

use crate::sync::MutexExt;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

// The rig's DNS half (§129 3a). Everything above this line injects
// faults AFTER a connection exists; `dns` injects them before one does.
pub mod dns;

/// Failure injection for one mock server.
#[derive(Default, Clone)]
pub struct Chaos {
    /// Message-ids (with angle brackets) answered with 430.
    pub missing: HashSet<String>,
    /// Ids whose decoded payload gets a byte flipped (yEnc CRC fails).
    pub corrupt: HashSet<String>,
    /// Ids whose body is cut off mid-payload (connection then closed).
    pub truncate: HashSet<String>,
    /// Ids that hang after the status line (stall detection). Each id
    /// stalls only its FIRST request - retries succeed, so tests prove
    /// recovery rather than permanent failure.
    pub stall: HashSet<String>,
    /// Drop the connection after this many successful BODY responses
    /// (0 = never). Tests reconnect + requeue.
    pub drop_after: u64,
    /// Fixed delay before every successful BODY response (a "slow
    /// server" - per-connection throughput ≈ article_size / delay).
    pub delay_ms: u64,
    /// Echo the requested message-id on the refusal line ("430 no such
    /// article <id>") instead of the bare form. Real providers split
    /// both ways, and the difference is not cosmetic: the pool treats an
    /// UN-echoed 430 as positional-only evidence and requeues the
    /// article uncharged for one confirming repeat (see `Work::soft_430`
    /// - a frontend that dropped a pipelined response would otherwise
    /// misfile the refusal onto the next article). So a non-echoing
    /// provider is asked up to TWICE for every article it does not have,
    /// and an echoing one exactly once. §129 3d's baseline has to price
    /// both, because which family the provider belongs to doubles the
    /// cost of its absence.
    pub echo_missing_id: bool,
    /// Fixed delay before every 430. `delay_ms` deliberately does not
    /// cover the refusal path, but a real 430 is a full round trip like
    /// any other (~30-80 ms transatlantic), and a wholly-dead post is
    /// nothing BUT refusals - so how long it takes to drive a dead queue
    /// to terminal is set by exactly this number. Zero keeps every
    /// existing test at localhost speed.
    pub missing_delay_ms: u64,
    /// Swallow QUIT silently: no goodbye, connection held open. Models a
    /// provider that ACKs the QUIT at TCP level but never answers it
    /// (seen live; used to park the exit path forever).
    pub mute_quit: bool,
    /// Read DATE and answer it with nothing, forever, while every other
    /// command is served normally. RFC 3977 makes DATE mandatory, but a
    /// frontend that never implemented it is the fault §129 3g's
    /// `fence_dud` retirement exists for: every fence this server is
    /// sent goes unanswered, so without retirement each session dies on
    /// its own alignment check and the job never finishes.
    pub mute_date: bool,
    /// Accept connections but never send the greeting - the connection
    /// just sits. Models a mute/half-dead frontend; a worker stuck in
    /// connect() must not hang a finished run's join.
    pub mute_greeting: bool,
    /// Reject OVER (but serve XOVER) with "400 Unrecognized command" -
    /// models XOVER-only providers (Newshosting) for the client's
    /// over_supported latch.
    pub xover_only: bool,
    /// Answer every OVER *and* XOVER with "411 no such newsgroup" - a
    /// genuine failure, as opposed to the empty-range 423 the mock serves
    /// on its own. The client must keep telling the two apart.
    pub over_rejected: bool,
    /// Accept `XFEATURE COMPRESS GZIP` (290) and serve subsequent
    /// OVER/XOVER bodies as one gzip stream followed by a plain-text
    /// ".\r\n" terminator (the Highwinds TERMINATOR variant).
    pub gzip_headers: bool,
    /// With `gzip_headers`: flip one byte in the middle of every gzip
    /// overview stream after the header magic - a corrupted compressed
    /// payload from a broken cache node. The client must fail the READ
    /// cleanly (a session error it can requeue), never accept garbage
    /// rows or hang the inflater.
    pub gzip_corrupt: bool,
    /// Reject POST with "440 posting not allowed" - models providers
    /// that only accept peer-fed articles, forcing the IHAVE fallback.
    pub post_rejected: bool,
    /// Answer the first `n` BODY requests (counted across ALL connections)
    /// with "502 byte limit exceeded" instead of a body - a non-BODY status
    /// the client can only treat as a protocol error, so it drops the
    /// session and reconnects. `Some(u64::MAX)` models the broken-account
    /// shape: connect and AUTH always succeed, every BODY fails, forever.
    /// A finite `n` models an account that starts working again.
    pub body_error: Option<u64>,
    /// Answer AUTHINFO PASS with "481 authentication failed" - models a
    /// wrong password or an expired account. TCP connects fine every
    /// time, so without a per-server circuit break the worker burns its
    /// whole connect budget on a session it can use for nothing.
    pub auth_rejected: bool,
    /// Replace the refusal line `auth_rejected` sends. The point is the
    /// TEXT: a capacity refusal and a bad credential share reply code
    /// 481, and only the wording tells them apart, so the tests drive
    /// the real thing (`481 max simultaneous IP addresses reached`)
    /// rather than a code.
    pub auth_refusal_text: Option<String>,
    /// Upload-side failure injection (POST/IHAVE).
    pub post: PostChaos,
    /// Bandwidth model (all zero = off, existing tests unaffected).
    pub throttle: Throttle,
    /// Delay before the greeting on every accepted connection - the
    /// localhost stand-in for what a real dial costs (TCP + TLS + AUTH
    /// round-trips), so tests can price hiding that latency (hot
    /// spare) without a real network. 0 = greet immediately.
    pub greet_delay_ms: u64,
    /// The Nth ACCEPTED connection (1-based) is capped to this many
    /// bytes/sec; every other connection runs at the normal throttle.
    /// Models ONE degraded TCP session on an otherwise healthy server
    /// - the shape the slope recycle and the dup races exist for. A
    /// reconnect naturally gets a fresh, healthy session.
    pub slow_conn: Option<(u64, u64)>,
    /// IP/connection cap: while this many connections are already live,
    /// a further accept is greeted with the provider's own capacity
    /// refusal ("502 max connections reached")
    /// and closed. With `drop_after` this reproduces the flap shape: the
    /// few winners keep dying, the rest keep bouncing off the cap.
    pub accept_cap: Option<u64>,
    /// Ghost capacity window (issue #16's restart shape): for this many
    /// ms from server start, EVERY accept is greeted with the capacity
    /// refusal and closed - the provider is still counting a dead
    /// process's sessions against the account cap, and no amount of
    /// dialing helps until the lease expires. Distinct from
    /// `accept_cap` (which counts live connections): here there is
    /// nothing to count and nothing the client can shed. 0 = off.
    pub cap_ghost_ms: u64,
    /// Hard outage window: for this many ms from server start, every
    /// ACCEPTED connection is immediately closed with NO refusal line
    /// at all - the client's connect sees a hard failure (EOF before
    /// the greeting), exactly what a wifi drop, VPN reconnect, or
    /// router reboot looks like. Distinct from `cap_ghost_ms`, which
    /// greets with the 502 capacity text (a refusal the client can
    /// classify); here there is nothing to classify. 0 = off.
    pub refuse_connect_ms: u64,
    /// Ids whose FIRST request hangs BEFORE the status line (the
    /// dead-air shape a flat read timeout waits full length on, and the
    /// adaptive TTFB budget cuts short). Retries succeed, like `stall`.
    pub stall_pre: HashSet<String>,
    /// Ids whose FIRST body arrives in two halves with `gap_ms` of
    /// silence between them - the starved-share shape of TODO 208.2:
    /// bytes, then nothing, then the rest, on a connection that is
    /// alive the whole time (a socket on the losing side of a 360-way
    /// share through a small queue sits in TCP backoff for tens of
    /// seconds with nothing wrong on either end). Retries serve whole,
    /// like `stall`, so a client that kills the read at its stall
    /// deadline still finishes - one reconnect and one discarded half
    /// body later.
    pub gap: HashSet<String>,
    /// The silence `gap` opens, in ms.
    pub gap_ms: u64,
    /// Brownout: once this many bodies have been served (across all
    /// connections), EVERY further BODY request hangs in dead air - the
    /// whole frontend goes mute mid-run and never comes back. 0 = off.
    pub brownout_after: u64,
    /// Heal instant for the brownout, in ms from server start: from
    /// this moment NEW requests serve normally again (connections
    /// already parked in dead air stay parked - a recovered frontend
    /// does not resurrect the sockets it wedged). 0 = never heals,
    /// the original permanent shape. The §123 heal-after surface: the
    /// client's job is to cut the dead air, keep the fleet alive, and
    /// resume at full width when the frontend returns.
    pub brownout_heal_ms: u64,
    /// Takedown mid-job: once this many bodies have been served
    /// (across all connections), EVERY id answers 430 - including ids
    /// served moments ago, because a DMCA takedown removes the whole
    /// post from the spool, not the unread tail. The client's job is
    /// to drive the remainder to an honest terminal verdict quickly -
    /// a mid-job vanish must not look like a wedged pool. 0 = off.
    pub vanish_after: u64,
    /// AUTH blip window, in ms from server start: AUTHINFO PASS inside
    /// the window gets the permanent-shaped refusal (or
    /// `auth_refusal_text`), after it authentication succeeds. One
    /// 481 reply is indistinguishable from a wrong password, so the
    /// DESIGNED response is fail-fast-and-surface, not retry - the rig
    /// exists to pin that the failure is quick and honest, never a
    /// hang. 0 = off.
    pub auth_reject_ms: u64,
    /// Jitter: every Nth body (server-wide, deterministic) is preceded
    /// by an extra delay of this many ms - a spiky but perfectly
    /// healthy link (the satellite shape). The SAFETY rig for any
    /// timeout tightening: the right behaviour here is to kill
    /// nothing.
    pub jitter: Option<(u64, u64)>,
    /// Corrupt-article storm: every Nth BODY request (server-wide,
    /// counted in arrival order like `jitter`) gets one payload byte
    /// flipped, so its yEnc pcrc32 fails downstream. The per-id
    /// `corrupt` set models a damaged POST; this models a damaged
    /// SERVER (a broken cache node) - a deterministic fraction of
    /// everything it serves is bad, and every re-request to the same
    /// server serves the same bad copy. 0 = off.
    pub corrupt_every: u64,
    /// Split-brain: a request for the key id is answered with the
    /// VALUE id's article instead - a fully valid, self-consistent
    /// yEnc body that is simply the wrong article (storage backend
    /// serving mismatched content, seen live as "downloads complete
    /// but never verify"). Its own pcrc32 PASSES; only the article's
    /// declared identity (yEnc part number) can give it away. Every
    /// copy from this server is the same wrong copy.
    pub swap: HashMap<String, String>,
    /// Slow-start trickle: for the first `ms` milliseconds of every
    /// connection's life, its BODY bytes are paced at `bps` instead of
    /// the normal throttle - a congestion-window/middlebox warm-up
    /// where each fresh session crawls before it runs. Punishes
    /// reconnect-heavy behaviour specifically; a parked spare rides
    /// the window out while idle.
    pub slow_start: Option<(u64, u64)>,
    /// Satellite handover: `(period_ms, freeze_ms, wans)`. Every
    /// `period_ms`, BODY service freezes in dead air for `freeze_ms`
    /// (mid-pipeline, all at once) - the Starlink route switch. With
    /// `wans > 1`, connections belong to WAN `conn_no % wans` (the
    /// multi-WAN load balancer) and the WANs' freeze windows are
    /// staggered evenly across the period, so some of the fleet is
    /// always healthy - the single-WAN whole-fleet freeze and the
    /// multi-WAN half-fleet freeze are the same knob. Brief and
    /// RECOVERING, unlike `brownout_after`; whole-connection, unlike
    /// the per-id stalls.
    pub handover: Option<(u64, u64, u64)>,
    /// Asymmetric multi-WAN rates: connection `conn_no` gets per-conn
    /// ceiling `wan_conn_bps[(conn_no - 1) % len]` - one entry per WAN
    /// of a load-balanced router (Starlink beside a DSL fallback).
    /// `slow_conn`, when it names the same connection, wins. Empty =
    /// off.
    pub wan_conn_bps: Vec<u64>,
    /// CGNAT eviction: after this many bodies, the connection goes
    /// PERMANENTLY silent - no close, no RST, the next response simply
    /// never comes (a NAT table entry aged out mid-transfer). Unlike
    /// `drop_after` (clean close, instant requeue) the client learns
    /// nothing until its read bound fires; a reconnect gets a fresh
    /// NAT entry and works. 0 = off.
    pub mute_after_bodies: u64,
    /// Desync: every Nth BODY/ARTICLE request (server-wide, counted in
    /// arrival order like `jitter`/`corrupt_every`) has its response
    /// silently WITHHELD - the command is consumed and logged, nothing
    /// at all is written back, and the connection stays up. Every
    /// later response on that connection then answers an EARLIER
    /// pipeline slot than positional attribution assumes, so a client
    /// that discards the echoed message-id files every subsequent body
    /// under the wrong article. A response-stream fault (broken
    /// frontend/LB dropping one reply), distinct from `stall`/`stall_pre`
    /// (which stop answering entirely) - here the conversation keeps
    /// flowing, one slot out of phase. 0 = off.
    pub skip_nth_response: u64,
    /// Cold-storage lookups: id → ms of dead air before the STATUS
    /// line, on EVERY request (unlike `stall_pre`, which hangs only the
    /// first and answers the retry instantly). The article is healthy
    /// and always answers - eventually. This is the §121.1 shape: a
    /// trained-to-floor adaptive budget expires attempt after attempt
    /// on an article that a wider budget serves fine.
    pub slow_ttfb: HashMap<String, u64>,
}

/// Bandwidth shaping for the BODY/ARTICLE path - the model the
/// connection-tuner tests replay a real provider against. A provider is
/// two ceilings: a per-socket cap (why more connections help at all)
/// and the line (why they stop helping). The knee the tuner must find
/// is line/per_conn.
#[derive(Default, Clone)]
pub struct Throttle {
    /// Per-connection ceiling, bytes/sec (0 = uncapped). Each socket
    /// delivers at most this, however deep the pipeline.
    pub per_conn_bps: u64,
    /// Whole-server ceiling, bytes/sec (0 = uncapped), shared by every
    /// connection - the line.
    pub line_bps: u64,
    /// One TRANSIENT dip: the first time at least this many connections
    /// are open at once, the line drops to `dip_to_bps` - and recovers
    /// at the FIRST connection close after that, then full speed
    /// forever. First-close is the one prompt, deterministic marker of
    /// "the rung that triggered this is done measuring": teardown
    /// begins the moment the window ends, while the LAST straggler can
    /// drain queued bodies seconds into the next sample. Replays the
    /// noisy sample that faked a knee on a healthy link (James's
    /// 6-of-18): the reading of the trigger rung lies, every later one
    /// is honest. 0 = no dip.
    pub dip_at_conns: usize,
    /// What the line dips TO while the dip is active (bytes/sec).
    pub dip_to_bps: u64,
}

/// Shared pacing state for one mock server's [`Throttle`].
struct ThrottleState {
    /// Virtual availability clock for the line: each body reserves its
    /// transfer time on it, so aggregate throughput can't exceed the
    /// cap no matter how many sockets pull at once.
    line_next: tokio::sync::Mutex<std::time::Instant>,
    /// Open connections right now (drives the dip trigger).
    active: std::sync::atomic::AtomicUsize,
    /// Dip lifecycle: 0 = armed, 2 = dipping, 1 = spent. Spent by the
    /// FIRST connection close after arming: the trigger rung's teardown
    /// begins the moment its measuring window ends, while stragglers
    /// (server tasks draining queued bodies to dead sockets at dip
    /// pace) can linger seconds into the NEXT sample - so first-close
    /// marks the rung boundary and last-close does not.
    dip_state: std::sync::atomic::AtomicUsize,
    /// TODO 112 rig 2 (the facts-changed case): a LIVE replacement for
    /// the configured `line_bps`, settable mid-run via
    /// [`MockServer::set_line_bps`]. 0 = no override. The dip, while
    /// active, still wins - it models a transient, this models the
    /// provider genuinely re-provisioning the line.
    line_override: std::sync::atomic::AtomicU64,
    /// Server birth - the shared epoch the handover schedule ticks
    /// against, so every connection freezes on the SAME clock.
    started: std::time::Instant,
    /// Body bytes THIS server put on the wire (dot-stuffed payload
    /// plus, on the ARTICLE path, its header block), across every
    /// connection - the server-side twin of the client's per-server
    /// byte ledger, shared with [`MockServer::bytes_out`].
    ///
    /// Counted here rather than at the call sites because
    /// [`Self::pace_write`] is the one funnel every SERVED body passes
    /// through (overview and header responses are not body bytes and
    /// do not go through it); only the two truncation arms, which
    /// bypass pacing to cut the socket mid-body, charge themselves.
    ///
    /// The §129 3c contract asserts provider accounting, and that
    /// assertion is only worth making against an independent witness:
    /// "the client says server A moved 4 MB" means nothing unless A
    /// itself agrees it wrote 4 MB. Truncated and corrupted bodies
    /// count what actually went out, which is what the client's own
    /// counter sees too.
    bytes_out: Arc<AtomicU64>,
}

impl ThrottleState {
    fn new() -> Arc<Self> {
        Arc::new(ThrottleState {
            line_next: tokio::sync::Mutex::new(std::time::Instant::now()),
            active: Default::default(),
            dip_state: Default::default(),
            line_override: Default::default(),
            started: std::time::Instant::now(),
            bytes_out: Default::default(),
        })
    }

    /// Charge `data` to the wire ledger without pacing it - for the
    /// truncation arms, which cut the socket mid-body and so never
    /// reach [`Self::pace_write`].
    fn note_out(&self, data: &[u8]) {
        self.bytes_out
            .fetch_add(data.len() as u64, Ordering::Relaxed);
    }

    /// The line cap in force right now, arming the dip when concurrency
    /// first reaches the trigger.
    fn line_bps_now(&self, t: &Throttle) -> u64 {
        if t.dip_at_conns > 0 {
            match self.dip_state.load(Ordering::Relaxed) {
                0 if self.active.load(Ordering::Relaxed) >= t.dip_at_conns => {
                    self.dip_state.store(2, Ordering::Relaxed);
                    return t.dip_to_bps.max(1);
                }
                2 => return t.dip_to_bps.max(1),
                _ => {}
            }
        }
        match self.line_override.load(Ordering::Relaxed) {
            0 => t.line_bps,
            n => n,
        }
    }

    /// Pace `data` onto the wire: reserve each 64 KB chunk's transfer
    /// time on both ceilings, sleep the reservation, then write THAT
    /// chunk - the shape of a real throttled TCP stream, where bytes
    /// trickle for the whole transfer. The old shape (reserve the whole
    /// body, then burst it) gave a pipelined response a first-byte time
    /// equal to its full queue delay, which no real line produces - on
    /// a slow shared line that tripped the client's adaptive TTFB
    /// budget into a timeout/requeue cascade the wire never earned,
    /// and every abandoned socket then drained its queued bodies into
    /// the void at line pace (~20 s of dead wire on the playback rig).
    async fn pace_write<W: tokio::io::AsyncWrite + Unpin>(
        &self,
        t: &Throttle,
        conn_next: &mut std::time::Instant,
        w: &mut W,
        data: &[u8],
    ) -> std::io::Result<()> {
        self.bytes_out
            .fetch_add(data.len() as u64, Ordering::Relaxed);
        if t.per_conn_bps == 0 && t.line_bps == 0 && self.line_override.load(Ordering::Relaxed) == 0
        {
            return w.write_all(data).await;
        }
        for chunk in data.chunks(64 * 1024) {
            self.pace(t, conn_next, chunk.len()).await;
            w.write_all(chunk).await?;
        }
        Ok(())
    }

    /// Reserve `bytes` of transfer time on both ceilings; sleeps until
    /// the reservation comes due. Paced in 64 KB chunks so a rate
    /// change mid-article (the dip arming or spending) takes effect
    /// within a chunk - reserving a whole article at the old rate left
    /// stale future reservations that throttled the NEXT rung long
    /// after the dip was over. No lock is held across the sleeps.
    async fn pace(&self, t: &Throttle, conn_next: &mut std::time::Instant, bytes: usize) {
        if t.per_conn_bps == 0 && t.line_bps == 0 && self.line_override.load(Ordering::Relaxed) == 0
        {
            return;
        }
        let mut left = bytes;
        while left > 0 {
            let chunk = left.min(64 * 1024);
            left -= chunk;
            let now = std::time::Instant::now();
            let mut until = now;
            if t.per_conn_bps > 0 {
                let d = std::time::Duration::from_secs_f64(chunk as f64 / t.per_conn_bps as f64);
                *conn_next = (*conn_next).max(now) + d;
                until = until.max(*conn_next);
            }
            let line_bps = self.line_bps_now(t);
            if line_bps > 0 {
                let d = std::time::Duration::from_secs_f64(chunk as f64 / line_bps as f64);
                let mut next = self.line_next.lock().await;
                *next = (*next).max(now) + d;
                until = until.max(*next);
            }
            tokio::time::sleep_until(until.into()).await;
        }
    }
}

/// Failure injection for the POSTING path. Grouped because these only
/// ever matter together and only to the upload tests: the posting path
/// writes to the operator's real account, so every shape it has to
/// survive is modelled here rather than tried against a provider.
#[derive(Default, Clone)]
pub struct PostChaos {
    /// Answer the first `n` POST/IHAVE command lines (counted across all
    /// connections) with a try-again-later status - "503 service
    /// temporarily unavailable" for POST, "436 transfer failed, try again
    /// later" for IHAVE. RFC 3977 means these as "ask again", not "give
    /// up", and nothing is stored.
    pub try_later: u64,
    /// Read the first `n` POSTed articles off the wire and then close the
    /// connection without ever sending the 240/441 - the acknowledgement
    /// that never arrives (a dead session, or a read the client had to
    /// time out).
    pub ack_lost: u64,
    /// Whether an `ack_lost` article was actually filed. True models "it
    /// landed, only the acknowledgement was lost"; false models "it never
    /// landed at all". The two look identical to the client and must not
    /// be guessed at.
    pub ack_lost_keeps: bool,
    /// Answer the first `n` STATs with 430 even for a filed article. Large
    /// providers commonly separate posting and read farms, so an accepted
    /// article can be duplicate-rejected on resend before STAT propagation.
    pub stat_miss: u64,
    /// Drop the connection when a STAT arrives, so it is never ANSWERED at
    /// all. This is the posting-only account (no read access, so nothing
    /// can STAT) and the severed read path - distinct from `stat_miss`,
    /// which is a decisive "not here". The client must not let an
    /// unanswerable STAT erase what the server already said.
    pub stat_dies: bool,
    /// Wording for the 441 a server gives when it ALREADY HOLDS the
    /// resent article. Defaults to INN's `441 435 Duplicate article
    /// rejected`. 441 is free-form, so a server is free to say it any
    /// other way, and the client must not treat an unfamiliar spelling as
    /// proof the article is absent.
    pub duplicate_text: Option<String>,
    /// Once `reject_after` articles have been received, answer every
    /// POSTed article with `441 <text>` and store nothing - a genuine
    /// rejection, whose free-form text is whatever the server feels like
    /// saying.
    pub reject_441: Option<String>,
    /// How many articles are accepted before `reject_441` starts.
    pub reject_after: u64,
}

/// Shared counters for one server, across every connection of it:
/// POST/IHAVE command lines seen, articles read off the wire, STATs
/// answered, and the DATE log. Body bytes are NOT here: they are
/// charged on the pacing funnel, in [`ThrottleState::bytes_out`].
#[derive(Default)]
struct Counters {
    commands: AtomicU64,
    articles: AtomicU64,
    /// STAT commands answered, across every connection. Shared with
    /// [`MockServer::stats`] so a test can assert on probe traffic:
    /// STAT leaves no trace in `body_log` (it transfers no body), and
    /// "nothing probed while a download ran" is only checkable from the
    /// server's side.
    stats: Arc<AtomicU64>,
    /// The value of `served` at the moment each DATE command arrived,
    /// across every connection. Shared with [`MockServer::date_log`]:
    /// the §129 3g alignment fence is a DATE written behind a BODY, so
    /// this is the only place from which "is this server still being
    /// fenced" is observable at all, and its LAST entry against the
    /// final `served` is what says fencing stopped for good.
    date_log: Arc<std::sync::Mutex<Vec<u64>>>,
}

/// One overview row served for OVER/XOVER (spot-ingestion tests).
#[derive(Debug, Clone)]
pub struct OverRow {
    pub number: u64,
    pub subject: String,
    pub from: String,
    /// With angle brackets.
    pub message_id: String,
    pub bytes: u64,
}

/// Header-plane data (HEAD + OVER); empty for the classic body-only mock.
///
/// The overview is behind a mutex because a real group GROWS while a
/// client is connected: [`MockServer::post_overview`] appends rows
/// mid-run, which is what lets a test watch a post finish going up.
#[derive(Default)]
struct HeaderPlane {
    /// Message-id (with angle brackets) → raw header block (CRLF lines).
    headers: HashMap<String, Vec<u8>>,
    overview: std::sync::Mutex<Vec<OverRow>>,
}

impl HeaderPlane {
    fn rows(&self) -> std::sync::MutexGuard<'_, Vec<OverRow>> {
        self.overview.lock_ok()
    }
}

/// Pause before a 430, so a refusal costs a round trip like a real one.
/// `Chaos::gzip_corrupt`: a broken cache node - valid magic, garbage
/// middle. The flip lands past the 10-byte gzip header so the client's
/// framing sniff still says gzip and the fault reaches the inflater,
/// where a real one would.
fn maybe_corrupt_gzip(chaos: &Chaos, z: &mut [u8]) {
    if chaos.gzip_corrupt && z.len() > 16 {
        let mid = z.len() / 2;
        z[mid] ^= 0x01;
    }
}

/// The takedown arm (`Chaos::vanish_after`): true once the post has
/// left the spool - every id refuses from that moment, served tail
/// included.
fn vanished(chaos: &Chaos, served: &AtomicU64) -> bool {
    chaos.vanish_after > 0 && served.load(Ordering::Relaxed) >= chaos.vanish_after
}

/// The brownout arm, with its heal instant (`Chaos::brownout_heal_ms`):
/// active once `brownout_after` bodies have been served, until the heal
/// instant (0 = never heals).
fn browned_out(chaos: &Chaos, served: &AtomicU64, started: std::time::Instant) -> bool {
    chaos.brownout_after > 0
        && served.load(Ordering::Relaxed) >= chaos.brownout_after
        && (chaos.brownout_heal_ms == 0
            || (started.elapsed().as_millis() as u64) < chaos.brownout_heal_ms)
}

async fn refuse_delay(chaos: &Chaos) {
    if chaos.missing_delay_ms > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(chaos.missing_delay_ms)).await;
    }
}

/// The refusal line for `id`, in whichever of the two real-world shapes
/// [`Chaos::echo_missing_id`] selects. The bare form stays the default
/// because it is the harder one - the client cannot attribute it
/// positionally with confidence, which is the whole reason `soft_430`
/// exists.
fn refusal(chaos: &Chaos, id: &str) -> String {
    if chaos.echo_missing_id {
        format!("430 no such article {id}\r\n")
    } else {
        "430 no such article\r\n".to_string()
    }
}

/// One article on the wire: the raw dot-stuffed yEnc body.
fn wire_body(article: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(article.len() + 16);
    for line in article.split_inclusive(|&b| b == b'\n') {
        if line.first() == Some(&b'.') {
            out.push(b'.');
        }
        out.extend_from_slice(line);
    }
    out.extend_from_slice(b".\r\n");
    out
}

/// The mock's BODY arrival record: every message-id it was asked for,
/// in arrival order, each with the `Instant` the request LANDED.
///
/// The ids alone are what nearly every reader wants, so this `Deref`s to
/// `Vec<String>` and `log.contains(..)` / `.len()` / `.iter()` / `log[n..]`
/// all keep working unchanged. The stamps exist for the one question the
/// ids cannot answer: WHEN, and specifically when as the SERVER saw it.
///
/// A test that wants "B was not asked until 2 s after A" must read these
/// and never `Instant::now()` in its own polling loop - a poller stamps
/// the moment it NOTICED an entry, which is the arrival time plus however
/// long that thread was descheduled, and on a box running a full parallel
/// sweep that is unbounded. Measured on the mac dev box, 24 Aug 2026: 0-6 ms
/// of that lateness on an idle box or a single test binary, 74 ms and 121 ms
/// under the full parallel sweep. See `with_the_handoff_off_the_queue_is_serial`
/// in `crates/nzbfast/tests/integration/queue_handoff.rs`, which failed
/// exactly that way once in seven CI sweeps that day - it had ~300 ms of
/// margin, and the observer was spending it.
///
/// The stamp is taken BEFORE any `slow_ttfb` / stall chaos sleeps, so it
/// is the request's arrival and never its answer's departure.
///
/// WHAT IT STILL ASSUMES, said out loud because a server-side clock is
/// better than a poller's but is not an oracle: the stamp lands after
/// this connection's task has been scheduled, read the BODY line and
/// parsed it, so a starved mock stamps LATE, by however long that took.
/// What makes that harmless for a `slow_ttfb` bound is that the sleep is
/// DOWNSTREAM of the stamp in the same task - the answer departs at
/// stamp + `slow_ttfb`, and a client cannot ask for the next article
/// until it has that answer. So a late stamp pushes the whole rest of
/// the sequence out with it and the floor holds by construction: no
/// amount of scheduling can put a successor's arrival less than
/// `slow_ttfb` after the stamp. It is only an UPPER bound on a gap that
/// a starved mock (or a starved daemon) can inflate, and a test asserting
/// one needs margin for that in a way a lower bound does not.
#[derive(Default)]
pub struct BodyLog {
    ids: Vec<String>,
    /// Arrival `Instant` of `ids[i]`, at the same index. Kept in the same
    /// mutex as the ids so the two cannot be read out of step.
    at: Vec<std::time::Instant>,
}

/// Deliberately the IDS ONLY, so that every `{:?}` of this log that
/// predates the stamps still reads exactly as it did - a dozen assertion
/// messages across the test tree format the whole log, and none of them
/// wants a parallel array of `Instant` debug structs. Ask for
/// [`BodyLog::timeline`] when the times are the point.
impl std::fmt::Debug for BodyLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.ids.fmt(f)
    }
}

impl std::ops::Deref for BodyLog {
    type Target = Vec<String>;
    fn deref(&self) -> &Vec<String> {
        &self.ids
    }
}

impl BodyLog {
    /// Record one BODY request's arrival and return the new length -
    /// the 1-based ordinal of this request across every connection.
    fn record(&mut self, id: &str) -> u64 {
        self.ids.push(id.to_string());
        self.at.push(std::time::Instant::now());
        self.ids.len() as u64
    }

    /// When `id` was FIRST asked for, or `None` if it never was.
    pub fn first_asked(&self, id: &str) -> Option<std::time::Instant> {
        self.ids.iter().position(|x| x == id).map(|i| self.at[i])
    }

    /// When the first id satisfying `pred` was asked for, with that id.
    pub fn first_matching(
        &self,
        pred: impl Fn(&str) -> bool,
    ) -> Option<(String, std::time::Instant)> {
        self.ids
            .iter()
            .position(|x| pred(x))
            .map(|i| (self.ids[i].clone(), self.at[i]))
    }

    /// The whole record as `(id, offset)` pairs, each offset measured
    /// from `since`. For a failure message that has to say what actually
    /// happened on the wire, and when.
    pub fn timeline(&self, since: std::time::Instant) -> Vec<(String, std::time::Duration)> {
        self.ids
            .iter()
            .cloned()
            .zip(self.at.iter().map(|t| t.saturating_duration_since(since)))
            .collect()
    }
}

pub struct MockServer {
    pub addr: SocketAddr,
    /// Total BODY requests served (across all connections).
    pub served: Arc<AtomicU64>,
    /// Total TCP connections accepted, ever. The pacing tests assert on
    /// this: a broken account must not be reconnected to at full rate.
    pub accepted: Arc<AtomicU64>,
    /// Total STAT commands answered, across all connections. The §77
    /// pre-flight prober is STAT-only, so this is the one place its
    /// traffic (or its absence, while a download runs) is visible.
    pub stats: Arc<AtomicU64>,
    /// The `served` count at the moment of each DATE command, across
    /// all connections - see [`Counters::date_log`]. The §129 3g
    /// alignment fence rides behind a BODY as a DATE, so this is where
    /// a test reads whether this server is being fenced, and where it
    /// stopped being fenced.
    pub date_log: Arc<std::sync::Mutex<Vec<u64>>>,
    /// Body bytes this server put on the wire, across all connections -
    /// the independent witness for the §129 3c provider-accounting
    /// clause (see [`ThrottleState::bytes_out`]).
    pub bytes_out: Arc<AtomicU64>,
    /// Every BODY request's message-id (with angle brackets) in arrival
    /// order, across all connections - the M11 tests assert queue-order
    /// effects (head/tail burst, seek promotion) against this. It also
    /// carries each request's arrival `Instant`, which is the only
    /// honest clock for an ordering test - see [`BodyLog`].
    pub body_log: Arc<std::sync::Mutex<BodyLog>>,
    /// Test-controllable serving gate: while true, every connection stops
    /// reading (and thus logging/serving) commands at its next loop turn.
    /// Lets ordering tests freeze the world, land a queue reorder at a
    /// known point in `body_log`, and then release - no wall-clock races.
    pub pause: Arc<std::sync::atomic::AtomicBool>,
    /// The header plane, so a test can keep posting after the server is
    /// up - see [`MockServer::post_overview`].
    plane: Arc<HeaderPlane>,
    /// Shared pacing state, kept so a test can re-provision the line
    /// mid-run - see [`MockServer::set_line_bps`].
    throttle_state: Arc<ThrottleState>,
    /// The article spool itself, kept so a test can take the post down
    /// mid-run - see [`MockServer::take_down`].
    articles: Arc<std::sync::Mutex<HashMap<String, Vec<u8>>>>,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// See [`MockServer::line_control`].
#[derive(Clone)]
pub struct LineControl(Arc<ThrottleState>);

impl LineControl {
    pub fn set_line_bps(&self, bps: u64) {
        self.0.line_override.store(bps, Ordering::Relaxed);
    }
}

impl MockServer {
    /// `articles`: message-id (WITH angle brackets) → yEnc article body
    /// (un-stuffed; stuffing happens at the wire).
    pub async fn start(articles: HashMap<String, Vec<u8>>, chaos: Chaos) -> MockServer {
        Self::start_full(articles, HashMap::new(), Vec::new(), chaos).await
    }

    /// Like [`MockServer::start`], plus a header plane: per-article HEAD
    /// responses and OVER/XOVER overview rows (spot-ingestion E2E). With a
    /// non-empty overview, GROUP reports its real low/high range.
    pub async fn start_full(
        articles: HashMap<String, Vec<u8>>,
        headers: HashMap<String, Vec<u8>>,
        overview: Vec<OverRow>,
        chaos: Chaos,
    ) -> MockServer {
        Self::start_bound("127.0.0.1:0", articles, headers, overview, chaos).await
    }

    /// Like [`MockServer::start_full`] on a caller-chosen bind address -
    /// the standalone `mockserv` example needs a stable port so an
    /// installed daemon can be pointed at it (installer acceptance runs
    /// on boxes with no Usenet account).
    pub async fn start_bound(
        bind: &str,
        articles: HashMap<String, Vec<u8>>,
        headers: HashMap<String, Vec<u8>>,
        overview: Vec<OverRow>,
        chaos: Chaos,
    ) -> MockServer {
        let listener = TcpListener::bind(bind).await.expect("bind mock");
        let addr = listener.local_addr().unwrap();
        // Mutex (not plain Arc): POST/IHAVE insert articles at runtime,
        // and `take_down` removes them (the test-driven DMCA sweep).
        let articles = Arc::new(std::sync::Mutex::new(articles));
        let articles_handle = articles.clone();
        let plane = Arc::new(HeaderPlane {
            headers,
            overview: std::sync::Mutex::new(overview),
        });
        let plane2 = plane.clone();
        let served = Arc::new(AtomicU64::new(0));
        let served2 = served.clone();
        let body_log: Arc<std::sync::Mutex<BodyLog>> = Default::default();
        let body_log2 = body_log.clone();
        let stall_once: Arc<std::sync::Mutex<HashSet<String>>> =
            Arc::new(std::sync::Mutex::new(chaos.stall.clone()));
        let stall_pre_once: Arc<std::sync::Mutex<HashSet<String>>> =
            Arc::new(std::sync::Mutex::new(chaos.stall_pre.clone()));
        let gap_once: Arc<std::sync::Mutex<HashSet<String>>> =
            Arc::new(std::sync::Mutex::new(chaos.gap.clone()));
        let pause: Arc<std::sync::atomic::AtomicBool> = Default::default();
        let pause2 = pause.clone();
        let accepted = Arc::new(AtomicU64::new(0));
        let accepted2 = accepted.clone();
        let counters: Arc<Counters> = Default::default();
        let stats = counters.stats.clone();
        let date_log = counters.date_log.clone();
        let throttle_state = ThrottleState::new();
        let bytes_out = throttle_state.bytes_out.clone();
        let throttle_state2 = throttle_state.clone();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    return;
                };
                let conn_no = accepted2.fetch_add(1, Ordering::Relaxed) + 1;
                let articles = articles.clone();
                let plane = plane.clone();
                let mut chaos = chaos.clone();
                // Asymmetric multi-WAN: this connection's per-socket
                // ceiling is its WAN's rate (round-robin by accept
                // order, the load-balancer stand-in).
                if !chaos.wan_conn_bps.is_empty() {
                    let wan = ((conn_no - 1) % chaos.wan_conn_bps.len() as u64) as usize;
                    chaos.throttle.per_conn_bps = chaos.wan_conn_bps[wan];
                }
                // One degraded session: the designated accept gets its
                // own per-connection ceiling via the existing throttle
                // pacing; later accepts (reconnects) are healthy.
                if let Some((n, bps)) = chaos.slow_conn
                    && conn_no == n
                {
                    chaos.throttle.per_conn_bps = bps;
                }
                let served = served2.clone();
                let body_log = body_log2.clone();
                let stall_once = stall_once.clone();
                let stall_pre_once = stall_pre_once.clone();
                let gap_once = gap_once.clone();
                let pause = pause2.clone();
                let counters = counters.clone();
                let ts = throttle_state.clone();
                ts.active.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    // Hard outage window: the accept succeeds (the TCP
                    // stack answers before the process does) but the
                    // connection is torn down before a single byte -
                    // no greeting, no refusal text. The client's dial
                    // fails hard, indistinguishable from the network
                    // going away under it.
                    if chaos.refuse_connect_ms > 0
                        && (ts.started.elapsed().as_millis() as u64) < chaos.refuse_connect_ms
                    {
                        drop(sock);
                        ts.active.fetch_sub(1, Ordering::Relaxed);
                        return;
                    }
                    // Ghost capacity window (issue #16's restart shape): the
                    // provider still counts a DEAD process's sessions against
                    // the account cap, so for the first `cap_ghost_ms` every
                    // fresh accept - there are no live ghosts to count - is
                    // greeted with the capacity refusal and closed. The lease
                    // then expires and accepts run normally. The client's job
                    // is to keep paced redials alive through the window and
                    // ease back in when it clears, not to stall at zero.
                    if chaos.cap_ghost_ms > 0
                        && (ts.started.elapsed().as_millis() as u64) < chaos.cap_ghost_ms
                    {
                        use tokio::io::AsyncWriteExt;
                        let (_, mut w) = sock.into_split();
                        let _ = w
                            .write_all(
                                b"502 max number of simultaneous IP addresses reached: 0\r\n",
                            )
                            .await;
                        ts.active.fetch_sub(1, Ordering::Relaxed);
                        return;
                    }
                    if let Some(cap) = chaos.accept_cap
                        && ts.active.load(Ordering::Relaxed) as u64 > cap
                    {
                        use tokio::io::AsyncWriteExt;
                        let (_, mut w) = sock.into_split();
                        let _ = w
                            .write_all(
                                // A CONNECTION limit, which is what
                                // `accept_cap` models. It used to say
                                // "simultaneous IP addresses", which is
                                // a different fact - and since those two
                                // stopped sharing telemetry (Codex sweep
                                // 5, M9) the wording has to match what
                                // is being simulated.
                                format!("502 max connections reached: {cap}\r\n").as_bytes(),
                            )
                            .await;
                        ts.active.fetch_sub(1, Ordering::Relaxed);
                        return;
                    }
                    if chaos.greet_delay_ms > 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(chaos.greet_delay_ms))
                            .await;
                    }
                    let _ = serve_conn(
                        sock,
                        conn_no,
                        articles,
                        plane,
                        chaos.clone(),
                        served,
                        body_log,
                        stall_once,
                        stall_pre_once,
                        gap_once,
                        pause,
                        counters,
                        ts.clone(),
                    )
                    .await;
                    ts.active.fetch_sub(1, Ordering::Relaxed);
                    // First close after arming = the trigger rung's
                    // teardown has begun: the dip is spent.
                    let _ =
                        ts.dip_state
                            .compare_exchange(2, 1, Ordering::Relaxed, Ordering::Relaxed);
                });
            }
        });
        MockServer {
            addr,
            served,
            accepted,
            stats,
            date_log,
            bytes_out,
            body_log,
            pause,
            plane: plane2,
            throttle_state: throttle_state2,
            articles: articles_handle,
            handle,
        }
    }

    /// Take the whole post down NOW, as a DMCA sweep would: every
    /// article is removed from the spool, so from the next request on
    /// every id - including ones served moments ago - answers 430. The
    /// count-triggered twin is [`Chaos::vanish_after`]; this one is
    /// test-DRIVEN, for scenarios where the takedown must land between
    /// two moments the test controls (the retention-insurance A/B: add,
    /// bank, take down, promote) rather than after N served bodies.
    /// Returns how many articles the sweep removed.
    pub fn take_down(&self) -> usize {
        let mut a = self.articles.lock_ok();
        let n = a.len();
        a.clear();
        n
    }

    /// Re-provision the line LIVE (TODO 112 rig 2): from the next 64 KB
    /// pacing chunk on, the whole-server ceiling is `bps`. 0 restores
    /// the configured `line_bps`. Connections in flight feel it
    /// mid-article - that is the point.
    pub fn set_line_bps(&self, bps: u64) {
        self.throttle_state
            .line_override
            .store(bps, Ordering::Relaxed);
    }

    /// A cloneable, 'static handle for [`MockServer::set_line_bps`], so
    /// a rig can schedule the re-provision from a task or closure that
    /// cannot borrow the server.
    pub fn line_control(&self) -> LineControl {
        LineControl(self.throttle_state.clone())
    }

    /// Sessions this server has open RIGHT NOW, as the far end counts
    /// them - `accepted` is a lifetime total and says nothing about
    /// what is still there.
    ///
    /// The number a provider's connection cap is judged against, and
    /// the only honest way for a test to wait until a whole fleet is up
    /// before it does something to it: the client's own conn gauge
    /// answers from the client's bookkeeping, which is exactly what a
    /// test about handing sessions back must not take on trust.
    pub fn conns_open(&self) -> usize {
        self.throttle_state.active.load(Ordering::Relaxed)
    }

    /// Per-message-id REQUEST counts, across every connection, in id
    /// order. Derived from `body_log`, so it counts what the client
    /// ASKED for - a 430, a stalled request and a served body are each
    /// one request, because each is one round trip the client paid for.
    ///
    /// The §129 3c contract's refetch clause reads this: after a
    /// crash-and-resume, the ids requested twice must be bounded by
    /// what was genuinely in flight at the kill, not by the whole
    /// download.
    pub fn serve_counts(&self) -> std::collections::BTreeMap<String, u64> {
        let mut out: std::collections::BTreeMap<String, u64> = Default::default();
        for id in self.body_log.lock_ok().iter() {
            *out.entry(id.clone()).or_default() += 1;
        }
        out
    }

    /// Ids this server was asked for more than once, with their counts,
    /// most-repeated first. The refetch ledger in one call.
    pub fn refetched(&self) -> Vec<(String, u64)> {
        let mut v: Vec<(String, u64)> = self
            .serve_counts()
            .into_iter()
            .filter(|(_, n)| *n > 1)
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v
    }

    /// One-line serve-count dump for a rig log: totals plus the worst
    /// offenders. `chaos-serve` prints this per tick, and once more on
    /// shutdown, so the bench-box matrix can check the refetch clause
    /// from the server's own log the way an in-process test checks it
    /// from [`Self::refetched`].
    ///
    /// Carries `dials` (accepted connections) as well, so one line
    /// answers both the failover and the refetch clause and neither has
    /// to be read off a tick that may be a tick stale.
    pub fn serve_count_line(&self, label: &str) -> String {
        let counts = self.serve_counts();
        let requests: u64 = counts.values().sum();
        let repeats: Vec<(String, u64)> = self.refetched();
        let extra: u64 = repeats.iter().map(|(_, n)| n - 1).sum();
        let top: Vec<String> = repeats
            .iter()
            .take(5)
            .map(|(id, n)| format!("{id}x{n}"))
            .collect();
        format!(
            "SERVE-COUNTS {label}: dials={} requests={requests} distinct={} refetched_ids={} \
             extra_requests={extra} bytes_out={}{}",
            self.accepted.load(Ordering::Relaxed),
            counts.len(),
            repeats.len(),
            self.bytes_out.load(Ordering::Relaxed),
            if top.is_empty() {
                String::new()
            } else {
                format!(" top={}", top.join(","))
            }
        )
    }

    /// Append overview rows, as if those articles had just been posted.
    /// GROUP's high-water mark moves with them, so a client tracking the
    /// head of the group sees them on its next tick - which is how a post
    /// that is still going up becomes a complete one.
    pub fn post_overview(&self, rows: Vec<OverRow>) {
        self.plane.rows().extend(rows);
    }

    /// A ServerConfig pointing at this mock (plain TCP, no auth).
    pub fn server_config(&self) -> crate::config::ServerConfig {
        crate::config::ServerConfig {
            host: self.addr.ip().to_string(),
            port: self.addr.port(),
            tls: false,
            username: None,
            password: None,
            connections: 50,
            pin_connections: false,
            rcvbuf: None,
            level: 0,
            group: None,
            retention_days: 0,
            block_bytes: None,
            block_account: false,
            bind_ip: None,
            socks5: None,
            enabled: true,
            warm_pool: false,
            idle_release_secs: None,
            idle_keep: None,
            max_source_ips: None,
            address_family: Default::default(),
            tls_hostname: None,
        }
    }
}

/// The POST arm of [`serve_conn`], lifted out to keep that function
/// under the size gate: the reject / try-later gates, the ack-lost
/// hang-up, and the duplicate / 441 response shapes. Returns false
/// when the connection must close (ack-lost simulates a dead socket).
async fn handle_post(
    w: &mut tokio::net::tcp::OwnedWriteHalf,
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    articles: &Arc<std::sync::Mutex<HashMap<String, Vec<u8>>>>,
    chaos: &Chaos,
    counters: &Arc<Counters>,
) -> std::io::Result<bool> {
    if chaos.post_rejected {
        w.write_all(b"440 posting not allowed\r\n").await?;
    } else if counters.commands.fetch_add(1, Ordering::Relaxed) < chaos.post.try_later {
        w.write_all(b"503 service temporarily unavailable\r\n")
            .await?;
    } else {
        w.write_all(b"340 send article to be posted\r\n").await?;
        w.flush().await?;
        match read_posted_article(reader).await? {
            Some((id, body)) => {
                let nth = counters.articles.fetch_add(1, Ordering::Relaxed) + 1;
                if nth <= chaos.post.ack_lost {
                    // Article read, nothing said back, socket gone.
                    if chaos.post.ack_lost_keeps {
                        articles.lock_ok().insert(id, body);
                    }
                    return Ok(false);
                }
                let reject = chaos
                    .post
                    .reject_441
                    .as_deref()
                    .filter(|_| nth > chaos.post.reject_after);
                let duplicate = articles.lock_ok().contains_key(&id);
                if let Some(text) = reject {
                    w.write_all(format!("441 {text}\r\n").as_bytes()).await?;
                } else if duplicate {
                    // A real server keeps the copy it already has and
                    // refuses the resend, quoting the reason code in
                    // the free-form part (INN's shape). Only a STAT
                    // distinguishes this from a rejection that merely
                    // mentions duplicates.
                    let line = chaos
                        .post
                        .duplicate_text
                        .as_deref()
                        .unwrap_or("441 435 Duplicate article rejected");
                    w.write_all(format!("{line}\r\n").as_bytes()).await?;
                } else {
                    articles.lock_ok().insert(id, body);
                    w.write_all(b"240 article received\r\n").await?;
                }
            }
            None => w.write_all(b"441 posting failed\r\n").await?,
        }
    }
    Ok(true)
}

/// Which command asked for the article. The only two things that differ
/// between the two answers: the status code, and whether a header block
/// precedes the payload.
#[derive(Clone, Copy, PartialEq)]
enum Fetch {
    /// `222`, the yEnc payload alone.
    Body,
    /// `220`, a minimal synthetic header block and then the same
    /// payload, byte for byte - so a decoder scanning for `=ybegin` is
    /// unaffected by which one it asked for.
    Article,
}

/// What `serve_article` decided about the connection.
enum Served {
    /// Answered; fall through to the flush at the foot of the loop.
    Answered,
    /// Handled without an answer (or already flushed) - straight round
    /// again, skipping the flush.
    Skip,
    /// This connection is finished.
    Hangup,
}

/// Serve one article, with every chaos hook in the order BODY defines
/// them.
///
/// BODY and ARTICLE were written out twice, and the copy drifted: the
/// §111 fault matrix caught the ARTICLE arm missing stall_pre, brownout
/// and jitter, so a client that fetches with ARTICLE (rustnzb does)
/// sailed untouched through three fault profiles and scored walls
/// nothing can reach - a green leg is not a result. They were
/// re-synchronised by hand and then kept in step by a comment asking
/// the next person to remember. One body instead, so a hook cannot land
/// on one arm only.
#[expect(clippy::too_many_arguments)]
async fn serve_article(
    w: &mut tokio::net::tcp::OwnedWriteHalf,
    fetch: Fetch,
    id: &str,
    conn_no: u64,
    conn_next: &mut std::time::Instant,
    conn_started: std::time::Instant,
    bodies_served: &mut u64,
    articles: &Arc<std::sync::Mutex<HashMap<String, Vec<u8>>>>,
    chaos: &Chaos,
    served: &Arc<AtomicU64>,
    body_log: &Arc<std::sync::Mutex<BodyLog>>,
    stall_once: &Arc<std::sync::Mutex<HashSet<String>>>,
    stall_pre_once: &Arc<std::sync::Mutex<HashSet<String>>>,
    gap_once: &Arc<std::sync::Mutex<HashSet<String>>>,
    throttle: &Arc<ThrottleState>,
) -> std::io::Result<Served> {
    // Stamped HERE, before every chaos sleep below, so the record is
    // the request's ARRIVAL and not its answer's departure - see
    // [`BodyLog`] for why a test must read this rather than its own
    // poller's clock.
    let nth = body_log.lock_ok().record(id);
    // Desync: consume the request, answer NOTHING, keep the
    // connection - later responses shift one slot forward.
    if chaos.skip_nth_response > 0 && nth.is_multiple_of(chaos.skip_nth_response) {
        return Ok(Served::Skip);
    }
    // CGNAT eviction: this connection's NAT entry is gone -
    // dead air forever, no close. A reconnect gets a fresh
    // entry (a fresh accept), which is the recovery path.
    if chaos.mute_after_bodies > 0 && *bodies_served >= chaos.mute_after_bodies {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        return Ok(Served::Hangup);
    }
    // Satellite handover: dead air while this connection's WAN
    // switches routes. All connections of one WAN freeze on the
    // shared server clock; other WANs' windows are staggered.
    if let Some((period, freeze, wans)) = chaos.handover
        && period > 0
        && freeze > 0
    {
        let wans = wans.max(1);
        let offset = ((conn_no - 1) % wans) * (period / wans);
        let phase = (throttle.started.elapsed().as_millis() as u64 + period - offset) % period;
        if phase < freeze {
            tokio::time::sleep(std::time::Duration::from_millis(freeze - phase)).await;
        }
    }
    if chaos.body_error.is_some_and(|n| nth <= n) {
        // Not a BODY status at all: the client can only treat this
        // as a protocol error and drop the session.
        w.write_all(b"502 byte limit exceeded\r\n").await?;
        w.flush().await?;
        return Ok(Served::Skip);
    }
    if vanished(chaos, served) {
        refuse_delay(chaos).await;
        w.write_all(refusal(chaos, id).as_bytes()).await?;
        return Ok(Served::Skip);
    }
    if chaos.missing.contains(id) {
        refuse_delay(chaos).await;
        w.write_all(refusal(chaos, id).as_bytes()).await?;
        return Ok(Served::Skip);
    }
    // Split-brain: the index knows the requested id (no 430),
    // but the storage backend hands back a different article's
    // bytes - so the swap applies after the missing checks and
    // the status line still echoes what was ASKED for.
    let stored = chaos.swap.get(id).map_or(id, String::as_str);
    let Some(article) = articles.lock_ok().get(stored).cloned() else {
        refuse_delay(chaos).await;
        w.write_all(refusal(chaos, id).as_bytes()).await?;
        return Ok(Served::Skip);
    };
    if chaos.delay_ms > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(chaos.delay_ms)).await;
    }
    if let Some((nth, ms)) = chaos.jitter
        && nth > 0
        && served.load(Ordering::Relaxed).is_multiple_of(nth)
    {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    }
    if browned_out(chaos, served, throttle.started) {
        // The frontend has browned out: dead air for everyone.
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        return Ok(Served::Hangup);
    }
    if stall_pre_once.lock_ok().remove(id) {
        // Dead air: no status, no bytes - the client sees pure
        // silence until its pre-byte bound fires.
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        return Ok(Served::Hangup);
    }
    if let Some(ms) = chaos.slow_ttfb.get(id) {
        // Cold storage: dead air, then a normal answer - on
        // every request, so only a wide-enough pre-byte budget
        // ever sees the status line.
        tokio::time::sleep(std::time::Duration::from_millis(*ms)).await;
    }
    let status = match fetch {
        Fetch::Body => 222,
        Fetch::Article => 220,
    };
    w.write_all(format!("{status} 0 {id}\r\n").as_bytes())
        .await?;
    if stall_once.lock_ok().remove(id) {
        // Status sent, body never comes - the client's per-response
        // timeout must fire; the NEXT request for this id succeeds.
        w.flush().await?;
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        return Ok(Served::Hangup);
    }
    let mut body = article;
    if chaos.corrupt.contains(id)
        || (chaos.corrupt_every > 0 && nth.is_multiple_of(chaos.corrupt_every))
    {
        // Flip a byte in the middle of the payload region.
        let mid = body.len() / 2;
        body[mid] ^= 0x01;
    }
    let mut wire = match fetch {
        Fetch::Body => Vec::new(),
        // Minimal header block, blank line, then the dot-stuffed yEnc
        // body (which already carries the terminating ".\r\n").
        Fetch::Article => format!(
            "Message-ID: {id}\r\nNewsgroups: alt.binaries.bench\r\nSubject: bench article\r\n\r\n"
        )
        .into_bytes(),
    };
    wire.extend_from_slice(&wire_body(&body));
    if chaos.truncate.contains(id) {
        wire.truncate(wire.len() / 2);
        throttle.note_out(&wire); // bypasses pace_write's ledger
        w.write_all(&wire).await?;
        return Ok(Served::Hangup); // cut the connection mid-body
    }
    if gap_once.lock_ok().remove(id) {
        // Starved share: half the body, a silence, then the rest -
        // paced like any other body on either side of the gap.
        let (head, tail) = wire.split_at(wire.len() / 2);
        throttle
            .pace_write(&chaos.throttle, conn_next, w, head)
            .await?;
        w.flush().await?;
        tokio::time::sleep(std::time::Duration::from_millis(chaos.gap_ms)).await;
        throttle
            .pace_write(&chaos.throttle, conn_next, w, tail)
            .await?;
        served.fetch_add(1, Ordering::Relaxed);
        *bodies_served += 1;
        return Ok(Served::Answered);
    }
    // Slow-start trickle: a young connection is paced at the
    // crawl rate instead of its normal ceiling.
    let in_slow_start = chaos
        .slow_start
        .is_some_and(|(ms, _)| conn_started.elapsed() < std::time::Duration::from_millis(ms));
    if let Some((_, bps)) = chaos.slow_start.filter(|_| in_slow_start) {
        let crawl = Throttle {
            per_conn_bps: bps,
            ..chaos.throttle.clone()
        };
        throttle.pace_write(&crawl, conn_next, w, &wire).await?;
    } else {
        throttle
            .pace_write(&chaos.throttle, conn_next, w, &wire)
            .await?;
    }
    served.fetch_add(1, Ordering::Relaxed);
    *bodies_served += 1;
    if chaos.drop_after > 0 && *bodies_served >= chaos.drop_after {
        return Ok(Served::Hangup); // abrupt close; client must reconnect/requeue
    }
    Ok(Served::Answered)
}

#[expect(clippy::too_many_arguments)]
async fn serve_conn(
    sock: tokio::net::TcpStream,
    conn_no: u64,
    articles: Arc<std::sync::Mutex<HashMap<String, Vec<u8>>>>,
    plane: Arc<HeaderPlane>,
    chaos: Chaos,
    served: Arc<AtomicU64>,
    body_log: Arc<std::sync::Mutex<BodyLog>>,
    stall_once: Arc<std::sync::Mutex<HashSet<String>>>,
    stall_pre_once: Arc<std::sync::Mutex<HashSet<String>>>,
    gap_once: Arc<std::sync::Mutex<HashSet<String>>>,
    pause: Arc<std::sync::atomic::AtomicBool>,
    counters: Arc<Counters>,
    throttle: Arc<ThrottleState>,
) -> std::io::Result<()> {
    sock.set_nodelay(true)?;
    // This connection's slot on the per-socket ceiling.
    let mut conn_next = std::time::Instant::now();
    // Birth of this connection, for the slow-start trickle window.
    let conn_started = std::time::Instant::now();
    let (r, mut w) = sock.into_split();
    let mut reader = BufReader::new(r);
    if chaos.mute_greeting {
        // Hold the connection open, saying nothing, discarding everything.
        use tokio::io::AsyncReadExt;
        let mut sink = [0u8; 1024];
        loop {
            if reader.read(&mut sink).await? == 0 {
                return Ok(());
            }
        }
    }
    w.write_all(b"200 mock ready\r\n").await?;

    let mut line = String::new();
    let mut bodies_served = 0u64;
    // Per-connection header-compression state (XFEATURE COMPRESS GZIP).
    let mut gzip_on = false;
    loop {
        while pause.load(Ordering::Acquire) {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            return Ok(());
        }
        let cmd = line.trim_end();
        let upper = cmd.to_ascii_uppercase();
        if upper.starts_with("AUTHINFO USER") {
            w.write_all(b"381 password required\r\n").await?;
        } else if upper.starts_with("AUTHINFO PASS") {
            if chaos.auth_rejected
                || (chaos.auth_reject_ms > 0
                    && (throttle.started.elapsed().as_millis() as u64) < chaos.auth_reject_ms)
            {
                let line = chaos
                    .auth_refusal_text
                    .as_deref()
                    .unwrap_or("481 authentication failed");
                w.write_all(format!("{line}\r\n").as_bytes()).await?;
                return Ok(());
            }
            w.write_all(b"281 welcome\r\n").await?;
        } else if upper.starts_with("QUIT") {
            if chaos.mute_quit {
                continue; // no goodbye, connection stays up - client's problem
            }
            w.write_all(b"205 bye\r\n").await?;
            return Ok(());
        } else if upper.starts_with("GROUP") {
            // Snapshot under the lock, answer outside it: the guard is
            // not Send and this connection is a spawned task.
            let span = {
                let rows = plane.rows();
                (!rows.is_empty()).then(|| {
                    (
                        rows.iter().map(|r| r.number).min().unwrap_or(1),
                        rows.iter().map(|r| r.number).max().unwrap_or(1),
                        rows.len(),
                    )
                })
            };
            match span {
                None => w.write_all(b"211 100 1 100 mock.group\r\n").await?,
                Some((low, high, n)) => {
                    let name = cmd.split_whitespace().nth(1).unwrap_or("mock.group");
                    w.write_all(format!("211 {n} {low} {high} {name}\r\n").as_bytes())
                        .await?;
                }
            }
        } else if upper.starts_with("XFEATURE COMPRESS GZIP") {
            if chaos.gzip_headers {
                gzip_on = true;
                w.write_all(b"290 Feature Enabled\r\n").await?;
            } else {
                w.write_all(b"400 Unrecognized command\r\n").await?;
            }
        } else if upper.starts_with("OVER") && !upper.starts_with("XOVER") && chaos.xover_only {
            // XOVER-only provider: OVER is an unknown command
            // (Newshosting's exact wording).
            w.write_all(b"400 Unrecognized command\r\n").await?;
        } else if (upper.starts_with("OVER") || upper.starts_with("XOVER")) && chaos.over_rejected {
            w.write_all(b"411 no such newsgroup\r\n").await?;
        } else if upper.starts_with("OVER") || upper.starts_with("XOVER") {
            // "OVER a-b" / "OVER a" - overview rows within the range.
            let range = cmd.split_whitespace().nth(1).unwrap_or("");
            let (a, b) = match range.split_once('-') {
                Some((a, b)) => (
                    a.trim().parse().unwrap_or(0),
                    b.trim().parse().unwrap_or(u64::MAX),
                ),
                None => {
                    let n = range.trim().parse().unwrap_or(0);
                    (n, n)
                }
            };
            let rows: Vec<OverRow> = plane
                .rows()
                .iter()
                .filter(|r| r.number >= a && r.number <= b)
                .cloned()
                .collect();
            if rows.is_empty() {
                // RFC 3977: a valid range holding no articles is 423, not an
                // empty 224 body - INN answers exactly this. Serving 224 for
                // every range is what let an empty-range bug ship unnoticed.
                w.write_all(b"423 no articles in that range\r\n").await?;
            } else {
                w.write_all(b"224 overview follows\r\n").await?;
                let mut body = Vec::new();
                for r in rows {
                    body.extend_from_slice(
                        format!(
                            "{}\t{}\t{}\tThu, 1 Jan 2026 00:00:00 GMT\t{}\t\t{}\t1\r\n",
                            r.number, r.subject, r.from, r.message_id, r.bytes
                        )
                        .as_bytes(),
                    );
                }
                if gzip_on {
                    // Highwinds TERMINATOR variant: one gzip stream, then a
                    // plain-text dot line on the wire.
                    use std::io::Write as _;
                    let mut enc =
                        flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
                    enc.write_all(&body)?;
                    let mut z = enc.finish()?;
                    maybe_corrupt_gzip(&chaos, &mut z);
                    w.write_all(&z).await?;
                } else {
                    w.write_all(&body).await?;
                }
                w.write_all(b".\r\n").await?;
            }
        } else if let Some(id) = cmd
            .strip_prefix("HEAD ")
            .or_else(|| cmd.strip_prefix("head "))
        {
            match plane.headers.get(id.trim()) {
                Some(h) => {
                    w.write_all(format!("221 0 {}\r\n", id.trim()).as_bytes())
                        .await?;
                    w.write_all(&wire_body(h)).await?;
                }
                None => w.write_all(b"430 no such article\r\n").await?,
            }
        } else if upper == "POST" {
            if !handle_post(&mut w, &mut reader, &articles, &chaos, &counters).await? {
                return Ok(());
            }
        } else if let Some(id) = cmd
            .strip_prefix("IHAVE ")
            .or_else(|| cmd.strip_prefix("ihave "))
        {
            let claimed = id.trim().to_string();
            if counters.commands.fetch_add(1, Ordering::Relaxed) < chaos.post.try_later {
                w.write_all(b"436 transfer failed, try again later\r\n")
                    .await?;
            } else if articles.lock_ok().contains_key(&claimed) {
                w.write_all(b"435 article not wanted\r\n").await?;
            } else {
                w.write_all(b"335 send it\r\n").await?;
                w.flush().await?;
                match read_posted_article(&mut reader).await? {
                    Some((_, body)) => {
                        let nth = counters.articles.fetch_add(1, Ordering::Relaxed) + 1;
                        if nth <= chaos.post.ack_lost {
                            // Article read, nothing said back, socket gone.
                            if chaos.post.ack_lost_keeps {
                                articles.lock_ok().insert(claimed, body);
                            }
                            return Ok(());
                        }
                        // File under the id the client CLAIMED - that is
                        // the id its NZB will carry.
                        articles.lock_ok().insert(claimed, body);
                        w.write_all(b"235 article transferred\r\n").await?;
                    }
                    None => w.write_all(b"436 transfer failed\r\n").await?,
                }
            }
        } else if upper.starts_with("HELP") {
            // RFC 3977 makes HELP mandatory, and a third-party client
            // may send it as part of its handshake and treat a refusal
            // as fatal. Newsbin Pro 6.90 does exactly that: against the
            // 500 this arm replaced it logged "NEWS SERVER ERROR ...
            // Cmd: HELP" once per connection and abandoned the job,
            // which reads as a dead server rather than a missing
            // command. Our own client never sends it, so nothing in
            // this tree noticed until a commercial client was pointed
            // at the loopback rig (23 Aug 2026).
            w.write_all(b"100 help text follows\r\nARTICLE\r\nBODY\r\nGROUP\r\nQUIT\r\n.\r\n")
                .await?;
        } else if upper.starts_with("MODE READER") {
            // Same class: legal, common in a client handshake, and
            // answered 500 here until the same day.
            w.write_all(b"200 reader mode\r\n").await?;
        } else if upper.starts_with("CAPABILITIES") {
            w.write_all(b"101 capabilities\r\nVERSION 2\r\nPIPELINING\r\n.\r\n")
                .await?;
        } else if upper.starts_with("DATE") {
            counters
                .date_log
                .lock_ok()
                .push(served.load(Ordering::Relaxed));
            // A provider that reads DATE and answers nothing at all.
            // The command is legal and mandatory, so nothing upstream
            // of the read can tell: the client only finds out when the
            // slot it expected the answer in holds the next response.
            if !chaos.mute_date {
                w.write_all(b"111 20260719000000\r\n").await?;
            }
        } else if let Some(id) = cmd
            .strip_prefix("STAT ")
            .or_else(|| cmd.strip_prefix("stat "))
        {
            let id = id.trim();
            let nth = counters.stats.fetch_add(1, Ordering::Relaxed) + 1;
            if chaos.post.stat_dies {
                return Ok(());
            }
            if nth > chaos.post.stat_miss
                && articles.lock_ok().contains_key(id)
                && !chaos.missing.contains(id)
                && !vanished(&chaos, &served)
            {
                w.write_all(format!("223 0 {id}\r\n").as_bytes()).await?;
            } else {
                refuse_delay(&chaos).await;
                w.write_all(refusal(&chaos, id).as_bytes()).await?;
            }
        } else if let Some(id) = cmd
            .strip_prefix("BODY ")
            .or_else(|| cmd.strip_prefix("body "))
        {
            match serve_article(
                &mut w,
                Fetch::Body,
                id.trim(),
                conn_no,
                &mut conn_next,
                conn_started,
                &mut bodies_served,
                &articles,
                &chaos,
                &served,
                &body_log,
                &stall_once,
                &stall_pre_once,
                &gap_once,
                &throttle,
            )
            .await?
            {
                Served::Answered => {}
                Served::Skip => continue,
                Served::Hangup => return Ok(()),
            }
        } else if let Some(id) = cmd
            .strip_prefix("ARTICLE ")
            .or_else(|| cmd.strip_prefix("article "))
        {
            // ARTICLE = headers + body in one response. Some clients
            // fetch via ARTICLE rather than BODY (rustnzb does); every
            // chaos hook applies identically, which is why both go
            // through one body (see `serve_article`).
            match serve_article(
                &mut w,
                Fetch::Article,
                id.trim(),
                conn_no,
                &mut conn_next,
                conn_started,
                &mut bodies_served,
                &articles,
                &chaos,
                &served,
                &body_log,
                &stall_once,
                &stall_pre_once,
                &gap_once,
                &throttle,
            )
            .await?
            {
                Served::Answered => {}
                Served::Skip => continue,
                Served::Hangup => return Ok(()),
            }
        } else {
            w.write_all(b"500 what\r\n").await?;
        }
        w.flush().await?;
    }
}

/// Read one POST/IHAVE continuation article off the wire: headers, blank
/// line, dot-stuffed body, lone-dot terminator. Returns the Message-ID
/// (with angle brackets) and the UN-stuffed body - the same shape the
/// `articles` map holds, so BODY re-stuffs it on the way back out.
/// Byte-oriented on purpose: yEnc payload lines are not valid UTF-8.
async fn read_posted_article<R>(reader: &mut R) -> std::io::Result<Option<(String, Vec<u8>)>>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    let mut msgid: Option<String> = None;
    let mut body: Vec<u8> = Vec::new();
    let mut in_body = false;
    let mut line: Vec<u8> = Vec::new();
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line).await? == 0 {
            return Ok(None); // connection died mid-article
        }
        let trimmed: &[u8] = {
            let mut t = &line[..];
            while t.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
                t = &t[..t.len() - 1];
            }
            t
        };
        if trimmed == b"." {
            break;
        }
        if !in_body {
            if trimmed.is_empty() {
                in_body = true;
                continue;
            }
            let text = String::from_utf8_lossy(trimmed);
            if let Some(v) = text
                .strip_prefix("Message-ID:")
                .or_else(|| text.strip_prefix("Message-Id:"))
            {
                msgid = Some(v.trim().to_string());
            }
            continue;
        }
        // Un-dot-stuff and store with CRLF endings.
        let payload = if trimmed.starts_with(b"..") {
            &trimmed[1..]
        } else {
            trimmed
        };
        body.extend_from_slice(payload);
        body.extend_from_slice(b"\r\n");
    }
    match msgid {
        Some(id) if !id.is_empty() && !body.is_empty() => Ok(Some((id, body))),
        _ => Ok(None),
    }
}

/// Build the articles for one file: split `data` into `art_size` pieces and
/// yEnc-encode each as `<stem>-partNN@mock`. Returns (segments for the NZB:
/// (message-id-sans-brackets, encoded-size, part-no), articles map entries).
pub fn make_file_articles(
    name: &str,
    data: &[u8],
    art_size: usize,
    idtag: &str,
    out: &mut HashMap<String, Vec<u8>>,
) -> Vec<(String, u64, u32)> {
    let total = data.len().div_ceil(art_size).max(1) as u32;
    let mut segs = Vec::new();
    for (i, chunk) in data.chunks(art_size.max(1)).enumerate() {
        let part = i as u32 + 1;
        let begin = (i * art_size) as u64 + 1;
        let article =
            crate::yenc::encode(name, data.len() as u64, Some((part, total)), begin, chunk);
        let id = format!("{idtag}-{part}@mock");
        segs.push((id.clone(), article.len() as u64, part));
        out.insert(format!("<{id}>"), article);
    }
    segs
}

#[cfg(test)]
#[path = "mock_tests.rs"]
mod mock_tests;
