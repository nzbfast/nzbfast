//! The process-wide in-flight request-body budget: 8 HTTP workers times
//! the per-request cap could hold ~2 GB of half-read uploads at once, so
//! every capped body read reserves against one shared pool first.
//!
//! Split out of serve/mod.rs by TODO 106 phase 4 - the code is verbatim,
//! only visibility changed.

use super::*;

/// Process-wide in-flight request-body budget (28 Jul sweep finding):
/// 8 HTTP workers x the 256 MB per-request cap could hold ~2 GB of
/// half-read uploads at once - enough to OOM a memory-clamped container
/// - and `addfile` accepts the add-only tier, so the exposure does not
/// need the admin key. Every `read_body_capped_hold` reserves here as its
/// body grows and releases when the read completes; a reader that would
/// push the total past the cap WAITS for another body to finish -
/// except a sole reader, which may take everything alone, so one
/// huge-NZB upload still works on a box whose whole budget is smaller
/// than the per-request cap. A deliberately slow uploader therefore
/// stalls OTHER large uploads rather than eating RAM - it already
/// pinned a worker thread either way, and blocked-and-small beats
/// admitted-and-huge. Sized from the process memory budget at first use
/// (serve() publishes that before the listener exists).
pub(super) struct BodyBudget {
    pub(super) cap: u64,
    /// How long a blocked holder waits per round. A field rather than the
    /// constant so the tests can drive many rounds in milliseconds - the
    /// overshoot bound below is a statement about what happens over MANY
    /// rounds, and a test that takes 5 s each to make the point would not
    /// be written.
    pub(super) wait: std::time::Duration,
    pub(super) cur: std::sync::Mutex<Reserved>,
    pub(super) cv: std::sync::Condvar,
}

/// In-flight reserved bytes, plus the ticket of every body currently
/// holding some. Tickets are handed out in arrival order and the LOWEST
/// live one is the body allowed to finish (see [`BodyBudget::grow`]).
#[derive(Default)]
pub(super) struct Reserved {
    pub(super) bytes: u64,
    pub(super) next_ticket: u64,
    pub(super) live: std::collections::BTreeSet<u64>,
}

/// One body's claim on the pool: the bytes it holds and its place in the
/// queue. Carried by the reader for the length of its read.
#[derive(Default)]
pub(super) struct Hold {
    pub(super) bytes: u64,
    pub(super) ticket: Option<u64>,
}

/// How long a blocked holder waits before re-checking. Purely a
/// belt-and-braces re-read of the predicate now - forward progress comes
/// from the oldest-holder rule, not from this expiring - so it no longer
/// has to be tuned against anything.
pub(super) const BODY_BUDGET_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

pub(super) static BODY_BUDGET: std::sync::OnceLock<BodyBudget> = std::sync::OnceLock::new();

pub(super) fn body_budget() -> &'static BodyBudget {
    BODY_BUDGET.get_or_init(|| {
        BodyBudget::new((nzbkit::mem::process_budget().total / 4).clamp(64 << 20, 512 << 20))
    })
}

impl BodyBudget {
    pub(super) fn new(cap: u64) -> BodyBudget {
        BodyBudget::with_wait(cap, BODY_BUDGET_WAIT)
    }

    pub(super) fn with_wait(cap: u64, wait: std::time::Duration) -> BodyBudget {
        BodyBudget {
            cap,
            wait,
            cur: std::sync::Mutex::new(Reserved::default()),
            cv: std::sync::Condvar::new(),
        }
    }

    /// Reserve `more` bytes for `h`. Blocks while OTHER bodies have the
    /// pool exhausted.
    ///
    /// A waiter that already holds bytes cannot be made to wait forever:
    /// its own reservation is part of the total everyone else is queued
    /// behind, and it only releases when its read loop ENDS - so two
    /// bodies that together reach the cap would each block on a condvar
    /// only the other could signal, wedging every HTTP worker behind
    /// them. (`read_body_capped_hold` reserves before each read, so even a
    /// reader that has hit its own `take` limit - one line from breaking
    /// out and releasing - parks here first.)
    ///
    /// The way out is to name ONE body that may always proceed: the
    /// oldest live holder. It runs to its own per-request `take` cap,
    /// releases, and the next-oldest inherits the right - so the pool
    /// always drains, and the total is bounded by `cap` plus that single
    /// over-runner's per-request cap.
    ///
    /// This replaces a timeout-based escape that let ANY holder through
    /// after a wait in which nothing was released. That looked equally
    /// deadlock-free and was not bounded: the grant repeated every round,
    /// for every holder, so a set of stalled uploads ratcheted the pool
    /// upward by a chunk each per wait - 8 MiB per 5 s with the HTTP
    /// worker count, walking back to the multi-gigabyte figure this
    /// budget exists to prevent. It needed no credentials beyond the
    /// add-only tier `addfile` accepts. Found by Codex on the 31 Jul
    /// sweep; `stalled_holders_cannot_ratchet_the_pool_upward` is the
    /// regression test, and it reached 7x the cap in 600 ms against the
    /// old rule.
    pub(super) fn grow(&self, h: &mut Hold, more: u64) {
        let mut cur = self.cur.lock_ok();
        // Join the queue on first contact, so arrival order is the order
        // bodies started reading rather than the order they blocked.
        let ticket = *h.ticket.get_or_insert_with(|| {
            let t = cur.next_ticket;
            cur.next_ticket += 1;
            cur.live.insert(t);
            t
        });
        loop {
            let others = cur.bytes - h.bytes;
            // Sole reader, or it fits: the ordinary cases.
            if others == 0 || cur.bytes + more <= self.cap {
                break;
            }
            // The designated finisher. Only ever one body, and only while
            // it is the oldest thing in the pool.
            if cur.live.first() == Some(&ticket) {
                break;
            }
            cur = self.cv.wait_timeout(cur, self.wait).unwrap().0;
        }
        cur.bytes += more;
        h.bytes += more;
    }

    pub(super) fn release(&self, h: Hold) {
        let Some(ticket) = h.ticket else { return };
        {
            let mut cur = self.cur.lock_ok();
            cur.bytes -= h.bytes;
            cur.live.remove(&ticket);
        }
        // Always: dropping out of `live` can promote a new finisher even
        // when this body held nothing.
        self.cv.notify_all();
    }
}

/// RAII form of a body's budget claim: the reservation lives exactly as
/// long as this guard. The read used to release its claim at the end of
/// the READ, before the body was parsed - so the parse phase (and a body
/// retained for later arms, like the pre-auth form buffer) sat entirely
/// outside the budget, and concurrent workers could each hold a full
/// 256 MiB body "for free" while parsing (Codex H8). Callers that keep
/// the bytes keep the guard beside them.
///
/// Since Codex sweep 2's H1 the /api pre-read covers EVERY post, so this
/// window now spans dispatch for bodies that used to be read (and
/// released) inside a handler - an untyped or `text/plain` POST among
/// them. The extra exposure is bounded by [`api_body_cap`], which gives
/// those [`API_BODY_DEFAULT`] rather than the ceiling, so it is ~1 MiB
/// per worker; the modes that can hold the ceiling open through dispatch
/// (addfile, wall_art) already did so through the old form path.
pub(super) struct BodyHold(Option<Hold>);
impl Drop for BodyHold {
    fn drop(&mut self) {
        if let Some(h) = self.0.take() {
            body_budget().release(h);
        }
    }
}

/// Largest body a POST to `/api` may carry, when nothing more specific
/// is known: the ceiling every endpoint that takes a whole NZB needs.
pub(super) const API_BODY_MAX: u64 = 256 << 20;

/// The cap for an /api POST that names no size-hungry mode. Generous
/// enough for any JSON settings blob (the watchlist, feeds, notify
/// targets and *arr instances all live well inside it) and far below
/// the ceiling.
pub(super) const API_BODY_DEFAULT: u64 = 1 << 20;

/// How large a body each `/api` mode is allowed to send.
///
/// The gateway reads every POST body before authorizing (see the
/// pre-read at the front controller), so this is where the endpoint's
/// real limit has to be applied - the handlers' own capped-read
/// fallbacks are unreachable now, and a flat ceiling would let a
/// nominal 1 MiB endpoint buffer and parse 256 MiB (Codex sweep 2,
/// 3 Aug M1).
///
/// Only the modes that legitimately carry bulk are listed; everything
/// else takes [`API_BODY_DEFAULT`]. Erring large costs memory on a
/// request that was going to be refused anyway; erring small breaks a
/// real upload, so anything that can carry an NZB, an archive of them,
/// or an image is at the ceiling.
/// Each figure is the cap the handler itself already declared, so this
/// changes no endpoint's real limit - it moves the decision to the only
/// place that still runs.
pub(super) fn api_body_cap(mode: &str) -> u64 {
    match mode {
        // A whole NZB, or a multipart batch of them.
        //
        // `nzb_preview` takes the SAME payload - `api::queue::preview`
        // accepts the identical bare-or-multipart NZB that `addfile`
        // does, and its whole job is to parse it and report what is in
        // it - so it needs the same ceiling. It was on
        // `API_BODY_DEFAULT`, which truncated any NZB over 1 MiB and
        // then reported the truncation as "not an NZB", while dropping
        // the very same bytes on `addfile` worked.
        "addfile" | "nzb_preview" => API_BODY_MAX,
        // A settings backup archive.
        "backup_import" => 8 << 20,
        // Poster/fanart upload.
        "wall_art" => 10 << 20,
        _ => API_BODY_DEFAULT,
    }
}

/// Read a request body with a hard size cap, returning the budget claim
/// alongside the bytes so the caller can keep the reservation alive
/// through parsing.
///
/// The cap exists because no single POST may balloon the daemon's RSS -
/// tiny_http hands us the raw reader and nothing upstream bounds it. A
/// body that hits the cap comes back truncated and fails its parse,
/// which surfaces as the normal bad-request error for that endpoint.
pub(super) fn read_body_capped_hold(r: impl std::io::Read, cap: u64) -> (Vec<u8>, BodyHold) {
    use std::io::Read as _;
    let budget = body_budget();
    let mut hold = Hold::default();
    let mut raw = Vec::new();
    let mut r = r.take(cap);
    // Chunked so the reservation tracks the body as it arrives instead
    // of front-loading the worst case: a 30 KB NZB reserves one chunk,
    // not 256 MB. Accounting is by bytes read (Vec spare capacity is
    // bounded by one doubling and not worth modelling).
    const CHUNK: u64 = 1 << 20;
    loop {
        budget.grow(&mut hold, CHUNK);
        // Error handling matches the pre-budget behavior: a broken read
        // returns whatever arrived (the parsers judge it).
        match (&mut r).take(CHUNK).read_to_end(&mut raw) {
            Ok(n) if n as u64 == CHUNK => continue,
            _ => break,
        }
    }
    // `r.take(cap)` is what bounds the one body the pool may let past its
    // cap: the designated finisher can over-run by its own per-request
    // limit and no more.
    (raw, BodyHold(Some(hold)))
}
