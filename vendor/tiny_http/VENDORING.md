# Vendored `tiny_http` 0.12.0 - why, and exactly what we changed

Upstream: <https://github.com/tiny-http/tiny-http>, crates.io `tiny_http 0.12.0`.
Vendored 24 Jul 2026 from `~/.cargo/registry/src/.../tiny_http-0.12.0`.
Licence unchanged (MIT OR Apache-2.0); `LICENSE-APACHE` and `LICENSE-MIT` are
vendored alongside the source.

## Why this is vendored and not a dependency

A full-surface hardening sweep found **two unauthenticated, one-request,
permanent kills** of the whole HTTP surface, plus the long-standing slowloris,
all of them unreachable from the public API. 0.12.0 is the newest published
release, so there was no version to upgrade to, and `ServerConfig` exposes only
`addr` + `ssl` while `Request` never hands out the socket - so none of the three
could be fixed from our side.

Full write-up: `research/bug-sweep-2026-07-24-full-surface.md` (C1, C2, H1).

## The patches

Each is marked in-source with `nzbfast patch N`, so a diff against a fresh
0.12.0 checkout should show exactly these and nothing else. Patches 1-4 came
from the vendoring itself; 5-8 came out of the 25 Jul security sweep; 9-12 are
that sweep's remaining four HTTP findings, done as one pass (see
"Admission control" below for why they are not four separate patches).

1. **`src/util/equal_reader.rs` - bounded drop-drain.** Upstream discards an
   unread request body with `vec![0; remaining_to_read]`: one zeroed allocation
   of the entire *declared* `Content-Length`, on the thread that drops the
   `Request`. `Content-Length: 2^47` on `GET /` made `alloc_zeroed` fail →
   `handle_alloc_error` → **`abort()`** of the whole daemon from ~90
   unauthenticated bytes; `usize::MAX` panicked instead, killing the worker loop.
   Now drains through a reused 64 KiB buffer. Drain semantics and the
   `last_read_signal` contract are unchanged.
2. **`src/request.rs` - cap `Content-Length` at parse.** Upstream parses it into
   `usize` with no ceiling and then trusts it to size allocations. Anything over
   1 GiB (nzbfast's own largest body cap is a 256 MiB NZB upload) is a malformed
   request, so it now parses as "no Content-Length" - the handler sees an empty
   body and there is nothing to drain.
3. **`src/lib.rs` - survive a transient `accept()` error.** Upstream `break`s the
   accept thread on **any** error, permanently: the listener never accepts again
   while the process stays alive (so no supervisor restarts it) and downloads keep
   running. `ECONNABORTED` is producible at will (connect + `SO_LINGER{1,0}`) and
   `EMFILE`/`ENFILE` need no attacker at all. Transient kinds - plus errno 23/24
   on unix, since Rust has no stable `ErrorKind` for fd exhaustion - now log,
   sleep 50 ms (so a persistent fd shortage cannot busy-loop) and keep listening.
   Genuinely unrecoverable errors still end the thread as before.
4. **`src/connection.rs` - read/write timeouts on every accepted socket** (30 s).
   Closes the slowloris at all three of its blocking points: stalled request body,
   stalled drop-drain of an unread body (needs no auth and no body-reading
   handler), and stalled response write. Best-effort - the result is ignored, so a
   platform that refuses leaves us no worse off than upstream.
5. **`src/client.rs` - reject an unsupported HTTP version before allocating a
   response writer.** Upstream checked *after* `read()` had already taken
   sequential writer #1 into the `Request`, then took writer #2 to print the 505
   synchronously. Writer #2 blocks until #1 drops, and #1 could not drop while
   the print held its frame: one well-formed `GET / HTTP/2.0` deadlocked its
   parser thread forever, unbreakable by socket timeouts (the wait is on a
   channel). The version is now checked off the request line, before any writer
   exists, and the connection closes instead of `continue`-ing - upstream's
   `continue` left the rejected request's body to be parsed as another request.
6. **`src/request.rs` - unusable framing fails the request.** Patch 2 filtered an
   over-cap `Content-Length` to `None`, and upstream does the same for anything
   unparsable. `None` installs `io::empty()` and drops the real reader, whose
   `Drop` returns the `BufReader` - body bytes still in it - to header parsing,
   so the declared body is parsed as the **next request**. A standards-framing
   proxy in front sees one request; we see two. Now a `Content-Length` we cannot
   honour, and `Content-Length` together with `Transfer-Encoding` (RFC 7230
   3.3.3), produce `BadFraming` → 400 → close.
7. **`src/client.rs` - stop trimming header lines before validation.**
   `read_next_line` already strips CRLF, so the `.trim()` only removed *leading*
   whitespace - exactly what `Header`'s strict parser rejects to defend
   RUSTSEC-2020-0031 (see its own `test_strict_headers`). Trimming first handed
   that parser a repaired line, so an obs-fold continuation `\tTransfer-Encoding:
   chunked` became a genuine TE header and re-opened the smuggling differential
   the strict parser existed to close.
8. **`src/util/refined_tcp_stream.rs` + `src/lib.rs` - fallible socket split.**
   Splitting an accepted socket dups its descriptor; that was spelled
   `try_clone().unwrap()` inside `impl Clone`, whose signature cannot fail. Under
   FD exhaustion `accept()` takes the last descriptor and succeeds, the `dup`
   then fails with EMFILE, and the unwrap panicked the server's **only** accept
   thread - HTTP never accepts again, and patch 3 cannot help because `accept()`
   itself did not fail. Now `Stream::try_split` returns `io::Result`, and the
   accept loop drops that one connection and keeps listening.
9. **`src/util/task_pool.rs` + `src/lib.rs` - bounded connection admission,
   fallible spawn.** One task in this pool is one whole *connection*, and
   upstream created a thread whenever none was idle, with `thread::spawn` -
   which cannot fail without panicking. An unauthenticated client that opened
   sockets and dribbled a partial request line on each held a thread per socket
   indefinitely; when the OS finally refused another thread, the panic landed in
   the **only** accept thread, so HTTP stayed dead for the life of the process
   even after the pressure eased. Now: a hard ceiling on threads (so, on
   concurrent connections), `Builder::spawn` with the task handed back on
   failure so the accept loop sheds that connection and keeps listening, and a
   slot released even if a task panics - otherwise the ceiling would erode to
   zero. Two upstream bugs fell out on the way: queue claiming now compares
   against the queue length instead of testing `idle != 0`, because two racing
   `spawn` calls could queue two tasks for one idle thread and the second
   connection then sat unparsed until an unrelated one closed; and
   `peer_addr()`, which fails with ENOTCONN if the peer RSTs between `accept()`
   and `ClientConnection::new`, is no longer unwrapped.
10. **`src/util/deadline.rs` (new) + `src/client.rs` - absolute per-request
    bounds.** Patch 4's socket timeouts are per-syscall *inactivity* timeouts
    that the kernel restarts on every byte that moves, so a peer dribbling one
    byte every 20 s never tripped them. Four of them held all four application
    workers, and `POST /nonexistent` reaches it with no auth and no body-reading
    handler at all. Header parsing had no clock and no limits either: no
    request-line length, no per-header length, no total header bytes, no header
    count. Now the header phase has a total deadline (armed by the request's
    *first byte*, so an idle keep-alive connection is still governed only by the
    socket timeout, unchanged) plus all four size limits → 414/431/408 and
    close; and a `DeadlineReader` sits *beneath* every body shape - handler
    reads, the small-body pre-read, the chunked decoder and the drop-drain -
    with a `DeadlineWriter` doing the same for responses. Both use a **minimum
    sustained rate**, not a fixed deadline, because that is what separates a
    slow uploader from an attacker: a 256 MiB NZB on a bad link still beats
    8 KiB/s, and the drip moves 0.05 B/s. The response clock counts only time
    spent *inside* `write`, never wall time, so a `/stream` response waiting
    minutes on articles is not mistaken for a stalled client.
11. **`src/util/equal_reader.rs`, `src/util/sequential.rs`,
    `src/util/messages_queue.rs` - bounded drain, and desync closes the
    connection.** Discarding an unread body is only ever a courtesy that lets
    the socket be reused, so it is now bounded in bytes (`max_drain`, 1 MiB) and
    in time (`max_drain_time`, 2 s - deliberately far shorter than
    `body_grace`, which exists for a body a handler is actually READING; on the
    same clock the drip just bought that grace over and over for a body sized
    under the byte cap). Both bounds mean a body can now stop short of its
    declared end, and so the connection **must** close: handing it back with
    body bytes still on the wire makes the next "request line" come out of the
    middle of a body, which is the desynchronisation patch 6 closed on the
    rejected-framing path. Upstream did exactly that, silently, on any drain
    that hit a read error. The marking is checked in the parser after a new
    `SequentialReader::acquire` - which takes our turn on the socket without
    consuming a byte, because folding the hand-over into the first `read` makes
    the decision one byte too late. `MessagesQueue::with_capacity` is also now a
    real bound rather than a `VecDeque` size hint (its name was the whole bug),
    with `push_control` for the messages that must never block.
12. **`src/lib.rs` + `src/request.rs` - one outstanding request per connection,
    on every connection.** Upstream ran its notify-sender handshake only for
    HTTPS, where it was needed to avoid a deadlock, and let plain connections
    push every pipelined request straight through. That is what made the request
    queue growable from a single socket, and it is also how one unauthenticated
    `/stream` response - which can legitimately hold its writer for 300 s - got
    four ordinary requests pipelined behind it onto all four application
    workers, each blocked on response ordering with no deadline: the dashboard
    gone for five minutes at a time, repeatably. The handshake now runs for
    every connection, so a connection cannot run ahead of its own responses, a
    hostile pipeline only wedges itself, and response ordering becomes trivially
    satisfied instead of something later requests queue behind. Turning it on
    universally also put upstream's three `send(()).unwrap()` calls and two
    `recv().unwrap()` calls on the path of every response, where an absent
    parser thread is normal, so all five no longer panic.

13. **`Cargo.toml`, `src/lib.rs`, `src/ssl/rustls.rs` - the rustls backend is
    real, and takes a prebuilt config (TODO §129 2a, native HTTPS for the
    daemon UI/API).** The `ssl-rustls` feature was vendored as a declared-but-
    empty stub; it now enables an optional `rustls 0.23` dependency (upstream's
    implementation targeted the 0.20 API). Deliberate departure from upstream:
    `SslConfig` under this feature carries `Arc<rustls::ServerConfig>` instead
    of raw PEM byte vectors, so certificate parsing, validation and error
    wording live with the caller - which can name the offending FILE, check
    expiry, and choose the crypto provider. The last point is load-bearing:
    the workspace links both aws-lc-rs and ring, so a provider-less
    `rustls::ServerConfig::builder()` in here would panic at run time (same
    trap `nzbkit::benchserve::tls_config` documents). No provider feature is
    enabled on the dependency for the same reason. The handshake stays lazy
    (`StreamOwned` handshakes on first read/write in the worker, never in the
    accept thread), and patch 12's per-connection handshake - which upstream
    ran ONLY for HTTPS - already runs everywhere, so HTTPS connections get the
    same one-outstanding-request admission as plain ones. `ssl-openssl`
    remains a stub.

14. **`src/connection.rs` + `src/util/messages_queue.rs` - two small gaps
    (14 Oct 2026 Gemini sweep, L8).** Patch 4's 30 s read/write deadlines
    were applied to accepted TCP sockets only; a Unix-socket listener's
    accepted streams got none. nzbfast serves over TCP and never builds a
    Unix listener, so this was latent, but the rule is "every accepted
    socket" and now holds. And `MessagesQueue::pop_timeout` computed the
    time left after each wakeup and then passed the ORIGINAL `timeout` to
    `wait_timeout` anyway, so a wakeup that found nothing restarted the
    whole wait - `Server::recv_timeout`, which the daemon's HTTP loop polls,
    could block for nearly twice its timeout. It now waits for what is
    left. Test `util::messages_queue::tests::an_empty_wakeup_does_not_restart_the_timeout`
    (707 ms against a 600 ms bound before, ~400 ms after).

## Admission control (patches 9-12)

These four were reported as separate findings (2, 3, 4 and A5 of the 25 Jul
sweep) and are one missing feature: nothing in upstream ever said what a
connection or a request may cost. Fixing them individually gives four unrelated
band-aids over a model that is still unbounded, which is why both the sweep and
the architectural review called for one pass.

The budget lives in `ServerLimits`, reachable via `Server::http_with_limits` and
`ServerConfig.limits`; `Server::http` uses the defaults, which is what the daemon
does. Every default is sized for what nzbfast actually serves and is far above
each legitimate case while far below each hostile one - the reasoning for each
number is on its field.

**`/stream` keeps its keep-alive connection.** That is a deliberate choice, and it is
what patch 12 makes safe: a long response now holds only its own parser thread
and one admission slot, and can never occupy an application worker, so forcing
`Connection: close` (and paying a TCP handshake per range request, against the
M11 seek-latency work) buys nothing further.

### Who actually stops a slow reader

Measured against the live daemon and over a real socket, because the arithmetic
alone is misleading:

- **Nothing this server serves except `/stream` is big enough to block.** The
  dashboard is the largest non-stream response at ~252 KB, and macOS loopback
  offers ~256 KB of kernel buffering (`net.inet.tcp.sendspace` +
  `recvspace`, 128 KB each), so `respond` completes and frees the worker before
  the peer has read any of it. The write floor is not consulted at all, and the
  slow-dashboard-client false positive it would have to be tuned around does not
  arise.
- **On a `/stream`-scale response, patch 4's 30 s `SO_SNDTIMEO` usually fires
  first, not the floor.** A slow reader drains the *kernel buffer*, so from the
  server's side the socket stays full and the write makes zero progress for as
  long as that takes - which reads as a stalled peer and times out (`EAGAIN`, so
  `WouldBlock` rather than `TimedOut` on macOS: do not match on the kind).
- **The floor's job is the narrow case the timeout cannot see:** a peer that
  reads just enough to keep each write returning inside 30 s while the sustained
  rate stays derisory. That is precisely the peer the sweep described, and it is
  what `a_slow_reader_fails_the_response_on_sustained_rate` covers. Confirmed
  firing over a real socket on an 8 MiB response: `respond` returns an error and
  the worker is released, while the peer goes on draining whatever was already
  buffered - the worker is the resource being protected here, not the socket.

So the two response-side mechanisms do not overlap as much as they look like they
do, and neither is redundant. If you retune either, retune it knowing which
regime it owns.

## Regression tests

`tests/nzbfast_framing.rs` drives patches 5-12 over a real TCP socket against the
real connection parser. That matters: every one of these lives in how the
*connection* assembles a request, not in how a header string parses, and the
obs-fold hole sat behind passing strict-header unit tests for exactly that
reason.

Patches 9-12 are about resources and timing rather than bytes on the wire, so
those tests assert availability the way the sweep stated it - *an unrelated
client is still served, promptly* - and were each checked by disabling the
mechanism they guard and confirming they fail. Three things that verification
caught, all of which had looked covered:

- a body under 1024 bytes never reaches `EqualReader` at all (`new_request` reads
  it eagerly into a buffer), so any drain or desync test has to use a bigger one;
- a drip declaring over `max_drain` is stopped by patch 11's byte cap before
  patch 10's rate floor is ever consulted, so the rate floor needs its own test
  sized under the cap;
- asserting only that a *later* client is served proves nothing about a deadline,
  since a large enough thread pool satisfies it with the bug still present. The
  header-drip test asserts the 408 on the dripping connection itself.

`the_shipped_defaults_bound_a_body_drip_within_seconds` deliberately does not
shorten the budgets: the other tests assert the mechanisms exist, that one
asserts they are configured tightly enough to matter.

## Trimmed vs the published crate

- `Cargo.toml` rewritten: dev-dependencies dropped (`fdlimit`,
  `rustc-serialize`, `sha1` - old, and the crate's own test suite is not
  vendored). The openssl TLS backend is dropped entirely; the rustls backend
  was dropped at vendoring time and restored by patch 13 for the daemon's
  opt-in native HTTPS (NNTP TLS is separate and stays in `nzbkit`).
- `benches/`, `tests/`, `examples/`, `README.md`, `CHANGELOG.md` not vendored.
- The crate's own `#[cfg(test)]` unit tests **are** kept (they ship inside
  `src/`), and they pass - including `equal_reader`'s, which cover the patched
  drain.

## If you ever re-sync

There is deliberately no `sync-from-fork.sh` here (unlike `vendor/rars`, which
tracks our own fork): this is a one-time snapshot of a crates.io release. To move
to a newer upstream, diff for the `nzbfast patch N` markers and
re-apply each one by hand - none of them is mechanical, and patch 3's transient
set in particular deserves a fresh look at whatever the new accept loop does.
Then re-check that `Server::from_listener` still bypasses patch 4 (it does today:
a caller-supplied `TcpListener` reaches `Listener::accept`, so accepted sockets
still get the timeouts).

Patches 9-12 are the ones to re-apply as a unit rather than one at a time; each
of the four is load-bearing for the others. Two specific things to re-check
against any new upstream, because both are invariants of *their* code that ours
depends on:

- the small-body fast path still reads bodies of 1024 bytes or fewer eagerly at
  request creation. Patch 11's drain and desync logic only covers bodies above
  it, which is correct only because a short read on that path already fails
  request creation and closes the connection;
- `MIN_THREADS` threads are **not** pre-spawned. They are created on demand
  (patch 9 removed the warm-up loop): `threads` is what the ceiling applies to,
  and a warm-up thread that has not parked yet is not claimable, so pre-spawning
  would let the very first connections be refused while four threads sat idle.

`from_listener` also takes a `ServerLimits` now, and `ServerConfig` carries one.
