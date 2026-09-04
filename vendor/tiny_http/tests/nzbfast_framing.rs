//! Regressions for the nzbfast hardening patches, driven over a real TCP
//! socket against the real connection parser.
//!
//! Unit-testing `Header::from_str` was not enough to catch any of these: every
//! one lives in how the CONNECTION assembles a request, not in how a single
//! header string parses. The leading-whitespace case in particular passed the
//! strict header tests the whole time, because the connection parser trimmed
//! the line before handing it over.
//!
//! test-target-gate: the vendored fork's only tests/ target - the only
//! fold destination is upstream's lib, judged not worth the fork churn
//! (research/TEST-BINARY-FOLD-AUDIT-2026-09-01.md, the UNCLEAR verdict)

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tiny_http::{Request, Response, Server, ServerLimits};

/// A server on an ephemeral port with a thread answering 200 to anything it
/// is given. Returns the address plus a handle that stops the thread on drop.
fn serve() -> (String, std::sync::Arc<Server>) {
    serve_with(ServerLimits::default(), 1, |rq| {
        let _ = rq.respond(Response::from_string("ok"));
    })
}

/// As `serve`, with an explicit admission budget, a worker count (four mirrors
/// the daemon's own pool) and a handler.
fn serve_with<F>(limits: ServerLimits, workers: usize, handle: F) -> (String, Arc<Server>)
where
    F: Fn(Request) + Send + Sync + 'static,
{
    let server = Arc::new(Server::http_with_limits("127.0.0.1:0", limits).unwrap());
    let addr = match server.server_addr() {
        tiny_http::ListenAddr::IP(a) => a.to_string(),
        #[cfg(unix)]
        other => panic!("unexpected listen addr {:?}", other),
    };
    let handle = Arc::new(handle);
    for _ in 0..workers {
        let worker = server.clone();
        let handle = handle.clone();
        std::thread::spawn(move || {
            while let Ok(rq) = worker.recv() {
                handle(rq);
            }
        });
    }
    (addr, server)
}

fn send_raw(addr: &str, wire: &[u8]) -> String {
    let mut sock = TcpStream::connect(addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    sock.write_all(wire).unwrap();
    sock.flush().unwrap();
    let mut got = Vec::new();
    // Read to EOF: every case here must end with the server closing.
    let _ = sock.read_to_end(&mut got);
    String::from_utf8_lossy(&got).to_string()
}

/// As `send_raw`, but tolerates the server closing mid-write - which is the
/// correct behaviour for the over-limit cases, and would otherwise make the
/// write, not the assertion, decide the test.
fn send_raw_tolerant(addr: &str, wire: &[u8]) -> String {
    let mut sock = TcpStream::connect(addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let _ = sock.write_all(wire);
    let _ = sock.flush();
    let mut got = Vec::new();
    let _ = sock.read_to_end(&mut got);
    String::from_utf8_lossy(&got).to_string()
}

/// One normal request on its own connection, and how long it took to answer.
/// The elapsed time is the point in the availability tests: an unrelated client
/// must not wait behind somebody else's hostile connection.
fn timed_request(addr: &str, path: &str, patience: Duration) -> (Option<String>, Duration) {
    let at = Instant::now();
    let mut sock = TcpStream::connect(addr).unwrap();
    sock.set_read_timeout(Some(patience)).unwrap();
    let wire = format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    if sock.write_all(wire.as_bytes()).is_err() {
        return (None, at.elapsed());
    }
    let mut got = Vec::new();
    let _ = sock.read_to_end(&mut got);
    let elapsed = at.elapsed();
    if got.is_empty() {
        return (None, elapsed);
    }
    (Some(String::from_utf8_lossy(&got).to_string()), elapsed)
}

/// Patch 5. Upstream allocated response writer #1 to the request, then took
/// writer #2 to print the 505 - and sequential writers block until the
/// previous one drops, which it could not while the print held it. This one
/// well-formed request wedged its parser thread forever.
///
/// The assertion that matters is that this test RETURNS: before the fix it
/// hangs until the harness kills it.
#[test]
fn http_2_request_is_rejected_without_deadlocking_the_parser() {
    let (addr, _server) = serve();
    let reply = send_raw(&addr, b"GET / HTTP/2.0\r\nHost: x\r\n\r\n");
    assert!(
        reply.starts_with("HTTP/1.1 505"),
        "expected 505, got: {:?}", reply
    );
}

/// ...and the connection must be dead afterwards. Upstream `continue`d, which
/// left an unconsumed body to be parsed as the next request.
#[test]
fn http_2_request_closes_the_connection() {
    let (addr, _server) = serve();
    let mut sock = TcpStream::connect(&addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    sock.write_all(b"GET / HTTP/2.0\r\nHost: x\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let mut got = String::new();
    let _ = sock.read_to_string(&mut got);
    assert!(got.starts_with("HTTP/1.1 505"), "got: {:?}", got);
    assert_eq!(
        got.matches("HTTP/1.1 ").count(),
        1,
        "the bytes after a rejected request must not be served: {:?}", got
    );
}

/// Patch 7. `read_next_line` already strips CRLF, so the parser's `.trim()`
/// only ever removed LEADING whitespace - exactly what the strict header
/// parser rejects to defend RUSTSEC-2020-0031. An obs-fold continuation line
/// therefore arrived as a genuine Transfer-Encoding header, letting a
/// CL-framing proxy and this server disagree about the message boundary.
#[test]
fn obs_fold_continuation_is_not_promoted_to_a_real_header() {
    let (addr, _server) = serve();
    let wire = b"POST / HTTP/1.1\r\n\
                 Host: x\r\n\
                 Content-Length: 38\r\n\
                 X: x\r\n\
                 \tTransfer-Encoding: chunked\r\n\
                 \r\n\
                 0\r\n\
                 \r\n\
                 GET /smuggled HTTP/1.1\r\n\r\n";
    let reply = send_raw(&addr, wire);
    assert!(
        reply.starts_with("HTTP/1.1 400"),
        "a folded header line must be refused, got: {:?}", reply
    );
    assert!(
        !reply.contains("/smuggled"),
        "nothing after the body boundary may be served: {:?}", reply
    );
}

/// Patch 6. An unusable Content-Length used to be filtered to `None`, which
/// installed an empty body and handed the buffered body bytes back to header
/// parsing - so the declared body became the next request.
#[test]
fn oversized_content_length_does_not_become_a_second_request() {
    let (addr, _server) = serve();
    let wire = b"POST / HTTP/1.1\r\n\
                 Host: x\r\n\
                 Content-Length: 1073741825\r\n\
                 \r\n\
                 GET /api?mode=shutdown HTTP/1.1\r\n\
                 Host: x\r\n\r\n";
    let reply = send_raw(&addr, wire);
    assert!(
        reply.starts_with("HTTP/1.1 400"),
        "expected the request to be refused, got: {:?}", reply
    );
    assert_eq!(
        reply.matches("HTTP/1.1 ").count(),
        1,
        "the smuggled request must never be answered: {:?}", reply
    );
}

/// Same hole, reached through a length that simply does not parse - the
/// addendum's point that this was never only about the 1 GiB cap.
#[test]
fn unparsable_content_length_does_not_become_a_second_request() {
    let (addr, _server) = serve();
    for bad in ["abc", "-1", "0x10", "99999999999999999999999999"] {
        let wire = format!(
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {bad}\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n"
        );
        let reply = send_raw(&addr, wire.as_bytes());
        assert!(
            reply.starts_with("HTTP/1.1 400"),
            "Content-Length {:?} should be refused, got: {:?}", bad, reply
        );
        assert_eq!(
            reply.matches("HTTP/1.1 ").count(),
            1,
            "Content-Length {:?} leaked a second request: {:?}", bad, reply
        );
    }
}

/// Content-Length together with Transfer-Encoding is the classic smuggling
/// pair. Upstream silently preferred TE and dropped CL, which is precisely the
/// disagreement an intermediary resolves the other way.
#[test]
fn content_length_with_transfer_encoding_is_refused() {
    let (addr, _server) = serve();
    let wire = b"POST / HTTP/1.1\r\n\
                 Host: x\r\n\
                 Content-Length: 6\r\n\
                 Transfer-Encoding: chunked\r\n\
                 \r\n\
                 0\r\n\r\n";
    let reply = send_raw(&addr, wire);
    assert!(
        reply.starts_with("HTTP/1.1 400"),
        "CL+TE must be refused, got: {:?}", reply
    );
}

/// The rejections above must not cost the server its listener: a later client
/// still gets served. (This is also the shape A3's FD-exhaustion panic broke -
/// there the accept thread died and nothing was ever served again.)
#[test]
fn the_server_keeps_serving_after_refusing_bad_requests() {
    let (addr, _server) = serve();
    send_raw(&addr, b"GET / HTTP/2.0\r\nHost: x\r\n\r\n");
    send_raw(&addr, b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: nope\r\n\r\n");

    let reply = send_raw(&addr, b"GET /healthy HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    assert!(
        reply.starts_with("HTTP/1.1 200"),
        "server stopped serving after bad requests: {:?}", reply
    );
}

// ---------------------------------------------------------------------------
// Patches 9-12: admission control. Findings 2, 3, 4 and A5 of the 25 Jul sweep.
//
// All four were one missing feature - nothing ever said what a connection or a
// request may cost - so the regressions below are about resources and timing
// rather than about bytes on the wire. Each states the availability property in
// the form the sweep did: an unrelated client must still be served.
// ---------------------------------------------------------------------------

/// Short budgets, so the tests assert the mechanism rather than wait out the
/// shipped 30-second defaults.
fn tight_limits() -> ServerLimits {
    ServerLimits {
        header_deadline: Duration::from_secs(1),
        body_grace: Duration::from_secs(1),
        write_grace: Duration::from_secs(1),
        ..ServerLimits::default()
    }
}

/// Four connections dribbling one byte at a time into a declared body, and a
/// fifth ordinary client that must still be served. `declared` decides which of
/// the two independent bounds does the work, so both are exercised below.
fn assert_body_drip_does_not_hold_the_workers(declared: u64, what: &str) {
    let (addr, _server) = serve_with(tight_limits(), 4, |rq| {
        // Respond without reading the body, exactly like a 404 route. Dropping
        // the request is what enters the drain.
        let _ = rq.respond(Response::from_string("ok").with_status_code(404));
    });

    let mut drips = Vec::new();
    for _ in 0..4 {
        let addr = addr.clone();
        drips.push(std::thread::spawn(move || {
            let mut sock = TcpStream::connect(&addr).unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let head =
                format!("POST /zzz HTTP/1.1\r\nHost: x\r\nContent-Length: {declared}\r\n\r\n");
            if sock.write_all(head.as_bytes()).is_err() {
                return;
            }
            let _ = sock.flush();
            // One byte at a time, comfortably faster than any idle timeout, so
            // nothing here ever trips SO_RCVTIMEO. Long enough that the peer
            // giving up cannot be what ends it - the server has to.
            for _ in 0..300 {
                if sock.write_all(b"x").is_err() {
                    break;
                }
                let _ = sock.flush();
                std::thread::sleep(Duration::from_millis(100));
            }
        }));
    }

    // Let all four 404s go out and all four drains start.
    std::thread::sleep(Duration::from_millis(500));

    let (reply, elapsed) = timed_request(&addr, "/dashboard", Duration::from_secs(20));
    let reply = reply
        .unwrap_or_else(|| panic!("the dashboard was never answered ({})", what));
    assert!(
        reply.starts_with("HTTP/1.1 404"),
        "unexpected reply ({}): {:?}",
        what,
        reply
    );
    // The bound has to be well under the 30 s the peer keeps dribbling for, or
    // the peer running out of patience would pass this instead of the server
    // enforcing anything.
    assert!(
        elapsed < Duration::from_secs(5),
        "the dashboard waited {:?} behind four dripping bodies ({})",
        elapsed,
        what
    );

    for d in drips {
        let _ = d.join();
    }
}

/// Finding 2. Four connections declaring a large body and dribbling one byte at
/// a time held all four application workers indefinitely: `SO_RCVTIMEO` is an
/// inactivity timeout and every byte reset it, while `EqualReader`'s drop-drain
/// kept reading until the *declared* body was exhausted. `POST /nonexistent`
/// reaches it with no authentication and no body-reading handler.
///
/// A gigabyte is past `max_drain`, so this is the patch 11 path: not worth
/// discarding, so the connection is closed instead of drained.
#[test]
fn four_body_drip_connections_do_not_hold_the_workers() {
    assert_body_drip_does_not_hold_the_workers(1024 * 1024 * 1024, "over the drain cap");
}

/// The same attack sized to stay UNDER `max_drain`, so the drain really does run
/// and patch 10's sustained-rate floor is the only thing that ends it. Without
/// the floor these four bodies hold all four workers for as long as the peer
/// keeps dribbling - which is the finding exactly as reported.
#[test]
fn a_dripped_body_under_the_drain_cap_still_hits_the_rate_floor() {
    assert_body_drip_does_not_hold_the_workers(512 * 1024, "under the drain cap");
}

/// ...and at the SHIPPED defaults, which is the number that actually protects
/// the daemon. The tests above shorten the budgets to assert the mechanism; this
/// one asserts the mechanism is configured tightly enough to matter, because
/// `body_grace` alone would let this repeat every 30 seconds indefinitely.
///
/// Deliberately not using `tight_limits`.
#[test]
fn the_shipped_defaults_bound_a_body_drip_within_seconds() {
    let (addr, _server) = serve_with(ServerLimits::default(), 4, |rq| {
        let _ = rq.respond(Response::from_string("ok").with_status_code(404));
    });

    let mut drips = Vec::new();
    for _ in 0..4 {
        let addr = addr.clone();
        drips.push(std::thread::spawn(move || {
            let mut sock = TcpStream::connect(&addr).unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            // Under the 1 MiB default drain cap, so the drain really runs.
            if sock
                .write_all(b"POST /zzz HTTP/1.1\r\nHost: x\r\nContent-Length: 524288\r\n\r\n")
                .is_err()
            {
                return;
            }
            let _ = sock.flush();
            for _ in 0..300 {
                if sock.write_all(b"x").is_err() {
                    break;
                }
                let _ = sock.flush();
                std::thread::sleep(Duration::from_millis(100));
            }
        }));
    }

    std::thread::sleep(Duration::from_millis(500));
    let (reply, elapsed) = timed_request(&addr, "/dashboard", Duration::from_secs(25));
    let reply = reply.expect("the dashboard was never answered at the shipped defaults");
    assert!(reply.starts_with("HTTP/1.1 404"), "got: {:?}", reply);
    assert!(
        elapsed < Duration::from_secs(8),
        "at the shipped defaults the dashboard waited {:?} behind four drips",
        elapsed
    );

    for d in drips {
        let _ = d.join();
    }
}

/// Finding 3. Header parsing was byte-at-a-time with no clock, so a partial
/// request line plus one byte every so often held a parser thread for as long as
/// the peer cared to keep it - and threads were created per connection with no
/// ceiling, so repeating it exhausted the process.
/// The assertion is on the DRIPPING connection: it must be given up on, on total
/// elapsed time, while it is still dripping happily inside every idle timeout.
/// (Asserting only that a later client is served would prove nothing - a large
/// enough thread pool satisfies that with the bug still present.)
#[test]
fn a_dripped_header_times_out_on_total_elapsed_time() {
    let (addr, _server) = serve_with(tight_limits(), 1, |rq| {
        let _ = rq.respond(Response::from_string("ok"));
    });

    let at = Instant::now();
    let mut sock = TcpStream::connect(&addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    // A request line that never terminates.
    sock.write_all(b"GET /").unwrap();
    let _ = sock.flush();

    let mut writer = sock.try_clone().unwrap();
    let dripper = std::thread::spawn(move || {
        for _ in 0..400 {
            if writer.write_all(b"x").is_err() {
                break;
            }
            let _ = writer.flush();
            std::thread::sleep(Duration::from_millis(50));
        }
    });

    let mut got = Vec::new();
    let _ = sock.read_to_end(&mut got);
    let elapsed = at.elapsed();
    let got = String::from_utf8_lossy(&got).to_string();
    assert!(
        got.starts_with("HTTP/1.1 408"),
        "expected 408 on the dripping connection, got: {:?}",
        got
    );
    assert!(
        elapsed < Duration::from_secs(15),
        "the dripping connection was held for {:?}",
        elapsed
    );

    // And the parser thread it held comes back.
    let (reply, _) = timed_request(&addr, "/healthy", Duration::from_secs(20));
    let reply = reply.expect("the server never answered after a dripped header");
    assert!(reply.starts_with("HTTP/1.1 200"), "got: {:?}", reply);
    let _ = dripper.join();
}

/// Finding 3, the size half: no request-line limit at all.
#[test]
fn an_oversized_request_line_is_refused() {
    let limits = ServerLimits {
        max_request_line: 2048,
        ..tight_limits()
    };
    let (addr, _server) = serve_with(limits, 1, |rq| {
        let _ = rq.respond(Response::from_string("ok"));
    });

    let mut wire = b"GET /".to_vec();
    wire.extend(std::iter::repeat_n(b'a', 64 * 1024));
    wire.extend_from_slice(b" HTTP/1.1\r\nHost: x\r\n\r\n");
    let reply = send_raw_tolerant(&addr, &wire);
    assert!(
        reply.starts_with("HTTP/1.1 414"),
        "expected 414 URI Too Long, got: {:?}",
        reply
    );
}

/// One unterminated header line could be grown until the allocator gave up.
#[test]
fn an_oversized_header_line_is_refused() {
    let limits = ServerLimits {
        max_header_line: 2048,
        ..tight_limits()
    };
    let (addr, _server) = serve_with(limits, 1, |rq| {
        let _ = rq.respond(Response::from_string("ok"));
    });

    let mut wire = b"GET / HTTP/1.1\r\nHost: x\r\nX: ".to_vec();
    wire.extend(std::iter::repeat_n(b'a', 64 * 1024));
    wire.extend_from_slice(b"\r\n\r\n");
    let reply = send_raw_tolerant(&addr, &wire);
    assert!(
        reply.starts_with("HTTP/1.1 431"),
        "expected 431, got: {:?}",
        reply
    );
}

/// ...and a request could carry an unbounded NUMBER of short headers, or an
/// unbounded total, with every individual line inside its limit.
#[test]
fn too_many_headers_are_refused() {
    let limits = ServerLimits {
        max_headers: 8,
        ..tight_limits()
    };
    let (addr, _server) = serve_with(limits, 1, |rq| {
        let _ = rq.respond(Response::from_string("ok"));
    });

    let mut wire = b"GET / HTTP/1.1\r\nHost: x\r\n".to_vec();
    for i in 0..64 {
        wire.extend_from_slice(format!("X-Pad-{i}: v\r\n").as_bytes());
    }
    wire.extend_from_slice(b"\r\n");
    let reply = send_raw_tolerant(&addr, &wire);
    assert!(
        reply.starts_with("HTTP/1.1 431"),
        "expected 431 on header count, got: {:?}",
        reply
    );
}

#[test]
fn oversized_total_header_bytes_are_refused() {
    let limits = ServerLimits {
        max_headers: 100_000,
        max_header_line: 4096,
        max_header_bytes: 4096,
        ..tight_limits()
    };
    let (addr, _server) = serve_with(limits, 1, |rq| {
        let _ = rq.respond(Response::from_string("ok"));
    });

    let mut wire = b"GET / HTTP/1.1\r\nHost: x\r\n".to_vec();
    for i in 0..512 {
        wire.extend_from_slice(format!("X-Pad-{i}: 0123456789abcdef\r\n").as_bytes());
    }
    wire.extend_from_slice(b"\r\n");
    let reply = send_raw_tolerant(&addr, &wire);
    assert!(
        reply.starts_with("HTTP/1.1 431"),
        "expected 431 on total header bytes, got: {:?}",
        reply
    );
}

/// Finding 3, the thread half. Past the ceiling a connection is closed rather
/// than accepted and never parsed - and crucially the accept thread survives it,
/// which is what upstream's infallible `thread::spawn` did not.
#[test]
fn the_connection_ceiling_closes_extra_connections_and_recovers() {
    // The floor is MIN_THREADS (4), so this is the smallest testable ceiling.
    let limits = ServerLimits {
        max_connections: 4,
        header_deadline: Duration::from_secs(30),
        ..ServerLimits::default()
    };
    let (addr, _server) = serve_with(limits, 4, |rq| {
        let _ = rq.respond(Response::from_string("ok"));
    });

    // Four keep-alive connections, each answered and then left open: their
    // parser threads are blocked reading for a follow-up request.
    let mut held = Vec::new();
    for _ in 0..4 {
        let mut sock = TcpStream::connect(&addr).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        sock.write_all(b"GET /hold HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let mut buf = [0u8; 128];
        let n = sock.read(&mut buf).unwrap();
        assert!(
            String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"),
            "a held connection was not served"
        );
        held.push(sock);
    }

    // The fifth is over the ceiling: closed with no response.
    let (reply, _) = timed_request(&addr, "/over", Duration::from_secs(5));
    assert!(
        reply.is_none(),
        "a connection past the ceiling was served anyway: {:?}",
        reply
    );

    // Freeing one must free a slot - the ceiling is a concurrency limit, not a
    // lifetime budget.
    held.pop();
    let mut served = None;
    for _ in 0..100 {
        if let (Some(reply), _) = timed_request(&addr, "/again", Duration::from_secs(5)) {
            served = Some(reply);
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let served = served.expect("the freed slot was never reused");
    assert!(served.starts_with("HTTP/1.1 200"), "got: {:?}", served);
}

/// Finding 4. `MessagesQueue::with_capacity` only sized a `VecDeque`, and plain
/// connections pushed every pipelined request without waiting for the previous
/// response - so one peer that never reads could grow the queue until allocation
/// failed. Patch 12 allows exactly one outstanding request per connection.
#[test]
fn a_pipelining_peer_gets_one_outstanding_request_at_a_time() {
    let seen = Arc::new(AtomicUsize::new(0));
    // Requests are parked, never answered, so the count is what the parser was
    // allowed to run ahead by.
    let parked: Arc<Mutex<Vec<Request>>> = Arc::new(Mutex::new(Vec::new()));
    let (addr, _server) = {
        let seen = seen.clone();
        let parked = parked.clone();
        serve_with(tight_limits(), 4, move |rq| {
            seen.fetch_add(1, Ordering::AcqRel);
            parked.lock().unwrap().push(rq);
        })
    };

    let mut sock = TcpStream::connect(&addr).unwrap();
    let mut wire = Vec::new();
    for i in 0..200 {
        wire.extend_from_slice(format!("GET /p{i} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes());
    }
    // Never read a single response.
    let _ = sock.write_all(&wire);
    let _ = sock.flush();
    std::thread::sleep(Duration::from_millis(500));

    assert_eq!(
        seen.load(Ordering::Acquire),
        1,
        "the parser ran {} requests ahead of the responses",
        seen.load(Ordering::Acquire)
    );

    // Releasing them must not panic on the notification channel (patch 12) even
    // though the peer is about to vanish.
    drop(sock);
    parked.lock().unwrap().clear();
}

/// Finding A5. `/stream` is unauthenticated and can hold response writer #1 for
/// 300 s. Four ordinary requests pipelined behind it each took an application
/// worker and blocked on response ordering with no deadline, so one client made
/// the dashboard unavailable for about five minutes, repeatably.
#[test]
fn a_long_response_does_not_starve_other_connections() {
    let (addr, _server) = serve_with(tight_limits(), 4, |rq| {
        if rq.url().starts_with("/slow") {
            // Stands in for a LiveRangeReader waiting on an uncovered span.
            std::thread::sleep(Duration::from_secs(4));
        }
        let _ = rq.respond(Response::from_string("ok"));
    });

    // One connection: the long response, with four ordinary requests pipelined
    // behind it, and nothing ever read back.
    let hostile = {
        let addr = addr.clone();
        std::thread::spawn(move || {
            let mut sock = TcpStream::connect(&addr).unwrap();
            let mut wire = b"GET /slow HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
            for i in 0..4 {
                wire.extend_from_slice(
                    format!("GET /normal{i} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes(),
                );
            }
            let _ = sock.write_all(&wire);
            let _ = sock.flush();
            std::thread::sleep(Duration::from_secs(6));
        })
    };

    std::thread::sleep(Duration::from_millis(300));

    // An unrelated client must be served now, not in four seconds' time.
    let (reply, elapsed) = timed_request(&addr, "/dashboard", Duration::from_secs(10));
    let reply = reply.expect("the dashboard was never answered behind a long response");
    assert!(reply.starts_with("HTTP/1.1 200"), "got: {:?}", reply);
    assert!(
        elapsed < Duration::from_secs(2),
        "the dashboard waited {:?} behind one connection's long response",
        elapsed
    );

    let _ = hostile.join();
}

/// Backpressure must not break the ordinary case: sequential requests on one
/// keep-alive connection still work, and responses still come back in order.
#[test]
fn keep_alive_still_serves_requests_in_order() {
    let (addr, _server) = serve_with(tight_limits(), 4, |rq| {
        let body = rq.url().to_owned();
        let _ = rq.respond(Response::from_string(body));
    });

    let mut sock = TcpStream::connect(&addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();

    // Sequential: the shape every real client and media player uses.
    for i in 0..5 {
        let wire = format!("GET /seq{i} HTTP/1.1\r\nHost: x\r\n\r\n");
        sock.write_all(wire.as_bytes()).unwrap();
        sock.flush().unwrap();
        let mut buf = [0u8; 512];
        let n = sock.read(&mut buf).unwrap();
        let reply = String::from_utf8_lossy(&buf[..n]).to_string();
        assert!(reply.starts_with("HTTP/1.1 200"), "request {}: {:?}", i, reply);
        assert!(
            reply.ends_with(&format!("/seq{i}")),
            "request {} got the wrong body: {:?}",
            i,
            reply
        );
    }

    // Pipelined, and read back: still answered, still in order.
    let mut wire = Vec::new();
    for i in 0..3 {
        wire.extend_from_slice(format!("GET /pipe{i} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes());
    }
    wire.extend_from_slice(b"GET /last HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    sock.write_all(&wire).unwrap();
    sock.flush().unwrap();
    let mut got = Vec::new();
    let _ = sock.read_to_end(&mut got);
    let got = String::from_utf8_lossy(&got).to_string();
    let order: Vec<usize> = ["/pipe0", "/pipe1", "/pipe2", "/last"]
        .iter()
        .map(|p| got.find(p).unwrap_or_else(|| panic!("{} missing from {:?}", p, got)))
        .collect();
    let mut sorted = order.clone();
    sorted.sort_unstable();
    assert_eq!(order, sorted, "pipelined responses came back out of order: {:?}", got);
}

/// Patch 11. A body too big to be worth discarding is not drained - which is
/// only safe because the connection is then closed instead of reused. If it were
/// reused, the undrained body would be parsed as the next request, which is
/// exactly the smuggling patch 6 closed on the rejected-framing path. Upstream
/// left a connection desynchronised the same way on any drain that stopped
/// short, silently.
///
/// Three things have to hold together here, so the wire is built to catch each
/// of them failing:
///   * the body must be over 1024 bytes, or `new_request` reads it eagerly into
///     a buffer and `EqualReader` - which owns all of this - never appears;
///   * the body must START with a valid request, so a connection wrongly reused
///     serves `/smuggled`;
///   * a further real request must FOLLOW the declared body, so a connection
///     wrongly *drained* and then reused serves `/after`.
///
/// Exactly one response means none of that happened.
#[test]
fn an_undrained_body_closes_the_connection_rather_than_being_reused() {
    let limits = ServerLimits {
        max_drain: 2048,
        ..tight_limits()
    };
    let (addr, _server) = serve_with(limits, 4, |rq| {
        // Answer without reading the body, like a 404 route, echoing the target
        // so the test can see exactly what got served.
        let body = rq.url().to_owned();
        let _ = rq.respond(Response::from_string(body).with_status_code(404));
    });

    let mut body = b"GET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
    body.extend(std::iter::repeat_n(b'x', 3000));
    let mut wire =
        format!("POST /zzz HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n", body.len())
            .into_bytes();
    wire.extend_from_slice(&body);
    wire.extend_from_slice(b"GET /after HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");

    let reply = send_raw_tolerant(&addr, &wire);
    assert!(
        reply.starts_with("HTTP/1.1 404"),
        "expected the POST to be answered, got: {:?}",
        reply
    );
    assert!(
        !reply.contains("/smuggled"),
        "the undrained body was parsed as a request: {:?}",
        reply
    );
    assert!(
        !reply.contains("/after"),
        "the connection was reused after an undrained body: {:?}",
        reply
    );
    assert_eq!(
        reply.matches("HTTP/1.1 ").count(),
        1,
        "more than one response came back: {:?}",
        reply
    );
}

/// ...while a body small enough to discard still leaves the connection usable,
/// so patch 11 is not a blanket "close after any unread body".
#[test]
fn a_drained_body_leaves_the_connection_usable() {
    let (addr, _server) = serve_with(tight_limits(), 4, |rq| {
        let _ = rq.respond(Response::from_string("ok").with_status_code(404));
    });

    let mut sock = TcpStream::connect(&addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    sock.write_all(b"POST /zzz HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello")
        .unwrap();
    sock.flush().unwrap();
    let mut buf = [0u8; 256];
    let n = sock.read(&mut buf).unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 404"));

    // Same connection, second request: the drain put us exactly where the next
    // request starts.
    sock.write_all(b"GET /after HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    sock.flush().unwrap();
    let mut got = Vec::new();
    let _ = sock.read_to_end(&mut got);
    let got = String::from_utf8_lossy(&got).to_string();
    assert!(
        got.starts_with("HTTP/1.1 404"),
        "the connection was not reusable after a drained body: {:?}",
        got
    );
}

/// Patch 6 (addendum). Two DISAGREEING Content-Lengths are the CL.CL half
/// of RFC 7230 3.3.3: we took the first with `.find` while a front end may
/// take the last, so the declared body was served as a second request -
/// with full API authority on a keyless origin behind an auth proxy.
#[test]
fn conflicting_content_lengths_do_not_become_a_second_request() {
    let (addr, _server) = serve();
    let smuggled = "GET /api?mode=shutdown HTTP/1.1\r\nHost: x\r\n\r\n";
    let wire = format!(
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nContent-Length: {}\r\n\r\n{}",
        smuggled.len(),
        smuggled
    );
    let reply = send_raw_tolerant(&addr, wire.as_bytes());
    assert!(
        reply.starts_with("HTTP/1.1 400"),
        "expected refusal, got: {:?}",
        reply
    );
    assert_eq!(
        reply.matches("HTTP/1.1 ").count(),
        1,
        "the smuggled request must never be answered: {reply:?}"
    );
}

/// ...and the deliberate limit of that check. Repeats that AGREE are framed
/// identically by every recipient and the RFC allows collapsing them, so
/// they stay served. Refusing these would be over-tightening.
#[test]
fn identical_repeated_content_lengths_are_still_served() {
    let (addr, _server) = serve();
    let wire = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    let reply = send_raw_tolerant(&addr, wire);
    assert!(
        reply.starts_with("HTTP/1.1 200"),
        "identical repeats must still be served: {:?}",
        reply
    );
}
