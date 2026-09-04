//! Which of this host's own addresses would reach a given destination -
//! the question behind the dashboard's "connect your phone" panel.
//!
//! The answer comes from the kernel's routing table, never from a
//! packet: `connect()` on a UDP socket resolves the route and records
//! the source address it would use, and sends nothing at all, so
//! `local_addr()` reads the answer straight back.
//!
//! What this module exists for is the BIND that trick needs. A
//! `0.0.0.0:0` bind is an all-interfaces bind, which is the exact shape
//! macOS's application firewall prompts about ("do you want the
//! application to accept incoming network connections?"), per binary
//! path plus signature. `remote_info` did two of them on EVERY call -
//! one for the LAN address, one for the Tailscale address - so opening
//! the settings panel from a dev binary, whose path changes on every
//! rebuild, banked another two dialogs. TODO 33.
//!
//! So the probe runs at most once per TTL per destination and the
//! answer is cached process-wide. The TTL is the invalidation: a laptop
//! that moves from Wi-Fi to Ethernet, or brings Tailscale up, is picked
//! up on the next refresh instead of being wrong until restart, which
//! is what a probe-once-per-process cache would be.
//!
//! Narrowing the bind to a specific interface is the other option §33
//! lists, and it is deliberately NOT taken. The address to narrow to is
//! the very thing being discovered, and binding the LAST known one
//! still succeeds after the route has moved off it (the address is
//! still on the box, just no longer the way out), so the probe would
//! answer confidently with an address the phone cannot reach. A QR code
//! that silently stops working is worse than a rare dialog.
//!
//! A failed lookup is cached too, and that is the half that matters
//! most: the common machine has no Tailscale at all, so an
//! answer-only cache would still bind a wildcard socket per call for
//! the negative.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::tools::MutexExt;

/// How long a discovered source address is trusted before the route is
/// looked up again. Long enough that a dashboard poll or a reload costs
/// no socket, short enough that plugging in Ethernet or starting
/// Tailscale shows up while the person is still looking at the panel.
const TTL: Duration = Duration::from_secs(60);

type Cache = HashMap<String, (Instant, Option<IpAddr>)>;

pub fn cache() -> &'static Mutex<Cache> {
    static C: OnceLock<Mutex<Cache>> = OnceLock::new();
    C.get_or_init(Mutex::default)
}

/// This host's source address on the route toward `dest` (an
/// `ip:port` literal), or `None` when there is no route to it.
///
/// `dest` is never contacted - see the module docs.
pub fn route_src(dest: &str) -> Option<IpAddr> {
    cached(cache(), dest, Instant::now(), TTL, probe)
}

/// The cache itself, with the map, the clock and the probe passed in so
/// the tests can drive all three without opening a socket - which is
/// the point of the module, and a test that bound one would be another
/// firewall dialog of exactly the kind being removed.
pub fn cached(
    cache: &Mutex<Cache>,
    dest: &str,
    now: Instant,
    ttl: Duration,
    probe: impl FnOnce(&str) -> Option<IpAddr>,
) -> Option<IpAddr> {
    // Two guards rather than one held across `probe`: the lookup is a
    // syscall, and nothing here is worth serialising callers behind.
    // The cost of a race is a duplicate probe, not a wrong answer.
    if let Some(&(at, ip)) = cache.lock_ok().get(dest)
        && now.saturating_duration_since(at) < ttl
    {
        return ip;
    }
    let ip = probe(dest);
    cache.lock_ok().insert(dest.to_string(), (now, ip));
    ip
}

/// One route lookup. The only `UdpSocket::bind` in the daemon.
pub fn probe(dest: &str) -> Option<IpAddr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect(dest).ok()?;
    s.local_addr().ok().map(|a| a.ip())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    /// A counting probe: hands back `answer` and records the call.
    fn counted<'a>(
        calls: &'a AtomicUsize,
        answer: Option<IpAddr>,
    ) -> impl FnOnce(&str) -> Option<IpAddr> + 'a {
        move |_| {
            calls.fetch_add(1, Ordering::Relaxed);
            answer
        }
    }

    #[test]
    fn a_second_call_inside_the_ttl_costs_no_socket() {
        let c = Mutex::new(Cache::new());
        let calls = AtomicUsize::new(0);
        let now = Instant::now();
        let first = cached(
            &c,
            "8.8.8.8:53",
            now,
            TTL,
            counted(&calls, ip("192.168.1.7")),
        );
        let again = cached(
            &c,
            "8.8.8.8:53",
            now + Duration::from_secs(59),
            TTL,
            counted(&calls, ip("10.0.0.1")),
        );
        assert_eq!(first, ip("192.168.1.7"));
        assert_eq!(again, first, "the cached answer, not the second probe's");
        assert_eq!(calls.load(Ordering::Relaxed), 1, "one probe, one bind");
    }

    /// The invalidation half: a machine that changed networks must not
    /// be told its old address forever.
    #[test]
    fn the_route_is_looked_up_again_once_the_ttl_is_out() {
        let c = Mutex::new(Cache::new());
        let calls = AtomicUsize::new(0);
        let now = Instant::now();
        cached(
            &c,
            "8.8.8.8:53",
            now,
            TTL,
            counted(&calls, ip("192.168.1.7")),
        );
        let later = cached(
            &c,
            "8.8.8.8:53",
            now + TTL + Duration::from_secs(1),
            TTL,
            counted(&calls, ip("10.0.0.1")),
        );
        assert_eq!(later, ip("10.0.0.1"), "the fresh answer wins");
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }

    /// The common machine has no Tailscale, and that negative is
    /// exactly the answer `remote_info` asked for on every call.
    #[test]
    fn a_no_route_answer_is_cached_too() {
        let c = Mutex::new(Cache::new());
        let calls = AtomicUsize::new(0);
        let now = Instant::now();
        assert_eq!(
            cached(&c, "100.100.100.100:53", now, TTL, counted(&calls, None)),
            None
        );
        assert_eq!(
            cached(
                &c,
                "100.100.100.100:53",
                now,
                TTL,
                counted(&calls, ip("100.64.0.2"))
            ),
            None,
            "the cached miss stands until the TTL is out"
        );
        assert_eq!(calls.load(Ordering::Relaxed), 1, "one probe, one bind");
    }

    /// The two live destinations (LAN and Tailscale) share the cache,
    /// so they must not share an entry.
    #[test]
    fn destinations_do_not_share_an_answer() {
        let c = Mutex::new(Cache::new());
        let calls = AtomicUsize::new(0);
        let now = Instant::now();
        let lan = cached(
            &c,
            "8.8.8.8:53",
            now,
            TTL,
            counted(&calls, ip("192.168.1.7")),
        );
        let ts = cached(
            &c,
            "100.100.100.100:53",
            now,
            TTL,
            counted(&calls, ip("100.64.0.2")),
        );
        assert_eq!(lan, ip("192.168.1.7"));
        assert_eq!(ts, ip("100.64.0.2"));
        assert_eq!(calls.load(Ordering::Relaxed), 2, "one probe each");
    }

    /// The class, not the instance: this module owns the daemon's only
    /// wildcard UDP bind, and a new one anywhere in `src/` is a new
    /// firewall dialog on every macOS desktop the daemon runs on. The
    /// test sites are a separate story and already gated behind
    /// `NZBFAST_LAN_TESTS`.
    #[test]
    fn nothing_else_in_the_crate_binds_a_udp_socket() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut found = Vec::new();
        let mut scanned = 0usize;
        let mut dirs = vec![src.clone()];
        while let Some(d) = dirs.pop() {
            for e in std::fs::read_dir(&d).expect("read src/").flatten() {
                let p = e.path();
                if p.is_dir() {
                    dirs.push(p);
                } else if p.extension().is_some_and(|x| x == "rs")
                    && p.file_name().is_some_and(|f| f != "lanaddr.rs")
                    && let Ok(text) = std::fs::read_to_string(&p)
                {
                    scanned += 1;
                    if text.contains("UdpSocket::bind") {
                        found.push(p.strip_prefix(&src).unwrap_or(&p).display().to_string());
                    }
                }
            }
        }
        // A walker that quietly reached nothing would pass this test
        // for ever, which is the failure mode of every source scan.
        assert!(scanned > 100, "only {scanned} files scanned - walk broken");
        assert!(
            found.is_empty(),
            "UdpSocket::bind outside serve/lanaddr.rs (TODO 33 - route \
             lookups go through lanaddr::route_src, which caches): {found:?}"
        );
    }

    /// The real probe, against loopback. Gated like the other
    /// wildcard-bind test sites: on macOS this one call is a firewall
    /// dialog, and `.github/workflows/pr-check.yml` sets the variable
    /// because a Linux runner has no firewall to prompt.
    #[test]
    fn probe_reads_back_a_source_address() {
        if std::env::var("NZBFAST_LAN_TESTS").as_deref() != Ok("1") {
            eprintln!("skipped: set NZBFAST_LAN_TESTS=1 (binds a UDP socket to 0.0.0.0)");
            return;
        }
        // Port 9 (discard) is never contacted - connect() only resolves
        // the route.
        assert_eq!(
            probe("127.0.0.1:9"),
            ip("127.0.0.1"),
            "the route to loopback leaves by loopback"
        );
    }
}
