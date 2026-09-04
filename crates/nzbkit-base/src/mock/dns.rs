//! DNS fault injection for the rig (TODO §129 3a).
//!
//! A registry keyed by hostname, installed once per test binary as the
//! process resolver ([`crate::nntp::install_resolver`]). Each test owns
//! a hostname and mutates that zone's answer, delay, or failure through
//! its own [`Zone`] handle, so tests in one binary stay independent
//! even though the seam itself is process-wide. Anything NOT registered
//! falls through to the system resolver, which is what keeps installing
//! this from disturbing every other test's `127.0.0.1` dial.
//!
//! Answers are stored as bare `IpAddr`s and the requested port is
//! attached on the way out, exactly as `lookup_host` does - a fake
//! resolver that could vary the port per candidate would let tests
//! build shapes DNS cannot produce.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use crate::nntp::{Resolve, ResolveFuture, SystemResolver};
use crate::sync::MutexExt;

/// What a registered zone answers with.
#[derive(Debug, Clone)]
pub enum Answer {
    /// Candidate addresses, in the order the resolver wants them tried.
    Addrs(Vec<IpAddr>),
    /// A resolution failure. `lookup_host` reports these as a plain
    /// `io::Error` whose text is the platform's getaddrinfo string; the
    /// client only ever surfaces the text, never the kind, so the rig
    /// matches that shape rather than inventing an ErrorKind.
    Fail(String),
}

/// One registered hostname: its answer, how long it takes to give it,
/// and how many times it has been asked.
#[derive(Debug)]
pub struct Zone {
    answer: Mutex<Answer>,
    delay: Mutex<Duration>,
    calls: AtomicU64,
}

impl Zone {
    /// Answer with these addresses, in this order.
    pub fn set_addrs(&self, addrs: Vec<IpAddr>) {
        *self.answer.lock_ok() = Answer::Addrs(addrs);
    }

    /// Answer with a resolution failure carrying this text.
    pub fn set_fail(&self, msg: impl Into<String>) {
        *self.answer.lock_ok() = Answer::Fail(msg.into());
    }

    /// Take this long before answering (either way). Applies from the
    /// next resolve on; a lookup already in flight keeps its old delay.
    pub fn set_delay(&self, d: Duration) {
        *self.delay.lock_ok() = d;
    }

    /// How many lookups this zone has served. The no-hot-loop
    /// assertions read this: a client that redials without backoff
    /// shows up here as a runaway count, whatever it does on the wire.
    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::Relaxed)
    }
}

/// The rig resolver: hostname → [`Zone`], everything else delegated.
#[derive(Debug, Default)]
pub struct TestResolver {
    zones: Mutex<std::collections::HashMap<String, Arc<Zone>>>,
}

impl TestResolver {
    /// Register (or fetch) a zone. A fresh zone answers NXDOMAIN-shaped
    /// until the test sets something, so a name registered but never
    /// configured fails loudly instead of silently resolving.
    pub fn zone(&self, host: &str) -> Arc<Zone> {
        self.zones
            .lock_ok()
            .entry(host.to_string())
            .or_insert_with(|| {
                Arc::new(Zone {
                    answer: Mutex::new(Answer::Fail(format!(
                        "failed to lookup address information: {host}"
                    ))),
                    delay: Mutex::new(Duration::ZERO),
                    calls: AtomicU64::new(0),
                })
            })
            .clone()
    }
}

impl Resolve for TestResolver {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolveFuture<'a> {
        // Snapshot under the lock, then await - holding a std Mutex
        // across an await point is how a rig deadlocks a runtime.
        let zone = self.zones.lock_ok().get(host).cloned();
        Box::pin(async move {
            let Some(zone) = zone else {
                return SystemResolver.resolve(host, port).await;
            };
            zone.calls.fetch_add(1, Ordering::Relaxed);
            let delay = *zone.delay.lock_ok();
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let answer = zone.answer.lock_ok().clone();
            match answer {
                Answer::Addrs(ips) => Ok(ips
                    .into_iter()
                    .map(|ip| SocketAddr::new(ip, port))
                    .collect()),
                Answer::Fail(msg) => Err(std::io::Error::other(msg)),
            }
        })
    }
}

static SHARED: OnceLock<Arc<TestResolver>> = OnceLock::new();

/// The test binary's registry, installed as the process resolver on
/// first use.
///
/// Idempotent, so every test can call it. Panics if something else
/// already owns the process resolver: that is a rig bug (two seams
/// fighting), and a silent loss here would show up later as an
/// inexplicable real DNS lookup for a `.invalid` name.
pub fn shared() -> Arc<TestResolver> {
    SHARED
        .get_or_init(|| {
            let r = Arc::new(TestResolver::default());
            let installed: Arc<dyn Resolve> = r.clone();
            assert!(
                crate::nntp::install_resolver(installed).is_ok(),
                "a resolver was already installed - mock::dns::shared() must own \
                 the process resolver"
            );
            r
        })
        .clone()
}

/// A hostname no other test in this binary uses.
///
/// Under `.invalid` (RFC 2606) on purpose: the registry falls through
/// to the system resolver for unregistered names, so a test that
/// mistypes its host gets a hard NXDOMAIN instead of quietly reaching
/// the real internet.
pub fn unique_host(tag: &str) -> String {
    static N: AtomicUsize = AtomicUsize::new(0);
    format!("{tag}-{}.dns.invalid", N.fetch_add(1, Ordering::Relaxed))
}

/// The one v4 address that REFUSES (RST, instantly) on every platform
/// the suite runs on when nothing is listening on the port.
///
/// Not a loopback alias: `127.0.0.2` is refused on Linux, where the
/// whole `127.0.0.0/8` is bound to lo, but on macOS only `127.0.0.1` is
/// assigned and the rest of the /8 swallows the SYN - which turned the
/// refused-node test into a ten-second blackhole test by accident.
/// A dead-v4-first candidate list is therefore built by putting the
/// mock on `[::1]` and this address, at the same (unlistened-on v4)
/// port, ahead of it: the IPv4-first sort then leads with the dead one.
pub fn refused_v4() -> IpAddr {
    IpAddr::from([127, 0, 0, 1])
}

/// Loopback v6. Assigned on both platforms, so it refuses rather than
/// blackholes - the v6 half of the same trick.
pub fn loopback_v6() -> IpAddr {
    IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1])
}

/// TEST-NET-1 (RFC 5737): guaranteed never routed anywhere real, so the
/// SYN goes into a hole and no RST comes back. The "blackholed node"
/// candidate, as opposed to the refused one above. A host with no
/// default route may answer EHOSTUNREACH instead - both are the shape
/// the tests are about (the dial must not stop here), so either is fine.
pub fn blackhole_v4() -> IpAddr {
    IpAddr::from([192, 0, 2, 1])
}
