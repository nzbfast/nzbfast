//! The DNS seam (TODO §129 3a).
//!
//! Every fault shape the §111 campaign raced happens AFTER a TCP
//! connection exists. Name resolution had no seam at all: the dialer
//! called `tokio::net::lookup_host` inline, so a provider hostname that
//! resolves slowly, hands back a dead node ahead of a live one, mixes
//! address families, or stops resolving mid-run had no rig
//! reproduction - which means the client's behavior there was
//! unmeasured and unpinned. (It was also wrong; see the candidate walk
//! in `super::direct_connect_opts`.)
//!
//! Production installs nothing and gets `lookup_host`, unchanged.
//!
//! The override is process-wide rather than per-server on purpose. DNS
//! *is* process-wide, there is exactly one call site to seam, and the
//! alternative - a handle on `ServerConfig`, where `bind_ip`/`rcvbuf`
//! live - would put a runtime object inside a serde config struct and
//! rewrite ~50 struct literals to carry it. Tests inject a registry
//! keyed by hostname ([`crate::mock::dns`]) instead, which is what lets
//! one installed override serve a whole binary of parallel tests: each
//! test owns its own hostname and anything unregistered falls through
//! to the system resolver.

use crate::config::AddressFamily;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

/// A boxed resolve future. Hand-rolled rather than `async fn` in the
/// trait: the seam has to be `dyn`-compatible and there is no
/// `async-trait` in this tree.
pub type ResolveFuture<'a> =
    Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send + 'a>>;

/// Resolve a host to the candidate addresses a dial may walk, in the
/// order the resolver wants them tried.
///
/// The order is advisory: [`order_candidates`] still applies the
/// `bind_ip` family filter and the server's family preference on top,
/// and a stable sort means same-family candidates keep the resolver's
/// order.
pub trait Resolve: Send + Sync {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolveFuture<'a>;
}

/// `tokio::net::lookup_host` and nothing else - what every production
/// dial uses.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolveFuture<'a> {
        Box::pin(async move { Ok(tokio::net::lookup_host((host, port)).await?.collect()) })
    }
}

static OVERRIDE: OnceLock<Arc<dyn Resolve>> = OnceLock::new();

/// Install the process's resolver.
///
/// Once only, and deliberately so: a resolver swapped mid-flight makes
/// an in-progress dial's candidate list unexplainable after the fact,
/// and nothing needs it - the rig resolver is a registry, so one
/// instance serves every test in a binary. Returns the resolver back in
/// `Err` when one was already installed.
pub fn install_resolver(r: Arc<dyn Resolve>) -> Result<(), Arc<dyn Resolve>> {
    OVERRIDE.set(r)
}

/// True once something has been installed. The rig uses it to tell
/// "nobody asked for a resolver" apart from "my registry lost the
/// race", which are different bugs.
pub fn resolver_installed() -> bool {
    OVERRIDE.get().is_some()
}

/// The one name resolution the NNTP dialer performs.
pub(crate) async fn resolve(host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    match OVERRIDE.get() {
        Some(r) => r.resolve(host, port).await,
        // Not `SystemResolver.resolve(..)`: keeping the default arm a
        // direct call means a process that never installs anything pays
        // for the seam with one atomic load and no vtable hop.
        None => Ok(tokio::net::lookup_host((host, port)).await?.collect()),
    }
}

/// Apply the dial's address policy to a resolver's answer.
///
/// `Auto` prefers IPv4 - providers count simultaneous source IPs, and
/// macOS can otherwise spread connections across IPv4 plus rotating IPv6
/// privacy addresses. The server's [`AddressFamily`] moves that
/// preference (issue #60: a 464XLAT link reaches IPv4 only through a
/// translator, so v6 is the fast path there), and it is a SORT rather
/// than a filter - the other family stays on the list behind it, so a
/// provider whose preferred family is down still connects.
///
/// The sort alone is not enough to make that last sentence true, and
/// [`reserve_fallback_slot`] is what finishes it: the dial walk is
/// bounded, so a preferred family with enough addresses to fill the
/// window would starve the fallback entirely. Under an explicit
/// preference the last walked slot is held for the other family.
///
/// A `bind_ip`'s family overrides both outright: binding a v6 source to
/// a v4 target cannot work, so that one filters. It is checked FIRST for
/// that reason, and a preference that disagrees with it is ignored
/// rather than an error - `bind_ip` is the older and more specific
/// control, and people already use it as the v6 workaround.
///
/// Lifted out of `direct_connect_opts` unchanged so the ordering and
/// the three error strings can be unit-tested directly - the strings
/// are what users have already seen in logs, so they are pinned, not
/// reworded.
pub(crate) fn order_candidates(
    host: &str,
    mut addrs: Vec<SocketAddr>,
    bind: Option<IpAddr>,
    family: AddressFamily,
) -> std::io::Result<Vec<SocketAddr>> {
    match bind {
        Some(ip) => addrs.retain(|a| a.is_ipv4() == ip.is_ipv4()),
        // Stable, so candidates of the same family keep the order the
        // resolver gave them. The key is "not the preferred family", so
        // the preferred one sorts to the front either way round.
        None => {
            let want_v4 = family != AddressFamily::Ipv6;
            addrs.sort_by_key(|a| a.is_ipv4() != want_v4);
            // A preference must not become a requirement; see the
            // function's own note.
            if family != AddressFamily::Auto {
                reserve_fallback_slot(&mut addrs, want_v4);
            }
        }
    }
    if addrs.is_empty() {
        return Err(std::io::Error::other(match bind {
            Some(ip) if ip.is_ipv4() => format!("{host} has no IPv4 address to match bind_ip"),
            Some(_) => format!("{host} has no IPv6 address to match bind_ip"),
            None => format!("{host} did not resolve"),
        }));
    }
    Ok(addrs)
}

/// Keep one address of the OTHER family inside the window the dial
/// actually walks.
///
/// The sort in [`order_candidates`] is a preference and not a filter,
/// but the walk that consumes it is BOUNDED
/// ([`super::MAX_DIAL_CANDIDATES`]), and those two facts together undo
/// each other: a provider that publishes three or more addresses of the
/// preferred family fills the whole window with them, so the fallback
/// family is never dialled at all. That turns the preference into a
/// REQUIREMENT - the operator asks for IPv6 first, the provider's IPv6
/// blackholes, and a server with a dozen working IPv4 addresses stops
/// connecting - which is the one thing `order_candidates` promises does
/// not happen.
///
/// Not a corner case. Measured 26 Aug 2026: `news.frugalusenet.com`
/// answers with 8 AAAA and 11 A, so a v6 preference there walks three
/// v6 addresses and nothing else, every dial, forever.
///
/// So the LAST walked slot goes to the first address of the other
/// family, keeping the two best preferred-family candidates ahead of
/// it. The displaced address keeps its relative place behind them
/// rather than being dropped - every dial re-resolves and re-orders, so
/// nothing here pins anything.
///
/// ONLY when a preference was set explicitly, and that restraint is the
/// point rather than caution. `Auto` is left byte for byte as it was,
/// because it is what every install that never touched this setting
/// runs, and an upgrade must not move a single dial - the same reason
/// `Auto` and `Ipv4` are distinct values in the first place. An
/// operator who names a family has said something, and this is what
/// makes saying it safe.
fn reserve_fallback_slot(addrs: &mut Vec<SocketAddr>, want_v4: bool) {
    let cap = super::MAX_DIAL_CANDIDATES;
    // Every candidate is walked, so nothing can be starved.
    if addrs.len() <= cap {
        return;
    }
    // The list is sorted, so the preferred family is a prefix: if the
    // last walked slot already holds the other family, the fallback is
    // in the window and there is nothing to reserve.
    if addrs[cap - 1].is_ipv4() != want_v4 {
        return;
    }
    if let Some(rel) = addrs[cap..].iter().position(|a| a.is_ipv4() != want_v4) {
        let other = addrs.remove(cap + rel);
        addrs.insert(cap - 1, other);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use AddressFamily::{Auto, Ipv4, Ipv6};

    fn v4(n: u8) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, n], 119))
    }
    fn v6(n: u16) -> SocketAddr {
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, n], 119))
    }

    /// The IPv4-first preference, pinned end to end: a resolver that
    /// answers v6 first must still be dialed v4 first. The integration
    /// leg (`family_mix_*`) can only show that a mixed answer connects
    /// - with the candidate walk in place it would connect either way -
    /// so the ORDER is pinned here.
    #[test]
    fn ipv4_sorts_ahead_of_ipv6() {
        let got = order_candidates("h", vec![v6(1), v4(1), v6(2), v4(2)], None, Auto).unwrap();
        assert_eq!(got, vec![v4(1), v4(2), v6(1), v6(2)], "v4 must lead");
    }

    /// Same-family candidates keep the resolver's order - a resolver
    /// that puts its healthy node first must not have that undone.
    #[test]
    fn the_sort_is_stable_within_a_family() {
        let got = order_candidates("h", vec![v4(3), v4(1), v4(2)], None, Auto).unwrap();
        assert_eq!(got, vec![v4(3), v4(1), v4(2)]);
    }

    /// A bind_ip pins the family and drops everything else, in both
    /// directions.
    #[test]
    fn bind_ip_filters_to_its_own_family() {
        let b4: IpAddr = "127.0.0.1".parse().unwrap();
        let b6: IpAddr = "::1".parse().unwrap();
        assert_eq!(
            order_candidates("h", vec![v6(1), v4(1)], Some(b4), Auto).unwrap(),
            vec![v4(1)]
        );
        assert_eq!(
            order_candidates("h", vec![v6(1), v4(1)], Some(b6), Auto).unwrap(),
            vec![v6(1)]
        );
    }

    /// Issue #60 / §291: the whole point of the setting. A server set to
    /// prefer IPv6 must dial v6 FIRST off the same answer that `Auto`
    /// dials v4 first.
    #[test]
    fn a_server_that_prefers_ipv6_dials_ipv6_first() {
        let answer = || vec![v4(1), v6(1), v4(2), v6(2)];
        assert_eq!(
            order_candidates("h", answer(), None, Ipv6).unwrap(),
            vec![v6(1), v6(2), v4(1), v4(2)],
            "prefer ipv6 must lead with v6"
        );
        assert_eq!(
            order_candidates("h", answer(), None, Auto).unwrap(),
            vec![v4(1), v4(2), v6(1), v6(2)],
            "auto is unchanged: v4 leads"
        );
        assert_eq!(
            order_candidates("h", answer(), None, Ipv4).unwrap(),
            vec![v4(1), v4(2), v6(1), v6(2)],
            "prefer ipv4 says today's default out loud"
        );
    }

    /// A PREFERENCE, not a filter: the other family stays on the list
    /// behind it, so the dial walk still fails over when the preferred
    /// family is down. A filter here would turn "prefer" into "only" and
    /// take a working provider off a link whose v6 broke this morning.
    #[test]
    fn the_preference_keeps_the_other_family_as_a_fallback() {
        for f in [Auto, Ipv4, Ipv6] {
            let got = order_candidates("h", vec![v4(1), v6(1)], None, f).unwrap();
            assert_eq!(got.len(), 2, "{f:?} must keep both candidates");
        }
        // A single-family answer is served whichever way the preference
        // points - preferring v6 at a v4-only provider is not an error.
        assert_eq!(
            order_candidates("h", vec![v4(1)], None, Ipv6).unwrap(),
            vec![v4(1)]
        );
        assert_eq!(
            order_candidates("h", vec![v6(1)], None, Ipv4).unwrap(),
            vec![v6(1)]
        );
    }

    /// The fallback the test below asserts is only reachable if it is
    /// inside the window the dial actually WALKS, and that window is
    /// three addresses wide. A provider with a large pool of the
    /// preferred family fills it, and without the reserve the other
    /// family is never dialled - a preference silently become a
    /// requirement, and a server with working addresses of the other
    /// family stops connecting when the preferred one breaks.
    ///
    /// Written with the LITERAL three rather than
    /// `MAX_DIAL_CANDIDATES`: an expectation phrased in terms of the
    /// constant it is pinning moves with it and passes just as happily
    /// at a cap of four. The same reasoning as
    /// `resolve_tests::the_candidate_walk_stops_at_the_cap`.
    #[test]
    fn a_big_preferred_pool_cannot_starve_the_other_family() {
        // 8 AAAA and 11 A is `news.frugalusenet.com`, measured 26 Aug
        // 2026 - a real provider pool, not a constructed one.
        let answer = || {
            let mut a: Vec<SocketAddr> = (1..=8).map(v6).collect();
            a.extend((1..=11).map(v4));
            a
        };
        let got = order_candidates("h", answer(), None, Ipv6).unwrap();
        assert!(
            got[..3].iter().any(|a| a.is_ipv4()),
            "a v6 preference walked no IPv4 at all: {:?}",
            &got[..3]
        );
        // The two best preferred candidates keep the front; the
        // fallback takes the last walked slot and nothing is dropped.
        assert_eq!(&got[..3], &[v6(1), v6(2), v4(1)], "{got:?}");
        assert_eq!(got.len(), 19, "no candidate may be dropped");

        // And the same the other way round, so the guarantee is about
        // the preference and not about IPv6.
        let mut flipped: Vec<SocketAddr> = (1..=11).map(v4).collect();
        flipped.extend((1..=8).map(v6));
        let got = order_candidates("h", flipped, None, Ipv4).unwrap();
        assert_eq!(&got[..3], &[v4(1), v4(2), v6(1)], "{got:?}");
    }

    /// `Auto` is what every install that never touched the setting
    /// runs, so it must not move a single dial: no reserve, the plain
    /// v4-first sort, exactly as before the preference existed.
    #[test]
    fn auto_is_left_exactly_as_it_was() {
        let mut answer: Vec<SocketAddr> = (1..=8).map(v6).collect();
        answer.extend((1..=11).map(v4));
        let got = order_candidates("h", answer, None, Auto).unwrap();
        assert_eq!(
            &got[..3],
            &[v4(1), v4(2), v4(3)],
            "Auto must still be a plain v4-first sort: {got:?}"
        );
    }

    /// The reserve is a no-op wherever the fallback is already
    /// reachable, so it cannot cost a preferred-family candidate for
    /// nothing.
    #[test]
    fn the_reserve_does_nothing_when_the_fallback_is_already_in_reach() {
        // Two preferred addresses: the other family is the third
        // candidate already.
        let got = order_candidates("h", vec![v6(1), v6(2), v4(1), v4(2)], None, Ipv6).unwrap();
        assert_eq!(got, vec![v6(1), v6(2), v4(1), v4(2)]);
        // A whole answer that fits inside the window is walked entire.
        let got = order_candidates("h", vec![v4(1), v6(1), v6(2)], None, Ipv6).unwrap();
        assert_eq!(got, vec![v6(1), v6(2), v4(1)]);
        // Single family, nothing to reserve, nothing dropped.
        let got = order_candidates("h", (1..=5).map(v6).collect(), None, Ipv6).unwrap();
        assert_eq!(got.len(), 5, "{got:?}");
    }

    /// `bind_ip` still filters, and a filtered list has exactly one
    /// family in it - so there is no fallback to reserve and the
    /// reserve must not manufacture one.
    #[test]
    fn the_reserve_never_reopens_a_bind_ip_filter() {
        let b6: IpAddr = "::9".parse().unwrap();
        let mut answer: Vec<SocketAddr> = (1..=8).map(v6).collect();
        answer.extend((1..=11).map(v4));
        let got = order_candidates("h", answer, Some(b6), Ipv4).unwrap();
        assert!(
            got.iter().all(|a| !a.is_ipv4()),
            "bind_ip must still filter to its own family: {got:?}"
        );
    }

    /// The sort stays stable under every preference - a resolver that
    /// put its healthy node first inside a family must not have that
    /// undone by asking for the other family.
    #[test]
    fn the_sort_is_stable_within_a_family_under_every_preference() {
        let got = order_candidates("h", vec![v6(3), v4(3), v6(1), v4(1)], None, Ipv6).unwrap();
        assert_eq!(got, vec![v6(3), v6(1), v4(3), v4(1)]);
    }

    /// `bind_ip` outranks the preference, in both directions. That one
    /// is physics - a v6 source address cannot reach a v4 target - and
    /// it is also the workaround people already use to force v6, so a
    /// preference that disagrees is ignored rather than fatal.
    #[test]
    fn bind_ip_outranks_the_family_preference() {
        let b4: IpAddr = "127.0.0.1".parse().unwrap();
        let b6: IpAddr = "::1".parse().unwrap();
        assert_eq!(
            order_candidates("h", vec![v6(1), v4(1)], Some(b4), Ipv6).unwrap(),
            vec![v4(1)],
            "a v4 bind still dials v4 however the preference is set"
        );
        assert_eq!(
            order_candidates("h", vec![v6(1), v4(1)], Some(b6), Ipv4).unwrap(),
            vec![v6(1)]
        );
    }

    /// The three empty-answer messages. Users have seen these strings;
    /// a reword is a support-facing change, so they are pinned.
    #[test]
    fn the_empty_answer_messages_are_pinned() {
        let e = order_candidates("news.example", vec![], None, Auto).unwrap_err();
        assert_eq!(e.to_string(), "news.example did not resolve");
        let b6: IpAddr = "::1".parse().unwrap();
        let e = order_candidates("news.example", vec![v4(1)], Some(b6), Auto).unwrap_err();
        assert_eq!(
            e.to_string(),
            "news.example has no IPv6 address to match bind_ip"
        );
        let b4: IpAddr = "127.0.0.1".parse().unwrap();
        let e = order_candidates("news.example", vec![v6(1)], Some(b4), Auto).unwrap_err();
        assert_eq!(
            e.to_string(),
            "news.example has no IPv4 address to match bind_ip"
        );
    }
}
