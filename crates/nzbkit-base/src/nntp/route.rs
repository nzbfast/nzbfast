//! Per-server route controls beside SOCKS5: the bind-address KILL
//! SWITCH and an HTTP CONNECT tunnel (TODO 358 item 14, decision D3 of
//! the Weaver parity tranche).
//!
//! D3 is deliberately two pieces and no routing layer: no WireGuard, no
//! proxy chains or pools, no per-route DNS. Most users get their tunnel
//! from the OS, and the part they need from us is that a dead tunnel
//! STOPS this server's downloads instead of letting them carry on over
//! the bare line.
//!
//! THE KILL SWITCH. A server that names a `bind_ip` is a statement that
//! its traffic must leave from that address - in practice the address a
//! VPN client put on its tunnel interface. Before this, a dial to such a
//! server went straight to `bind()`, and the two ways that goes wrong
//! are both silent:
//!
//! - the address is GONE (the VPN client tore the interface down): the
//!   OS refuses the bind with EADDRNOTAVAIL, which is safe, but it reads
//!   as an anonymous OS error on a dial, after a DNS lookup that has
//!   already gone out over the bare line;
//! - the address is still ASSIGNED but its interface is DOWN (Linux
//!   keeps an address on a downed link): the bind SUCCEEDS, and the
//!   kernel then routes the SYN by its main table, which with the tunnel
//!   gone is the default route - the bare line.
//!
//! So `ensure_bind_up` runs FIRST in every direct dial, before the DNS
//! lookup and before any socket exists, and refuses with the named
//! [`BindAddressDown`] unless the address sits on an interface that is
//! up right now. It reads the interface table on EVERY dial (one
//! `getifaddrs` / `GetAdaptersAddresses`, microseconds against a TCP
//! handshake), so there is no cached verdict to go stale: the dial after
//! the VPN comes back simply succeeds, and the pool's ordinary redial
//! backoff is the "re-check periodically". A proxy dial is covered too,
//! because the connection to the proxy is itself a direct dial with the
//! server's `bind_ip`.
//!
//! WHAT IT DOES NOT COVER, stated so nobody reads it as more: a session
//! that is ALREADY OPEN when the address goes down. The check is at the
//! dial, and nothing re-reads the table under a live session, so one
//! mid-download carries on until its socket fails (with the tunnel gone
//! that is usually promptly, as the peer's replies no longer reach the
//! tunnel address). The warm pool's checkout runs the same check
//! (`WarmPool::take` drops a parked set whose bind address is down
//! rather than hand it out), but its keepalive tick can still ping a
//! parked session across a downed route until the next checkout or its
//! eviction.
//!
//! WHEN THE TABLE CANNOT BE READ the check fails OPEN and says so in the
//! log, leaving the decision to `bind()`, which still refuses an address
//! that is not assigned. Failing closed would turn a platform quirk into
//! a dead provider for every `bind_ip` user, with nothing they can fix.
//!
//! "Up" means IFF_UP on unix and `IfOperStatusUp` on Windows. IFF_RUNNING
//! is deliberately NOT required: it is carrier state, its meaning varies
//! by interface type and platform, and a false "down" here stops a
//! working provider dead.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::warn;

use super::NntpError;
use crate::config::ServerConfig;

/// The kill switch's refusal: this server names `bind_ip` = `addr`, and
/// no interface that is up carries that address right now.
///
/// It reaches callers inside `NntpError::Io` (kind `AddrNotAvailable`),
/// so every existing connect-failure path - the pool's backoff, the
/// outage record, the server Test button - handles it with no new arm;
/// [`BindAddressDown::of`] recovers it for a caller that wants to say
/// more. The sentence is the user-facing one, so it names the address
/// and the likely cause and carries no credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "kill switch: bind address {addr} is not on any network interface that is up, \
     so this server is not dialled (is the VPN down?)"
)]
pub struct BindAddressDown {
    /// The `bind_ip` that was not found up.
    pub addr: IpAddr,
}

impl BindAddressDown {
    /// The kill-switch refusal inside an I/O error, if that is what it is.
    pub fn of_io(e: &std::io::Error) -> Option<&BindAddressDown> {
        e.get_ref()
            .and_then(|inner| inner.downcast_ref::<BindAddressDown>())
    }

    /// The kill-switch refusal inside a connect error, if that is what
    /// it is.
    pub fn of(e: &NntpError) -> Option<&BindAddressDown> {
        match e {
            NntpError::Io(io) => Self::of_io(io),
            _ => None,
        }
    }

    fn into_io(self) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, self)
    }
}

/// One address on one interface, and whether that interface is up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalAddr {
    /// The address, IPv4 or IPv6 (scope dropped).
    pub ip: IpAddr,
    /// The interface carrying it is administratively up (IFF_UP), or on
    /// Windows operationally up.
    pub up: bool,
}

/// Every unicast address on this machine's interfaces, with each
/// interface's up state. `Err` when the platform will not say.
pub fn local_addrs() -> std::io::Result<Vec<LocalAddr>> {
    imp::local_addrs()
}

/// The pure half of the check: is `ip` on an interface that is up?
///
/// Compared in canonical form, so a `bind_ip` written as an IPv4-mapped
/// IPv6 address matches the IPv4 address the table lists. An address
/// listed only on DOWN interfaces is not up, which is the whole point:
/// Linux keeps a downed link's address assigned, and a bind to it
/// succeeds.
pub fn addr_is_up(ip: IpAddr, addrs: &[LocalAddr]) -> bool {
    let want = ip.to_canonical();
    addrs.iter().any(|a| a.up && a.ip.to_canonical() == want)
}

/// The kill switch's verdict on one bind address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindState {
    /// On an interface that is up (or the wildcard address, which binds
    /// to whatever the route picks and is no statement at all).
    Up,
    /// Not on any interface that is up: dialling is refused.
    Down,
    /// The interface table could not be read; the check fails open.
    Unknown,
}

/// Read the interface table now and judge `ip` against it.
pub fn bind_state(ip: IpAddr) -> BindState {
    if ip.is_unspecified() {
        return BindState::Up;
    }
    match local_addrs() {
        Ok(addrs) if addr_is_up(ip, &addrs) => BindState::Up,
        Ok(_) => BindState::Down,
        Err(_) => BindState::Unknown,
    }
}

/// The kill-switch state of a server's stored `bind_ip`, for a status
/// surface: `Some` exactly when a dial right now would be refused. An
/// unset, unparsable (the dial names that itself) or unreadable case is
/// `None`, so a status line never claims a refusal the dial would not
/// make.
pub fn bind_ip_down(bind_ip: Option<&str>) -> Option<BindAddressDown> {
    let ip = bind_ip?.trim().parse::<IpAddr>().ok()?;
    (bind_state(ip) == BindState::Down).then_some(BindAddressDown { addr: ip })
}

/// The dial-side check: refuse with [`BindAddressDown`] unless `ip` is
/// up. Called before the DNS lookup, so a dead tunnel leaks no lookup
/// over the bare line either.
pub(super) fn ensure_bind_up(ip: IpAddr) -> std::io::Result<()> {
    match bind_state(ip) {
        BindState::Up => Ok(()),
        BindState::Down => Err(BindAddressDown { addr: ip }.into_io()),
        BindState::Unknown => {
            // Fail open, loudly: `bind()` still refuses an address that
            // is not assigned at all. Module header has the reasoning.
            warn!(
                target: "nntp",
                "kill switch: could not read this machine's network interfaces, \
                 so bind address {ip} was not checked before dialling"
            );
            Ok(())
        }
    }
}

/// Split a stored proxy spec into its optional `user`, `pass` and its
/// `host:port`. Same parse as SOCKS5's (`super::socks5_connect`), so the
/// two options read one shape.
fn split_spec(spec: &str) -> (Option<(&str, &str)>, &str) {
    match spec.rsplit_once('@') {
        Some((c, hp)) => (Some(c.split_once(':').unwrap_or((c, ""))), hp),
        None => (None, spec),
    }
}

/// Split a proxy's `host:port` into the host the resolver is handed and
/// the port, for both proxy kinds. An IPv6 literal is written bracketed
/// (`[::1]:8080`, which is what the server form accepts and the only
/// unambiguous spelling with a port), and the brackets are URL syntax,
/// not part of the address: handed to the resolver verbatim they read as
/// a hostname that never resolves, so every dial through the proxy
/// failed. A bare host or an unbracketed literal passes through as
/// before.
pub(super) fn split_host_port(hp: &str) -> Option<(&str, u16)> {
    let (h, p) = hp.rsplit_once(':')?;
    let p = p.parse::<u16>().ok()?;
    let h = h
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(h);
    Some((h, p))
}

/// Standard base64 with padding, for the Basic credential. Eleven lines
/// rather than a dependency; the decoder side never exists here.
fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            let pad = i > chunk.len();
            out.push(if pad {
                '='
            } else {
                T[((n >> shift) & 63) as usize] as char
            });
        }
    }
    out
}

/// The response head is read ONE BYTE AT A TIME up to the blank line,
/// because the news server greets the moment the tunnel opens and a
/// proxy may hand us its `200` and that greeting in one segment: a
/// buffered read would swallow the greeting and the session would wait
/// for one that already came. A head is tens of bytes; the cap only
/// stops a hostile proxy growing it without bound.
const MAX_HEAD: usize = 16 * 1024;

async fn read_head(s: &mut tokio::net::TcpStream) -> std::io::Result<Vec<u8>> {
    let mut head = Vec::with_capacity(128);
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_HEAD {
            return Err(std::io::Error::other("http proxy: response head too long"));
        }
        if s.read(&mut b).await? == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "http proxy closed the connection before answering CONNECT",
            ));
        }
        head.push(b[0]);
    }
    Ok(head)
}

/// Minimal HTTP CONNECT client (RFC 9110 section 9.3.6): `spec` is
/// "host:port" or "user:pass@host:port". The tunnel is asked for by the
/// news server's NAME, so the proxy resolves it; the caller then runs
/// TLS and NNTP over the returned socket exactly as it does over SOCKS5.
///
/// Every error names the proxy by `host:port` only. The spec can carry a
/// password, and these messages reach the log, mode=log's ring and the
/// bench history verbatim (`socks5_connect` records the incident).
pub(super) async fn http_connect(
    spec: &str,
    host: &str,
    port: u16,
    server: &ServerConfig,
) -> std::io::Result<tokio::net::TcpStream> {
    fn err(m: impl Into<String>) -> std::io::Error {
        std::io::Error::other(m.into())
    }
    let (creds, proxy_hp) = split_spec(spec);
    let (phost, pport) = split_host_port(proxy_hp)
        .ok_or_else(|| err(format!("http proxy {proxy_hp:?}: expected host:port")))?;
    // The target goes into a request line: a name carrying whitespace or
    // a line break would let a config value write headers of its own.
    if host.is_empty()
        || host
            .bytes()
            .any(|c| c.is_ascii_whitespace() || c.is_ascii_control())
    {
        return Err(err(
            "http proxy: the server name is not usable in a CONNECT request",
        ));
    }
    let authority = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let mut s = super::direct_connect(phost, pport, server).await?;

    let mut req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some((user, pass)) = creds {
        req.push_str("Proxy-Authorization: Basic ");
        req.push_str(&b64(format!("{user}:{pass}").as_bytes()));
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await?;

    let head = read_head(&mut s).await?;
    // "HTTP/1.1 200 Connection established" - the code is the second
    // token; the reason phrase is free text and never trusted.
    let line = head.split(|&c| c == b'\n').next().unwrap_or_default();
    let line = String::from_utf8_lossy(line);
    let mut parts = line.split_ascii_whitespace();
    let code = match (parts.next(), parts.next()) {
        (Some(v), Some(c)) if v.starts_with("HTTP/") => c.parse::<u16>().ok(),
        _ => None,
    }
    .ok_or_else(|| {
        err(format!(
            "http proxy {proxy_hp}: not an HTTP answer to CONNECT"
        ))
    })?;
    match code {
        200..=299 => Ok(s),
        407 if creds.is_some() => Err(err(format!(
            "http proxy {proxy_hp} rejected the proxy sign-in (407 Proxy Authentication Required)"
        ))),
        407 => Err(err(format!(
            "http proxy {proxy_hp} wants a sign-in (407 Proxy Authentication Required): \
             set the proxy user and password"
        ))),
        c => Err(err(format!(
            "http proxy {proxy_hp} refused the tunnel to {authority} (HTTP {c})"
        ))),
    }
}

#[cfg(unix)]
mod imp {
    use super::{IpAddr, Ipv4Addr, Ipv6Addr, LocalAddr};

    /// `getifaddrs(3)`: one entry per (interface, address), the
    /// interface's flags on each. Present on every unix target this tree
    /// builds (macOS, iOS, Linux incl. musl, Android, FreeBSD).
    pub(super) fn local_addrs() -> std::io::Result<Vec<LocalAddr>> {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        // SAFETY: `head` is a valid out-pointer; on success the list it
        // receives is ours until the `freeifaddrs` below.
        if unsafe { libc::getifaddrs(&mut head) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut out = Vec::new();
        let mut cur = head;
        while !cur.is_null() {
            // SAFETY: `cur` is a non-null node of the list getifaddrs
            // returned, which stays allocated until freeifaddrs.
            let ifa = unsafe { &*cur };
            let up = ifa.ifa_flags & (libc::IFF_UP as libc::c_uint) != 0;
            if !ifa.ifa_addr.is_null() {
                // SAFETY: a non-null ifa_addr points at a sockaddr whose
                // family field is always readable.
                let fam = libc::c_int::from(unsafe { (*ifa.ifa_addr).sa_family });
                if fam == libc::AF_INET {
                    // SAFETY: AF_INET means the storage is a sockaddr_in;
                    // read_unaligned makes no alignment assumption.
                    let sin = unsafe {
                        std::ptr::read_unaligned(ifa.ifa_addr.cast::<libc::sockaddr_in>())
                    };
                    let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                    out.push(LocalAddr {
                        ip: IpAddr::V4(ip),
                        up,
                    });
                } else if fam == libc::AF_INET6 {
                    // SAFETY: AF_INET6 means the storage is a
                    // sockaddr_in6; read_unaligned as above.
                    let sin6 = unsafe {
                        std::ptr::read_unaligned(ifa.ifa_addr.cast::<libc::sockaddr_in6>())
                    };
                    let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                    out.push(LocalAddr {
                        ip: IpAddr::V6(ip),
                        up,
                    });
                }
            }
            cur = ifa.ifa_next;
        }
        // SAFETY: `head` came from a successful getifaddrs and is freed
        // exactly once; nothing borrowed from it outlives this line.
        unsafe { libc::freeifaddrs(head) };
        Ok(out)
    }
}

#[cfg(windows)]
mod imp {
    use super::{IpAddr, Ipv4Addr, Ipv6Addr, LocalAddr};
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
        GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6,
    };

    /// `GetAdaptersAddresses`: every adapter, its operational status and
    /// its unicast addresses. Grown and retried on ERROR_BUFFER_OVERFLOW,
    /// which is how the API reports an adapter appearing between calls.
    pub(super) fn local_addrs() -> std::io::Result<Vec<LocalAddr>> {
        let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        let mut size: u32 = 16 * 1024;
        for _ in 0..4 {
            // u64 storage so the list's first struct is 8-byte aligned.
            let mut buf = vec![0u64; (size as usize).div_ceil(8)];
            size = (buf.len() * 8) as u32;
            let first = buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
            // SAFETY: `first` points at `size` writable, aligned bytes;
            // the call writes at most that many and updates `size`.
            let rc = unsafe {
                GetAdaptersAddresses(
                    u32::from(AF_UNSPEC),
                    flags,
                    std::ptr::null(),
                    first,
                    &mut size,
                )
            };
            if rc == ERROR_BUFFER_OVERFLOW {
                continue;
            }
            if rc != NO_ERROR {
                return Err(std::io::Error::from_raw_os_error(rc as i32));
            }
            let mut out = Vec::new();
            let mut ad = first.cast_const();
            while !ad.is_null() {
                // SAFETY: `ad` is a node of the list the call wrote into
                // `buf`, which is alive for this whole loop.
                let a = unsafe { &*ad };
                let up = a.OperStatus == IfOperStatusUp;
                let mut ua = a.FirstUnicastAddress.cast_const();
                while !ua.is_null() {
                    // SAFETY: as above, a node inside `buf`.
                    let u = unsafe { &*ua };
                    let sa: *const SOCKADDR = u.Address.lpSockaddr;
                    if !sa.is_null() {
                        // SAFETY: a non-null lpSockaddr points at a
                        // SOCKADDR whose family field is readable.
                        let fam = unsafe { (*sa).sa_family };
                        if fam == AF_INET {
                            // SAFETY: AF_INET storage is a SOCKADDR_IN.
                            let sin = unsafe { std::ptr::read_unaligned(sa.cast::<SOCKADDR_IN>()) };
                            // SAFETY: every IN_ADDR union view is plain data.
                            let raw = unsafe { sin.sin_addr.S_un.S_addr };
                            let ip = Ipv4Addr::from(u32::from_be(raw));
                            out.push(LocalAddr {
                                ip: IpAddr::V4(ip),
                                up,
                            });
                        } else if fam == AF_INET6 {
                            // SAFETY: AF_INET6 storage is a SOCKADDR_IN6.
                            let sin6 =
                                unsafe { std::ptr::read_unaligned(sa.cast::<SOCKADDR_IN6>()) };
                            // SAFETY: every IN6_ADDR union view is plain data.
                            let bytes = unsafe { sin6.sin6_addr.u.Byte };
                            out.push(LocalAddr {
                                ip: IpAddr::V6(Ipv6Addr::from(bytes)),
                                up,
                            });
                        }
                    }
                    ua = u.Next.cast_const();
                }
                ad = a.Next.cast_const();
            }
            return Ok(out);
        }
        Err(std::io::Error::other(
            "GetAdaptersAddresses kept growing its answer",
        ))
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    use super::LocalAddr;

    /// No interface table on this target: the check fails open.
    pub(super) fn local_addrs() -> std::io::Result<Vec<LocalAddr>> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_only_on_a_down_interface_is_not_up() {
        let ip: IpAddr = "10.8.0.2".parse().unwrap();
        let table = [
            LocalAddr {
                ip: "127.0.0.1".parse().unwrap(),
                up: true,
            },
            LocalAddr { ip, up: false },
        ];
        assert!(
            !addr_is_up(ip, &table),
            "Linux keeps a downed link's address"
        );
        let table = [LocalAddr { ip, up: false }, LocalAddr { ip, up: true }];
        assert!(addr_is_up(ip, &table), "up on any interface is up");
        assert!(!addr_is_up(ip, &[]), "absent is not up");
    }

    #[test]
    fn a_mapped_v6_bind_matches_its_v4_address() {
        let table = [LocalAddr {
            ip: "10.8.0.2".parse().unwrap(),
            up: true,
        }];
        assert!(addr_is_up("::ffff:10.8.0.2".parse().unwrap(), &table));
    }

    #[test]
    fn the_real_table_lists_loopback_up_and_not_test_net() {
        let addrs = local_addrs().expect("interface table must be readable on a dev box");
        assert!(
            addr_is_up(IpAddr::V4(Ipv4Addr::LOCALHOST), &addrs),
            "{addrs:?}"
        );
        assert_eq!(bind_state("127.0.0.1".parse().unwrap()), BindState::Up);
        // TEST-NET-1 (RFC 5737) and an unassigned ULA: never on a box.
        assert_eq!(bind_state("192.0.2.77".parse().unwrap()), BindState::Down);
        assert_eq!(
            bind_state("fd00:dead:beef::77".parse().unwrap()),
            BindState::Down
        );
        assert_eq!(
            bind_state("0.0.0.0".parse().unwrap()),
            BindState::Up,
            "wildcard"
        );
    }

    #[test]
    fn bind_ip_down_is_some_only_for_a_refusal_the_dial_would_make() {
        assert_eq!(bind_ip_down(None), None);
        assert_eq!(bind_ip_down(Some("not-an-ip")), None);
        assert_eq!(bind_ip_down(Some(" 127.0.0.1 ")), None);
        let d = bind_ip_down(Some("192.0.2.77")).expect("TEST-NET is never up");
        assert_eq!(d.addr, "192.0.2.77".parse::<IpAddr>().unwrap());
        let msg = d.to_string();
        assert!(
            msg.starts_with("kill switch: bind address 192.0.2.77"),
            "{msg}"
        );
        assert!(
            !msg.contains('\u{2014}') && !msg.contains('\u{2013}'),
            "{msg}"
        );
    }

    #[test]
    fn base64_matches_the_rfc_4648_vectors() {
        for (i, o) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(b64(i.as_bytes()), o, "{i:?}");
        }
        // RFC 7617's own example credential.
        assert_eq!(b64(b"Aladdin:open sesame"), "QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
    }

    #[test]
    fn the_refusal_survives_the_io_wrapping() {
        let e = NntpError::Io(
            BindAddressDown {
                addr: "192.0.2.1".parse().unwrap(),
            }
            .into_io(),
        );
        assert_eq!(
            BindAddressDown::of(&e).map(|d| d.addr),
            Some("192.0.2.1".parse().unwrap())
        );
        assert!(BindAddressDown::of(&NntpError::Closed).is_none());
    }
}
