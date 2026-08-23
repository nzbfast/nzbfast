//! Which local account owns the far end of a loopback connection.
//!
//! The first-run handoff token (`bootstrap::Handoff`) rides the argv of
//! the `open` / `start` / `xdg-open` child, where every other account on
//! the box can read it. The browser that child hands the URL to is not
//! our child either (it is whatever browser was already running), so
//! there is no process we could bind the token to, and a web page cannot
//! read a user-only file to compute a `launcher_proof`. What IS attested
//! by the kernel, and cannot be forged by a reader of argv, is the
//! account that owns the socket on the other end of the loopback
//! connection presenting the token: an argv reader in another account
//! can copy the token, but every TCP socket it opens is owned by its own
//! uid (Linux, macOS) or runs in a process under its own SID (Windows).
//! So a presenter from another account is refused before the token is
//! burned, and the refusal is logged, which is the report the
//! browser-never-arrives sequence lacked.
//!
//! Each arm reads the kernel's connection table and finds the row whose
//! LOCAL end is the peer's address and port and whose REMOTE port is
//! ours. `Unknown` - no table, no row, a lookup error - keeps the
//! loopback-only rule that held before this existed, so a box where the
//! table cannot be read is exactly as safe as it was yesterday and no
//! launch is refused for a reason the user cannot act on. The lookup is
//! made only after the token has matched, so a process spraying tokens
//! never makes us walk the table.

use std::net::SocketAddr;

/// Whose socket is on the far end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum PeerAccount {
    /// Owned by the account this daemon runs as.
    Ours,
    /// Owned by some other local account; the string names it for the
    /// log (a uid, or a pid on Windows where the SID is not readable
    /// across accounts).
    Other(String),
    /// Could not be determined.
    Unknown,
}

/// The account owning the socket at `peer`, which is connected to this
/// daemon's listener on `local_port`.
pub(super) fn peer_account(peer: SocketAddr, local_port: u16) -> PeerAccount {
    // A daemon bound to `::` sees a v4 peer as `::ffff:127.0.0.1`; the
    // peer's own table row may carry either spelling, so both are tried.
    let peer = SocketAddr::new(peer.ip().to_canonical(), peer.port());
    if !peer.ip().is_loopback() {
        return PeerAccount::Unknown;
    }
    imp::lookup(peer, local_port)
}

/// `/proc/net/tcp` and `/proc/net/tcp6`. Portable so the parser is
/// tested on every box; only `imp` reads the files and asks for the uid.
#[cfg(any(target_os = "linux", test))]
mod proc_net {
    use std::net::{IpAddr, SocketAddr};

    /// The `local_address` column spelling of `addr`: each 32-bit word of
    /// the address printed as `%08X` of the NATIVE-endian word holding
    /// the network-order bytes (so 127.0.0.1 is `0100007F` on a
    /// little-endian host), then `:` and the port as `%04X` in host
    /// order. The same address in the v6 table is its v4-mapped form.
    pub(super) fn spellings(addr: SocketAddr) -> Vec<(bool, String)> {
        fn words(b: &[u8]) -> String {
            b.chunks(4)
                .map(|w| format!("{:08X}", u32::from_ne_bytes([w[0], w[1], w[2], w[3]])))
                .collect()
        }
        let port = format!(":{:04X}", addr.port());
        match addr.ip() {
            IpAddr::V4(v4) => vec![
                (false, words(&v4.octets()) + &port),
                (true, words(&v4.to_ipv6_mapped().octets()) + &port),
            ],
            IpAddr::V6(v6) => vec![(true, words(&v6.octets()) + &port)],
        }
    }

    /// The uid column of the row whose local end is `local` and whose
    /// remote port is `remote_port`, if the table has one.
    pub(super) fn owner_in(table: &str, local: &str, remote_port: u16) -> Option<u32> {
        let rport = format!(":{remote_port:04X}");
        table.lines().skip(1).find_map(|line| {
            let mut f = line.split_whitespace();
            let (_sl, l, r) = (f.next()?, f.next()?, f.next()?);
            if l != local || !r.ends_with(&rport) {
                return None;
            }
            // st tx:rx tr:when retrnsmt uid
            f.nth(4)?.parse().ok()
        })
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::{PeerAccount, proc_net};
    use std::net::SocketAddr;

    pub(super) fn lookup(peer: SocketAddr, local_port: u16) -> PeerAccount {
        // SAFETY: getuid takes no arguments, touches no memory and cannot
        // fail.
        let me = unsafe { libc::getuid() };
        for (v6, local) in proc_net::spellings(peer) {
            let path = if v6 {
                "/proc/net/tcp6"
            } else {
                "/proc/net/tcp"
            };
            let Ok(table) = std::fs::read_to_string(path) else {
                continue;
            };
            if let Some(uid) = proc_net::owner_in(&table, &local, local_port) {
                return if uid == me {
                    PeerAccount::Ours
                } else {
                    PeerAccount::Other(format!("uid {uid}"))
                };
            }
        }
        PeerAccount::Unknown
    }
}

/// `net.inet.tcp.pcblist64`: a `struct xinpgen` header, then one
/// `struct xtcpcb64` per connection, then a trailing `xinpgen`. The
/// offsets below are those of the public SDK headers on arm64 and x86_64
/// (checked with `offsetof` and `_Static_assert` on both, 23 Aug 2026;
/// these are the fixed-width "64" variants that exist so the layout does
/// not move with the architecture), walked by the per-record length the
/// kernel writes so a longer record in a later release is stepped over
/// rather than misread.
#[cfg(any(target_os = "macos", test))]
mod pcblist {
    use std::net::{IpAddr, SocketAddr};

    const XINPGEN_LEN: usize = 24;
    const XTCPCB64_MIN: usize = 472;
    const FPORT: usize = 20;
    const LPORT: usize = 22;
    const VFLAG: usize = 96;
    const LADDR: usize = 116; // struct in_dependladdr: 16 bytes; a v4 address sits at +12
    const SO_UID: usize = 252;
    const INP_IPV4: u8 = 0x1;

    fn u16_at(b: &[u8], at: usize) -> u16 {
        u16::from_be_bytes([b[at], b[at + 1]])
    }

    /// The `so_uid` of the record whose local end is `local` and whose
    /// foreign port is `remote_port`.
    pub(super) fn owner_in(buf: &[u8], local: SocketAddr, remote_port: u16) -> Option<u32> {
        let mut off = XINPGEN_LEN;
        while off + XTCPCB64_MIN <= buf.len() {
            let rec = &buf[off..];
            let len = u32::from_ne_bytes([rec[0], rec[1], rec[2], rec[3]]) as usize;
            if len < XTCPCB64_MIN {
                break; // the trailing xinpgen
            }
            if u16_at(rec, LPORT) == local.port() && u16_at(rec, FPORT) == remote_port {
                let laddr = &rec[LADDR..LADDR + 16];
                let hit = match local.ip() {
                    IpAddr::V4(v4) => {
                        rec[VFLAG] & INP_IPV4 != 0 && laddr[12..] == v4.octets()
                            || laddr == v4.to_ipv6_mapped().octets()
                    }
                    IpAddr::V6(v6) => laddr == v6.octets(),
                };
                if hit {
                    return Some(u32::from_ne_bytes([
                        rec[SO_UID],
                        rec[SO_UID + 1],
                        rec[SO_UID + 2],
                        rec[SO_UID + 3],
                    ]));
                }
            }
            off += len;
        }
        None
    }

    /// One record as the kernel would write it, for the parser test.
    #[cfg(test)]
    pub(super) fn fake_table(rows: &[(SocketAddr, u16, u32)]) -> Vec<u8> {
        let mut buf = vec![0u8; XINPGEN_LEN];
        buf[..4].copy_from_slice(&(XINPGEN_LEN as u32).to_ne_bytes());
        for (local, fport, uid) in rows {
            let mut rec = vec![0u8; XTCPCB64_MIN];
            rec[..4].copy_from_slice(&(XTCPCB64_MIN as u32).to_ne_bytes());
            rec[FPORT..FPORT + 2].copy_from_slice(&fport.to_be_bytes());
            rec[LPORT..LPORT + 2].copy_from_slice(&local.port().to_be_bytes());
            match local.ip() {
                IpAddr::V4(v4) => {
                    rec[VFLAG] = INP_IPV4;
                    rec[LADDR + 12..LADDR + 16].copy_from_slice(&v4.octets());
                }
                IpAddr::V6(v6) => rec[LADDR..LADDR + 16].copy_from_slice(&v6.octets()),
            }
            rec[SO_UID..SO_UID + 4].copy_from_slice(&uid.to_ne_bytes());
            buf.extend(rec);
        }
        buf.extend((XINPGEN_LEN as u32).to_ne_bytes());
        buf.extend(vec![0u8; XINPGEN_LEN - 4]);
        buf
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::{PeerAccount, pcblist};
    use std::net::SocketAddr;

    fn read_pcblist() -> Option<Vec<u8>> {
        let name = c"net.inet.tcp.pcblist64";
        // Sized twice: ask, allocate with room for connections opened in
        // between, read. ENOMEM on the read means the table grew past the
        // slack; one retry, then give up to Unknown.
        for _ in 0..2 {
            let mut len: libc::size_t = 0;
            // SAFETY: a null oldp with a valid oldlenp asks for the size
            // only; newp null / newlen 0 writes nothing.
            let rc = unsafe {
                libc::sysctlbyname(
                    name.as_ptr(),
                    std::ptr::null_mut(),
                    &mut len,
                    std::ptr::null_mut(),
                    0,
                )
            };
            if rc != 0 || len == 0 {
                return None;
            }
            let mut buf = vec![0u8; len + len / 8 + 4096];
            let mut got: libc::size_t = buf.len();
            // SAFETY: buf is live and `got` is its length, which is what
            // the kernel bounds its write by; it updates `got` to the bytes
            // written.
            let rc = unsafe {
                libc::sysctlbyname(
                    name.as_ptr(),
                    buf.as_mut_ptr().cast(),
                    &mut got,
                    std::ptr::null_mut(),
                    0,
                )
            };
            if rc == 0 {
                buf.truncate(got);
                return Some(buf);
            }
        }
        None
    }

    pub(super) fn lookup(peer: SocketAddr, local_port: u16) -> PeerAccount {
        let Some(buf) = read_pcblist() else {
            return PeerAccount::Unknown;
        };
        match pcblist::owner_in(&buf, peer, local_port) {
            // SAFETY: getuid takes no arguments, touches no memory and
            // cannot fail.
            Some(uid) if uid == unsafe { libc::getuid() } => PeerAccount::Ours,
            Some(uid) => PeerAccount::Other(format!("uid {uid}")),
            None => PeerAccount::Unknown,
        }
    }
}

/// `GetExtendedTcpTable` names the owning pid of every connection; the
/// pid's token user is then compared with ours. Opening another
/// account's process is refused to a standard user (`ERROR_ACCESS_DENIED`),
/// which is itself the answer: a process we may not even open is not
/// running as us. Any other failure is `Unknown`.
#[cfg(windows)]
mod imp {
    use super::PeerAccount;
    use std::net::{IpAddr, SocketAddr};
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, GetLastError, HANDLE, NO_ERROR,
    };
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
        TCP_TABLE_OWNER_PID_CONNECTIONS,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
    use windows_sys::Win32::Security::{
        EqualSid, GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    /// The table for `family` as raw bytes: a u32 row count, then rows.
    fn table(family: u16) -> Option<Vec<u8>> {
        let mut size: u32 = 0;
        // SAFETY: a null table with size 0 asks for the needed size.
        let rc = unsafe {
            GetExtendedTcpTable(
                std::ptr::null_mut(),
                &mut size,
                0,
                family as u32,
                TCP_TABLE_OWNER_PID_CONNECTIONS,
                0,
            )
        };
        if rc != ERROR_INSUFFICIENT_BUFFER && rc != NO_ERROR {
            return None;
        }
        for _ in 0..2 {
            let mut buf = vec![0u8; size as usize + 4096];
            size = buf.len() as u32;
            // SAFETY: buf is live and `size` is its length; the call
            // writes at most that many bytes and updates `size`.
            let rc = unsafe {
                GetExtendedTcpTable(
                    buf.as_mut_ptr().cast(),
                    &mut size,
                    0,
                    family as u32,
                    TCP_TABLE_OWNER_PID_CONNECTIONS,
                    0,
                )
            };
            if rc == NO_ERROR {
                return Some(buf);
            }
            if rc != ERROR_INSUFFICIENT_BUFFER {
                return None;
            }
        }
        None
    }

    /// `dwLocalPort` carries the port in network byte order in its low
    /// 16 bits.
    fn port(dw: u32) -> u16 {
        u16::from_be((dw & 0xffff) as u16)
    }

    fn rows<T: Copy>(buf: &[u8]) -> impl Iterator<Item = T> + '_ {
        let n = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let rows = &buf[4..];
        (0..n)
            .take_while(move |i| (i + 1) * std::mem::size_of::<T>() <= rows.len())
            .map(move |i| {
                // SAFETY: the slice holds at least i+1 whole rows (checked
                // above) and these are plain-data repr(C) structs, so an
                // unaligned read of the bytes is a valid T.
                unsafe {
                    std::ptr::read_unaligned(rows.as_ptr().add(i * std::mem::size_of::<T>()).cast())
                }
            })
    }

    /// The pid owning the socket whose local end is `peer` and whose
    /// remote port is `local_port`.
    fn owning_pid(peer: SocketAddr, local_port: u16) -> Option<u32> {
        match peer.ip() {
            IpAddr::V4(v4) => {
                let t = table(AF_INET)?;
                let want = u32::from_ne_bytes(v4.octets());
                rows::<MIB_TCPROW_OWNER_PID>(&t)
                    .find(|r| {
                        r.dwLocalAddr == want
                            && port(r.dwLocalPort) == peer.port()
                            && port(r.dwRemotePort) == local_port
                    })
                    .map(|r| r.dwOwningPid)
            }
            IpAddr::V6(v6) => {
                let t = table(AF_INET6)?;
                rows::<MIB_TCP6ROW_OWNER_PID>(&t)
                    .find(|r| {
                        r.ucLocalAddr == v6.octets()
                            && port(r.dwLocalPort) == peer.port()
                            && port(r.dwRemotePort) == local_port
                    })
                    .map(|r| r.dwOwningPid)
            }
        }
    }

    /// The `TOKEN_USER` block of `process`'s primary token, as the bytes
    /// the SID pointer inside it points into.
    fn token_user(process: HANDLE) -> Option<Vec<u8>> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: process is an open handle and token receives the result.
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
            return None;
        }
        let mut need: u32 = 0;
        // SAFETY: a null buffer with length 0 asks for the size.
        unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut need) };
        let mut buf = vec![0u8; need as usize];
        // SAFETY: buf has `need` bytes, which is what the first call said
        // the block takes; the block is self-contained (the SID pointer
        // points into the same allocation).
        let ok = unsafe {
            GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), need, &mut need)
        };
        // SAFETY: closing a handle we opened.
        unsafe { CloseHandle(token) };
        (ok != 0 && buf.len() >= std::mem::size_of::<TOKEN_USER>()).then_some(buf)
    }

    fn sid_of(block: &[u8]) -> *mut core::ffi::c_void {
        // SAFETY: block is a TOKEN_USER written by GetTokenInformation
        // (length checked by token_user); read_unaligned needs no
        // alignment.
        let tu: TOKEN_USER = unsafe { std::ptr::read_unaligned(block.as_ptr().cast()) };
        tu.User.Sid
    }

    pub(super) fn lookup(peer: SocketAddr, local_port: u16) -> PeerAccount {
        let Some(pid) = owning_pid(peer, local_port) else {
            return PeerAccount::Unknown;
        };
        // SAFETY: plain FFI; a failed open returns null and sets the
        // last error.
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if h.is_null() {
            // SAFETY: reads the calling thread's last-error value.
            return if unsafe { GetLastError() } == ERROR_ACCESS_DENIED {
                PeerAccount::Other(format!("pid {pid}"))
            } else {
                PeerAccount::Unknown
            };
        }
        let theirs = token_user(h);
        // SAFETY: closing a handle we opened.
        unsafe { CloseHandle(h) };
        // SAFETY: the current-process pseudo handle needs no closing.
        let mine = token_user(unsafe { GetCurrentProcess() });
        match (theirs, mine) {
            (Some(t), Some(m)) => {
                // SAFETY: both SIDs point into live buffers held by t and m.
                if unsafe { EqualSid(sid_of(&t), sid_of(&m)) } != 0 {
                    PeerAccount::Ours
                } else {
                    PeerAccount::Other(format!("pid {pid}"))
                }
            }
            _ => PeerAccount::Unknown,
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod imp {
    use super::PeerAccount;
    pub(super) fn lookup(_: std::net::SocketAddr, _: u16) -> PeerAccount {
        PeerAccount::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one live test: a connection this process makes to itself is,
    /// on every platform with an arm, owned by us - and on none of them
    /// is it somebody else's.
    #[test]
    fn the_far_end_of_our_own_loopback_connection_is_ours() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let client = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let (_server, peer) = l.accept().unwrap();
        let got = peer_account(peer, port);
        assert!(!matches!(got, PeerAccount::Other(_)), "{got:?}");
        if cfg!(any(target_os = "linux", target_os = "macos", windows)) {
            assert_eq!(got, PeerAccount::Ours, "client {:?}", client.local_addr());
        }
        // Not loopback: nothing to say.
        let lan: SocketAddr = "192.168.1.44:5000".parse().unwrap();
        assert_eq!(peer_account(lan, port), PeerAccount::Unknown);
    }

    #[test]
    fn proc_net_rows_are_matched_on_local_end_and_remote_port() {
        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:A1B2 0100007F:1A85 01 00000000:00000000 00:00000000 00000000   502        0 12345 1 0000000000000000 20 4 30 10 -1\n\
   1: 0100007F:A1B3 0100007F:1A85 01 00000000:00000000 00:00000000 00000000  1001        0 12346 1 0000000000000000 20 4 30 10 -1\n\
   2: 0100007F:A1B4 0100007F:0050 01 00000000:00000000 00:00000000 00000000   502        0 12347 1 0000000000000000 20 4 30 10 -1\n";
        let le = cfg!(target_endian = "little");
        let lo = |p: u16| {
            let s = proc_net::spellings(SocketAddr::new("127.0.0.1".parse().unwrap(), p));
            assert_eq!(
                s[0].1,
                if le {
                    format!("0100007F:{p:04X}")
                } else {
                    format!("7F000001:{p:04X}")
                }
            );
            s[0].1.clone()
        };
        assert_eq!(proc_net::owner_in(table, &lo(0xA1B2), 6789), Some(502));
        assert_eq!(proc_net::owner_in(table, &lo(0xA1B3), 6789), Some(1001));
        // Same local end, but the remote port is not ours: no match.
        assert_eq!(proc_net::owner_in(table, &lo(0xA1B4), 6789), None);
        assert_eq!(proc_net::owner_in(table, &lo(0xA1B4), 80), Some(502));
        // The v4-mapped spelling for the v6 table, and a plain v6 one.
        let s = proc_net::spellings("127.0.0.1:80".parse().unwrap());
        assert!(s[1].0);
        assert_eq!(
            s[1].1,
            if le {
                "0000000000000000FFFF00000100007F:0050"
            } else {
                "00000000000000000000FFFF7F000001:0050"
            }
        );
        let s = proc_net::spellings("[::1]:80".parse().unwrap());
        assert_eq!(s.len(), 1);
        assert_eq!(
            s[0].1,
            if le {
                "00000000000000000000000001000000:0050"
            } else {
                "00000000000000000000000000000001:0050"
            }
        );
    }

    #[test]
    fn pcblist_records_are_matched_on_local_end_and_foreign_port() {
        let a: SocketAddr = "127.0.0.1:41394".parse().unwrap();
        let b: SocketAddr = "127.0.0.1:41395".parse().unwrap();
        let c: SocketAddr = "[::1]:41396".parse().unwrap();
        let buf = pcblist::fake_table(&[(a, 6789, 502), (b, 6789, 1001), (c, 6789, 7), (a, 80, 9)]);
        assert_eq!(pcblist::owner_in(&buf, a, 6789), Some(502));
        assert_eq!(pcblist::owner_in(&buf, b, 6789), Some(1001));
        assert_eq!(pcblist::owner_in(&buf, c, 6789), Some(7));
        assert_eq!(pcblist::owner_in(&buf, a, 80), Some(9));
        assert_eq!(pcblist::owner_in(&buf, a, 81), None);
        let d: SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert_eq!(pcblist::owner_in(&buf, d, 6789), None);
        // A truncated or empty buffer is not a match, not a panic.
        assert_eq!(pcblist::owner_in(&buf[..100], a, 6789), None);
        assert_eq!(pcblist::owner_in(&[], a, 6789), None);
    }
}
