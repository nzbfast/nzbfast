//! Abstractions of Tcp and Unix socket types

#[cfg(unix)]
use std::os::unix::net as unix_net;
use std::{
    net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    path::PathBuf,
};

/// Unified listener. Either a [`TcpListener`] or [`std::os::unix::net::UnixListener`]
pub enum Listener {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(unix_net::UnixListener),
}
impl Listener {
    pub(crate) fn local_addr(&self) -> std::io::Result<ListenAddr> {
        match self {
            Self::Tcp(l) => l.local_addr().map(ListenAddr::from),
            #[cfg(unix)]
            Self::Unix(l) => l.local_addr().map(ListenAddr::from),
        }
    }

    pub(crate) fn accept(&self) -> std::io::Result<(Connection, Option<SocketAddr>)> {
        match self {
            Self::Tcp(l) => l.accept().map(|(conn, addr)| {
                Self::set_timeouts(&conn);
                (Connection::from(conn), Some(addr))
            }),
            #[cfg(unix)]
            // nzbfast patch 14 (see VENDORING.md): the same deadlines patch 4
            // gives a TCP socket. A Unix-socket peer can stall a read or a
            // write exactly as a TCP one can, on the same worker pool.
            Self::Unix(l) => l.accept().map(|(conn, _)| {
                let t = Some(std::time::Duration::from_secs(30));
                let _ = conn.set_read_timeout(t);
                let _ = conn.set_write_timeout(t);
                (Connection::from(conn), None)
            }),
        }
    }

    /// nzbfast patch 4 (see VENDORING.md): give every accepted socket a
    /// read AND write deadline.
    ///
    /// Upstream sets neither, and the public API exposes no way to add them
    /// (`ServerConfig` carries only `addr` + `ssl`, and `Request` never hands out
    /// the socket) - which made the server trivially slowloris-able at three
    /// separate blocking points, all of them on the small shared worker pool:
    ///   1. a stalled request body (the handler blocks in read),
    ///   2. a stalled drop-drain of an unread body - needs no authentication and
    ///      no body-reading handler at all, just `POST /nonexistent` with a
    ///      Content-Length and no body,
    ///   3. a stalled response write, once the peer's receive window fills (a
    ///      242 KB dashboard through a 1 KB BufWriter does this easily against a
    ///      client with a clamped SO_RCVBUF).
    /// A handful of connections holding a few hundred bytes each could therefore
    /// wedge the entire HTTP surface for as long as they stayed open.
    ///
    /// 30 s is far longer than any real local/LAN client needs for one read or
    /// write, and a timed-out socket just fails that request rather than parking
    /// a worker forever. Best-effort: a platform that refuses is no worse off
    /// than upstream, so the result is deliberately ignored.
    fn set_timeouts(conn: &TcpStream) {
        let t = Some(std::time::Duration::from_secs(30));
        let _ = conn.set_read_timeout(t);
        let _ = conn.set_write_timeout(t);
    }
}
impl From<TcpListener> for Listener {
    fn from(s: TcpListener) -> Self {
        Self::Tcp(s)
    }
}
#[cfg(unix)]
impl From<unix_net::UnixListener> for Listener {
    fn from(s: unix_net::UnixListener) -> Self {
        Self::Unix(s)
    }
}

/// Unified connection. Either a [`TcpStream`] or [`std::os::unix::net::UnixStream`].
#[derive(Debug)]
pub(crate) enum Connection {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(unix_net::UnixStream),
}
impl std::io::Read for Connection {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(s) => s.read(buf),
            #[cfg(unix)]
            Self::Unix(s) => s.read(buf),
        }
    }
}
impl std::io::Write for Connection {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(s) => s.write(buf),
            #[cfg(unix)]
            Self::Unix(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tcp(s) => s.flush(),
            #[cfg(unix)]
            Self::Unix(s) => s.flush(),
        }
    }
}
impl Connection {
    /// Gets the peer's address. Some for TCP, None for Unix sockets.
    pub(crate) fn peer_addr(&mut self) -> std::io::Result<Option<SocketAddr>> {
        match self {
            Self::Tcp(s) => s.peer_addr().map(Some),
            #[cfg(unix)]
            Self::Unix(_) => Ok(None),
        }
    }

    pub(crate) fn shutdown(&self, how: Shutdown) -> std::io::Result<()> {
        match self {
            Self::Tcp(s) => s.shutdown(how),
            #[cfg(unix)]
            Self::Unix(s) => s.shutdown(how),
        }
    }

    pub(crate) fn try_clone(&self) -> std::io::Result<Self> {
        match self {
            Self::Tcp(s) => s.try_clone().map(Self::from),
            #[cfg(unix)]
            Self::Unix(s) => s.try_clone().map(Self::from),
        }
    }
}
impl From<TcpStream> for Connection {
    fn from(s: TcpStream) -> Self {
        Self::Tcp(s)
    }
}
#[cfg(unix)]
impl From<unix_net::UnixStream> for Connection {
    fn from(s: unix_net::UnixStream) -> Self {
        Self::Unix(s)
    }
}

#[derive(Debug, Clone)]
pub enum ConfigListenAddr {
    IP(Vec<SocketAddr>),
    #[cfg(unix)]
    // TODO: use SocketAddr when bind_addr is stabilized
    Unix(std::path::PathBuf),
}
impl ConfigListenAddr {
    pub fn from_socket_addrs<A: ToSocketAddrs>(addrs: A) -> std::io::Result<Self> {
        addrs.to_socket_addrs().map(|it| Self::IP(it.collect()))
    }

    #[cfg(unix)]
    pub fn unix_from_path<P: Into<PathBuf>>(path: P) -> Self {
        Self::Unix(path.into())
    }

    pub(crate) fn bind(&self) -> std::io::Result<Listener> {
        match self {
            Self::IP(a) => TcpListener::bind(a.as_slice()).map(Listener::from),
            #[cfg(unix)]
            Self::Unix(a) => unix_net::UnixListener::bind(a).map(Listener::from),
        }
    }
}

/// Unified listen socket address. Either a [`SocketAddr`] or [`std::os::unix::net::SocketAddr`].
#[derive(Debug, Clone)]
pub enum ListenAddr {
    IP(SocketAddr),
    #[cfg(unix)]
    Unix(unix_net::SocketAddr),
}
impl ListenAddr {
    pub fn to_ip(self) -> Option<SocketAddr> {
        match self {
            Self::IP(s) => Some(s),
            #[cfg(unix)]
            Self::Unix(_) => None,
        }
    }

    /// Gets the Unix socket address.
    ///
    /// This is also available on non-Unix platforms, for ease of use, but always returns `None`.
    #[cfg(unix)]
    pub fn to_unix(self) -> Option<unix_net::SocketAddr> {
        match self {
            Self::IP(_) => None,
            Self::Unix(s) => Some(s),
        }
    }
    #[cfg(not(unix))]
    pub fn to_unix(self) -> Option<SocketAddr> {
        None
    }
}
impl From<SocketAddr> for ListenAddr {
    fn from(s: SocketAddr) -> Self {
        Self::IP(s)
    }
}
#[cfg(unix)]
impl From<unix_net::SocketAddr> for ListenAddr {
    fn from(s: unix_net::SocketAddr) -> Self {
        Self::Unix(s)
    }
}
impl std::fmt::Display for ListenAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IP(s) => s.fmt(f),
            #[cfg(unix)]
            Self::Unix(s) => std::fmt::Debug::fmt(s, f),
        }
    }
}
