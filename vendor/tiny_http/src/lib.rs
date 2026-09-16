//! # Simple usage
//!
//! ## Creating the server
//!
//! The easiest way to create a server is to call `Server::http()`.
//!
//! The `http()` function returns an `IoResult<Server>` which will return an error
//! in the case where the server creation fails (for example if the listening port is already
//! occupied).
//!
//! ```no_run
//! let server = tiny_http::Server::http("0.0.0.0:0").unwrap();
//! ```
//!
//! A newly-created `Server` will immediately start listening for incoming connections and HTTP
//! requests.
//!
//! ## Receiving requests
//!
//! Calling `server.recv()` will block until the next request is available.
//! This function returns an `IoResult<Request>`, so you need to handle the possible errors.
//!
//! ```no_run
//! # let server = tiny_http::Server::http("0.0.0.0:0").unwrap();
//!
//! loop {
//!     // blocks until the next request is received
//!     let request = match server.recv() {
//!         Ok(rq) => rq,
//!         Err(e) => { println!("error: {}", e); break }
//!     };
//!
//!     // do something with the request
//!     // ...
//! }
//! ```
//!
//! In a real-case scenario, you will probably want to spawn multiple worker tasks and call
//! `server.recv()` on all of them. Like this:
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use std::thread;
//! # let server = tiny_http::Server::http("0.0.0.0:0").unwrap();
//! let server = Arc::new(server);
//! let mut guards = Vec::with_capacity(4);
//!
//! for _ in (0 .. 4) {
//!     let server = server.clone();
//!
//!     let guard = thread::spawn(move || {
//!         loop {
//!             let rq = server.recv().unwrap();
//!
//!             // ...
//!         }
//!     });
//!
//!     guards.push(guard);
//! }
//! ```
//!
//! If you don't want to block, you can call `server.try_recv()` instead.
//!
//! ## Handling requests
//!
//! The `Request` object returned by `server.recv()` contains informations about the client's request.
//! The most useful methods are probably `request.method()` and `request.url()` which return
//! the requested method (`GET`, `POST`, etc.) and url.
//!
//! To handle a request, you need to create a `Response` object. See the docs of this object for
//! more infos. Here is an example of creating a `Response` from a file:
//!
//! ```no_run
//! # use std::fs::File;
//! # use std::path::Path;
//! let response = tiny_http::Response::from_file(File::open(&Path::new("image.png")).unwrap());
//! ```
//!
//! All that remains to do is call `request.respond()`:
//!
//! ```no_run
//! # use std::fs::File;
//! # use std::path::Path;
//! # let server = tiny_http::Server::http("0.0.0.0:0").unwrap();
//! # let request = server.recv().unwrap();
//! # let response = tiny_http::Response::from_file(File::open(&Path::new("image.png")).unwrap());
//! let _ = request.respond(response);
//! ```
#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![allow(clippy::match_like_matches_macro)]

#[cfg(feature = "ssl-openssl")]
use zeroize::Zeroizing;

use std::error::Error;
use std::io::Error as IoError;
use std::io::ErrorKind as IoErrorKind;
use std::io::Result as IoResult;
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use client::ClientConnection;
use connection::Connection;
use util::MessagesQueue;

pub use common::{HTTPVersion, Header, HeaderField, Method, StatusCode};
pub use connection::{ConfigListenAddr, ListenAddr, Listener};
pub use request::{ReadWrite, Request};
pub use response::{Response, ResponseBox};
pub use test::TestRequest;

mod client;
mod common;
mod connection;
mod request;
mod response;
mod ssl;
mod test;
mod util;

/// The main class of this library.
///
/// Destroying this object will immediately close the listening socket and the reading
///  part of all the client's connections. Requests that have already been returned by
///  the `recv()` function will not close and the responses will be transferred to the client.
pub struct Server {
    // should be false as long as the server exists
    // when set to true, all the subtasks will close within a few hundreds ms
    close: Arc<AtomicBool>,

    // queue for messages received by child threads
    messages: Arc<MessagesQueue<Message>>,

    // result of TcpListener::local_addr()
    listening_addr: ListenAddr,
}

enum Message {
    Error(IoError),
    NewRequest(Request),
}

impl From<IoError> for Message {
    fn from(e: IoError) -> Message {
        Message::Error(e)
    }
}

impl From<Request> for Message {
    fn from(rq: Request) -> Message {
        Message::NewRequest(rq)
    }
}

// this trait is to make sure that Server implements Share and Send
#[doc(hidden)]
// Upstream idiom: a compile-time assertion, so nothing ever names it. Allowed
// rather than removed, so that the diff against upstream 0.12.0 stays
// exactly the patches VENDORING.md documents and nothing else. There
// were four of those when this was written and there are thirteen now;
// the reason is the inventory, not its size.
#[allow(dead_code)]
trait MustBeShareDummy: Sync + Send {}
#[doc(hidden)]
impl MustBeShareDummy for Server {}

pub struct IncomingRequests<'a> {
    server: &'a Server,
}

/// Represents the parameters required to create a server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// The addresses to try to listen to.
    pub addr: ConfigListenAddr,

    /// If `Some`, then the server will use SSL to encode the communications.
    pub ssl: Option<SslConfig>,

    /// nzbfast patches 9-11 (see VENDORING.md): what one connection, and one
    /// request on it, is allowed to cost.
    pub limits: ServerLimits,
}

/// nzbfast patches 9-11 (see VENDORING.md): the admission-control budget.
///
/// Upstream had none of this. Threads were created per connection with no
/// ceiling, the cross-thread request queue was unbounded, header parsing had no
/// size or count or time limit, and the only clocks anywhere were per-syscall
/// socket timeouts that every successful byte resets. Each of those is a
/// separate unauthenticated way to take the HTTP surface down, and they are one
/// missing feature: nothing ever said what a request may cost in total.
///
/// The defaults are sized for what nzbfast actually serves - a dashboard, a
/// SABnzbd-compatible API, a handful of media players - and are far above every
/// legitimate case while being far below every hostile one.
#[derive(Debug, Clone)]
pub struct ServerLimits {
    /// Maximum connections being parsed at once. One connection is one thread,
    /// so this is also the thread ceiling. Past it new connections are closed
    /// rather than accepted-and-never-read.
    pub max_connections: usize,

    /// Total time allowed for a request line plus its headers, measured from the
    /// first byte of the request - so an idle keep-alive connection is still
    /// governed only by the socket's own read timeout, unchanged from patch 4.
    pub header_deadline: Duration,

    /// Longest request line (method, target and version).
    pub max_request_line: usize,

    /// Longest single header line.
    pub max_header_line: usize,

    /// Total bytes of request line plus headers.
    pub max_header_bytes: usize,

    /// Most header fields in one request.
    pub max_headers: usize,

    /// How long a request body may move nothing much before the sustained-rate
    /// floor starts to apply.
    pub body_grace: Duration,

    /// Minimum sustained request-body rate, in bytes per second, once
    /// `body_grace` has passed. This - not a fixed deadline - is what separates
    /// a slow uploader from a peer dripping a byte every 20 s to hold a worker.
    pub min_body_rate: u64,

    /// Absolute ceiling on one request body, however fast it arrives, so a
    /// worker cannot be occupied indefinitely by a body at exactly the floor.
    pub max_body_time: Duration,

    /// As `body_grace`, for response writes. The clock counts only time spent
    /// blocked *inside* a write, never wall time, so a `/stream` response
    /// waiting minutes for articles is not mistaken for a stalled client.
    pub write_grace: Duration,

    /// Minimum sustained response-write rate, in bytes per second.
    pub min_write_rate: u64,

    /// Most unread body bytes worth discarding to keep a connection alive. Past
    /// this the connection is closed instead of drained.
    pub max_drain: usize,

    /// How long discarding an unread body may take, whatever its rate.
    ///
    /// Deliberately far shorter than `body_grace`. That grace exists so a slow
    /// client uploading a body some handler is actually reading is not cut off -
    /// but nothing legitimate depends on discarding a body *quickly*, and if the
    /// drain gives up the connection simply closes. Without a separate clock here
    /// the four-connection drip still bought `body_grace` of held workers, over
    /// and over, for bodies sized just under `max_drain`.
    pub max_drain_time: Duration,
}

impl Default for ServerLimits {
    fn default() -> ServerLimits {
        ServerLimits {
            // 256 concurrent HTTP connections is far past any real install: a
            // browser opens ~6, *arr a couple, and /stream caps itself at 64
            // player threads. It is also well under the point where thread
            // stacks and descriptors matter on a NAS.
            max_connections: 256,
            // Matches patch 4's socket timeout, so a drip cannot outlive the
            // idle bound it already had to respect.
            header_deadline: Duration::from_secs(30),
            // nginx's large_client_header_buffers is 8k; our longest real
            // targets are index searches and /stream tokens, far below it.
            max_request_line: 8 * 1024,
            max_header_line: 8 * 1024,
            max_header_bytes: 64 * 1024,
            max_headers: 100,
            body_grace: Duration::from_secs(30),
            // 8 KiB/s: a 256 MiB NZB upload on a genuinely bad link still beats
            // this by a wide margin, and the drip attack moves 0.05 B/s.
            min_body_rate: 8 * 1024,
            max_body_time: Duration::from_secs(3600),
            write_grace: Duration::from_secs(30),
            // 2 KiB/s of blocked-write throughput. A 242 KiB dashboard at the
            // floor takes two minutes; the peer that reads 8 KiB every 25 s to
            // keep resetting SO_SNDTIMEO manages 327 B/s.
            min_write_rate: 2 * 1024,
            max_drain: 1024 * 1024,
            // A megabyte off a local or LAN socket is milliseconds. Two seconds
            // is the ceiling on what an unauthenticated `POST /nonexistent` can
            // cost a worker, and it repeats rather than accumulating.
            max_drain_time: Duration::from_secs(2),
        }
    }
}

/// Configuration of the server for SSL.
///
/// nzbfast patch 13 (see VENDORING.md): under `ssl-rustls` this carries a
/// PREBUILT `rustls::ServerConfig` instead of upstream's raw PEM byte
/// vectors. The caller owns certificate parsing, validation and its error
/// messages (which can then name the offending file), and this crate stays
/// out of the PEM business entirely - no rustls-pemfile, no zeroize, and no
/// provider choice made here (the workspace links both aws-lc-rs and ring,
/// so a bare `rustls::ServerConfig::builder()` would panic at run time).
#[cfg(feature = "ssl-rustls")]
#[derive(Debug, Clone)]
pub struct SslConfig {
    /// The fully built server-side TLS configuration to accept with.
    pub server_config: std::sync::Arc<rustls::ServerConfig>,
}

/// Configuration of the server for SSL (upstream shape: raw PEM bytes).
#[cfg(not(feature = "ssl-rustls"))]
#[derive(Debug, Clone)]
pub struct SslConfig {
    /// Contains the public certificate to send to clients.
    pub certificate: Vec<u8>,
    /// Contains the ultra-secret private key used to decode communications.
    pub private_key: Vec<u8>,
}

impl Server {
    /// Shortcut for a simple server on a specific address.
    #[inline]
    pub fn http<A>(addr: A) -> Result<Server, Box<dyn Error + Send + Sync + 'static>>
    where
        A: ToSocketAddrs,
    {
        Server::http_with_limits(addr, ServerLimits::default())
    }

    /// nzbfast patches 9-11 (see VENDORING.md): as `http`, with an explicit
    /// admission-control budget instead of the defaults.
    #[inline]
    pub fn http_with_limits<A>(
        addr: A,
        limits: ServerLimits,
    ) -> Result<Server, Box<dyn Error + Send + Sync + 'static>>
    where
        A: ToSocketAddrs,
    {
        Server::new(ServerConfig {
            addr: ConfigListenAddr::from_socket_addrs(addr)?,
            ssl: None,
            limits,
        })
    }

    /// Shortcut for an HTTPS server on a specific address.
    #[cfg(any(feature = "ssl-openssl", feature = "ssl-rustls"))]
    #[inline]
    pub fn https<A>(
        addr: A,
        config: SslConfig,
    ) -> Result<Server, Box<dyn Error + Send + Sync + 'static>>
    where
        A: ToSocketAddrs,
    {
        Server::new(ServerConfig {
            addr: ConfigListenAddr::from_socket_addrs(addr)?,
            ssl: Some(config),
            limits: ServerLimits::default(),
        })
    }

    #[cfg(unix)]
    #[inline]
    /// Shortcut for a UNIX socket server at a specific path
    pub fn http_unix(
        path: &std::path::Path,
    ) -> Result<Server, Box<dyn Error + Send + Sync + 'static>> {
        Server::new(ServerConfig {
            addr: ConfigListenAddr::unix_from_path(path),
            ssl: None,
            limits: ServerLimits::default(),
        })
    }

    /// Builds a new server that listens on the specified address.
    pub fn new(config: ServerConfig) -> Result<Server, Box<dyn Error + Send + Sync + 'static>> {
        let listener = config.addr.bind()?;
        Self::from_listener(listener, config.ssl, config.limits)
    }

    /// Builds a new server using the specified TCP listener.
    ///
    /// This is useful if you've constructed TcpListener using some less usual method
    /// such as from systemd. For other cases, you probably want the `new()` function.
    ///
    /// nzbfast patches 9-11 (see VENDORING.md) added the `limits` argument;
    /// pass `ServerLimits::default()` to keep the shipped budget.
    pub fn from_listener<L: Into<Listener>>(
        listener: L,
        ssl_config: Option<SslConfig>,
        limits: ServerLimits,
    ) -> Result<Server, Box<dyn Error + Send + Sync + 'static>> {
        let listener = listener.into();
        let limits = Arc::new(limits);
        // building the "close" variable
        let close_trigger = Arc::new(AtomicBool::new(false));

        // building the TcpListener
        let (server, local_addr) = {
            let local_addr = listener.local_addr()?;
            log::debug!("Server listening on {}", local_addr);
            (listener, local_addr)
        };

        // building the SSL capabilities
        #[cfg(all(feature = "ssl-openssl", feature = "ssl-rustls"))]
        compile_error!(
            "Features 'ssl-openssl' and 'ssl-rustls' must not be enabled at the same time"
        );
        #[cfg(not(any(feature = "ssl-openssl", feature = "ssl-rustls")))]
        type SslContext = ();
        #[cfg(any(feature = "ssl-openssl", feature = "ssl-rustls"))]
        type SslContext = crate::ssl::SslContextImpl;
        let ssl: Option<SslContext> = {
            match ssl_config {
                #[cfg(feature = "ssl-rustls")]
                Some(config) => Some(SslContext::from_config(config)),
                #[cfg(all(feature = "ssl-openssl", not(feature = "ssl-rustls")))]
                Some(config) => Some(SslContext::from_pem(
                    config.certificate,
                    Zeroizing::new(config.private_key),
                )?),
                #[cfg(not(any(feature = "ssl-openssl", feature = "ssl-rustls")))]
                Some(_) => return Err(
                    "Building a server with SSL requires enabling the `ssl` feature in tiny-http"
                        .into(),
                ),
                None => None,
            }
        };

        // creating a task where server.accept() is continuously called
        // and ClientConnection objects are pushed in the messages queue
        //
        // nzbfast patch 11 (see VENDORING.md): this bound is now real. It is set
        // from the connection ceiling because patch 12 allows each connection one
        // outstanding request, so the queue cannot legitimately exceed it; the
        // slack is for the control messages that bypass the bound.
        let messages = MessagesQueue::with_capacity(limits.max_connections + 8);

        let inside_close_trigger = close_trigger.clone();
        let inside_messages = messages.clone();
        let inside_limits = limits.clone();
        thread::spawn(move || {
            // a tasks pool is used to dispatch the connections into threads
            // (nzbfast patch 9: bounded, and refusing rather than panicking)
            let tasks_pool = util::TaskPool::new(inside_limits.max_connections);
            // Whether we are currently shedding connections, so the log says so
            // once per episode rather than once per refused socket.
            let mut refusing = false;

            log::debug!("Running accept thread");
            while !inside_close_trigger.load(Relaxed) {
                let new_client = match server.accept() {
                    Ok((sock, _)) => {
                        use util::RefinedTcpStream;
                        // nzbfast patch 8 (see VENDORING.md): splitting the
                        // accepted socket dups its descriptor and can fail with
                        // EMFILE right after accept() succeeded. That used to
                        // be an `unwrap` inside `Clone`, i.e. a panic in this
                        // thread - the only accept thread - so one descriptor
                        // squeeze killed HTTP permanently. Drop just this
                        // connection and keep listening; the pressure that
                        // caused it is transient by nature.
                        let split = match ssl {
                            None => RefinedTcpStream::new(sock),
                            #[cfg(any(feature = "ssl-openssl", feature = "ssl-rustls"))]
                            Some(ref ssl) => {
                                // trying to apply SSL over the connection
                                // if an error occurs, we just close the socket and resume listening
                                let sock = match ssl.accept(sock) {
                                    Ok(s) => s,
                                    Err(_) => continue,
                                };

                                RefinedTcpStream::new(sock)
                            }
                            #[cfg(not(any(feature = "ssl-openssl", feature = "ssl-rustls")))]
                            Some(ref _ssl) => unreachable!(),
                        };
                        let (read_closable, write_closable) = match split {
                            Ok(halves) => halves,
                            Err(e) => {
                                log::debug!("could not split accepted socket: {e}");
                                continue;
                            }
                        };

                        Ok(ClientConnection::new(
                            write_closable,
                            read_closable,
                            inside_limits.clone(),
                        ))
                    }
                    Err(e) => Err(e),
                };

                match new_client {
                    Ok(client) => {
                        let messages = inside_messages.clone();
                        let mut client = Some(client);
                        let task = Box::new(move || {
                            if let Some(client) = client.take() {
                                // nzbfast patch 12 (see VENDORING.md): ONE
                                // outstanding request per connection, on every
                                // connection.
                                //
                                // Upstream ran this handshake only for HTTPS,
                                // where it was needed to avoid a deadlock, and
                                // let plain connections push every pipelined
                                // request straight through. That is what made
                                // the request queue growable from one socket,
                                // and it is also how one unauthenticated
                                // /stream response - which can legitimately hold
                                // its writer for 300 s - got four ordinary
                                // requests pipelined behind it onto all four
                                // application workers, each blocked on response
                                // ordering with no deadline. The dashboard went
                                // away for five minutes at a time, repeatably.
                                //
                                // Waiting here instead means a connection cannot
                                // run ahead of its own responses: a hostile
                                // pipeline now only ever wedges itself, and
                                // sequential response ordering becomes trivially
                                // satisfied rather than something later requests
                                // queue up behind. Players keep their keep-alive
                                // connection for follow-up range requests.
                                let (sender, receiver) = mpsc::channel();
                                for rq in client {
                                    messages.push(rq.with_notify_sender(sender.clone()).into());
                                    // Err means the request was dropped without
                                    // ever signalling, so no notification is
                                    // coming: stop parsing this connection
                                    // rather than panicking on an unwrap.
                                    if receiver.recv().is_err() {
                                        break;
                                    }
                                }
                            }
                        });
                        // nzbfast patch 9: refusing a connection must never kill
                        // the accept thread. Dropping the task closes the socket
                        // (RefinedTcpStream shuts both halves down on drop),
                        // which is the honest answer at the ceiling and is what
                        // the listen backlog does one layer down anyway.
                        // Deliberately no response is written: this is the only
                        // accept thread, and it must not block on a socket.
                        if tasks_pool.spawn(task).is_err() {
                            if !refusing {
                                log::warn!(
                                    "HTTP connection ceiling ({}) reached - refusing new \
                                     connections until some close",
                                    inside_limits.max_connections
                                );
                                refusing = true;
                            }
                            continue;
                        }
                        refusing = false;
                    }

                    Err(e) => {
                        // nzbfast patch 3 (see VENDORING.md): a transient
                        // accept() error must NOT end the accept thread.
                        //
                        // Upstream `break`s on ANY error here, and that is
                        // permanent: the listener never accepts again, while the
                        // process stays alive (so no supervisor restarts it) and
                        // downloads keep running. The consumer side then sees one
                        // error from recv() and its worker exits, leaving the rest
                        // blocked forever on a queue with no producer - the whole
                        // HTTP surface (dashboard, /api, /newznab, /jsonrpc,
                        // /stream) dead until a manual restart.
                        //
                        // These errors are all NORMAL and expected:
                        //   ECONNABORTED - the peer RST'd between the SYN and our
                        //     accept(); Linux surfaces pending network errors on
                        //     the new socket as an accept() error. Anyone can
                        //     produce it at will (connect + SO_LINGER{1,0}).
                        //   EMFILE / ENFILE - fd exhaustion, reachable with no
                        //     attacker at all (macOS's default soft limit is 256
                        //     and we hold tens of NNTP sockets, up to 64 stream
                        //     threads, plus file writers).
                        //   EINTR - a signal arrived mid-accept.
                        // Log, sleep briefly so a persistent fd shortage cannot
                        // become a busy-loop, and keep listening. Only a genuinely
                        // unrecoverable listener error ends the thread.
                        let kind_is_transient = matches!(
                            e.kind(),
                            std::io::ErrorKind::ConnectionAborted
                                | std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::Interrupted
                                | std::io::ErrorKind::WouldBlock
                                | std::io::ErrorKind::TimedOut
                        );
                        // Rust has no stable ErrorKind for EMFILE/ENFILE, so
                        // match the errno directly (unix only - the numbers mean
                        // something else on Windows).
                        #[cfg(unix)]
                        let fd_exhausted = matches!(e.raw_os_error(), Some(23) | Some(24));
                        #[cfg(not(unix))]
                        let fd_exhausted = false;
                        if kind_is_transient || fd_exhausted {
                            log::warn!("transient error accepting new client (continuing): {}", e);
                            std::thread::sleep(std::time::Duration::from_millis(50));
                            continue;
                        }
                        log::error!("Error accepting new client: {}", e);
                        // nzbfast patch 11: the queue is bounded now, and this
                        // thread is about to exit - blocking here would leave
                        // every consumer waiting on a queue with no producer.
                        inside_messages.push_control(e.into());
                        break;
                    }
                }
            }
            log::debug!("Terminating accept thread");
        });

        // result
        Ok(Server {
            messages,
            close: close_trigger,
            listening_addr: local_addr,
        })
    }

    /// Returns an iterator for all the incoming requests.
    ///
    /// The iterator will return `None` if the server socket is shutdown.
    #[inline]
    pub fn incoming_requests(&self) -> IncomingRequests<'_> {
        IncomingRequests { server: self }
    }

    /// Returns the address the server is listening to.
    #[inline]
    pub fn server_addr(&self) -> ListenAddr {
        self.listening_addr.clone()
    }

    /// Returns the number of clients currently connected to the server.
    pub fn num_connections(&self) -> usize {
        unimplemented!()
        //self.requests_receiver.lock().len()
    }

    /// Blocks until an HTTP request has been submitted and returns it.
    pub fn recv(&self) -> IoResult<Request> {
        match self.messages.pop() {
            Some(Message::Error(err)) => Err(err),
            Some(Message::NewRequest(rq)) => Ok(rq),
            None => Err(IoError::new(IoErrorKind::Other, "thread unblocked")),
        }
    }

    /// Same as `recv()` but doesn't block longer than timeout
    pub fn recv_timeout(&self, timeout: Duration) -> IoResult<Option<Request>> {
        match self.messages.pop_timeout(timeout) {
            Some(Message::Error(err)) => Err(err),
            Some(Message::NewRequest(rq)) => Ok(Some(rq)),
            None => Ok(None),
        }
    }

    /// Same as `recv()` but doesn't block.
    pub fn try_recv(&self) -> IoResult<Option<Request>> {
        match self.messages.try_pop() {
            Some(Message::Error(err)) => Err(err),
            Some(Message::NewRequest(rq)) => Ok(Some(rq)),
            None => Ok(None),
        }
    }

    /// Unblock thread stuck in recv() or incoming_requests().
    /// If there are several such threads, only one is unblocked.
    /// This method allows graceful shutdown of server.
    pub fn unblock(&self) {
        self.messages.unblock();
    }
}

impl Iterator for IncomingRequests<'_> {
    type Item = Request;
    fn next(&mut self) -> Option<Request> {
        self.server.recv().ok()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.close.store(true, Relaxed);
        // Connect briefly to ourselves to unblock the accept thread
        let maybe_stream = match &self.listening_addr {
            ListenAddr::IP(addr) => TcpStream::connect(addr).map(Connection::from),
            #[cfg(unix)]
            ListenAddr::Unix(addr) => {
                // TODO: use connect_addr when its stabilized.
                let path = addr.as_pathname().unwrap();
                std::os::unix::net::UnixStream::connect(path).map(Connection::from)
            }
        };
        if let Ok(stream) = maybe_stream {
            let _ = stream.shutdown(Shutdown::Both);
        }

        #[cfg(unix)]
        if let ListenAddr::Unix(addr) = &self.listening_addr {
            if let Some(path) = addr.as_pathname() {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}
