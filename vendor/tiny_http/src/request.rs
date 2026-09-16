use std::io::Error as IoError;
use std::io::{self, Cursor, ErrorKind, Read, Write};

use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;

use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Sender;
use std::sync::Arc;

use crate::util::{DeadlineReader, DeadlineWriter, DesyncGuard, EqualReader, FusedReader};
use crate::{HTTPVersion, Header, Method, Response, ServerLimits, StatusCode};
use chunked_transfer::Decoder;

/// nzbfast patches 10 and 11 (see VENDORING.md): what a socket-backed request
/// may cost, and where it reports having desynchronised its connection.
///
/// `None` for a `TestRequest`, which has no socket and no connection to protect.
pub(crate) struct ConnectionGuards {
    pub limits: Arc<ServerLimits>,
    pub desynced: Arc<AtomicBool>,
}

/// Represents an HTTP request made by a client.
///
/// A `Request` object is what is produced by the server, and is your what
/// your code must analyse and answer.
///
/// This object implements the `Send` trait, therefore you can dispatch your requests to
/// worker threads.
///
/// # Pipelining
///
/// If a client sends multiple requests in a row (without waiting for the response), then you will
/// get multiple `Request` objects simultaneously. This is called *requests pipelining*.
/// Tiny-http automatically reorders the responses so that you don't need to worry about the order
/// in which you call `respond` or `into_writer`.
///
/// This mechanic is disabled if:
///
///  - The body of a request is large enough (handling requires pipelining requires storing the
///    body of the request in a buffer ; if the body is too big, tiny-http will avoid doing that)
///  - A request sends a `Expect: 100-continue` header (which means that the client waits to
///    know whether its body will be processed before sending it)
///  - A request sends a `Connection: close` header or `Connection: upgrade` header (used for
///    websockets), which indicates that this is the last request that will be received on this
///    connection
///
/// # Automatic cleanup
///
/// If a `Request` object is destroyed without `into_writer` or `respond` being called,
/// an empty response with a 500 status code (internal server error) will automatically be
/// sent back to the client.
/// This means that if your code fails during the handling of a request, this "internal server
/// error" response will automatically be sent during the stack unwinding.
///
/// # Testing
///
/// If you want to build fake requests to test your server, use [`TestRequest`](crate::test::TestRequest).
pub struct Request {
    // where to read the body from
    data_reader: Option<Box<dyn Read + Send + 'static>>,

    // if this writer is empty, then the request has been answered
    response_writer: Option<Box<dyn Write + Send + 'static>>,

    remote_addr: Option<SocketAddr>,

    // true if HTTPS, false if HTTP
    secure: bool,

    method: Method,

    path: String,

    http_version: HTTPVersion,

    headers: Vec<Header>,

    body_length: Option<usize>,

    // true if a `100 Continue` response must be sent when `as_reader()` is called
    must_send_continue: bool,

    // If Some, a message must be sent after responding
    notify_when_responded: Option<Sender<()>>,
}

struct NotifyOnDrop<R> {
    sender: Sender<()>,
    inner: R,
}

impl<R: Read> Read for NotifyOnDrop<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}
impl<R: Write> Write for NotifyOnDrop<R> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
impl<R> Drop for NotifyOnDrop<R> {
    fn drop(&mut self) {
        // nzbfast patch 12 (see VENDORING.md): never panic on the notification.
        //
        // Upstream unwrapped all three of these sends. That was survivable while
        // the handshake only ran for HTTPS; patch 12 runs it on every connection,
        // which puts the send on the path of every response. An Err means the
        // parser thread has already gone - the peer closed, or the connection was
        // shed - and the only thing left to notify is nobody. Unwrapping there
        // would panic on whichever of the four application workers happened to be
        // holding that response.
        self.sender.send(()).ok();
    }
}

/// Error that can happen when building a `Request` object.
#[derive(Debug)]
pub enum RequestCreationError {
    /// The client sent an `Expect` header that was not recognized by tiny-http.
    ExpectationFailed,

    /// nzbfast patch 6 (see VENDORING.md): the request's framing headers are
    /// unusable, so where the body ends is unknown. The connection must be
    /// answered and closed, never reused - reusing it is how the declared body
    /// becomes a smuggled second request.
    BadFraming,

    /// Error while reading data from the socket during the creation of the `Request`.
    CreationIoError(IoError),
}

impl From<IoError> for RequestCreationError {
    fn from(err: IoError) -> RequestCreationError {
        RequestCreationError::CreationIoError(err)
    }
}

/// Builds a new request.
///
/// After the request line and headers have been read from the socket, a new `Request` object
/// is built.
///
/// You must pass a `Read` that will allow the `Request` object to read from the incoming data.
/// It is the responsibility of the `Request` to read only the data of the request and not further.
///
/// The `Write` object will be used by the `Request` to write the response.
#[allow(clippy::too_many_arguments)]
pub fn new_request<R, W>(
    secure: bool,
    method: Method,
    path: String,
    version: HTTPVersion,
    headers: Vec<Header>,
    remote_addr: Option<SocketAddr>,
    source_data: R,
    writer: W,
    guards: Option<ConnectionGuards>,
) -> Result<Request, RequestCreationError>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    // finding the transfer-encoding header
    let transfer_encoding = headers
        .iter()
        .find(|h: &&Header| h.field.equiv("Transfer-Encoding"))
        .map(|h| h.value.clone());
    // nzbfast: and it must actually BE chunked. Upstream decoded ANY
    // Transfer-Encoding value as chunked - `identity`, `gzip`,
    // `xchunked`, or `chunked, gzip` where chunked is not last - while
    // RFC 7230 3.3.3 requires that a request whose final transfer coding
    // is not `chunked` be rejected, because its length cannot be
    // determined. That disagreement with whatever sits in front is the
    // TE.TE half of the smuggling class patches 6 and 7 close, and it
    // was the half still open.
    //
    // Only the final coding is checked, and only for equality: a request
    // declaring `gzip, chunked` is well formed by the RFC and this
    // server does not implement the gzip layer, so it is refused rather
    // than mis-decoded. Refusing is the safe direction either way - a
    // browser or an *arr sends `chunked` alone.
    if let Some(te) = transfer_encoding.as_ref() {
        let te = te.as_str();
        let final_coding = te.rsplit(',').next().unwrap_or("").trim();
        if !final_coding.eq_ignore_ascii_case("chunked") || te.split(',').count() != 1 {
            return Err(RequestCreationError::BadFraming);
        }
    }

    // finding the content-length header
    let content_length = if transfer_encoding.is_some() {
        // nzbfast patch 6 (see VENDORING.md): Content-Length together with
        // Transfer-Encoding is the classic smuggling pair - upstream silently
        // preferred TE and dropped CL (RFC2616 #4.4), which is precisely the
        // disagreement an intermediary gets to resolve differently. RFC 7230
        // 3.3.3 says such a message "ought to be handled as an error"; we do.
        if headers.iter().any(|h: &Header| h.field.equiv("Content-Length")) {
            return Err(RequestCreationError::BadFraming);
        }
        None
    } else {
        // nzbfast patch 2 (see VENDORING.md): reject an absurd
        // Content-Length outright instead of believing it.
        //
        // Upstream parses this straight into `usize` with no ceiling, and that
        // number then sizes allocations and drives the drop-drain loop. Patch 1
        // stops the drain from allocating it, but a body length far past
        // anything this server will ever accept is a malformed request, not a
        // large upload: nzbfast's own largest cap is a 256 MiB NZB/jsonrpc body,
        // so 1 GiB is comfortably above every legitimate case. A request over
        // the cap parses as "no Content-Length", so the handler simply sees an
        // empty body and there is nothing to drain.
        const MAX_CONTENT_LENGTH: usize = 1024 * 1024 * 1024;
        let mut lengths = headers
            .iter()
            .filter(|h: &&Header| h.field.equiv("Content-Length"));
        match lengths.next() {
            None => None,
            Some(h) => {
                // nzbfast patch 6 (see VENDORING.md): a Content-Length we
                // cannot honour must FAIL the request, not quietly become
                // "no body".
                //
                // Patch 2 filtered an over-cap length to `None`, and upstream
                // does the same for anything unparsable. That looks safe and
                // is not: `None` installs `io::empty()` as the body and drops
                // the real reader, whose Drop hands the BufReader - still
                // holding the body bytes - straight back to header parsing.
                // The declared body is then parsed as the NEXT request:
                //     POST / HTTP/1.1
                //     Content-Length: 1073741825
                //
                //     GET /api?mode=shutdown HTTP/1.1
                // A standards-framing proxy in front sees one POST whose body
                // is that text; we see two requests and run the second on a
                // keyless origin, behind whatever path policy the proxy
                // believed it was enforcing.
                // nzbfast: 1*DIGIT and nothing else. RFC 7230 3.3.2
                // defines Content-Length that way, but `usize::from_str`
                // also accepts a leading '+', so `Content-Length: +44`
                // parsed as 44 here while a standards-framing proxy in
                // front reads it as invalid or absent - and the two then
                // disagree about where the body ends, which is the whole
                // desync class the surrounding patches close.
                let raw = h.value.as_str();
                let digits_only = !raw.is_empty() && raw.bytes().all(|b| b.is_ascii_digit());
                let len: usize = match FromStr::from_str(raw) {
                    Ok(len) if digits_only && len <= MAX_CONTENT_LENGTH => len,
                    _ => return Err(RequestCreationError::BadFraming),
                };
                // nzbfast patch 6 (addendum): the SAME desync reached
                // through two Content-Length headers rather than one bad
                // one. `.find` took the FIRST while a front end may take
                // the last, so
                //     Content-Length: 0
                //     Content-Length: 44
                // let the declared body be parsed as the next request -
                // the CL.CL half of RFC 7230 3.3.3, whose CL+TE half is
                // already refused above. Repeats that AGREE are framed
                // identically by every recipient and the RFC allows
                // collapsing them, so only a DISAGREEMENT is refused:
                // refusing the rest would be over-tightening against
                // middleboxes that duplicate headers harmlessly.
                for other in lengths {
                    match other.value.as_str().parse::<usize>() {
                        Ok(n) if n == len => {}
                        _ => return Err(RequestCreationError::BadFraming),
                    }
                }
                Some(len)
            }
        }
    };

    // true if the client sent a `Expect: 100-continue` header
    let expects_continue = {
        match headers
            .iter()
            .find(|h: &&Header| h.field.equiv("Expect"))
            .map(|h| h.value.as_str())
        {
            None => false,
            Some(v) if v.eq_ignore_ascii_case("100-continue") => true,
            _ => return Err(RequestCreationError::ExpectationFailed),
        }
    };

    // true if the client sent a `Connection: upgrade` header
    let connection_upgrade = {
        match headers
            .iter()
            .find(|h: &&Header| h.field.equiv("Connection"))
            .map(|h| h.value.as_str())
        {
            Some(v) if v.to_ascii_lowercase().contains("upgrade") => true,
            _ => false,
        }
    };

    // nzbfast patch 10 (see VENDORING.md): put the total-cost bound UNDER every
    // body shape.
    //
    // One wrapper here covers the handler's own reads, the small-body pre-read
    // below, the chunked decoder and - the unauthenticated one -
    // `EqualReader`'s drop-drain, because they all read through this. Doing it
    // per shape instead would leave whichever one was overlooked unbounded, and
    // the drain is exactly the one that needs no auth and no body-reading
    // handler: `POST /nonexistent` with a `Content-Length` and no body.
    //
    // Boxing costs one dyn dispatch per body read, which happens in 64 KiB
    // chunks.
    let mut source_data: Box<dyn Read + Send + 'static> = match &guards {
        Some(g) => Box::new(DeadlineReader::new(
            source_data,
            g.limits.body_grace,
            g.limits.min_body_rate,
            g.limits.max_body_time,
        )),
        None => Box::new(source_data),
    };

    // nzbfast patch 10: and the same for the response, whose only clock was
    // `SO_SNDTIMEO` - reset by every byte the peer deigned to read.
    let writer: Box<dyn Write + Send + 'static> = match &guards {
        Some(g) => Box::new(DeadlineWriter::new(
            writer,
            g.limits.write_grace,
            g.limits.min_write_rate,
        )),
        None => Box::new(writer),
    };

    // we wrap `source_data` around a reading whose nature depends on the transfer-encoding and
    // content-length headers
    let reader = if connection_upgrade {
        // if we have a `Connection: upgrade`, always keeping the whole reader
        Box::new(source_data) as Box<dyn Read + Send + 'static>
    } else if let Some(content_length) = content_length {
        if content_length == 0 {
            Box::new(io::empty()) as Box<dyn Read + Send + 'static>
        } else if content_length <= 1024 && !expects_continue {
            // if the content-length is small enough, we just read everything into a buffer

            let mut buffer = vec![0; content_length];
            let mut offset = 0;

            while offset != content_length {
                let read = source_data.read(&mut buffer[offset..])?;
                if read == 0 {
                    // the socket returned EOF, but we were before the expected content-length
                    // aborting
                    let info = "Connection has been closed before we received enough data";
                    let err = IoError::new(ErrorKind::ConnectionAborted, info);
                    return Err(RequestCreationError::CreationIoError(err));
                }

                offset += read;
            }

            // A short read above already returned CreationIoError, and the caller
            // closes the connection on that - so there is nothing left on the
            // wire to desynchronise against.
            Box::new(Cursor::new(buffer)) as Box<dyn Read + Send + 'static>
        } else {
            let (data_reader, _) = EqualReader::new(source_data, content_length); // TODO:
            // nzbfast patch 11 (see VENDORING.md): bound the drop-drain by bytes
            // as well as time, and have a body that stops short of its declared
            // end close the connection rather than desynchronise it.
            let data_reader = match &guards {
                Some(g) => data_reader.with_connection_guard(
                    g.limits.max_drain,
                    g.limits.max_drain_time,
                    g.desynced.clone(),
                ),
                None => data_reader,
            };
            Box::new(FusedReader::new(data_reader)) as Box<dyn Read + Send + 'static>
        }
    } else if transfer_encoding.is_some() {
        // if a transfer-encoding was specified, then "chunked" is ALWAYS applied
        // over the message (RFC2616 #3.6)
        let decoded = FusedReader::new(Decoder::new(source_data));
        // nzbfast patch 11: a chunked body nobody decodes to the terminating
        // chunk - a 404 on a chunked POST, say - leaves undecoded bytes on the
        // wire. There is no length to drain against here, so the only safe
        // answer is to close.
        match &guards {
            Some(g) => {
                Box::new(DesyncGuard::new(decoded, g.desynced.clone()))
                    as Box<dyn Read + Send + 'static>
            }
            None => Box::new(decoded) as Box<dyn Read + Send + 'static>,
        }
    } else {
        // if we have neither a Content-Length nor a Transfer-Encoding,
        // assuming that we have no data
        // TODO: could also be multipart/byteranges
        Box::new(io::empty()) as Box<dyn Read + Send + 'static>
    };

    Ok(Request {
        data_reader: Some(reader),
        response_writer: Some(Box::new(writer) as Box<dyn Write + Send + 'static>),
        remote_addr,
        secure,
        method,
        path,
        http_version: version,
        headers,
        body_length: content_length,
        must_send_continue: expects_continue,
        notify_when_responded: None,
    })
}

impl Request {
    /// Returns true if the request was made through HTTPS.
    #[inline]
    pub fn secure(&self) -> bool {
        self.secure
    }

    /// Returns the method requested by the client (eg. `GET`, `POST`, etc.).
    #[inline]
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// Returns the resource requested by the client.
    #[inline]
    pub fn url(&self) -> &str {
        &self.path
    }

    /// Returns a list of all headers sent by the client.
    #[inline]
    pub fn headers(&self) -> &[Header] {
        &self.headers
    }

    /// Returns the HTTP version of the request.
    #[inline]
    pub fn http_version(&self) -> &HTTPVersion {
        &self.http_version
    }

    /// Returns the length of the body in bytes.
    ///
    /// Returns `None` if the length is unknown.
    #[inline]
    pub fn body_length(&self) -> Option<usize> {
        self.body_length
    }

    /// Returns the address of the client that sent this request.
    ///
    /// The address is always `Some` for TCP listeners, but always `None` for UNIX listeners
    /// (as the remote address of a UNIX client is almost always unnamed).
    ///
    /// Note that this is gathered from the socket. If you receive the request from a proxy,
    /// this function will return the address of the proxy and not the address of the actual
    /// user.
    #[inline]
    pub fn remote_addr(&self) -> Option<&SocketAddr> {
        self.remote_addr.as_ref()
    }

    /// Sends a response with a `Connection: upgrade` header, then turns the `Request` into a `Stream`.
    ///
    /// The main purpose of this function is to support websockets.
    /// If you detect that the request wants to use some kind of protocol upgrade, you can
    ///  call this function to obtain full control of the socket stream.
    ///
    /// If you call this on a non-websocket request, tiny-http will wait until this `Stream` object
    ///  is destroyed before continuing to read or write on the socket. Therefore you should always
    ///  destroy it as soon as possible.
    pub fn upgrade<R: Read>(
        mut self,
        protocol: &str,
        response: Response<R>,
    ) -> Box<dyn ReadWrite + Send> {
        use crate::util::CustomStream;

        response
            .raw_print(
                self.response_writer.as_mut().unwrap().by_ref(),
                self.http_version.clone(),
                &self.headers,
                false,
                Some(protocol),
            )
            .ok(); // TODO: unused result

        self.response_writer.as_mut().unwrap().flush().ok(); // TODO: unused result

        let stream = CustomStream::new(self.extract_reader_impl(), self.extract_writer_impl());
        if let Some(sender) = self.notify_when_responded.take() {
            let stream = NotifyOnDrop {
                sender,
                inner: stream,
            };
            Box::new(stream) as Box<dyn ReadWrite + Send>
        } else {
            Box::new(stream) as Box<dyn ReadWrite + Send>
        }
    }

    /// Allows to read the body of the request.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # extern crate tiny_http;
    /// # use std::io::Read;
    /// # fn get_content_type(_: &tiny_http::Request) -> &'static str { "" }
    /// # fn main() {
    /// # let server = tiny_http::Server::http("0.0.0.0:0").unwrap();
    /// let mut request = server.recv().unwrap();
    ///
    /// if get_content_type(&request) == "application/json" {
    ///     let mut content = String::new();
    ///     request.as_reader().read_to_string(&mut content).unwrap();
    ///     // (upstream's example parsed `content` with rustc_serialize here;
    ///     // that dev-dependency is not vendored - see VENDORING.md.)
    /// }
    /// # }
    /// ```
    ///
    /// If the client sent a `Expect: 100-continue` header with the request, calling this
    ///  function will send back a `100 Continue` response.
    #[inline]
    pub fn as_reader(&mut self) -> &mut dyn Read {
        if self.must_send_continue {
            let msg = Response::new_empty(StatusCode(100));
            msg.raw_print(
                self.response_writer.as_mut().unwrap().by_ref(),
                self.http_version.clone(),
                &self.headers,
                true,
                None,
            )
            .ok();
            self.response_writer.as_mut().unwrap().flush().ok();
            self.must_send_continue = false;
        }

        self.data_reader.as_mut().unwrap()
    }

    /// Turns the `Request` into a writer.
    ///
    /// The writer has a raw access to the stream to the user.
    /// This function is useful for things like CGI.
    ///
    /// Note that the destruction of the `Writer` object may trigger
    /// some events. For exemple if a client has sent multiple requests and the requests
    /// have been processed in parallel, the destruction of a writer will trigger
    /// the writing of the next response.
    /// Therefore you should always destroy the `Writer` as soon as possible.
    #[inline]
    pub fn into_writer(mut self) -> Box<dyn Write + Send + 'static> {
        let writer = self.extract_writer_impl();
        if let Some(sender) = self.notify_when_responded.take() {
            let writer = NotifyOnDrop {
                sender,
                inner: writer,
            };
            Box::new(writer) as Box<dyn Write + Send + 'static>
        } else {
            writer
        }
    }

    /// Extract the response `Writer` object from the Request, dropping this `Writer` has the same side effects
    /// as the object returned by `into_writer` above.
    ///
    /// This may only be called once on a single request.
    fn extract_writer_impl(&mut self) -> Box<dyn Write + Send + 'static> {
        use std::mem;

        assert!(self.response_writer.is_some());

        let mut writer = None;
        mem::swap(&mut self.response_writer, &mut writer);
        writer.unwrap()
    }

    /// Extract the body `Reader` object from the Request.
    ///
    /// This may only be called once on a single request.
    fn extract_reader_impl(&mut self) -> Box<dyn Read + Send + 'static> {
        use std::mem;

        assert!(self.data_reader.is_some());

        let mut reader = None;
        mem::swap(&mut self.data_reader, &mut reader);
        reader.unwrap()
    }

    /// Sends a response to this request.
    #[inline]
    pub fn respond<R>(mut self, response: Response<R>) -> Result<(), IoError>
    where
        R: Read,
    {
        let res = self.respond_impl(response);
        // patch 12: see NotifyOnDrop::drop - an absent parser thread is not a
        // panic.
        if let Some(sender) = self.notify_when_responded.take() {
            sender.send(()).ok();
        }
        res
    }

    fn respond_impl<R>(&mut self, response: Response<R>) -> Result<(), IoError>
    where
        R: Read,
    {
        let mut writer = self.extract_writer_impl();

        let do_not_send_body = self.method == Method::Head;

        Self::ignore_client_closing_errors(response.raw_print(
            writer.by_ref(),
            self.http_version.clone(),
            &self.headers,
            do_not_send_body,
            None,
        ))?;

        Self::ignore_client_closing_errors(writer.flush())
    }

    fn ignore_client_closing_errors(result: io::Result<()>) -> io::Result<()> {
        result.or_else(|err| match err.kind() {
            ErrorKind::BrokenPipe => Ok(()),
            ErrorKind::ConnectionAborted => Ok(()),
            ErrorKind::ConnectionRefused => Ok(()),
            ErrorKind::ConnectionReset => Ok(()),
            _ => Err(err),
        })
    }

    pub(crate) fn with_notify_sender(mut self, sender: Sender<()>) -> Self {
        self.notify_when_responded = Some(sender);
        self
    }
}

impl fmt::Debug for Request {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            formatter,
            "Request({} {} from {:?})",
            self.method, self.path, self.remote_addr
        )
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        if self.response_writer.is_some() {
            let response = Response::empty(500);
            let _ = self.respond_impl(response); // ignoring any potential error
            // patch 12: see NotifyOnDrop::drop.
            if let Some(sender) = self.notify_when_responded.take() {
                sender.send(()).ok();
            }
        }
    }
}

/// Dummy trait that regroups the `Read` and `Write` traits.
///
/// Automatically implemented on all types that implement both `Read` and `Write`.
pub trait ReadWrite: Read + Write {}
impl<T> ReadWrite for T where T: Read + Write {}

#[cfg(test)]
mod tests {
    use super::Request;

    #[test]
    fn must_be_send() {
        #![allow(dead_code)]
        fn f<T: Send>(_: &T) {}
        fn bar(rq: &Request) {
            f(rq);
        }
    }
}
