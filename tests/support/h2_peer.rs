//! A raw HTTP/2 test peer shared by executable and worker-level regressions.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[derive(Debug, Default)]
pub struct PeerSummary {
    pub responses: usize,
    pub goaways: usize,
    pub drained_bytes: usize,
}

pub fn tls_config() -> Arc<rustls::ServerConfig> {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![certified.cert.der().clone()], key.into())
    .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
}

/// Joining each peer makes a failed write or drain visible to the test. The
/// wakeup connection ends accept after the worker has closed all its sockets.
pub struct TlsServer {
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: std::thread::JoinHandle<Vec<PeerSummary>>,
}

struct ObservedPeer<T> {
    inner: T,
    input: Vec<u8>,
}

impl<T> ObservedPeer<T> {
    /// An idle replacement may send its preface and connection controls before
    /// the worker's last request finishes elsewhere. Never excuse an error on
    /// a connection with a stream frame or an incomplete HTTP/2 frame.
    fn unused(&self) -> bool {
        if self.input.is_empty() {
            return true;
        }
        let Some(mut bytes) = self.input.strip_prefix(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") else {
            return false;
        };
        while bytes.len() >= 9 {
            let len = u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]) as usize;
            if bytes.len() < 9 + len || !matches!(bytes[3], 4 | 6 | 7 | 8) || bytes[5..9] != [0; 4]
            {
                return false;
            }
            bytes = &bytes[9 + len..];
        }
        bytes.is_empty()
    }
}

impl<T: Read> Read for ObservedPeer<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.input.extend_from_slice(&buf[..n]);
        Ok(n)
    }
}

impl<T: Write> Write for ObservedPeer<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl TlsServer {
    pub fn start(script: H2Script) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let config = tls_config();
        let thread = std::thread::spawn(move || {
            let mut peers = Vec::new();
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                if stopping.load(Ordering::Acquire) {
                    break;
                }
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let config = config.clone();
                let connection = peers.len();
                peers.push(std::thread::spawn(move || {
                    let mut tls = rustls::ServerConnection::new(config).unwrap();
                    let mut peer = ObservedPeer {
                        inner: rustls::Stream::new(&mut tls, &mut stream),
                        input: Vec::new(),
                    };
                    let result = serve_scripted_h2(&mut peer, script);
                    match result {
                        // A replacement connection can become unnecessary
                        // while another slot finishes the last request, even
                        // after its handshake/preface. It received no streams;
                        // exact peer/client response totals still detect any
                        // requests lost before this peer could read them.
                        Err(e)
                            if peer.unused()
                                && matches!(
                                    e.kind(),
                                    io::ErrorKind::UnexpectedEof
                                        | io::ErrorKind::ConnectionReset
                                        | io::ErrorKind::BrokenPipe
                                ) =>
                        {
                            PeerSummary::default()
                        }
                        other => other.unwrap_or_else(|e| {
                            panic!(
                                "scripted TLS peer {connection}, {} H2 bytes read: {e}",
                                peer.input.len()
                            )
                        }),
                    }
                }));
            }
            peers.into_iter().map(|p| p.join().unwrap()).collect()
        });
        Self { addr, stop, thread }
    }

    pub fn finish(self) -> Vec<PeerSummary> {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.addr).unwrap();
        self.thread.join().unwrap()
    }
}

fn drain_to_eof(sock: &mut (impl Read + Write)) -> io::Result<usize> {
    let mut bytes = 0;
    let mut buf = [0; 4096];
    loop {
        match sock.read(&mut buf) {
            Ok(0) => return Ok(bytes),
            Ok(n) => bytes += n,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(bytes),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

#[test]
fn unused_peer_requires_complete_connection_controls_and_no_streams() {
    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let mut peer = ObservedPeer {
        inner: (),
        input: Vec::new(),
    };
    assert!(peer.unused());
    peer.input.extend(preface);
    peer.input.extend(h2_frame(4, 0, 0, &[]));
    assert!(peer.unused());
    let controls = peer.input.len();
    for stream in [0, 1] {
        peer.input.truncate(controls);
        peer.input
            .extend(h2_frame(1, 5, stream, &[0x82, 0x86, 0x84]));
        assert!(!peer.unused(), "even malformed HEADERS must not be excused");
    }
    peer.input.truncate(controls);
    peer.input.extend(h2_frame(4, 0, 0, &[0; 6]));
    peer.input.pop();
    assert!(!peer.unused(), "a partial frame is not an idle connection");
}

/// What a scripted HTTP/2 server does, beyond answering every request 200
///
/// hyper behind axum is a well-behaved peer, and the things the protocol
/// lets a server do to a client - shrink the header table, refuse streams,
/// go away - are the things it does not do on demand. This one does nothing
/// but those, on a raw socket, one thread per connection.
#[derive(Clone, Copy, Default)]
pub struct H2Script {
    /// Advertise SETTINGS_HEADER_TABLE_SIZE 0 and, once the client has
    /// acknowledged it, tear the connection down unless the next header block
    /// opens with the dynamic table size update RFC 7541 Section 4.2 says it
    /// must. That is what nghttp2 does.
    pub header_table_size_zero: bool,
    /// Act on this many streams per connection and no more: the first one
    /// past the line draws a GOAWAY naming the last one acted on, streams
    /// above it are never answered. After answering those below it, drain
    /// until the client closes so late writes cannot reset its responses.
    pub streams_per_connection: Option<u32>,
    /// Advertise this many concurrent streams and take that many of the
    /// HEADERS in one read, refusing the rest with RST_STREAM(REFUSED_STREAM)
    /// as a server does when a client opens more than it said it would take.
    /// Node with maxConcurrentStreams does this to a first flight.
    pub accept_per_read: Option<usize>,
}

pub fn h2_frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut v = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags];
    v.extend_from_slice(&stream.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

pub fn serve_scripted_h2(mut sock: impl Read + Write, script: H2Script) -> io::Result<PeerSummary> {
    let mut summary = PeerSummary::default();
    const DATA: u8 = 0x0;
    const HEADERS: u8 = 0x1;
    const RST_STREAM: u8 = 0x3;
    const SETTINGS: u8 = 0x4;
    const PING: u8 = 0x6;
    const GOAWAY: u8 = 0x7;
    const WINDOW_UPDATE: u8 = 0x8;
    const FLAG_ACK: u8 = 0x1;
    const FLAG_END_STREAM: u8 = 0x1;
    const FLAG_END_HEADERS: u8 = 0x4;
    const NO_ERROR: u32 = 0x0;
    const REFUSED_STREAM: u32 = 0x7;
    const COMPRESSION_ERROR: u32 = 0x9;

    let goaway = |last: u32, code: u32| {
        let mut payload = last.to_be_bytes().to_vec();
        payload.extend_from_slice(&code.to_be_bytes());
        h2_frame(GOAWAY, 0, 0, &payload)
    };
    // The highest stream id this connection acts on
    let last_stream = script
        .streams_per_connection
        .map_or(u32::MAX, |n| (2 * n).saturating_sub(1));

    let mut settings = Vec::new();
    if script.header_table_size_zero {
        settings.extend_from_slice(&[0, 1, 0, 0, 0, 0]);
    }
    if let Some(n) = script.accept_per_read {
        settings.extend_from_slice(&[0, 3]);
        settings.extend_from_slice(&(n as u32).to_be_bytes());
    }
    sock.write_all(&h2_frame(SETTINGS, 0, 0, &settings))?;
    sock.flush()?;

    let mut pending = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    let mut preface_read = false;
    // The first header block after the client acknowledges our SETTINGS is
    // the one that owes the size update
    let mut size_update_due = false;
    // Streams whose request body has not finished arriving
    let mut awaiting_body: Vec<u32> = Vec::new();
    let mut goaway_sent = false;
    loop {
        match sock.read(&mut chunk) {
            Ok(0) => return Ok(summary),
            // A worker can close its final, completed connection without a
            // TLS close_notify. This is EOF, not a response from the peer.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(summary),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
            Ok(n) => pending.extend_from_slice(&chunk[..n]),
        }
        if !preface_read {
            if pending.len() < 24 {
                continue;
            }
            assert_eq!(&pending[..24], b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            pending.drain(..24);
            preface_read = true;
        }
        let mut out = Vec::new();
        let mut pos = 0;
        let mut accepted_this_read = 0;
        while pending.len() - pos >= 9 {
            let h = &pending[pos..pos + 9];
            let len = u32::from_be_bytes([0, h[0], h[1], h[2]]) as usize;
            let (kind, flags) = (h[3], h[4]);
            let stream = u32::from_be_bytes([h[5] & 0x7f, h[6], h[7], h[8]]);
            if pending.len() < pos + 9 + len {
                break;
            }
            let payload = &pending[pos + 9..pos + 9 + len];
            pos += 9 + len;

            let mut respond = |out: &mut Vec<u8>, stream: u32| {
                summary.responses += 1;
                out.extend_from_slice(&h2_frame(
                    HEADERS,
                    FLAG_END_HEADERS | FLAG_END_STREAM,
                    stream,
                    &[0x88],
                ));
            };
            match kind {
                SETTINGS if flags & FLAG_ACK != 0 => {
                    size_update_due = script.header_table_size_zero;
                }
                SETTINGS => out.extend_from_slice(&h2_frame(SETTINGS, FLAG_ACK, 0, &[])),
                PING if flags & FLAG_ACK == 0 => {
                    out.extend_from_slice(&h2_frame(PING, FLAG_ACK, 0, payload));
                }
                HEADERS => {
                    // The client sets neither PADDED nor PRIORITY, so the
                    // block starts at the payload. The update is 001xxxxx.
                    if std::mem::take(&mut size_update_due)
                        && payload.first().map(|b| b & 0xe0) != Some(0x20)
                    {
                        sock.write_all(&goaway(0, COMPRESSION_ERROR))?;
                        sock.flush()?;
                        return Err(io::Error::other("missing HPACK table size update"));
                    }
                    if stream > last_stream {
                        if !goaway_sent {
                            // Ahead of the responses already queued: nginx
                            // sends control frames in front of everything
                            // else, so its GOAWAY reaches the client before
                            // the answers to the streams below its line
                            out.splice(0..0, goaway(last_stream, NO_ERROR));
                            goaway_sent = true;
                            summary.goaways += 1;
                        }
                        continue;
                    }
                    if script
                        .accept_per_read
                        .is_some_and(|n| accepted_this_read >= n)
                    {
                        out.extend_from_slice(&h2_frame(
                            RST_STREAM,
                            0,
                            stream,
                            &REFUSED_STREAM.to_be_bytes(),
                        ));
                        continue;
                    }
                    accepted_this_read += 1;
                    if flags & FLAG_END_STREAM != 0 {
                        respond(&mut out, stream);
                    } else {
                        awaiting_body.push(stream);
                    }
                }
                DATA if stream > last_stream => {}
                DATA => {
                    // Credit goes straight back, on both windows
                    let credit = (len as u32).to_be_bytes();
                    out.extend_from_slice(&h2_frame(WINDOW_UPDATE, 0, 0, &credit));
                    out.extend_from_slice(&h2_frame(WINDOW_UPDATE, 0, stream, &credit));
                    if flags & FLAG_END_STREAM != 0
                        && let Some(i) = awaiting_body.iter().position(|s| *s == stream)
                    {
                        awaiting_body.swap_remove(i);
                        respond(&mut out, stream);
                    }
                }
                _ => {}
            }
        }
        pending.drain(..pos);
        sock.write_all(&out)?;
        sock.flush()?;
        if goaway_sent && awaiting_body.is_empty() {
            // The client may still be writing HEADERS or SETTINGS ACKs.
            // Closing over unread TCP data can reset the connection before
            // it has consumed the responses below the GOAWAY boundary.
            summary.drained_bytes = drain_to_eof(&mut sock)?;
            return Ok(summary);
        }
    }
}
