//! Controlled peer shutdowns: buffered output, late TLS writes, and a final
//! response held until another connection has finished. No scheduling sleeps.

use crate::h2_peer::{H2Script, TlsServer, h2_frame, serve_scripted_h2, tls_config};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(10);
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

fn requests() -> Vec<u8> {
    let mut bytes = PREFACE.to_vec();
    bytes.extend(h2_frame(4, 0, 0, &[]));
    for id in [1, 3] {
        bytes.extend(h2_frame(1, 5, id, &[0x82, 0x86, 0x84]));
    }
    bytes
}

fn goaway(last: u32) -> Vec<u8> {
    let mut payload = last.to_be_bytes().to_vec();
    payload.extend(0u32.to_be_bytes());
    h2_frame(7, 0, 0, &payload)
}

fn script() -> H2Script {
    H2Script {
        streams_per_connection: Some(1),
        ..H2Script::default()
    }
}

/// Deliberately buffers writes until flush, as Read+Write is allowed to do.
/// The second read is late client traffic, available after the final write.
#[derive(Default)]
struct BufferedPeer {
    reads: usize,
    pending: Vec<u8>,
    delivered: Vec<u8>,
    fail_final_flush: bool,
    fail_drain: bool,
}

impl Write for BufferedPeer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.pending.extend(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.reads != 0 && self.fail_final_flush {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        self.delivered.append(&mut self.pending);
        Ok(())
    }
}

impl Read for BufferedPeer {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        assert!(self.pending.is_empty(), "peer must flush before reading");
        let data = match self.reads {
            0 => requests(),
            1 if self.fail_drain => return Err(io::ErrorKind::TimedOut.into()),
            1 => h2_frame(4, 1, 0, &[]),
            _ => return Ok(0),
        };
        self.reads += 1;
        bytes[..data.len()].copy_from_slice(&data);
        Ok(data.len())
    }
}

#[test]
fn scripted_peer_flushes_responses_and_drains_late_input() {
    let mut peer = BufferedPeer::default();
    let result = serve_scripted_h2(&mut peer, script()).unwrap();
    let mut expected = h2_frame(4, 0, 0, &[]);
    expected.extend(goaway(1));
    expected.extend(h2_frame(4, 1, 0, &[]));
    expected.extend(h2_frame(1, 5, 1, &[0x88]));
    assert_eq!(peer.delivered, expected);
    assert!(peer.pending.is_empty());
    assert_eq!(
        (result.responses, result.goaways, result.drained_bytes),
        (1, 1, 9)
    );
}

#[test]
fn scripted_peer_reports_final_flush_and_drain_failures() {
    for (fail_final_flush, fail_drain, kind) in [
        (true, false, io::ErrorKind::BrokenPipe),
        (false, true, io::ErrorKind::TimedOut),
    ] {
        let mut peer = BufferedPeer {
            fail_final_flush,
            fail_drain,
            ..BufferedPeer::default()
        };
        let err = serve_scripted_h2(&mut peer, script()).unwrap_err();
        assert_eq!(err.kind(), kind);
    }
}

fn configure(sock: &TcpStream) {
    sock.set_read_timeout(Some(WAIT)).unwrap();
    sock.set_write_timeout(Some(WAIT)).unwrap();
    sock.set_nodelay(true).unwrap();
}

/// Pause after accepting the final plaintext, before the scripted peer can
/// return. The client then queues another TLS record in the server's socket.
struct GateOnGoaway<T> {
    inner: T,
    socket: TcpStream,
    written: mpsc::Sender<()>,
    resume: mpsc::Receiver<()>,
}

impl<T: Read> Read for GateOnGoaway<T> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.inner.read(bytes)
    }
}

impl<T: Write> Write for GateOnGoaway<T> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(bytes)?;
        if bytes.get(3) == Some(&7) {
            self.written.send(()).unwrap();
            self.resume.recv_timeout(WAIT).unwrap();
            // MSG_PEEK proves that closing here would leave unread TCP data;
            // neither wall-clock delays nor assumptions about TLS buffering.
            let mut unread = [0; 1];
            assert_eq!(self.socket.peek(&mut unread).unwrap(), 1);
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[test]
fn scripted_tls_peer_does_not_reset_over_late_client_records() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (written, ready) = mpsc::channel();
    let (resume, resumed) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        configure(&socket);
        let peek = socket.try_clone().unwrap();
        let mut tls = rustls::ServerConnection::new(tls_config()).unwrap();
        serve_scripted_h2(
            GateOnGoaway {
                inner: rustls::Stream::new(&mut tls, &mut socket),
                socket: peek,
                written,
                resume: resumed,
            },
            script(),
        )
        .unwrap()
    });
    let mut socket = TcpStream::connect(addr).unwrap();
    configure(&socket);
    let mut tls = rustls::ClientConnection::new(
        crate::tls::client_config(b"h2").unwrap(),
        "localhost".try_into().unwrap(),
    )
    .unwrap();
    let mut peer = rustls::Stream::new(&mut tls, &mut socket);
    peer.write_all(&requests()).unwrap();
    peer.flush().unwrap();
    ready.recv_timeout(WAIT).unwrap();
    let late = h2_frame(4, 1, 0, &[]);
    peer.write_all(&late).unwrap();
    peer.flush().unwrap();
    resume.send(()).unwrap();
    let mut expected = h2_frame(4, 0, 0, &[]);
    expected.extend(goaway(1));
    expected.extend(h2_frame(4, 1, 0, &[]));
    expected.extend(h2_frame(1, 5, 1, &[0x88]));
    let mut received = vec![0; expected.len()];
    peer.read_exact(&mut received).unwrap();
    assert_eq!(received, expected);
    tls.send_close_notify();
    while tls.wants_write() {
        tls.write_tls(&mut socket).unwrap();
    }
    socket.shutdown(Shutdown::Write).unwrap();
    let summary = server.join().unwrap();
    assert_eq!(summary.drained_bytes, late.len());
    assert_eq!((summary.responses, summary.goaways), (1, 1));
    assert_eq!(socket.read(&mut [0; 1]).unwrap(), 0, "TCP FIN, not RST");
}

#[test]
fn tls_reconnects_preserve_every_status_and_latency_sample() {
    let server = TlsServer::start(H2Script {
        streams_per_connection: Some(5),
        ..H2Script::default()
    });
    let target = crate::target::parse_target(
        &format!("https://{}/", server.addr),
        "GET",
        &[],
        None,
        false,
    )
    .unwrap();
    let setup = crate::tls::setup(&target.host, b"h2").unwrap();
    let stats = crate::http2::run_worker(
        &target,
        Some(&setup),
        8,
        crate::budget::Budget::Requests(256),
        WAIT,
        Some(WAIT),
        8,
    )
    .unwrap();
    let peers = server.finish();
    assert_eq!(peers.iter().map(|p| p.responses).sum::<usize>(), 256);
    assert!(peers.iter().map(|p| p.goaways).sum::<usize>() >= 8);
    assert_eq!(
        (stats.completed, stats.errors, stats.connect_errors),
        (256, 0, 0)
    );
    assert_eq!(stats.latencies_ns.len(), 256);
    assert_eq!(stats.status_counts[200], 256);
    assert_eq!(stats.status_counts.iter().sum::<u64>(), 256);
}

fn unused_connection(send_preface: bool) {
    let server = TlsServer::start(script());
    let mut socket = TcpStream::connect(server.addr).unwrap();
    configure(&socket);
    let mut tls = rustls::ClientConnection::new(
        crate::tls::client_config(b"h2").unwrap(),
        "localhost".try_into().unwrap(),
    )
    .unwrap();
    while tls.is_handshaking() {
        tls.complete_io(&mut socket).unwrap();
    }
    if send_preface {
        let mut control = PREFACE.to_vec();
        control.extend(h2_frame(4, 0, 0, &[]));
        control.extend(goaway(0));
        let mut peer = rustls::Stream::new(&mut tls, &mut socket);
        peer.write_all(&control).unwrap();
        peer.flush().unwrap();
    }
    // Model a replacement made unnecessary by the other slots consuming the
    // budget. No HTTP/2 request was sent, so this owes no response or sample.
    socket.shutdown(Shutdown::Both).unwrap();
    drop(socket);
    let peers = server.finish();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].responses, 0);
    assert_eq!(peers[0].goaways, 0);
}

#[test]
fn unused_tls_connections_can_close_after_handshake_or_preface() {
    for send_preface in [false, true] {
        unused_connection(send_preface);
    }
}

fn read_request(peer: &mut (impl Read + Write)) {
    let mut preface = [0; 24];
    peer.read_exact(&mut preface).unwrap();
    assert_eq!(preface, PREFACE);
    peer.write_all(&h2_frame(4, 0, 0, &[])).unwrap();
    peer.flush().unwrap();
    loop {
        let mut header = [0; 9];
        peer.read_exact(&mut header).unwrap();
        let len = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
        let mut payload = vec![0; len];
        peer.read_exact(&mut payload).unwrap();
        match header[3] {
            4 if header[4] & 1 == 0 => {
                peer.write_all(&h2_frame(4, 1, 0, &[])).unwrap();
                peer.flush().unwrap();
            }
            1 => {
                assert_eq!(&header[5..], &1u32.to_be_bytes());
                assert_eq!(header[4] & 5, 5);
                return;
            }
            _ => {}
        }
    }
}

fn wait_for_close(peer: &mut (impl Read + Write)) {
    loop {
        match peer.read(&mut [0; 1024]) {
            Ok(0) => return,
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return,
            Err(e) => panic!("client did not retire its completed connection: {e}"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum FinalFlight {
    Complete(usize),
    TruncatedTls,
    TruncatedH2,
}

fn final_flight(mode: FinalFlight) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut first, _) = listener.accept().unwrap();
        configure(&first);
        let config = tls_config();
        let mut tls = rustls::ServerConnection::new(config.clone()).unwrap();
        let mut peer = rustls::Stream::new(&mut tls, &mut first);
        read_request(&mut peer);
        // The response headers alone must not record a success. GOAWAY keeps
        // stream 1 alive, but prevents a completed slot from taking more work.
        let mut headers = goaway(1);
        headers.extend(h2_frame(1, 4, 1, &[0x08, 3, b'2', b'0', b'1']));
        peer.write_all(&headers).unwrap();
        peer.flush().unwrap();
        let mut data = h2_frame(0, 1, 1, b"done");
        if matches!(mode, FinalFlight::TruncatedH2) {
            data.pop();
        }
        tls.writer().write_all(&data).unwrap();
        let mut ciphertext = Vec::new();
        while tls.wants_write() {
            tls.write_tls(&mut ciphertext).unwrap();
        }
        let split = match mode {
            FinalFlight::Complete(n) => n.min(ciphertext.len() - 1),
            FinalFlight::TruncatedTls => ciphertext.len() - 1,
            FinalFlight::TruncatedH2 => ciphertext.len(),
        };
        first.write_all(&ciphertext[..split]).unwrap();

        // The worker must finish the other slot while this final record is
        // incomplete. Its EOF gates the last bytes: no arbitrary delay.
        let (mut second, _) = listener.accept().unwrap();
        configure(&second);
        let mut second_tls = rustls::ServerConnection::new(config).unwrap();
        let mut second_peer = rustls::Stream::new(&mut second_tls, &mut second);
        read_request(&mut second_peer);
        let mut response = goaway(1);
        response.extend(h2_frame(1, 5, 1, &[0x08, 3, b'2', b'0', b'2']));
        second_peer.write_all(&response).unwrap();
        second_peer.flush().unwrap();
        wait_for_close(&mut second_peer);

        if matches!(mode, FinalFlight::Complete(_)) {
            first.write_all(&ciphertext[split..]).unwrap();
            wait_for_close(&mut rustls::Stream::new(&mut tls, &mut first));
        } else {
            // FIN at a partial TLS record or HTTP/2 DATA frame must fail
            // exactly the unfinished request, with no status or sample.
            first.shutdown(Shutdown::Write).unwrap();
            wait_for_close(&mut rustls::Stream::new(&mut tls, &mut first));
        }
    });
    let target =
        crate::target::parse_target(&format!("https://{addr}/"), "GET", &[], None, false).unwrap();
    let setup = crate::tls::setup(&target.host, b"h2").unwrap();
    let stats = crate::http2::run_worker(
        &target,
        Some(&setup),
        2,
        crate::budget::Budget::Requests(2),
        WAIT,
        Some(WAIT),
        1,
    )
    .unwrap();
    server.join().unwrap();
    let complete = u64::from(matches!(mode, FinalFlight::Complete(_)));
    assert_eq!(
        (stats.completed, stats.errors, stats.connect_errors),
        (1 + complete, 1 - complete, 0),
        "{mode:?}"
    );
    assert_eq!(stats.latencies_ns.len() as u64, 1 + complete, "{mode:?}");
    assert_eq!(stats.status_counts[201], complete, "{mode:?}");
    assert_eq!(stats.status_counts[202], 1, "{mode:?}");
    assert_eq!(
        stats.status_counts.iter().sum::<u64>(),
        1 + complete,
        "{mode:?}"
    );
}

#[test]
fn delayed_fragmented_tls_final_flight_preserves_both_samples() {
    // Inside the record header, at its boundary, and inside encrypted data.
    for split in [1, 4, 5, usize::MAX] {
        final_flight(FinalFlight::Complete(split));
    }
}

#[test]
fn truncated_tls_or_h2_final_flight_is_charged_once() {
    for mode in [FinalFlight::TruncatedTls, FinalFlight::TruncatedH2] {
        final_flight(mode);
    }
}
