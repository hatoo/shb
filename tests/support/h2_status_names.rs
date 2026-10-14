//! Raw peers check status and sample accounting for literal HPACK names.
//! The fixed Huffman bytes are independently checked by
//! benchmarks/check-h2-status-names.py using python-hpack 4.1.0.

use crate::h2_peer::{h2_frame, tls_config};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(10);

struct Wire {
    socket: TcpStream,
    received: Vec<u8>,
    sent: u64,
}

impl Read for Wire {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let n = self.socket.read(bytes)?;
        self.received.extend_from_slice(&bytes[..n]);
        Ok(n)
    }
}

impl Write for Wire {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = self.socket.write(bytes)?;
        self.sent += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}

fn frame(peer: &mut impl Read) -> (u8, u8, u32, Vec<u8>) {
    let mut header = [0; 9];
    peer.read_exact(&mut header).unwrap();
    let len = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
    assert!(len <= 16384);
    let mut body = vec![0; len];
    peer.read_exact(&mut body).unwrap();
    (
        header[3],
        header[4],
        u32::from_be_bytes(header[5..].try_into().unwrap()),
        body,
    )
}

fn serve(peer: &mut (impl Read + Write), invalid: bool) {
    let mut preface = [0; 24];
    peer.read_exact(&mut preface).unwrap();
    assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    peer.write_all(&h2_frame(4, 0, 0, &[])).unwrap();
    peer.flush().unwrap();
    let count = if invalid { 1 } else { 12 };
    for n in 0..count {
        loop {
            let (kind, flags, stream, body) = frame(peer);
            match kind {
                4 if flags == 0 => {
                    peer.write_all(&h2_frame(4, 1, 0, &[])).unwrap();
                    peer.flush().unwrap();
                }
                4 => assert!(flags == 1 && body.is_empty()),
                8 => assert!(stream == 0 && body.len() == 4),
                1 => {
                    assert_eq!((flags, stream), (5, 2 * n + 1));
                    break;
                }
                _ => panic!("unexpected frame {kind}/{flags}/{stream}"),
            }
        }
        let stream = 2 * n + 1;
        let early = b"\x20\x10\x85\xb8\x84\x8d\x36\xa3\x82\x08\x19";
        let mut response = h2_frame(1, 4, stream, early); // 103 is not a completion
        let mut block = vec![[0x00, 0x10, 0x40][n as usize % 3], 0x85];
        block.extend_from_slice(b"\xb8\x84\x8d\x36\xa3");
        let value: &[u8] = if n % 2 == 0 {
            b"\x03201"
        } else {
            b"\x83\x6c\x0c\xff"
        };
        block.extend_from_slice(value);
        if invalid {
            // Recognizing the name must still reject a malformed status value.
            block.pop();
        }
        // Split the name, retain empty CONTINUATION, and end via trailers.
        response.extend(h2_frame(1, 0, stream, &block[..4]));
        response.extend(h2_frame(9, 0, stream, &[]));
        response.extend(h2_frame(9, 4, stream, &block[4..]));
        response.extend(h2_frame(0, 0, stream, b"body"));
        response.extend(h2_frame(1, 5, stream, b"\x00\x04done\x03103"));
        peer.write_all(&response).unwrap();
        peer.flush().unwrap();
    }
    // Drain whole control frames, so a late SETTINGS ACK is never mistaken
    // for teardown and unread request bytes cannot reset the responses.
    let mut tail = Vec::new();
    let mut bytes = [0; 1024];
    loop {
        match peer.read(&mut bytes) {
            Ok(0) => break,
            Ok(n) => tail.extend_from_slice(&bytes[..n]),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => panic!("drain: {e}"),
        }
    }
    let mut tail = tail.as_slice();
    let mut goaways = 0;
    while !tail.is_empty() {
        // Never excuse EOF inside a frame. Parse from a bounded slice only
        // after the connection has ended, including the error-close case.
        let (kind, flags, stream, body) = frame(&mut tail);
        if kind == 7 {
            assert_eq!((flags, stream, body.len()), (0, 0, 8));
            goaways += 1;
        } else {
            assert_eq!((kind, flags, stream, body.len()), (4, 1, 0, 0));
        }
    }
    assert_eq!(goaways, usize::from(!invalid));
}

fn check(tls: bool, invalid: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + WAIT;
        let socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "missing connection");
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) => panic!("accept: {e}"),
            }
        };
        socket.set_read_timeout(Some(WAIT)).unwrap();
        socket.set_write_timeout(Some(WAIT)).unwrap();
        socket.set_nodelay(true).unwrap();
        let mut wire = Wire {
            socket,
            received: Vec::new(),
            sent: 0,
        };
        let teardown = if tls {
            let mut session = rustls::ServerConnection::new(tls_config()).unwrap();
            serve(&mut rustls::Stream::new(&mut session, &mut wire), invalid);
            let mut records = wire.received.as_slice();
            let mut last = 0;
            while !records.is_empty() {
                assert!(records.len() >= 5);
                last = 5 + u16::from_be_bytes([records[3], records[4]]) as usize;
                assert!(records.len() >= last);
                records = &records[last..];
            }
            if invalid {
                0 // protocol errors close without a teardown GOAWAY
            } else {
                assert_eq!(last, 17 + 5 + 1 + 16); // GOAWAY in one TLS 1.3 record
                last
            }
        } else {
            serve(&mut wire, invalid);
            if invalid { 0 } else { 17 }
        };
        (wire.received.len() as u64 - teardown as u64, wire.sent)
    });
    let scheme = if tls { "https" } else { "http" };
    let target =
        crate::target::parse_target(&format!("{scheme}://{addr}/"), "GET", &[], None, false)
            .unwrap();
    let setup = tls.then(|| crate::tls::setup(&target.host, b"h2").unwrap());
    let result = crate::http2::run_worker(
        &target,
        setup.as_ref(),
        1,
        crate::budget::Budget::Requests(if invalid { 1 } else { 12 }),
        WAIT,
        Some(WAIT),
        1,
    );
    let (sent, received) = server.join().unwrap();
    let stats = result.unwrap();
    let successes = if invalid { 0 } else { 12 };
    assert_eq!(
        (stats.completed, stats.errors, stats.connect_errors),
        (successes, u64::from(invalid), 0)
    );
    assert_eq!(stats.status_counts[201], successes / 2);
    assert_eq!(stats.status_counts[503], successes / 2);
    assert_eq!(stats.status_counts.iter().sum::<u64>(), successes);
    assert_eq!(stats.latencies_ns.len() as u64, successes);
    assert!(stats.latencies_ns.iter().all(|&ns| ns > 0));
    assert_eq!(stats.bytes_sent, sent);
    assert_eq!(stats.bytes_received, received);
}

#[test]
fn literal_names_preserve_tcp_statuses_samples_and_bytes() {
    check(false, false);
}

#[test]
fn literal_names_preserve_tls_statuses_samples_and_bytes() {
    check(true, false);
}

#[test]
fn malformed_literal_status_has_no_completion_or_sample() {
    check(false, true);
    check(true, true);
}
