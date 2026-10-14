//! Exact wire accounting when the final response also asks for a PING ACK.
//! Keeping this exchange small exercises the same final flush as a connection
//! WINDOW_UPDATE at the end of a multi-gigabyte response workload.

use crate::h2_peer::{h2_frame, tls_config};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(10);
const PING: &[u8] = b"last ack";

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

fn read_frame(peer: &mut impl Read) -> io::Result<(u8, u8, u32, Vec<u8>)> {
    let mut header = [0; 9];
    peer.read_exact(&mut header)?;
    let len = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
    assert!(len <= 16384);
    let mut body = vec![0; len];
    peer.read_exact(&mut body)?;
    Ok((
        header[3],
        header[4],
        u32::from_be_bytes(header[5..].try_into().unwrap()),
        body,
    ))
}

fn exchange(peer: &mut (impl Read + Write), ping: bool) {
    let mut preface = [0; 24];
    peer.read_exact(&mut preface).unwrap();
    assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    peer.write_all(&h2_frame(4, 0, 0, &[])).unwrap();
    peer.flush().unwrap();
    let (mut request, mut ack) = (false, false);
    // Finish the SETTINGS exchange before answering. This keeps any earlier
    // control output out of the final send being tested.
    while !request || !ack {
        let (kind, flags, stream, body) = read_frame(peer).unwrap();
        match (kind, flags, stream) {
            (4, 0, 0) => {
                assert_eq!(body.len() % 6, 0);
                peer.write_all(&h2_frame(4, 1, 0, &[])).unwrap();
                peer.flush().unwrap();
            }
            (4, 1, 0) => {
                assert!(body.is_empty() && !ack);
                ack = true;
            }
            (1, 5, 1) => {
                assert!(!request && !body.is_empty());
                request = true;
            }
            (8, 0, 0) => assert_eq!(body.len(), 4),
            _ => panic!("unexpected request frame: {kind}/{flags}/{stream}"),
        }
    }
    let mut response = if ping {
        h2_frame(6, 0, 0, PING)
    } else {
        Vec::new()
    };
    response.extend(h2_frame(1, 5, 1, &[0x88]));
    peer.write_all(&response).unwrap();
    peer.flush().unwrap();
    if ping {
        assert_eq!(read_frame(peer).unwrap(), (6, 1, 0, PING.to_vec()));
    }
    assert_eq!(read_frame(peer).unwrap(), (7, 0, 0, vec![0; 8]));
    // An EOF inside a frame is never excused above. At this frame boundary a
    // TLS connection may end without close_notify, as normal worker teardown.
    match peer.read(&mut [0; 1]) {
        Ok(0) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {}
        other => panic!("expected EOF after GOAWAY, got {other:?}"),
    }
}

fn check(tls: bool, ping: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + WAIT;
        let socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    assert!(std::time::Instant::now() < deadline, "missing connection");
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
        let goaway_bytes = if tls {
            let mut session = rustls::ServerConnection::new(tls_config()).unwrap();
            exchange(&mut rustls::Stream::new(&mut session, &mut wire), ping);
            assert_eq!(
                session.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_3)
            );
            // The final GOAWAY is encrypted in its own record by teardown.
            // Inspect actual record boundaries, including all handshake bytes;
            // bytesSent measures ciphertext, not the decrypted HTTP/2 frames.
            let mut records = wire.received.as_slice();
            let mut last_len = 0;
            while !records.is_empty() {
                assert!(records.len() >= 5);
                last_len = 5 + u16::from_be_bytes([records[3], records[4]]) as usize;
                assert!(records.len() >= last_len);
                if records.len() == last_len {
                    assert_eq!(records[0], 23);
                }
                records = &records[last_len..];
            }
            assert_eq!(last_len, 17 + 5 + 1 + 16); // frame, header, type, AEAD tag
            last_len
        } else {
            exchange(&mut wire, ping);
            17
        };
        (wire.received.len() as u64 - goaway_bytes as u64, wire.sent)
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
        crate::budget::Budget::Requests(1),
        WAIT,
        Some(WAIT),
        1,
    );
    let (sent, received) = server.join().unwrap();
    let stats = result.unwrap();
    assert_eq!(
        (stats.completed, stats.errors, stats.connect_errors),
        (1, 0, 0)
    );
    assert_eq!(stats.status_counts[200], 1);
    assert_eq!(stats.status_counts.iter().sum::<u64>(), 1);
    assert_eq!(stats.latencies_ns.len(), 1);
    assert!(stats.latencies_ns[0] > 0);
    assert_eq!(stats.bytes_received, received);
    assert_eq!(stats.bytes_sent, sent, "tls={tls}, final ping={ping}");
}

#[test]
fn final_flush_counts_tcp_control_output() {
    check(false, false);
    check(false, true);
}

#[test]
fn final_flush_counts_tls_control_output() {
    check(true, false);
    check(true, true);
}
