//! A raw peer exercises the real receive loop, including events parsed before
//! a later frame fails. The unit ledger covers every byte boundary; these cases
//! also check socket/TLS ownership and exact transport-byte accounting.

use crate::h2_peer::{h2_frame, tls_config};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(10);

struct Wire {
    socket: TcpStream,
    received: u64,
    sent: u64,
}

impl Read for Wire {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let n = self.socket.read(bytes)?;
        self.received += n as u64;
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

#[derive(Clone, Copy, Debug)]
enum Case {
    PendingRequest,
    FinalBudget,
    MissingStatus,
}

impl Case {
    fn requests(self) -> u64 {
        match self {
            Self::FinalBudget => 1,
            Self::PendingRequest | Self::MissingStatus => 2,
        }
    }

    fn successes(self) -> u64 {
        match self {
            Self::PendingRequest | Self::FinalBudget => 1,
            Self::MissingStatus => 0,
        }
    }
}

fn read_frame(peer: &mut impl Read) -> (u8, u8, u32, Vec<u8>) {
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

fn exchange(peer: &mut (impl Read + Write), case: Case, split: bool) {
    let mut preface = [0; 24];
    peer.read_exact(&mut preface).unwrap();
    assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    peer.write_all(&h2_frame(4, 0, 0, &[])).unwrap();
    peer.flush().unwrap();
    let (mut settings, mut ack) = (false, false);
    let mut ids = Vec::new();
    // All requests and handshake controls must arrive before the response.
    // In particular, stream 3 is already owned when stream 1 completes.
    while !settings || !ack || ids.len() < case.requests() as usize {
        let (kind, flags, stream, body) = read_frame(peer);
        match (kind, flags, stream) {
            (4, 0, 0) => {
                assert!(!settings && body.len().is_multiple_of(6));
                settings = true;
                peer.write_all(&h2_frame(4, 1, 0, &[])).unwrap();
                peer.flush().unwrap();
            }
            (4, 1, 0) => {
                assert!(!ack && body.is_empty());
                ack = true;
            }
            (1, 5, id) => {
                assert_eq!(id, 1 + 2 * ids.len() as u32);
                assert!(!body.is_empty());
                ids.push(id);
            }
            (8, 0, 0) => assert_eq!(body.len(), 4),
            _ => panic!("unexpected request frame: {kind}/{flags}/{stream}"),
        }
    }
    assert_eq!(ids.len() as u64, case.requests());

    let mut response = match case {
        Case::PendingRequest | Case::FinalBudget => h2_frame(1, 5, 1, &[0x88]),
        Case::MissingStatus => h2_frame(0, 1, 1, &[]),
    };
    // An incomplete PING payload is a connection error. Keeping it in the
    // same write (and TLS record) as the completion exposes a worker that
    // discards already-parsed events when feed returns Err.
    response.extend(h2_frame(6, 0, 0, &[]));
    if split {
        // Split inside the first frame header, so it cannot complete before
        // the tail containing the malformed frame is sent. TCP may coalesce
        // writes; TLS uses separate records and the unit oracle exhausts cuts.
        peer.write_all(&response[..5]).unwrap();
        peer.flush().unwrap();
        peer.write_all(&response[5..]).unwrap();
    } else {
        peer.write_all(&response).unwrap();
    }
    peer.flush().unwrap();

    // A parse failure retires the socket, with no best-effort GOAWAY from
    // normal final-budget teardown. Any unaccounted output fails this check.
    match peer.read(&mut [0; 1]) {
        Ok(0) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {}
        other => panic!("expected EOF after malformed PING, got {other:?}"),
    }
}

fn check(tls: bool, case: Case, split: bool) {
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
            received: 0,
            sent: 0,
        };
        if tls {
            let mut session = rustls::ServerConnection::new(tls_config()).unwrap();
            exchange(
                &mut rustls::Stream::new(&mut session, &mut wire),
                case,
                split,
            );
            assert_eq!(
                session.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_3)
            );
            assert_eq!(session.alpn_protocol(), Some(b"h2".as_slice()));
        } else {
            exchange(&mut wire, case, split);
        }
        (wire.received, wire.sent)
    });
    let (finished, done) = mpsc::channel();
    let start = Instant::now();
    let worker = std::thread::spawn(move || {
        let scheme = if tls { "https" } else { "http" };
        let target =
            crate::target::parse_target(&format!("{scheme}://{addr}/"), "GET", &[], None, false)
                .unwrap();
        let setup = tls.then(|| crate::tls::setup(&target.host, b"h2").unwrap());
        let result = crate::http2::run_worker(
            &target,
            setup.as_ref(),
            1,
            crate::budget::Budget::Requests(case.requests()),
            WAIT,
            Some(WAIT),
            case.requests() as usize,
        );
        finished.send(result).unwrap();
    });
    // An accounting regression can leave no live requests but an unmet budget;
    // request timeouts cannot terminate that loop. Bound the worker separately.
    let stats = done.recv_timeout(WAIT * 2).expect("worker did not finish");
    worker.join().unwrap();
    let (sent, received) = server.join().unwrap();
    let elapsed = start.elapsed().as_nanos() as u64;
    let stats = stats.unwrap();
    assert_eq!(
        (stats.completed, stats.errors, stats.connect_errors),
        (case.successes(), case.requests() - case.successes(), 0),
        "tls={tls}, case={case:?}, split={split}"
    );
    assert_eq!(stats.status_counts[200], case.successes());
    assert_eq!(stats.status_counts.iter().sum::<u64>(), case.successes());
    assert_eq!(stats.latencies_ns.len() as u64, case.successes());
    assert!(stats.latencies_ns.iter().all(|&n| n > 0 && n <= elapsed));
    // Wire sits below TLS, so this includes every handshake and ciphertext byte.
    assert_eq!(stats.bytes_sent, sent);
    assert_eq!(stats.bytes_received, received);
}

#[test]
fn tcp_completion_before_parse_error_preserves_accounting() {
    for case in [Case::PendingRequest, Case::FinalBudget, Case::MissingStatus] {
        for split in [false, true] {
            check(false, case, split);
        }
    }
}

#[test]
fn tls_completion_before_parse_error_preserves_accounting() {
    for case in [Case::PendingRequest, Case::FinalBudget, Case::MissingStatus] {
        for split in [false, true] {
            check(true, case, split);
        }
    }
}
