use super::*;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Count encrypted bytes for TLS and response bytes for TCP at the socket.
struct Observed {
    socket: TcpStream,
    sent: Arc<AtomicU64>,
}

impl Read for Observed {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.socket.read(bytes)
    }
}

impl Write for Observed {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = self.socket.write(bytes)?;
        self.sent.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}

fn serve(mut stream: impl Read + Write, timeout: TcpStream) {
    for size in [0, 65536, 1048576] {
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        assert!(request.starts_with(b"GET / "));
        let mut wire =
            b"HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX: "
                .to_vec();
        wire.extend(std::iter::repeat_n(b'x', size));
        // CRCRLF is a nonempty line; ignored binary bytes stay opaque.
        wire.extend_from_slice(b"\r\n\r\r\nX: \0\xff\n");
        for bytes in wire.chunks(4093) {
            stream.write_all(bytes).unwrap();
        }
        stream.flush().unwrap();
        timeout
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        // The client must wait both before the empty line and between its CR
        // and LF. An early completion sends the next request (or closes).
        for bytes in [b"".as_slice(), b"\r"] {
            stream.write_all(bytes).unwrap();
            stream.flush().unwrap();
            let error = stream
                .read(&mut [0])
                .expect_err("response completed before final LF");
            assert!(matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ));
        }
        timeout
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(b"\n").unwrap();
        stream.flush().unwrap();
    }
}

fn check(tls: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let sent = Arc::new(AtomicU64::new(0));
    let peer_sent = sent.clone();
    let peer = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        socket.set_nodelay(true).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let timeout = socket.try_clone().unwrap();
        let socket = Observed {
            socket,
            sent: peer_sent,
        };
        if tls {
            let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let key =
                rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
            let config = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certified.cert.der().clone()], key.into())
            .unwrap();
            serve(
                rustls::StreamOwned::new(
                    rustls::ServerConnection::new(Arc::new(config)).unwrap(),
                    socket,
                ),
                timeout,
            );
        } else {
            serve(socket, timeout);
        }
    });
    let target = crate::target::parse_target(
        &format!("{}://{address}/", if tls { "https" } else { "http" }),
        "GET",
        &[],
        None,
        false,
    )
    .unwrap();
    let setup = tls.then(|| crate::tls::setup(&target.host, b"http/1.1").unwrap());
    let stats = run_worker(
        &target,
        setup.as_ref(),
        1,
        Budget::Requests(3),
        Duration::from_secs(5),
        Some(Duration::from_secs(5)),
    )
    .unwrap();
    peer.join().unwrap();
    assert_eq!(
        (stats.completed, stats.errors, stats.connect_errors),
        (3, 0, 0)
    );
    assert_eq!(stats.status_counts[201], 3);
    assert_eq!(stats.status_counts.iter().sum::<u64>(), 3);
    assert_eq!(stats.latencies_ns.len(), 3);
    assert!(stats.latencies_ns.iter().all(|&n| n >= 40_000_000));
    assert_eq!(stats.bytes_received, sent.load(Ordering::Relaxed));
}

#[test]
fn fragmented_trailers_preserve_plain_worker_completion_and_all_samples() {
    check(false);
}

#[test]
fn fragmented_trailers_preserve_tls_worker_completion_and_all_samples() {
    check(true);
}
