//! Independent TLS/raw-H2 peer: one connection owns both requests before
//! another fails its handshake. The delayed response must still be measured.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

fn config(h2: bool) -> Arc<rustls::ServerConfig> {
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
    if h2 {
        config.alpn_protocols = vec![b"h2".to_vec()];
    }
    Arc::new(config)
}

fn accept(listener: &TcpListener) -> TcpStream {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(std::time::Instant::now() < deadline, "missing connection");
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => panic!("accept: {e}"),
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.set_nodelay(true).unwrap();
    stream
}

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut frame = (payload.len() as u32).to_be_bytes()[1..].to_vec();
    frame.extend([kind, flags]);
    frame.extend(stream.to_be_bytes());
    frame.extend(payload);
    frame
}

fn check(no_alpn: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let (finished, done) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let mut first = rustls::StreamOwned::new(
            rustls::ServerConnection::new(config(true)).unwrap(),
            accept(&listener),
        );
        let mut preface = [0; 24];
        first.read_exact(&mut preface).unwrap();
        assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        first.write_all(&frame(4, 0, 0, &[])).unwrap();

        let mut second = accept(&listener);
        let mut hello = [0; 5];
        second.read_exact(&mut hello).unwrap();
        assert_eq!(hello[0], 22, "the second TLS handshake is pending");
        let len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        let mut record = hello.to_vec();
        record.resize(5 + len, 0);
        second.read_exact(&mut record[5..]).unwrap();

        let mut ids = Vec::new();
        while ids.len() < 2 {
            let mut header = [0; 9];
            first.read_exact(&mut header).unwrap();
            let len = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
            let mut payload = vec![0; len];
            first.read_exact(&mut payload).unwrap();
            match header[3] {
                4 if header[4] & 1 == 0 => first.write_all(&frame(4, 1, 0, &[])).unwrap(),
                1 => {
                    assert_eq!(header[4] & 5, 5, "complete GET headers");
                    ids.push(u32::from_be_bytes(header[5..9].try_into().unwrap()));
                }
                _ => {}
            }
        }
        assert_eq!(ids, [1, 3], "both requests belong to the first connection");
        first.write_all(&frame(1, 5, ids[0], &[0x88])).unwrap();
        if no_alpn {
            // Send a valid server flight selecting no ALPN protocol. Do not
            // wait for Finished: the client can close as soon as it rejects
            // the selection, before flushing its own final handshake flight.
            let mut tls = rustls::ServerConnection::new(config(false)).unwrap();
            tls.read_tls(&mut &record[..]).unwrap();
            tls.process_new_packets().unwrap();
            assert!(tls.wants_write());
            while tls.wants_write() {
                tls.write_tls(&mut second).unwrap();
            }
        } else {
            second.shutdown(std::net::Shutdown::Both).unwrap();
        }
        std::thread::sleep(Duration::from_millis(250));
        // Literal :status 201, with the name referenced from HPACK's static
        // table. Keeping distinct statuses also detects duplicate accounting.
        let delivered = first
            .write_all(&frame(1, 5, ids[1], &[0x08, 3, b'2', b'0', b'1']))
            .is_ok();
        // Keep the socket alive until the worker returns. A cancelled
        // multishot recv can retain a socket past the worker's ring teardown,
        // so TCP EOF is not a reliable signal inside the same test process.
        done.recv_timeout(Duration::from_secs(15)).unwrap();
        delivered
    });
    let target =
        crate::target::parse_target(&format!("https://{addr}/"), "GET", &[], None, false).unwrap();
    let setup = crate::tls::setup(&target.host, b"h2").unwrap();
    let stats = crate::http2::run_worker(
        &target,
        Some(&setup),
        2,
        crate::budget::Budget::Requests(2),
        Duration::from_secs(5),
        Some(Duration::from_secs(10)),
        2,
    )
    .unwrap();
    finished.send(()).unwrap();
    let delivered = server.join().unwrap();
    assert_eq!(
        (stats.completed, stats.errors, stats.connect_errors),
        (2, 0, 0)
    );
    assert!(delivered);
    assert_eq!(stats.latencies_ns.len(), 2);
    assert_eq!(stats.status_counts[200], 1);
    assert_eq!(stats.status_counts[201], 1);
    assert_eq!(stats.status_counts.iter().sum::<u64>(), 2);
    assert!(*stats.latencies_ns.iter().max().unwrap() >= 200_000_000);
}

#[test]
fn late_h2_tls_failure_preserves_both_responses_and_samples() {
    check(false);
}

#[test]
fn late_h2_alpn_rejection_preserves_both_responses_and_samples() {
    check(true);
}
