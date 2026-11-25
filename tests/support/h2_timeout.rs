//! Independent wire peer: leave the oldest request unanswered, complete the
//! rest in reverse order, then hold the replacements until the client times
//! out and reconnects. Both transports must charge exactly the live requests.

use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

fn serve(mut sock: impl Read + Write, first: bool, parallel: usize, rounds: usize) -> usize {
    let first_requests = parallel + rounds * (parallel - 1);
    let mut waves = 0;
    let mut preface = [0; 24];
    sock.read_exact(&mut preface).unwrap();
    assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    sock.write_all(&super::h2_frame(4, 0, 0, &[])).unwrap();
    let mut requests = 0;
    loop {
        let mut header = [0; 9];
        if let Err(e) = sock.read_exact(&mut header) {
            assert!(first, "second connection closed before its responses: {e}");
            assert!(
                matches!(
                    e.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                ),
                "waiting for client teardown failed: {e}"
            );
            assert_eq!(
                requests, first_requests,
                "all replacements arrived before timeout"
            );
            return requests;
        }
        let len = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
        let id = u32::from_be_bytes(header[5..9].try_into().unwrap());
        let mut payload = vec![0; len];
        sock.read_exact(&mut payload).unwrap();
        match header[3] {
            4 if header[4] & 1 == 0 => {
                sock.write_all(&super::h2_frame(4, 1, 0, &[])).unwrap();
            }
            1 => {
                requests += 1;
                assert_eq!(id, 2 * requests as u32 - 1);
                assert_eq!(header[4] & 5, 5, "complete GET headers");
                if first {
                    assert!(requests <= first_requests);
                    if waves < rounds && requests == parallel + waves * (parallel - 1) {
                        let mut responses = Vec::new();
                        let begin = 1 + waves * (parallel - 1);
                        for stream in (begin..begin + parallel - 1).rev() {
                            responses.extend(super::h2_frame(1, 5, 1 + stream as u32 * 2, &[0x88]));
                        }
                        sock.write_all(&responses).unwrap();
                        waves += 1;
                    }
                } else {
                    sock.write_all(&super::h2_frame(1, 5, id, &[0x88])).unwrap();
                    if requests == 512 - first_requests {
                        return requests;
                    }
                }
            }
            _ => {}
        }
    }
}

fn check(tls: bool, parallel: usize, rounds: usize) {
    let config = if tls {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key =
            rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certified.cert.der().clone()], key.into())
        .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec()];
        Some(Arc::new(config))
    } else {
        None
    };
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let mut requests = Vec::new();
        for first in [true, false] {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            stream.set_nodelay(true).unwrap();
            // Require retirement of the timed-out socket before answering
            // its replacement. A live old multishot receive would pin it
            // until worker teardown and prevent this run from succeeding.
            requests.push(if let Some(config) = &config {
                let mut session = rustls::ServerConnection::new(config.clone()).unwrap();
                serve(
                    rustls::Stream::new(&mut session, &mut stream),
                    first,
                    parallel,
                    rounds,
                )
            } else {
                serve(stream, first, parallel, rounds)
            });
        }
        requests
    });
    let scheme = if tls { "https" } else { "http" };
    let report = super::shb_json(&[
        "--http2",
        "--timeout",
        "2s",
        "-p",
        &parallel.to_string(),
        "-c",
        "1",
        "-t",
        "1",
        "-n",
        "512",
        &format!("{scheme}://{addr}/"),
    ]);
    let first = parallel + rounds * (parallel - 1);
    assert_eq!(server.join().unwrap(), [first, 512 - first]);
    assert_eq!(
        report["requests"],
        serde_json::json!({
            "ok": 512 - parallel, "errors": parallel, "connectErrors": 0, "total": 512,
        })
    );
    assert_eq!(
        report["statusCodes"],
        serde_json::json!({"200": 512 - parallel})
    );
    assert!(!report["latencySeconds"].is_null());
    super::latency_accounting::assert_samples(&report);
}

#[test]
fn h2_timeout_survives_holes_and_reconnects() {
    check(false, 128, 1);
}

#[test]
fn h2_tls_timeout_survives_holes_and_reconnects() {
    check(true, 128, 1);
}

// Four younger cohorts cross twice the peak concurrency, forcing the worker
// tracker sparse before the timeout. The server ledger remains independent.
#[test]
fn h2_sparse_worker_timeout_and_reconnect() {
    check(false, 32, 4);
}

#[test]
fn h2_tls_sparse_worker_timeout_and_reconnect() {
    check(true, 32, 4);
}
