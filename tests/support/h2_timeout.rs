//! Independent wire peer: leave the oldest request unanswered, complete the
//! rest in reverse order, then hold the replacements until the client times
//! out and reconnects. Both transports must charge exactly the live requests.

use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

fn serve(mut sock: impl Read + Write, first: bool) -> usize {
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
            assert_eq!(requests, 255, "all replacements arrived before timeout");
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
                    assert!(requests <= 255);
                    if requests == 128 {
                        let mut responses = Vec::new();
                        for stream in (1..128).rev() {
                            responses.extend(super::h2_frame(1, 5, 1 + stream * 2, &[0x88]));
                        }
                        sock.write_all(&responses).unwrap();
                    }
                } else {
                    sock.write_all(&super::h2_frame(1, 5, id, &[0x88])).unwrap();
                    if requests == 257 {
                        return requests;
                    }
                }
            }
            _ => {}
        }
    }
}

fn check(tls: bool) {
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
        let mut peers = Vec::new();
        for first in [true, false] {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            stream.set_nodelay(true).unwrap();
            // An outstanding multishot recv can retain the old socket until
            // the client's ring is dropped. Accept the replacement without
            // waiting for EOF on that socket.
            let config = config.clone();
            peers.push(std::thread::spawn(move || {
                if let Some(config) = config {
                    let mut session = rustls::ServerConnection::new(config).unwrap();
                    serve(rustls::Stream::new(&mut session, &mut stream), first)
                } else {
                    serve(stream, first)
                }
            }));
        }
        peers
            .into_iter()
            .map(|peer| peer.join().unwrap())
            .collect::<Vec<_>>()
    });
    let scheme = if tls { "https" } else { "http" };
    let report = super::shb_json(&[
        "--http2",
        "--timeout",
        "2s",
        "-p",
        "128",
        "-c",
        "1",
        "-t",
        "1",
        "-n",
        "512",
        &format!("{scheme}://{addr}/"),
    ]);
    assert_eq!(server.join().unwrap(), [255, 257]);
    assert_eq!(
        report["requests"],
        serde_json::json!({
            "ok": 384, "errors": 128, "connectErrors": 0, "total": 512,
        })
    );
    assert_eq!(report["statusCodes"], serde_json::json!({"200": 384}));
    assert!(!report["latencySeconds"].is_null());
}

#[test]
fn h2_timeout_survives_holes_and_reconnects() {
    check(false);
}

#[test]
fn h2_tls_timeout_survives_holes_and_reconnects() {
    check(true);
}
