use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

const STATUSES: [u16; 8] = [200, 201, 204, 304, 200, 201, 200, 200];

fn serve(mut stream: impl Read + Write, head: bool) {
    for (i, status) in STATUSES.into_iter().enumerate() {
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        assert!(request.starts_with(if head { b"HEAD / " } else { b"GET / " }));
        let mut wire = Vec::new();
        if i == 5 {
            wire.extend_from_slice(
                b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\n",
            );
        }
        wire.extend_from_slice(format!("HTTP/1.{} {status} Test\r\n", u8::from(i != 1)).as_bytes());
        wire.extend_from_slice(b"Connection: keep-alive\r\n");
        if i == 0 {
            for _ in 0..4096 {
                wire.extend_from_slice(b"X-Field: long-header-block\r\n");
            }
        }
        if i == 6 {
            wire.extend_from_slice(b"X-Long: ");
            wire.extend(std::iter::repeat_n(b'x', 65536));
            wire.extend_from_slice(b"\r\n");
        }
        if i == 4 {
            wire.extend_from_slice(
                b"Transfer-Encoding: gzip; x=\"a,b\"\r\nTransfer-Encoding: chunked\r\n\r\n",
            );
            if !head {
                wire.extend_from_slice(b"3\r\nabc\r\n0\r\nTrailer: yes\r\n\r\n");
            }
        } else {
            wire.extend_from_slice(b"Content-Length: 3\r\nContent-Length: 3\r\n\r\n");
            if !head && status != 204 && status != 304 {
                wire.extend_from_slice(b"abc");
            }
        }
        for (part, chunk) in wire.chunks(53).enumerate() {
            stream.write_all(chunk).unwrap();
            stream.flush().unwrap();
            if part < 3 {
                std::thread::sleep(Duration::from_micros(100));
            }
        }
    }
}

fn check(tls: bool, head: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let peer = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        socket.set_nodelay(true).unwrap();
        if tls {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
            let config = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key.into())
            .unwrap();
            serve(
                rustls::StreamOwned::new(
                    rustls::ServerConnection::new(Arc::new(config)).unwrap(),
                    socket,
                ),
                head,
            );
        } else {
            serve(socket, head);
        }
    });
    let target = crate::target::parse_target(
        &format!("{}://{address}/", if tls { "https" } else { "http" }),
        if head { "HEAD" } else { "GET" },
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
        Budget::Requests(8),
        Duration::from_secs(5),
        Some(Duration::from_secs(5)),
    )
    .unwrap();
    peer.join().unwrap();
    assert_eq!(stats.completed, 8);
    assert_eq!(stats.errors, 0);
    assert_eq!(stats.connect_errors, 0);
    assert_eq!(stats.latencies_ns.len(), 8);
    assert!(stats.latencies_ns.iter().all(|&n| n > 0));
    assert_eq!(stats.status_counts.iter().sum::<u64>(), 8);
    for status in [200, 201, 204, 304] {
        assert_eq!(
            stats.status_counts[status as usize],
            STATUSES.iter().filter(|&&n| n == status).count() as u64
        );
    }
}

#[test]
fn fragmented_headers_preserve_plain_worker_samples() {
    check(false, false);
    check(false, true);
}

#[test]
fn fragmented_headers_preserve_tls_worker_samples() {
    check(true, false);
    check(true, true);
}
