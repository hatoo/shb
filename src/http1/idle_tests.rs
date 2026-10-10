use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

const RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: keep-alive\r\n\r\nabc";

fn serve(mut first: impl Read + Write, mut second: impl Read + Write) -> bool {
    for stream in [&mut first as &mut dyn Read, &mut second as &mut dyn Read] {
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        assert!(request.starts_with(b"GET / "));
    }
    first.write_all(RESPONSE).unwrap();
    first.flush().unwrap();
    drop(first);
    // The first connection's EOF must not finish the other connection's
    // outstanding request budget. Leave time for the client to process it.
    std::thread::sleep(Duration::from_millis(250));
    second.write_all(RESPONSE).is_ok() && second.flush().is_ok()
}

fn check(tls: bool, timeout: Option<Duration>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let accept = || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket.set_nodelay(true).unwrap();
            socket
        };
        let (first, second) = (accept(), accept());
        if tls {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
            let config = Arc::new(
                rustls::ServerConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert.cert.der().clone()], key.into())
                .unwrap(),
            );
            serve(
                rustls::StreamOwned::new(
                    rustls::ServerConnection::new(config.clone()).unwrap(),
                    first,
                ),
                rustls::StreamOwned::new(rustls::ServerConnection::new(config).unwrap(), second),
            )
        } else {
            serve(first, second)
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
        2,
        Budget::Requests(2),
        Duration::from_secs(5),
        timeout,
    )
    .unwrap();
    let delivered = server.join().unwrap();
    assert_eq!(
        (stats.completed, stats.errors, stats.connect_errors),
        (2, 0, 0)
    );
    assert!(delivered);
    assert_eq!(stats.latencies_ns.len(), 2);
    assert_eq!(stats.status_counts[200], 2);
    assert_eq!(stats.status_counts.iter().sum::<u64>(), 2);
}

#[test]
fn idle_plain_eof_does_not_consume_another_connections_request_budget() {
    for timeout in [None, Some(Duration::from_secs(5))] {
        check(false, timeout);
    }
}

#[test]
fn idle_tls_eof_does_not_consume_another_connections_request_budget() {
    for timeout in [None, Some(Duration::from_secs(5))] {
        check(true, timeout);
    }
}

#[test]
fn completed_requests_disarm_timeout_and_ignore_late_transport_failures() {
    for timeout in [None, Some(Duration::from_secs(5))] {
        let mut conn = Conn::new();
        let mut stats = Stats::default();
        conn.begin_request(timeout);
        conn.mark_sent();
        assert_eq!(conn.parser.feed(RESPONSE).unwrap(), 1);
        stats.record_success(conn.parser.status(), conn.request_start);
        conn.end_request();
        assert!(!conn.active);
        assert!(conn.deadline.is_none());
        finish_at_eof(&mut conn, &mut stats);
        conn.fail_request(&mut stats); // A late send/receive failure.
        assert_eq!((stats.completed, stats.errors), (1, 0));

        // EOF after a new request has been assigned is still an error.
        conn.begin_request(timeout);
        finish_at_eof(&mut conn, &mut stats);
        conn.fail_request(&mut stats);
        assert_eq!((stats.completed, stats.errors), (1, 1));
        assert_eq!(stats.latencies_ns.len(), 1);
        assert_eq!(stats.status_counts[200], 1);
    }
}

#[test]
fn eof_still_finishes_close_delimited_bodies_and_rejects_truncation_once() {
    for (wire, ok, errors) in [
        (
            &b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nabc"[..],
            1,
            0,
        ),
        (
            &b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabc"[..],
            0,
            1,
        ),
    ] {
        let mut conn = Conn::new();
        let mut stats = Stats::default();
        conn.begin_request(None);
        conn.mark_sent();
        assert_eq!(conn.parser.feed(wire).unwrap(), 0);
        finish_at_eof(&mut conn, &mut stats);
        finish_at_eof(&mut conn, &mut stats);
        assert_eq!((stats.completed, stats.errors), (ok, errors));
        assert_eq!(stats.latencies_ns.len() as u64, ok);
        assert_eq!(stats.status_counts[200], ok);
        assert!(!conn.active);
    }
}
