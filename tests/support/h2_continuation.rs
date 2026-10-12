//! Check the worker's request budget, statuses and samples against raw peers.

use crate::h2_peer::{H2Script, TlsServer, h2_frame, serve_scripted_h2, tls_config};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(10);

fn configure(socket: &TcpStream) {
    socket.set_read_timeout(Some(WAIT)).unwrap();
    socket.set_write_timeout(Some(WAIT)).unwrap();
    socket.set_nodelay(true).unwrap();
}

fn check(stats: &crate::stats::Stats, successes: u64, errors: u64) {
    assert_eq!(
        (stats.completed, stats.errors, stats.connect_errors),
        (successes, errors, 0)
    );
    assert_eq!(stats.status_counts[200], successes);
    assert_eq!(stats.status_counts.iter().sum::<u64>(), successes);
    assert_eq!(stats.latencies_ns.len() as u64, successes);
}

#[test]
fn tcp_empty_header_fragments_preserve_every_sample() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        configure(&socket);
        serve_scripted_h2(
            socket,
            H2Script {
                fragmented_response_headers: true,
                ..H2Script::default()
            },
        )
        .unwrap()
    });
    let target =
        crate::target::parse_target(&format!("http://{addr}/"), "GET", &[], None, false).unwrap();
    let stats = crate::http2::run_worker(
        &target,
        None,
        1,
        crate::budget::Budget::Requests(64),
        WAIT,
        Some(WAIT),
        8,
    )
    .unwrap();
    let summary = peer.join().unwrap();
    assert_eq!(summary.responses, 64);
    check(&stats, 64, 0);
}

#[test]
fn tls_empty_header_fragments_preserve_samples_across_reconnects() {
    let server = TlsServer::start(H2Script {
        fragmented_response_headers: true,
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
    check(&stats, 256, 0);
}

fn read_request(peer: &mut (impl Read + Write)) {
    let mut preface = [0; 24];
    peer.read_exact(&mut preface).unwrap();
    assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    peer.write_all(&h2_frame(4, 0, 0, &[])).unwrap();
    peer.flush().unwrap();
    loop {
        let mut header = [0; 9];
        peer.read_exact(&mut header).unwrap();
        let len = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
        let mut payload = vec![0; len];
        peer.read_exact(&mut payload).unwrap();
        if header[3] == 1 {
            assert_eq!(&header[5..], &1u32.to_be_bytes());
            assert_eq!(header[4] & 5, 5);
            return;
        }
        if header[3] == 4 && header[4] & 1 == 0 {
            peer.write_all(&h2_frame(4, 1, 0, &[])).unwrap();
            peer.flush().unwrap();
        }
    }
}

fn drain(peer: &mut (impl Read + Write)) {
    loop {
        match peer.read(&mut [0; 4096]) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
                ) =>
            {
                break;
            }
            Err(e) => panic!("peer did not close: {e}"),
        }
    }
}

fn invalid_sequence(tls: bool, response: Vec<u8>, truncate: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        configure(&socket);
        let write_half = socket.try_clone().unwrap();
        if tls {
            let mut conn = rustls::ServerConnection::new(tls_config()).unwrap();
            serve_invalid(
                &mut rustls::Stream::new(&mut conn, &mut socket),
                &write_half,
                &response,
                truncate,
            );
        } else {
            serve_invalid(&mut socket, &write_half, &response, truncate);
        }
    });
    let scheme = if tls { "https" } else { "http" };
    let target =
        crate::target::parse_target(&format!("{scheme}://{addr}/"), "GET", &[], None, false)
            .unwrap();
    let setup = tls.then(|| crate::tls::setup(&target.host, b"h2").unwrap());
    let stats = crate::http2::run_worker(
        &target,
        setup.as_ref(),
        1,
        crate::budget::Budget::Requests(1),
        WAIT,
        Some(WAIT),
        1,
    )
    .unwrap();
    peer.join().unwrap();
    check(&stats, 0, 1);
}

fn serve_invalid(
    peer: &mut (impl Read + Write),
    write_half: &TcpStream,
    response: &[u8],
    truncate: bool,
) {
    read_request(peer);
    peer.write_all(response).unwrap();
    peer.flush().unwrap();
    if truncate {
        write_half.shutdown(Shutdown::Write).unwrap();
    }
    drain(peer);
}

#[test]
fn invalid_interleaving_fails_exactly_one_request_without_a_sample() {
    for tls in [false, true] {
        for next in [
            h2_frame(0, 1, 1, &[]),
            h2_frame(6, 0, 0, b"12345678"),
            h2_frame(1, 5, 1, &[0x88]),
            h2_frame(9, 4, 3, &[0x88]),
        ] {
            let mut bytes = h2_frame(1, 1, 1, &[]);
            bytes.extend(next);
            // Completing after the invalid frame must not turn it into success.
            bytes.extend(h2_frame(9, 4, 1, &[0x88]));
            invalid_sequence(tls, bytes, false);
        }
        invalid_sequence(tls, h2_frame(9, 4, 1, &[0x88]), false);
    }
}

#[test]
fn unfinished_header_blocks_at_eof_fail_without_a_sample() {
    for tls in [false, true] {
        let initial = h2_frame(1, 1, 1, &[]);
        invalid_sequence(tls, initial.clone(), true);
        let mut partial = initial;
        partial.extend(h2_frame(9, 4, 1, &[0x88]));
        partial.pop();
        invalid_sequence(tls, partial, true);
    }
}
