//! Real worker accounting across fragmented and coalesced HTTP/2 responses.
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

fn frame(out: &mut Vec<u8>, kind: u8, flags: u8, id: u32, payload: &[u8]) {
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(&[kind, flags]);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(payload);
}

fn serve(mut socket: impl Read + Write, finished: std::sync::mpsc::Receiver<()>) {
    let mut preface = [0; 24];
    socket.read_exact(&mut preface).unwrap();
    assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    // Split the server preface, then leave the eight requests in flight until
    // they can be answered together. Reads are bounded by socket timeouts.
    socket.write_all(&[0]).unwrap();
    socket.flush().unwrap();
    std::thread::sleep(Duration::from_millis(2));
    socket.write_all(&[0, 0, 4, 0, 0, 0, 0, 0]).unwrap();
    socket.flush().unwrap();
    let mut streams = Vec::new();
    while streams.len() < 8 {
        let mut header = [0; 9];
        socket.read_exact(&mut header).unwrap();
        let len = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
        let id = u32::from_be_bytes(header[5..9].try_into().unwrap());
        let mut payload = vec![0; len];
        socket.read_exact(&mut payload).unwrap();
        match header[3] {
            1 => {
                assert_eq!(header[4] & 5, 5, "GET headers end the request");
                assert_eq!(id, 1 + 2 * streams.len() as u32);
                streams.push(id);
            }
            4 if header[4] & 1 == 0 => {
                socket.write_all(&[0, 0, 0, 4, 1, 0, 0, 0, 0]).unwrap();
                socket.flush().unwrap();
            }
            4 | 8 => {}
            kind => panic!("unexpected request frame {kind}"),
        }
    }
    let mut responses = Vec::new();
    // Reverse completion order so samples cannot accidentally be tied to the
    // most recently opened stream. Each response spans several DATA frames.
    for id in streams.into_iter().rev() {
        frame(&mut responses, 1, 0, id, &[0x88]);
        frame(&mut responses, 9, 4, id, &[0, 1, b'x', 1, b'y']);
        frame(&mut responses, 0, 0, id, &[b'a'; 16_384]);
        frame(&mut responses, 0, 0, id, &[b'b'; 53]);
        frame(&mut responses, 0, 1, id, b"end");
    }
    let mut pos = 0;
    for size in [1, 8, 9, 53, 16_384].into_iter().cycle() {
        if pos == responses.len() {
            break;
        }
        let end = (pos + size).min(responses.len());
        socket.write_all(&responses[pos..end]).unwrap();
        socket.flush().unwrap();
        pos = end;
        if pos < responses.len() {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    // io_uring teardown can release its socket references asynchronously.
    // Keep the peer alive until the caller reports worker completion, without
    // requiring a transport EOF before returning the statistics.
    finished.recv_timeout(Duration::from_secs(10)).unwrap();
}

fn exercise(tls: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (finished, done) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        configure_socket(&socket);
        if tls {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
            let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key.into())
            .unwrap();
            config.alpn_protocols = vec![b"h2".to_vec()];
            let conn = rustls::ServerConnection::new(Arc::new(config)).unwrap();
            serve(rustls::StreamOwned::new(conn, socket), done);
        } else {
            serve(socket, done);
        }
    });
    let scheme = if tls { "https" } else { "http" };
    let target =
        crate::target::parse_target(&format!("{scheme}://{address}/"), "GET", &[], None, false)
            .unwrap();
    let setup = tls.then(|| crate::tls::setup("localhost", b"h2").unwrap());
    let timeout = Duration::from_secs(5);
    let result = crate::http2::run_worker(
        &target,
        setup.as_ref(),
        1,
        crate::budget::Budget::Requests(8),
        timeout,
        Some(timeout),
        8,
    );
    let _ = finished.send(());
    thread.join().unwrap();
    let stats = result.unwrap();
    assert_eq!(
        (stats.completed, stats.errors, stats.connect_errors),
        (8, 0, 0)
    );
    assert_eq!(stats.latencies_ns.len(), 8);
    assert!(stats.latencies_ns.iter().all(|n| *n > 0));
    assert_eq!(stats.status_counts[200], 8);
    assert_eq!(stats.status_counts.iter().sum::<u64>(), 8);
}

fn configure_socket(socket: &TcpStream) {
    socket.set_nodelay(true).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
}

#[test]
fn cleartext_fragmented_responses_keep_every_worker_sample() {
    exercise(false);
}

#[test]
fn tls_fragmented_responses_keep_every_worker_sample() {
    exercise(true);
}
