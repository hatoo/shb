//! Real worker accounting with delayed POST credit and an early response/reset.
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
    socket.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).unwrap();
    socket.flush().unwrap();
    let mut streams = Vec::new();
    let mut bodies = std::collections::BTreeMap::<u32, Vec<u8>>::new();
    let read_frame = |socket: &mut dyn Read| {
        let mut h = [0; 9];
        socket.read_exact(&mut h).unwrap();
        let len = u32::from_be_bytes([0, h[0], h[1], h[2]]) as usize;
        let id = u32::from_be_bytes(h[5..9].try_into().unwrap());
        let mut payload = vec![0; len];
        socket.read_exact(&mut payload).unwrap();
        (h[3], h[4], id, payload)
    };
    while streams.len() < 8 {
        let (kind, flags, id, payload) = read_frame(&mut socket);
        match kind {
            1 => {
                assert_eq!(flags & 5, 4);
                assert_eq!(id, 1 + 2 * streams.len() as u32);
                streams.push(id);
                bodies.insert(id, Vec::new());
            }
            0 => {
                assert_eq!(flags & 1, 0, "initial credit cannot finish a body");
                bodies.get_mut(&id).unwrap().extend(payload);
            }
            4 if flags & 1 == 0 => {
                socket.write_all(&[0, 0, 0, 4, 1, 0, 0, 0, 0]).unwrap();
                socket.flush().unwrap();
            }
            4 | 8 => {}
            kind => panic!("unexpected request frame {kind}"),
        }
    }
    assert_eq!(bodies.values().map(Vec::len).sum::<usize>(), 65535);
    // Shrink every stream to zero credit (the first becomes negative). A PING
    // ensures the worker observes another receive while all bodies are blocked.
    let mut blocked = Vec::new();
    frame(&mut blocked, 4, 0, 0, &[0, 4, 0, 0, 0, 0]);
    frame(&mut blocked, 6, 0, 0, b"blocked!");
    socket.write_all(&blocked).unwrap();
    socket.flush().unwrap();
    loop {
        let (kind, flags, _, payload) = read_frame(&mut socket);
        if kind == 6 {
            assert_eq!(flags, 1);
            assert_eq!(payload, b"blocked!");
            break;
        }
        assert!(matches!(kind, 4 | 8));
    }
    // End one blocked request early, followed by the common duplicate reset.
    // Grant connection credit first; another PING verifies that it alone does
    // not permit DATA on any of the remaining streams.
    let early = streams[7];
    let mut response = Vec::new();
    frame(&mut response, 1, 5, early, &[0x88]);
    frame(&mut response, 3, 0, early, &0u32.to_be_bytes());
    frame(&mut response, 8, 0, 0, &1_000_000u32.to_be_bytes());
    frame(&mut response, 6, 0, 0, b"connonly");
    socket.write_all(&response).unwrap();
    socket.flush().unwrap();
    loop {
        let (kind, flags, _, payload) = read_frame(&mut socket);
        if kind == 6 {
            assert_eq!(flags, 1);
            assert_eq!(payload, b"connonly");
            break;
        }
        assert!(matches!(kind, 4 | 8));
    }
    let mut credit = Vec::new();
    for &id in streams[..7].iter().rev() {
        frame(&mut credit, 8, 0, id, &100_000u32.to_be_bytes());
    }
    socket.write_all(&credit).unwrap();
    socket.flush().unwrap();
    let mut ended = std::collections::BTreeSet::new();
    while ended.len() < 7 {
        let (kind, flags, id, payload) = read_frame(&mut socket);
        match kind {
            0 => {
                assert_ne!(id, early);
                assert!(!ended.contains(&id));
                bodies.get_mut(&id).unwrap().extend(payload);
                if flags & 1 != 0 {
                    assert!(ended.insert(id));
                    assert_eq!(bodies[&id], vec![b'q'; 100_000]);
                }
            }
            4 | 8 => {}
            kind => panic!("unexpected request frame {kind}"),
        }
    }
    let mut responses = Vec::new();
    for &id in streams[..7].iter().rev() {
        frame(&mut responses, 1, 5, id, &[0x88]);
    }
    socket.write_all(&responses).unwrap();
    socket.flush().unwrap();
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
    let target = crate::target::parse_target(
        &format!("{scheme}://{address}/"),
        "POST",
        &[],
        Some(&vec![b'q'; 100_000]),
        false,
    )
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
fn cleartext_delayed_bodies_keep_every_worker_sample() {
    exercise(false);
}

#[test]
fn tls_delayed_bodies_keep_every_worker_sample() {
    exercise(true);
}
