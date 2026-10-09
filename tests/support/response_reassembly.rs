//! Large responses from an independent Quinn/h3 peer. A relay loses a
//! response packet, or holds it behind later packets and then duplicates it.
//! One exchange checks every body byte; the worker checks request/sample counts.

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const BODY_LEN: usize = 257_003;

fn body() -> Vec<u8> {
    (0..BODY_LEN).map(|i| (i * 37 % 251) as u8).collect()
}

struct Server {
    addr: SocketAddr,
    completed: Arc<AtomicUsize>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.stop.take().unwrap().send(());
        self.thread.take().unwrap().join().unwrap();
    }
}

fn server() -> Server {
    let (tx, rx) = std::sync::mpsc::channel();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let completed = Arc::new(AtomicUsize::new(0));
    let finished = completed.clone();
    let thread = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let key =
                rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
            let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certified.cert.der().clone()], key.into())
            .unwrap();
            tls.alpn_protocols = vec![b"h3".to_vec()];
            let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls)).unwrap();
            let config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
            let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
            tx.send(endpoint.local_addr().unwrap()).unwrap();
            let serve = async {
                while let Some(incoming) = endpoint.accept().await {
                    let finished = finished.clone();
                    tokio::spawn(async move {
                        let Ok(conn) = incoming.await else { return };
                        let Ok(mut conn) = h3::server::Connection::<_, bytes::Bytes>::new(
                            h3_quinn::Connection::new(conn),
                        )
                        .await
                        else {
                            return;
                        };
                        while let Ok(Some(resolver)) = conn.accept().await {
                            let finished = finished.clone();
                            tokio::spawn(async move {
                                let Ok((request, mut stream)) = resolver.resolve_request().await
                                else {
                                    return;
                                };
                                assert_eq!(request.method(), http::Method::GET);
                                match stream.recv_data().await {
                                    Ok(None) => {}
                                    Ok(Some(_)) => panic!("GET unexpectedly has a body"),
                                    Err(_) => return,
                                }
                                let response = http::Response::builder()
                                    .status(200)
                                    .header("content-length", BODY_LEN)
                                    .body(())
                                    .unwrap();
                                if stream.send_response(response).await.is_ok()
                                    && stream.send_data(bytes::Bytes::from(body())).await.is_ok()
                                    && stream.finish().await.is_ok()
                                {
                                    finished.fetch_add(1, Ordering::SeqCst);
                                }
                            });
                        }
                    });
                }
            };
            tokio::select! { _ = serve => {}, _ = stopped => {} }
        });
    });
    Server {
        addr: rx.recv().unwrap(),
        completed,
        stop: Some(stop),
        thread: Some(thread),
    }
}

struct Relay {
    addr: SocketAddr,
    affected: Arc<AtomicUsize>,
    overtook: Arc<AtomicUsize>,
    replayed: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.take().unwrap().join().unwrap();
    }
}

fn relay(upstream: SocketAddr, lose: bool) -> Relay {
    let front = UdpSocket::bind("127.0.0.1:0").unwrap();
    let back = UdpSocket::bind("127.0.0.1:0").unwrap();
    back.connect(upstream).unwrap();
    front.set_nonblocking(true).unwrap();
    back.set_nonblocking(true).unwrap();
    let addr = front.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let done = stop.clone();
    let affected = Arc::new(AtomicUsize::new(0));
    let first = affected.clone();
    let overtook = Arc::new(AtomicUsize::new(0));
    let later = overtook.clone();
    let replayed = Arc::new(AtomicUsize::new(0));
    let copies = replayed.clone();
    let thread = std::thread::spawn(move || {
        let mut client = None;
        let mut held = None;
        let mut release = Instant::now();
        let mut buf = vec![0; 65535];
        while !done.load(Ordering::Relaxed) {
            while let Ok((n, from)) = front.recv_from(&mut buf) {
                client = Some(from);
                back.send(&buf[..n]).unwrap();
            }
            while let Ok(n) = back.recv(&mut buf) {
                let to = client.expect("response follows a client packet");
                // Header form is unprotected. A large 1-RTT datagram carries
                // response data; leave the long-header handshake untouched.
                if n > 1000 && buf[0] & 0x80 == 0 && first.load(Ordering::Relaxed) == 0 {
                    first.fetch_add(1, Ordering::SeqCst);
                    if !lose {
                        held = Some(buf[..n].to_vec());
                        release = Instant::now() + Duration::from_millis(20);
                    }
                    continue;
                }
                front.send_to(&buf[..n], to).unwrap();
                if held.is_some() && n > 1000 {
                    later.fetch_add(1, Ordering::SeqCst);
                }
            }
            if held.is_some() && (later.load(Ordering::Relaxed) >= 4 || Instant::now() >= release) {
                let data = held.take().unwrap();
                for _ in 0..2 {
                    front.send_to(&data, client.unwrap()).unwrap();
                    copies.fetch_add(1, Ordering::SeqCst);
                }
            }
            std::thread::sleep(Duration::from_micros(100));
        }
    });
    Relay {
        addr,
        affected,
        overtook,
        replayed,
        stop,
        thread: Some(thread),
    }
}

fn assert_impairment(relay: &Relay, lose: bool) {
    assert_eq!(relay.affected.load(Ordering::SeqCst), 1);
    assert_eq!(
        relay.replayed.load(Ordering::SeqCst),
        if lose { 0 } else { 2 }
    );
    if !lose {
        assert!(
            relay.overtook.load(Ordering::SeqCst) > 0,
            "must actually reorder"
        );
    }
}

fn check_body(addr: SocketAddr) {
    use crate::clock::Instant as Clock;
    use crate::http3::{proto, qpack};
    use crate::quic::conn::{Connection, Event, LocalParamsInput};

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(addr).unwrap();
    socket.set_nonblocking(true).unwrap();
    let mut conn = Connection::connect(
        crate::tls::client_config(b"h3").unwrap(),
        "localhost",
        LocalParamsInput {
            initial_max_data: 65536,
            initial_max_stream_data: 32768,
            initial_max_streams_uni: 3,
            max_idle_timeout_ms: 5000,
            handshake_timeout_ms: 5000,
        },
    )
    .unwrap();
    let mut request = None;
    let mut received = Vec::new();
    let mut out = Vec::with_capacity(2048);
    let mut buf = vec![0; 65535];
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(Instant::now() < deadline, "large response timed out");
        while let Some(event) = conn.poll_event() {
            match event {
                Event::Connected => {
                    for kind in [
                        proto::STREAM_CONTROL,
                        proto::STREAM_QPACK_ENCODER,
                        proto::STREAM_QPACK_DECODER,
                    ] {
                        let id = conn.open_uni().unwrap();
                        let prelude = if kind == proto::STREAM_CONTROL {
                            proto::control_stream_prelude()
                        } else {
                            vec![kind as u8]
                        };
                        assert_eq!(conn.write(id, &prelude), prelude.len());
                    }
                    let headers = qpack::encode_request("GET", "https", "localhost", "/", &[], 0);
                    let bytes = proto::request_bytes(&headers, &[]);
                    let id = conn.open_bi().unwrap();
                    assert_eq!(conn.write(id, &bytes), bytes.len());
                    conn.finish(id);
                    request = Some(id);
                }
                Event::Readable(id) => {
                    conn.consume(id, |data| {
                        if Some(id) == request {
                            received.extend_from_slice(data);
                        }
                        Ok(())
                    })
                    .unwrap();
                }
                Event::Finished { id, reset } if Some(id) == request => {
                    assert_eq!(reset, None);
                    let mut reader = proto::ResponseReader::default();
                    reader.feed(&received).unwrap();
                    assert_eq!(reader.status(), 200);
                    let mut response_body = Vec::new();
                    let mut pos = 0;
                    while pos < received.len() {
                        let (kind, used) = proto::get_varint(&received[pos..]).unwrap();
                        pos += used;
                        let (len, used) = proto::get_varint(&received[pos..]).unwrap();
                        pos += used;
                        let len = len as usize;
                        let data = &received[pos..pos + len];
                        if kind == 0 {
                            response_body.extend_from_slice(data);
                        }
                        pos += len;
                    }
                    assert_eq!(
                        response_body,
                        body(),
                        "no missing, duplicate, or reordered bytes"
                    );
                    return;
                }
                Event::Lost(why) => panic!("connection lost: {why}"),
                _ => {}
            }
        }
        if conn.poll_timeout().is_some_and(|at| at <= Clock::now()) {
            conn.handle_timeout(Clock::now());
        }
        loop {
            out.clear();
            let n = conn.poll_transmit(Clock::now(), &mut out, None).unwrap();
            if n == 0 {
                break;
            }
            assert_eq!(socket.send(&out).unwrap(), n);
        }
        while let Ok(n) = socket.recv(&mut buf) {
            conn.handle_datagram(Clock::now(), &mut buf[..n]).unwrap();
        }
        std::thread::sleep(Duration::from_micros(100));
    }
}

fn exercise(lose: bool) {
    let server = server();
    {
        let relay = relay(server.addr, lose);
        check_body(relay.addr);
        assert_impairment(&relay, lose);
    }
    let relay = relay(server.addr, lose);
    let target =
        crate::target::parse_target(&format!("https://{}/", relay.addr), "GET", &[], None, false)
            .unwrap();
    let timeout = Duration::from_secs(5);
    let stats = crate::http3::run_worker(
        &target,
        1,
        crate::budget::Budget::Requests(8),
        timeout,
        Some(timeout),
        4,
    )
    .unwrap();
    assert_impairment(&relay, lose);
    assert_eq!(
        (stats.completed, stats.errors, stats.connect_errors),
        (8, 0, 0)
    );
    assert_eq!(stats.latencies_ns.len(), 8);
    assert_eq!(stats.status_counts[200], 8);
    assert_eq!(stats.status_counts.iter().sum::<u64>(), 8);
    assert_eq!(server.completed.load(Ordering::SeqCst), 9);
}

#[test]
fn large_responses_reassemble_after_a_lost_datagram() {
    exercise(true);
}

#[test]
fn large_responses_reassemble_with_reordering_and_a_late_duplicate() {
    exercise(false);
}
