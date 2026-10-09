//! A real Quinn/h3 peer behind a relay that loses the first request packet.
//! Its small connection window fills behind the missing stream prefix, so
//! recovery must retransmit bytes without waiting for fresh MAX_DATA credit.

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const BODY_LEN: usize = 8_007;

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
            let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
            let mut transport = quinn::TransportConfig::default();
            transport.receive_window(quinn::VarInt::from_u32(4096));
            transport.stream_receive_window(quinn::VarInt::from_u32(16 * 1024));
            config.transport_config(Arc::new(transport));
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
                                let mut received = Vec::new();
                                loop {
                                    match stream.recv_data().await {
                                        Ok(Some(mut chunk)) => {
                                            use bytes::Buf;
                                            while chunk.has_remaining() {
                                                let data = chunk.chunk();
                                                received.extend_from_slice(data);
                                                let len = data.len();
                                                chunk.advance(len);
                                            }
                                        }
                                        Ok(None) => break,
                                        Err(_) => return,
                                    }
                                }
                                let valid = request.method() == http::Method::POST
                                    && received == vec![b'x'; BODY_LEN];
                                let status = if valid { 200 } else { 400 };
                                if stream
                                    .send_response(
                                        http::Response::builder().status(status).body(()).unwrap(),
                                    )
                                    .await
                                    .is_ok()
                                    && stream.finish().await.is_ok()
                                    && valid
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
    dropped: Arc<AtomicUsize>,
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

fn relay(upstream: SocketAddr, late_duplicate: bool) -> Relay {
    let front = UdpSocket::bind("127.0.0.1:0").unwrap();
    let back = UdpSocket::bind("127.0.0.1:0").unwrap();
    back.connect(upstream).unwrap();
    front.set_nonblocking(true).unwrap();
    back.set_nonblocking(true).unwrap();
    let addr = front.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let done = stop.clone();
    let dropped = Arc::new(AtomicUsize::new(0));
    let losses = dropped.clone();
    let replayed = Arc::new(AtomicUsize::new(0));
    let duplicates = replayed.clone();
    let thread = std::thread::spawn(move || {
        let mut client = None;
        let mut buf = vec![0; 65535];
        let mut delayed = None;
        let mut release = None;
        let mut retry_after = None;
        let mut replies = Vec::new();
        while !done.load(Ordering::Relaxed) {
            while let Ok((n, from)) = front.recv_from(&mut buf) {
                client = Some(from);
                // The header form bit is not protected. Ignore ACK-only
                // packets: the first sizable short packet contains STREAMs.
                if n > 200 && buf[0] & 0x80 == 0 && losses.load(Ordering::Relaxed) == 0 {
                    losses.fetch_add(1, Ordering::SeqCst);
                    release = Some(Instant::now() + Duration::from_millis(50));
                    retry_after = release;
                    if late_duplicate {
                        delayed = Some(buf[..n].to_vec());
                    }
                    continue;
                }
                back.send(&buf[..n]).unwrap();
                // Deliver two copies of the original only after another
                // sizable packet arrives beyond the initial window's burst.
                // A client stuck emitting empty STREAMs cannot open this gate.
                if n > 200
                    && buf[0] & 0x80 == 0
                    && retry_after.is_some_and(|at| Instant::now() >= at)
                    && let Some(data) = delayed.take()
                {
                    back.send(&data).unwrap();
                    back.send(&data).unwrap();
                    duplicates.fetch_add(2, Ordering::SeqCst);
                }
            }
            while let Ok(n) = back.recv(&mut buf) {
                if release.is_some_and(|at| Instant::now() < at) {
                    replies.push(buf[..n].to_vec());
                } else if let Some(client) = client {
                    front.send_to(&buf[..n], client).unwrap();
                }
            }
            if release.is_some_and(|at| Instant::now() >= at) {
                if let Some(client) = client {
                    for reply in replies.drain(..) {
                        front.send_to(&reply, client).unwrap();
                    }
                }
                release = None;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    });
    Relay {
        addr,
        dropped,
        replayed,
        stop,
        thread: Some(thread),
    }
}

fn exercise(late_duplicate: bool) {
    let server = server();
    let relay = relay(server.addr, late_duplicate);
    let target = crate::target::parse_target(
        &format!("https://{}/", relay.addr),
        "POST",
        &[],
        Some(&vec![b'x'; BODY_LEN]),
        false,
    )
    .unwrap();
    let timeout = Duration::from_secs(5);
    let stats = crate::http3::run_worker(
        &target,
        1,
        crate::budget::Budget::Requests(8),
        timeout,
        Some(timeout),
        1,
    )
    .unwrap();
    assert_eq!(relay.dropped.load(Ordering::SeqCst), 1);
    assert_eq!(
        relay.replayed.load(Ordering::SeqCst),
        if late_duplicate { 2 } else { 0 }
    );
    assert_eq!(
        (stats.completed, stats.errors, stats.connect_errors),
        (8, 0, 0)
    );
    assert_eq!(stats.latencies_ns.len(), 8);
    assert_eq!(stats.status_counts[200], 8);
    assert_eq!(stats.status_counts.iter().sum::<u64>(), 8);
    assert_eq!(server.completed.load(Ordering::SeqCst), 8);
}

#[test]
fn h3_recovers_a_lost_prefix_with_a_small_connection_window() {
    exercise(false);
}

#[test]
fn h3_recovers_before_a_late_duplicate_of_the_lost_prefix() {
    exercise(true);
}
