//! Independent Quinn/h3 responses that leave holes behind the oldest request.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

#[derive(Clone, Copy)]
pub enum Mode {
    /// Return the first response only after all the younger ones were sent.
    Hold(usize),
    /// Leave 128 requests open on the first connection, then accept a retry.
    Timeout,
    /// Retire the head by reset and the unprocessed suffix by GOAWAY.
    ResetGoaway,
}

pub struct Server {
    pub addr: SocketAddr,
    pub responses: Arc<AtomicUsize>,
    pub cancellations: Arc<AtomicUsize>,
    pub connections: Arc<AtomicUsize>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.stop.take().unwrap().send(());
        self.thread.take().unwrap().join().unwrap();
    }
}

pub fn server(mode: Mode) -> Server {
    let (address, received) = std::sync::mpsc::channel();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let responses = Arc::new(AtomicUsize::new(0));
    let cancellations = Arc::new(AtomicUsize::new(0));
    let connections = Arc::new(AtomicUsize::new(0));
    let (replies, cancels, conns) = (
        responses.clone(),
        cancellations.clone(),
        connections.clone(),
    );
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
            transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(256));
            transport.receive_window(quinn::VarInt::from_u32(64 * 1024));
            transport.stream_receive_window(quinn::VarInt::from_u32(16 * 1024));
            config.transport_config(Arc::new(transport));
            let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
            address.send(endpoint.local_addr().unwrap()).unwrap();
            let serve = async {
                while let Some(incoming) = endpoint.accept().await {
                    let (replies, cancels, conns) =
                        (replies.clone(), cancels.clone(), conns.clone());
                    tokio::spawn(async move {
                        let conn = incoming.await.unwrap();
                        let generation = conns.fetch_add(1, Ordering::SeqCst);
                        let closed = conn.clone();
                        let closure = tokio::spawn(async move {
                            let reason = closed.closed().await;
                            if let quinn::ConnectionError::ApplicationClosed(reason) = reason
                                && reason.error_code.into_inner() == 0x10c
                            {
                                cancels.fetch_add(1, Ordering::SeqCst);
                            }
                        });
                        let mut h3 = h3::server::Connection::<_, bytes::Bytes>::new(
                            h3_quinn::Connection::new(conn.clone()),
                        )
                        .await
                        .unwrap();
                        let ready = Arc::new(tokio::sync::Notify::new());
                        let connection_replies = Arc::new(AtomicUsize::new(0));
                        let mut accepted = 0;
                        while let Ok(Some(resolver)) = h3.accept().await {
                            accepted += 1;
                            let (replies, ready, connection_replies, conn) = (
                                replies.clone(),
                                ready.clone(),
                                connection_replies.clone(),
                                conn.clone(),
                            );
                            tokio::spawn(async move {
                                let (request, mut stream) =
                                    resolver.resolve_request().await.unwrap();
                                assert_eq!(request.method(), http::Method::GET);
                                let id = stream.id().into_inner() / 4;
                                while let Some(data) = stream.recv_data().await.unwrap() {
                                    use bytes::Buf;
                                    assert_eq!(data.remaining(), 0);
                                }
                                match mode {
                                    Mode::Hold(count) if id == 0 => {
                                        while connection_replies.load(Ordering::SeqCst) < count - 1
                                        {
                                            ready.notified().await;
                                        }
                                        // Makes the retained latency visible even on a fast host.
                                        tokio::time::sleep(Duration::from_millis(100)).await;
                                    }
                                    Mode::Timeout if generation == 0 && (id == 0 || id > 256) => {
                                        // Keep the stream alive until the client cancels the connection.
                                        conn.closed().await;
                                        return;
                                    }
                                    Mode::ResetGoaway
                                        if generation == 0 && [0, 1, 31].contains(&id) =>
                                    {
                                        let code = if id == 1 {
                                            h3::error::Code::H3_GENERAL_PROTOCOL_ERROR
                                        } else {
                                            h3::error::Code::H3_REQUEST_REJECTED
                                        };
                                        stream.stop_stream(code);
                                        return;
                                    }
                                    _ => {}
                                }
                                stream
                                    .send_response(
                                        http::Response::builder().status(200).body(()).unwrap(),
                                    )
                                    .await
                                    .unwrap();
                                stream.finish().await.unwrap();
                                replies.fetch_add(1, Ordering::SeqCst);
                                connection_replies.fetch_add(1, Ordering::SeqCst);
                                ready.notify_one();
                            });
                            if matches!(mode, Mode::ResetGoaway)
                                && generation == 0
                                && accepted == 32
                            {
                                h3.shutdown(0).await.unwrap();
                            }
                        }
                        // Dropping h3 actively closes Quinn locally. Observe the
                        // peer's code before that drop can replace the reason.
                        closure.await.unwrap();
                    });
                }
            };
            tokio::select! { _ = serve => {}, _ = stopped => {} }
        });
    });
    Server {
        addr: received.recv().unwrap(),
        responses,
        cancellations,
        connections,
        stop: Some(stop),
        thread: Some(thread),
    }
}

#[cfg(test)]
fn run(server: &Server, budget: crate::budget::Budget, timeout: Duration) -> crate::stats::Stats {
    let target = crate::target::parse_target(
        &format!("https://{}/", server.addr),
        "GET",
        &[],
        None,
        false,
    )
    .unwrap();
    let stats = crate::http3::run_worker(
        &target,
        1,
        budget,
        Duration::from_secs(5),
        Some(timeout),
        128,
    )
    .unwrap();
    assert_eq!(stats.connect_errors, 0);
    assert_eq!(stats.latencies_ns.len() as u64, stats.completed);
    assert_eq!(stats.status_counts[200], stats.completed);
    assert_eq!(stats.status_counts.iter().sum::<u64>(), stats.completed);
    stats
}

#[test]
fn held_first_h3_response_keeps_its_latency_after_thousands_of_holes() {
    let server = server(Mode::Hold(8192));
    let stats = run(
        &server,
        crate::budget::Budget::Requests(8192),
        Duration::from_secs(10),
    );
    assert_eq!((stats.completed, stats.errors), (8192, 0));
    assert_eq!(server.responses.load(Ordering::SeqCst), 8192);
    assert!(*stats.latencies_ns.iter().max().unwrap() >= 100_000_000);
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
}

#[test]
fn sparse_h3_timeout_cancels_the_peer_and_reconnects_with_exact_accounting() {
    let server = server(Mode::Timeout);
    let stats = run(
        &server,
        crate::budget::Budget::Requests(512),
        Duration::from_secs(1),
    );
    assert_eq!((stats.completed, stats.errors), (384, 128));
    assert_eq!(server.responses.load(Ordering::SeqCst), 384);
    assert_eq!(server.connections.load(Ordering::SeqCst), 2);
    for _ in 0..100 {
        if server.cancellations.load(Ordering::SeqCst) == 1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(server.cancellations.load(Ordering::SeqCst), 1);
}

#[test]
fn h3_head_reset_and_goaway_preserve_retries_and_samples() {
    let server = server(Mode::ResetGoaway);
    let stats = run(
        &server,
        crate::budget::Budget::Requests(512),
        Duration::from_secs(5),
    );
    assert_eq!((stats.completed, stats.errors), (511, 1));
    assert_eq!(server.responses.load(Ordering::SeqCst), 511);
    assert_eq!(server.connections.load(Ordering::SeqCst), 2);
}

#[test]
fn duration_stopping_keeps_samples_with_a_live_oldest_h3_request() {
    let server = server(Mode::Timeout);
    let stats = run(
        &server,
        crate::budget::Budget::Duration(Duration::from_millis(500)),
        Duration::from_secs(10),
    );
    assert_eq!((stats.completed, stats.errors), (256, 0));
    assert_eq!(server.responses.load(Ordering::SeqCst), 256);
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
}
