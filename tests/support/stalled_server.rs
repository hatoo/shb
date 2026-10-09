//! Independent peers which keep their first response open across many later
//! completions. Shared by worker tests so they can inspect every latency sample.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

pub const BODY_LEN: usize = 1024;

pub struct Server {
    pub addr: SocketAddr,
    pub completed: Arc<AtomicUsize>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.stop.take().unwrap().send(());
        self.thread.take().unwrap().join().unwrap();
    }
}

struct Gate {
    accepted: AtomicUsize,
    completed: Arc<AtomicUsize>,
    ready: tokio::sync::Notify,
    release_at: Option<usize>,
}

impl Gate {
    async fn wait(&self, ticket: usize) {
        if ticket == 0 {
            loop {
                let notified = self.ready.notified();
                if self
                    .release_at
                    .is_some_and(|n| self.completed.load(Ordering::SeqCst) >= n)
                {
                    break;
                }
                notified.await;
            }
        }
    }

    fn finished(&self) {
        self.completed.fetch_add(1, Ordering::SeqCst);
        self.ready.notify_one();
    }
}

pub fn start(h3: bool, release_at: Option<usize>) -> Server {
    let (tx, rx) = std::sync::mpsc::channel();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let completed = Arc::new(AtomicUsize::new(0));
    let gate = Arc::new(Gate {
        accepted: AtomicUsize::new(0),
        completed: completed.clone(),
        ready: tokio::sync::Notify::new(),
        release_at,
    });
    let thread = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            if h3 {
                let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
                let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
                let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                    .with_safe_default_protocol_versions().unwrap()
                    .with_no_client_auth()
                    .with_single_cert(vec![certified.cert.der().clone()], key.into()).unwrap();
                tls.alpn_protocols = vec![b"h3".to_vec()];
                let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls)).unwrap();
                let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
                let mut transport = quinn::TransportConfig::default();
                transport.receive_window(quinn::VarInt::from_u32(64 * 1024));
                transport.stream_receive_window(quinn::VarInt::from_u32(16 * 1024));
                config.transport_config(Arc::new(transport));
                let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
                tx.send(endpoint.local_addr().unwrap()).unwrap();
                let serve = async {
                    while let Some(incoming) = endpoint.accept().await {
                        let gate = gate.clone();
                        tokio::spawn(async move {
                            let Ok(conn) = incoming.await else { return };
                            let Ok(mut conn) = h3::server::Connection::<_, bytes::Bytes>::new(h3_quinn::Connection::new(conn)).await else { return };
                            while let Ok(Some(resolver)) = conn.accept().await {
                                let ticket = gate.accepted.fetch_add(1, Ordering::SeqCst);
                                let gate = gate.clone();
                                tokio::spawn(async move {
                                    let Ok((request, mut stream)) = resolver.resolve_request().await else { return };
                                    let mut received = 0;
                                    while let Ok(Some(mut chunk)) = stream.recv_data().await {
                                        use bytes::Buf;
                                        while chunk.has_remaining() {
                                            let data = chunk.chunk();
                                            assert!(data.iter().all(|b| *b == b'x'));
                                            let n = data.len();
                                            received += n;
                                            chunk.advance(n);
                                        }
                                    }
                                    assert_eq!(request.method(), http::Method::POST);
                                    assert_eq!(received, BODY_LEN);
                                    gate.wait(ticket).await;
                                    let status = if ticket == 0 { 202 } else { 200 };
                                    if stream.send_response(http::Response::builder().status(status).body(()).unwrap()).await.is_ok()
                                        && stream.finish().await.is_ok() {
                                        gate.finished();
                                    }
                                });
                            }
                        });
                    }
                };
                tokio::select! { _ = serve => {}, _ = stopped => {} }
            } else {
                use axum::{Router, body::Bytes, http::StatusCode, routing::post};
                let app = Router::new().route("/", post(move |body: Bytes| {
                    let gate = gate.clone();
                    async move {
                        let ticket = gate.accepted.fetch_add(1, Ordering::SeqCst);
                        assert_eq!(body.len(), BODY_LEN);
                        assert!(body.iter().all(|b| *b == b'x'));
                        gate.wait(ticket).await;
                        gate.finished();
                        if ticket == 0 { StatusCode::ACCEPTED } else { StatusCode::OK }
                    }
                }));
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                tx.send(listener.local_addr().unwrap()).unwrap();
                tokio::select! { _ = axum::serve(listener, app).into_future() => {}, _ = stopped => {} }
            }
        });
    });
    Server {
        addr: rx.recv().unwrap(),
        completed,
        stop: Some(stop),
        thread: Some(thread),
    }
}

fn exercise(h3: bool, release: bool) {
    use crate::{budget::Budget, target::parse_target};
    use std::time::Duration;
    let server = start(h3, release.then_some(512));
    let scheme = if h3 { "https" } else { "http" };
    let target = parse_target(
        &format!("{scheme}://{}/", server.addr),
        "POST",
        &[],
        Some(&vec![b'x'; BODY_LEN]),
        false,
    )
    .unwrap();
    let run = |n| {
        let timeout = Duration::from_secs(10);
        if h3 {
            crate::http3::run_worker(&target, 1, Budget::Requests(n), timeout, Some(timeout), 32)
        } else {
            crate::http2::run_worker(
                &target,
                None,
                1,
                Budget::Requests(n),
                timeout,
                Some(timeout),
                32,
            )
        }
        .unwrap()
    };
    let total = if release { 1_025 } else { 513 };
    let stats = run(total);
    let failures = u64::from(!release);
    assert_eq!(stats.completed, total - failures);
    assert_eq!(stats.errors, failures);
    assert_eq!(stats.connect_errors, 0);
    assert_eq!(stats.latencies_ns.len() as u64, stats.completed);
    assert_eq!(stats.status_counts[200], total - 1);
    assert_eq!(stats.status_counts[202], u64::from(release));
    assert_eq!(stats.status_counts.iter().sum::<u64>(), stats.completed);
    assert_eq!(
        server.completed.load(Ordering::SeqCst) as u64,
        stats.completed
    );
    // A new connection starts its ids over after the prior sparse ring drains
    // or is discarded by the timeout. The peer now answers every request.
    let next = run(33);
    assert_eq!(
        (next.completed, next.errors, next.connect_errors),
        (33, 0, 0)
    );
    assert_eq!(next.latencies_ns.len(), 33);
    assert_eq!(next.status_counts[200], 33);
}

#[test]
fn h2_keeps_every_sample_across_a_stalled_response() {
    exercise(false, true);
}

#[test]
fn h3_keeps_every_sample_across_a_stalled_response() {
    exercise(true, true);
}

#[test]
fn h2_times_out_only_the_remaining_sparse_request() {
    exercise(false, false);
}

#[test]
fn h3_times_out_only_the_remaining_sparse_request() {
    exercise(true, false);
}
