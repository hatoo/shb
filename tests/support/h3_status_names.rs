//! A raw Quinn peer sends QPACK representations that ordinary H3 encoders
//! replace with static references. pylsqpack independently checks these bytes
//! in benchmarks/check-h3-status-names.py.

use quinn::{AsyncUdpSocket, Runtime};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

// Count at the socket: Quinn's per-connection receive statistics omit the
// first Initial, which the endpoint consumes before creating the connection.
#[derive(Debug)]
struct Wire {
    socket: Arc<dyn AsyncUdpSocket>,
    sent: AtomicU64,
    received: AtomicU64,
}

impl AsyncUdpSocket for Wire {
    fn create_io_poller(self: Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        self.socket.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> std::io::Result<()> {
        self.socket.try_send(transmit)?;
        self.sent
            .fetch_add(transmit.contents.len() as u64, Ordering::SeqCst);
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut std::task::Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let result = self.socket.poll_recv(cx, bufs, meta);
        if let std::task::Poll::Ready(Ok(n)) = result {
            self.received.fetch_add(
                meta[..n].iter().map(|m| m.len as u64).sum(),
                Ordering::SeqCst,
            );
        }
        result
    }

    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.socket.local_addr()
    }
    fn max_transmit_segments(&self) -> usize {
        self.socket.max_transmit_segments()
    }
    fn max_receive_segments(&self) -> usize {
        self.socket.max_receive_segments()
    }
    fn may_fragment(&self) -> bool {
        self.socket.may_fragment()
    }
}

const WAIT: Duration = Duration::from_secs(10);

fn headers(section: &[u8]) -> Vec<u8> {
    assert!(section.len() < 64);
    let mut out = vec![1, section.len() as u8];
    out.extend_from_slice(section);
    out
}

fn check(invalid: Option<&'static [u8]>) {
    let count = if invalid.is_some() { 1 } else { 16 };
    let (address, received) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
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
            let wire = Arc::new(Wire {
                socket: quinn::TokioRuntime
                    .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
                    .unwrap(),
                sent: AtomicU64::new(0),
                received: AtomicU64::new(0),
            });
            let endpoint = quinn::Endpoint::new_with_abstract_socket(
                Default::default(),
                Some(quinn::ServerConfig::with_crypto(Arc::new(crypto))),
                wire.clone(),
                Arc::new(quinn::TokioRuntime),
            )
            .unwrap();
            address.send(endpoint.local_addr().unwrap()).unwrap();
            tokio::time::timeout(WAIT, async {
                let conn = endpoint.accept().await.unwrap().await.unwrap();
                let mut control = conn.open_uni().await.unwrap();
                control.write_all(b"\0\x04\0").await.unwrap(); // control stream, empty SETTINGS
                // Keep the critical stream open until the client closes.
                let mut tasks = tokio::task::JoinSet::new();
                let mut first_request = None;
                for n in 0..count {
                    let (mut send, mut recv) = conn.accept_bi().await.unwrap();
                    assert_eq!(u64::from(recv.id()), n * 4);
                    let request = recv.read_to_end(4096).await.unwrap();
                    assert_eq!(request[0], 1); // HEADERS, no request body
                    assert_eq!(request.len(), request[1] as usize + 2);
                    assert_eq!(&request[2..6], b"\0\0\xd1\xd7"); // GET, https
                    assert_eq!(*request.last().unwrap(), 0xc1); // :path /
                    if let Some(first) = &first_request {
                        assert_eq!(&request, first);
                    } else {
                        first_request = Some(request);
                    }
                    tasks.spawn(async move {
                        let mut response = headers(b"\0\0\x3d\xb8\x84\x8d\x36\xa3\x82\x08\x19");
                        let mut section = vec![0, 0, if n % 2 == 0 { 0x2d } else { 0x3d }];
                        section.extend_from_slice(b"\xb8\x84\x8d\x36\xa3");
                        section.extend_from_slice(invalid.unwrap_or(if n % 2 == 0 {
                            b"\x03201"
                        } else {
                            b"\x83\x6c\x0c\xff"
                        }));
                        response.extend(headers(&section));
                        response.extend_from_slice(b"\0\x04body");
                        response.extend(headers(b"\0\0\x2c\x42\x46\x9b\x51\x03103"));
                        // Put the split inside the final Huffman name. The
                        // early 103 must not retire the request or its clock.
                        let split = 19;
                        send.write_all(&response[..split]).await.unwrap();
                        tokio::time::sleep(Duration::from_millis(2)).await;
                        send.write_all(&response[split..]).await.unwrap();
                        send.finish().unwrap();
                    });
                }
                while let Some(result) = tasks.join_next().await {
                    result.unwrap();
                }
                conn.closed().await;
                drop(control);
                (
                    wire.sent.load(Ordering::SeqCst),
                    wire.received.load(Ordering::SeqCst),
                )
            })
            .await
            .unwrap()
        })
    });
    let target = crate::target::parse_target(
        &format!("https://{}/", received.recv_timeout(WAIT).unwrap()),
        "GET",
        &[],
        None,
        false,
    )
    .unwrap();
    let result = crate::http3::run_worker(
        &target,
        1,
        crate::budget::Budget::Requests(count),
        WAIT,
        Some(WAIT),
        4,
    );
    let peer = server.join().unwrap();
    let stats = result.unwrap();
    let ok = if invalid.is_some() { 0 } else { count };
    assert_eq!(
        (stats.completed, stats.errors, stats.connect_errors),
        (ok, count - ok, 0)
    );
    assert_eq!(stats.status_counts[201], ok / 2);
    assert_eq!(stats.status_counts[503], ok / 2);
    assert_eq!(stats.status_counts.iter().sum::<u64>(), ok);
    assert_eq!(stats.latencies_ns.len() as u64, ok);
    assert!(stats.latencies_ns.iter().all(|&ns| ns > 0));
    // UDP payload totals include protocol packets; shutdown can leave final
    // ACKs unread, and the client's teardown packet is not benchmark traffic.
    assert!(stats.bytes_received > 0 && stats.bytes_received <= peer.0);
    assert!(stats.bytes_sent > 0 && stats.bytes_sent <= peer.1);
}

#[test]
fn literal_names_preserve_h3_statuses_and_samples() {
    check(None);
}

#[test]
fn malformed_literal_status_has_no_h3_completion_or_sample() {
    for value in [&b"\x0320"[..], b"\x032x0", b"\x83\x6c\x0c\xfe"] {
        check(Some(value));
    }
}
