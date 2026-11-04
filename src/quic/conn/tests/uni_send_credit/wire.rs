//! Quinn supplies the TLS handshake, actual stream grants and byte/FIN receiver.
//! Small windows force repeated MAX_STREAM_DATA and MAX_DATA on the wire.
use super::*;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicUsize, Ordering};

const STREAMS: usize = 3;
const WINDOW: u32 = 64;
const BODY: usize = 4096;

fn body(id: u64) -> Vec<u8> {
    (0..BODY)
        .map(|i| (id as usize ^ i ^ (i >> 8)) as u8)
        .collect()
}

fn run(disrupt: bool) {
    let (address_tx, address_rx) = std::sync::mpsc::channel();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let completed = Arc::new(AtomicUsize::new(0));
    let done = completed.clone();
    let server = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                tokio::time::timeout(Duration::from_secs(20), async move {
                    let certified =
                        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
                    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(
                        certified.signing_key.serialize_der(),
                    );
                    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
                        rustls::crypto::ring::default_provider(),
                    ))
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_no_client_auth()
                    .with_single_cert(vec![certified.cert.der().clone()], key.into())
                    .unwrap();
                    tls.alpn_protocols = vec![b"uni-credit-test".to_vec()];
                    let crypto =
                        quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls)).unwrap();
                    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
                    let mut transport = quinn::TransportConfig::default();
                    transport
                        .max_concurrent_bidi_streams(0u32.into())
                        .max_concurrent_uni_streams((STREAMS as u32).into())
                        .stream_receive_window(WINDOW.into())
                        .receive_window((WINDOW * STREAMS as u32).into());
                    config.transport_config(Arc::new(transport));
                    let endpoint =
                        quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
                    address_tx.send(endpoint.local_addr().unwrap()).unwrap();
                    let connection = endpoint.accept().await.unwrap().await.unwrap();
                    let mut tasks = tokio::task::JoinSet::new();
                    for n in 0..STREAMS {
                        let mut recv = connection.accept_uni().await.unwrap();
                        let id = u64::from(recv.id());
                        assert_eq!(id, 2 + n as u64 * 4);
                        let done = done.clone();
                        tasks.spawn(async move {
                            assert_eq!(recv.read_to_end(BODY).await.unwrap(), body(id));
                            done.fetch_add(1, Ordering::SeqCst);
                        });
                    }
                    while let Some(result) = tasks.join_next().await {
                        result.unwrap();
                    }
                    // Keep the peer alive until all FINs have been ACKed.
                    shutdown_rx.await.unwrap();
                    endpoint.close(0u32.into(), b"complete");
                })
                .await
                .expect("uni credit peer timed out");
            });
    });
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(address_rx.recv().unwrap()).unwrap();
    socket.set_nonblocking(true).unwrap();
    let mut conn = Connection::connect(
        crate::tls::client_config(b"uni-credit-test").unwrap(),
        "localhost",
        LocalParamsInput {
            initial_max_data: 1 << 20,
            initial_max_stream_data: 1 << 16,
            initial_max_streams_uni: 0,
            max_idle_timeout_ms: 10_000,
            handshake_timeout_ms: 5_000,
        },
    )
    .unwrap();
    let mut streams = Vec::new();
    let mut accepted = [0; STREAMS];
    let mut blocked = [false; STREAMS];
    let mut held = None;
    let mut held_spans = Vec::new();
    let mut replayed = false;
    let mut buf = [0u8; 65536];
    let mut out = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        assert!(
            std::time::Instant::now() < deadline,
            "uni credit stalled: accepted={accepted:?}, received={}, {}",
            completed.load(Ordering::SeqCst),
            conn.debug_state()
        );
        loop {
            match socket.recv(&mut buf) {
                Ok(n) => conn.handle_datagram(Instant::now(), &mut buf[..n]).unwrap(),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("receive: {e}"),
            }
        }
        while let Some(event) = conn.poll_event() {
            assert!(
                matches!(event, Event::Connected),
                "unexpected event: {event:?}, accepted={accepted:?}, received={}",
                completed.load(Ordering::SeqCst)
            );
        }
        if conn.connected && streams.is_empty() {
            assert_eq!(conn.params.initial_max_stream_data_uni, u64::from(WINDOW));
            for _ in 0..STREAMS {
                let id = conn.open_uni().unwrap();
                streams.push((id, body(id)));
            }
        }
        for (i, (id, body)) in streams.iter().enumerate() {
            if accepted[i] < BODY {
                let n = conn.write(*id, &body[accepted[i]..]);
                blocked[i] |= n < BODY - accepted[i];
                accepted[i] += n;
                if accepted[i] == BODY {
                    conn.finish(*id);
                }
            }
        }
        if completed.load(Ordering::SeqCst) == STREAMS
            && streams
                .iter()
                .all(|(id, _)| conn.send_mut(*id).unwrap().is_settled())
        {
            break;
        }
        let now = Instant::now();
        if conn.poll_timeout().is_some_and(|at| at <= now) {
            conn.handle_timeout(now);
        }
        loop {
            out.clear();
            if conn.poll_transmit(now, &mut out, None).unwrap() == 0 {
                break;
            }
            // Decode only to select a real application-data packet to delay.
            // Quinn independently decrypts and checks every delivered byte.
            let mut spans = Vec::new();
            if disrupt && out[0] & 0x80 == 0 {
                let mut packet = out.clone();
                let pn_offset = 1 + conn.peer_cid.len();
                let keys = conn.one_rtt_local.as_ref().unwrap();
                let (_, pn_len) = crate::quic::packet::unprotect_header(
                    keys.header.as_ref(),
                    &mut packet,
                    pn_offset,
                )
                .unwrap();
                let pn = conn.spaces[Space::Data as usize].next_packet_number - 1;
                let (head, payload) = packet.split_at_mut(pn_offset + pn_len);
                let plain = keys.packet.decrypt_in_place(pn, head, payload).unwrap();
                for frame in frame::Iter::new(plain) {
                    if let Frame::Stream {
                        id, offset, data, ..
                    } = frame.unwrap()
                        && !data.is_empty()
                    {
                        spans.push((id, offset, offset + data.len() as u64));
                    }
                }
            }
            if !spans.is_empty() && held.is_none() && !replayed {
                held = Some(out.clone());
                held_spans = spans;
                continue;
            }
            assert_eq!(socket.send(&out).unwrap(), out.len());
            let retried = spans.iter().any(|&(id, lo, hi)| {
                held_spans.iter().any(|&(lost_id, lost_lo, lost_hi)| {
                    id == lost_id && lo < lost_hi && lost_lo < hi
                })
            });
            if retried && let Some(original) = held.take() {
                assert_eq!(socket.send(&original).unwrap(), original.len());
                assert_eq!(socket.send(&original).unwrap(), original.len());
                replayed = true;
            }
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    assert_eq!(accepted, [BODY; STREAMS]);
    assert_eq!(blocked, [true; STREAMS]);
    assert_eq!(conn.data_sent, (BODY * STREAMS) as u64);
    assert_eq!(replayed, disrupt);
    shutdown_tx.send(()).unwrap();
    server.join().unwrap();
    eprintln!(
        "uni-credit-wire: disrupted={disrupt} bytes={} streams={STREAMS}",
        BODY * STREAMS
    );
}

#[test]
fn uni_send_credit_quinn_receives_exact_bytes_across_many_windows() {
    run(false);
}

#[test]
fn uni_send_credit_quinn_recovers_loss_reordering_and_duplicate_data() {
    run(true);
}
