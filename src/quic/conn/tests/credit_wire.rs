//! An independent Quinn server consumes the actual encrypted credit grants.
//! Small transport windows deliberately exercise the transport API; the CLI's
//! roughly 1 GiB receive window is not changed by this fixture.
use super::*;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicUsize, Ordering};

const BODY: usize = 32 * 1024;
const STREAMS: usize = 4;

fn byte(stream: u64, offset: usize) -> u8 {
    (stream as usize ^ offset ^ (offset >> 8)) as u8
}

fn run(disrupt: bool) {
    let (address_tx, address_rx) = std::sync::mpsc::channel();
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
                    tls.alpn_protocols = vec![b"credit-test".to_vec()];
                    let crypto =
                        quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls)).unwrap();
                    let endpoint = quinn::Endpoint::server(
                        quinn::ServerConfig::with_crypto(Arc::new(crypto)),
                        "127.0.0.1:0".parse().unwrap(),
                    )
                    .unwrap();
                    address_tx.send(endpoint.local_addr().unwrap()).unwrap();
                    let connection = endpoint.accept().await.unwrap().await.unwrap();
                    let mut tasks = tokio::task::JoinSet::new();
                    let mut send = connection.open_uni().await.unwrap();
                    let uni_done = done.clone();
                    tasks.spawn(async move {
                        let id = u64::from(send.id());
                        let body: Vec<_> = (0..BODY).map(|n| byte(id, n)).collect();
                        send.write_all(&body).await.unwrap();
                        send.finish().unwrap();
                        assert_eq!(send.stopped().await.unwrap(), None);
                        uni_done.fetch_add(1, Ordering::SeqCst);
                    });
                    for _ in 0..STREAMS {
                        let (mut send, mut recv) = connection.accept_bi().await.unwrap();
                        let done = done.clone();
                        tasks.spawn(async move {
                            let id = u64::from(send.id());
                            assert_eq!(recv.read_to_end(8).await.unwrap(), vec![id as u8]);
                            let body: Vec<_> = (0..BODY).map(|n| byte(id, n)).collect();
                            send.write_all(&body).await.unwrap();
                            send.finish().unwrap();
                            assert_eq!(send.stopped().await.unwrap(), None);
                            done.fetch_add(1, Ordering::SeqCst);
                        });
                    }
                    while let Some(result) = tasks.join_next().await {
                        result.unwrap();
                    }
                    // All responses including FIN have been acknowledged by shb.
                    endpoint.close(0u32.into(), b"complete");
                })
                .await
                .expect("independent credit peer timed out");
            });
    });
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(address_rx.recv().unwrap()).unwrap();
    socket.set_nonblocking(true).unwrap();
    let mut conn = Connection::connect(
        crate::tls::client_config(b"credit-test").unwrap(),
        "localhost",
        LocalParamsInput {
            initial_max_data: 1 << 20,
            initial_max_stream_data: 1024,
            initial_max_streams_uni: 1,
            max_idle_timeout_ms: 10_000,
            handshake_timeout_ms: 5_000,
        },
    )
    .unwrap();
    let mut opened = false;
    let mut received = std::collections::BTreeMap::<u64, usize>::new();
    let mut finished = std::collections::BTreeSet::new();
    let mut limits = std::collections::BTreeMap::<u64, u64>::new();
    let mut held = None;
    let mut held_after = None;
    let mut dropped_limit = None;
    let mut recovered = false;
    let mut credit_packets = 0;
    let mut credits = 0;
    let mut duplicate_sent = false;
    let mut queue_peak = 0;
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let mut buf = [0u8; 65536];
    let mut out = Vec::new();
    while completed.load(Ordering::SeqCst) < STREAMS + 1 {
        assert!(
            std::time::Instant::now() < deadline,
            "credit client stalled: {} {received:?}",
            conn.debug_state()
        );
        while let Ok(n) = socket.recv(&mut buf) {
            conn.handle_datagram(Instant::now(), &mut buf[..n]).unwrap();
        }
        if !opened && conn.connected {
            for n in 0..STREAMS {
                let id = n as u64 * 4;
                assert_eq!(conn.send_oneshot(&[id as u8]), Some((id, 1)));
            }
            opened = true;
        }
        while let Some(event) = conn.poll_event() {
            match event {
                Event::Readable(id) => {
                    let offset = received.entry(id).or_default();
                    conn.consume(id, |data| {
                        for (n, value) in data.iter().enumerate() {
                            assert_eq!(*value, byte(id, *offset + n));
                        }
                        *offset += data.len();
                        Ok(())
                    })
                    .unwrap();
                }
                Event::Finished { id, reset } => {
                    assert_eq!(reset, None);
                    finished.insert(id);
                }
                Event::Lost(reason) => {
                    assert_eq!(completed.load(Ordering::SeqCst), STREAMS + 1, "{reason}")
                }
                _ => {}
            }
        }
        queue_peak = queue_peak.max(conn.credit_pending.len());
        if conn.poll_timeout().is_some_and(|at| Instant::now() >= at) {
            conn.handle_timeout(Instant::now());
        }
        loop {
            out.clear();
            if conn.poll_transmit(Instant::now(), &mut out, None).unwrap() == 0 {
                break;
            }
            let mut grants = 0;
            let mut target_limit = None;
            if out[0] & 0x80 == 0 {
                // Decode what was actually sealed, independently of SentFrame.
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
                let plaintext = keys.packet.decrypt_in_place(pn, head, payload).unwrap();
                for frame in frame::Iter::new(plaintext) {
                    if let Frame::MaxStreamData { id, limit } = frame.unwrap() {
                        assert!(limit >= *limits.get(&id).unwrap_or(&1024));
                        assert_eq!(limit, received[&id] as u64 + 1024);
                        limits.insert(id, limit);
                        if id == 0 {
                            target_limit = Some(limit);
                        }
                        grants += 1;
                    }
                }
            }
            if grants > 0 {
                credits += grants;
                credit_packets += 1;
                if disrupt && !recovered {
                    if let Some(limit) = target_limit {
                        // A single early loss can be masked by the fresh grant
                        // from consuming the rest of the initial window. Drop
                        // every fresh limit for stream 0 until it is blocked.
                        // Only recovery can repeat its current, unadvanced limit.
                        if dropped_limit != Some(limit) {
                            dropped_limit = Some(limit);
                            continue;
                        }
                        recovered = true;
                    }
                } else if disrupt && held_after.is_none() {
                    // Hold another grant behind newer ones, then replay twice.
                    held = Some(out.clone());
                    held_after = Some(credit_packets);
                    continue;
                }
            }
            socket.send(&out).unwrap();
        }
        if held_after.is_some_and(|after| credit_packets > after)
            && let Some(packet) = held.take()
        {
            socket.send(&packet).unwrap();
            socket.send(&packet).unwrap();
            duplicate_sent = true;
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    server.join().unwrap();
    assert_eq!(received.len(), STREAMS + 1);
    assert!(received.values().all(|n| *n == BODY));
    assert_eq!(finished.len(), STREAMS);
    assert_eq!(limits.len(), STREAMS + 1);
    assert!(credits > 50);
    assert!(queue_peak > 0);
    assert_eq!(duplicate_sent, disrupt);
    assert_eq!(recovered, disrupt);
    eprintln!(
        "credit-wire: disrupted={disrupt} bytes={} streams={} grants={credits} peak={queue_peak}",
        BODY * (STREAMS + 1),
        STREAMS + 1
    );
}

#[test]
fn credit_wire_quinn_consumes_every_byte_beyond_many_receive_windows() {
    run(false);
}

#[test]
fn credit_wire_quinn_recovers_lost_reordered_and_duplicate_grants() {
    run(true);
}
