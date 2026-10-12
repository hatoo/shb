//! Native sparse-packet peer. Each batch must be acknowledged in full before
//! sending another. Frozen request ACKs never acknowledge client ACK-only
//! packets, so ACK-of-ACK cannot hide ACK storage growth within a burst.
#![allow(dead_code)]
mod h3;
mod quic;
use quic::{conn::Connection, packet, wire::ConnectionId};
use std::{
    io::Write,
    net::UdpSocket,
    sync::Arc,
    time::{Duration, Instant},
};

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let packets: usize = args[1].parse().unwrap();
    let requests: usize = args[2].parse().unwrap();
    let batch: usize = args[3].parse().unwrap();
    assert!(batch > 0 && batch <= 32 && packets.is_multiple_of(batch));
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into();
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert.cert.der().clone()], key)
    .unwrap();
    config.alpn_protocols = vec![b"h3".to_vec()];
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    println!("{}", socket.local_addr().unwrap());
    std::io::stdout().flush().unwrap();
    let mut buffer = [0_u8; 65536];
    let (len, client) = socket.recv_from(&mut buffer).unwrap();
    let head = packet::parse(&buffer[..len], 0).unwrap();
    assert_eq!(head.kind, packet::Kind::Initial);
    let mut conn = Connection::accept(
        &Arc::new(config),
        head.dcid,
        head.scid,
        ConnectionId::new(&[3; 8]).unwrap(),
        128,
        1 << 30,
        1 << 24,
    )
    .unwrap();
    conn.recv(&mut buffer[..len]).unwrap();
    let mut output = Vec::new();
    let mut responses = 0;
    let mut acknowledged = 0;
    let mut burst_seconds = Vec::new();
    loop {
        if conn.probe_ready() {
            let ack = conn.probe_ack_snapshot();
            assert!(!ack.is_empty());
            let start = Instant::now();
            for _ in 0..packets / batch {
                let mut expected = Vec::with_capacity(batch);
                for i in 0..batch {
                    let pn = conn.probe_packet(&mut output, &ack, i + 1 == batch);
                    expected.push(pn);
                    assert_eq!(socket.send_to(&output, client).unwrap(), output.len());
                }
                let last = *expected.last().unwrap();
                loop {
                    let (len, from) = socket.recv_from(&mut buffer).unwrap();
                    assert_eq!(from, client);
                    conn.recv(&mut buffer[..len]).unwrap();
                    assert!(!conn.closed);
                    if conn
                        .probe_seen()
                        .iter()
                        .any(|&(lo, hi)| (lo..=hi).contains(&last))
                    {
                        for pn in expected {
                            assert!(
                                conn.probe_seen()
                                    .iter()
                                    .any(|&(lo, hi)| (lo..=hi).contains(&pn)),
                                "lost packet {pn}"
                            );
                            acknowledged += 1;
                        }
                        break;
                    }
                }
            }
            burst_seconds.push(start.elapsed().as_secs_f64());
            responses += 1;
        }
        loop {
            output.clear();
            if !conn.poll_transmit(&mut output).unwrap() {
                break;
            }
            assert_eq!(socket.send_to(&output, client).unwrap(), output.len());
        }
        if responses == requests {
            println!(
                "{{\"responses\":{responses},\"sparse_packets\":{acknowledged},\"packets_per_request\":{packets},\"batch\":{batch},\"burst_seconds\":{burst_seconds:?},\"errors\":0}}"
            );
            // Keep the socket alive until the client confirms its full report.
            std::io::stdout().flush().unwrap();
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).unwrap();
            break;
        }
        let (len, from) = socket.recv_from(&mut buffer).unwrap();
        assert_eq!(from, client);
        conn.recv(&mut buffer[..len]).unwrap();
        assert!(!conn.closed);
    }
}
