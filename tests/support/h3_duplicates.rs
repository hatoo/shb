//! Replay real Quinn ciphertext immediately and after later response packets.
//! The worker must retain exactly one status and latency sample per response.

use std::collections::VecDeque;
use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[test]
fn immediate_and_delayed_response_replays_preserve_exact_worker_accounting() {
    let upstream = super::test_server::h3_server_addr();
    let relay = UdpSocket::bind("127.0.0.1:0").unwrap();
    relay
        .set_read_timeout(Some(Duration::from_millis(10)))
        .unwrap();
    let addr = relay.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let thread = std::thread::spawn(move || {
        let mut client = None;
        let mut held = VecDeque::new();
        let mut immediate = 0;
        let mut delayed = 0;
        let mut sent_bytes = 0;
        let mut buf = [0_u8; 65536];
        while !stopped.load(Ordering::SeqCst) {
            let (n, from) = match relay.recv_from(&mut buf) {
                Ok(packet) => packet,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(e) => panic!("relay receive: {e}"),
            };
            if from != upstream {
                if let Some(previous) = client {
                    assert_eq!(previous, from, "one benchmark connection");
                }
                client = Some(from);
                relay.send_to(&buf[..n], upstream).unwrap();
                continue;
            }
            let to = client.expect("a response follows a request");
            relay.send_to(&buf[..n], to).unwrap();
            sent_bytes += n as u64;
            // Long-header handshake packets pass unchanged. Short-header
            // packets are independently encrypted by Quinn, not this fixture.
            if n > 0 && buf[0] & 0x80 == 0 {
                for _ in 0..3 {
                    relay.send_to(&buf[..n], to).unwrap();
                    sent_bytes += n as u64;
                    immediate += 1;
                }
                held.push_back(buf[..n].to_vec());
                if held.len() > 4 {
                    let packet = held.pop_front().unwrap();
                    relay.send_to(&packet, to).unwrap();
                    sent_bytes += packet.len() as u64;
                    delayed += 1;
                }
            }
        }
        (immediate, delayed, sent_bytes)
    });
    let target =
        crate::target::parse_target(&format!("https://{addr}/"), "GET", &[], None, false).unwrap();
    let stats = crate::http3::run_worker(
        &target,
        1,
        crate::budget::Budget::Requests(512),
        Duration::from_secs(5),
        Some(Duration::from_secs(5)),
        8,
    );
    stop.store(true, Ordering::SeqCst);
    let (immediate, delayed, sent_bytes) = thread.join().unwrap();
    let stats = stats.unwrap();
    assert!(
        immediate >= 3 && delayed > 0,
        "replays: {immediate} immediate, {delayed} delayed"
    );
    assert_eq!(
        (stats.completed, stats.errors, stats.connect_errors),
        (512, 0, 0)
    );
    assert_eq!(stats.latencies_ns.len(), 512);
    assert!(stats.latencies_ns.iter().all(|&n| n > 0));
    assert_eq!(stats.status_counts[200], 512);
    assert_eq!(stats.status_counts.iter().sum::<u64>(), 512);
    // The existing byte counter measures UDP payload, including replayed
    // ciphertext. Some final copies can remain unread when the budget ends.
    assert!(stats.bytes_received > 512 * 11);
    assert!(stats.bytes_received <= sent_bytes);
}
