use super::*;
use crate::quic::{crypto::initial_keys, frame::Frame, packet::unprotect_header};
use std::os::fd::AsRawFd;

/// Exercise the real packet builder, GSO descriptors and io_uring send. Decode
/// everything the kernel delivers so a batch limit cannot discard an already
/// numbered packet, repeat a prefix, or lose the tail/FIN between batches.
fn exercise(address: &str, gso: bool, probe: bool) {
    let receiver = UdpSocket::bind(address).unwrap();
    let address = receiver.local_addr().unwrap();
    if gso && !probe_gso(&address) {
        eprintln!("UDP_SEGMENT is unavailable; skipping the kernel GSO fixture");
        return;
    }
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let sender = UdpSocket::bind(if address.is_ipv4() {
        "127.0.0.1:0"
    } else {
        "[::1]:0"
    })
    .unwrap();
    sender.connect(address).unwrap();
    sender.set_nonblocking(true).unwrap();
    let request: Vec<_> = (0..320_003).map(|i| (i * 71 + i / 251) as u8).collect();
    let mut quic = Connection::connect(
        crate::tls::client_config(b"h3").unwrap(),
        "localhost",
        local_params(Duration::from_secs(5), None),
    )
    .unwrap();
    quic.test_data_sender(request.len() as u64, probe);
    assert_eq!(quic.send_oneshot(&request), Some((0, request.len())));
    let keys = initial_keys(&[9; 8], rustls::Side::Server).unwrap().remote;
    let mut conn = Conn::new();
    // The socket owns the fd; Conn has no Drop implementation.
    conn.fd = sender.as_raw_fd();
    conn.quic = Some(quic);
    let mut ring = io_uring::IoUring::new(64).unwrap();
    let (submitter, mut sq, mut cq) = ring.split();
    submitter.register_files(&[sender.as_raw_fd()]).unwrap();
    let mut transmit = Vec::new();
    let mut received = Vec::new();
    let mut packets = 0u64;
    let mut fins = 0;
    let mut batches = 0;
    let now = Instant::now();
    loop {
        pump_transmits(&submitter, &mut sq, 0, &mut conn, now, &mut transmit, gso).unwrap();
        let Some(front) = conn.out_queue.front() else {
            break;
        };
        let segment = if front.segment_size == 0 {
            front.buf.len()
        } else {
            front.segment_size
        };
        let count = front.buf.len().div_ceil(segment);
        assert!(
            front.buf.len() <= 65_507,
            "GSO message has {} bytes",
            front.buf.len()
        );
        assert!(count <= 64);
        if !gso {
            assert_eq!(count, 1);
        }
        if probe && batches == 0 {
            assert!(count <= 2, "a PTO sends at most two probes");
        }
        if gso && !probe && batches == 0 {
            assert!(count > 2, "exercise a full batch");
        }
        sq.sync();
        submitter.submit_and_wait(1).unwrap();
        cq.sync();
        let completion = cq.next().unwrap();
        assert_eq!(
            completion.result(),
            front.buf.len() as i32,
            "kernel rejected the GSO message"
        );
        assert!(cq.next().is_none());
        for expected in front.buf.chunks(segment) {
            let mut datagram = [0u8; 2048];
            let size = receiver.recv(&mut datagram).unwrap();
            assert_eq!(&datagram[..size], expected);
            // A short header has an eight-byte destination connection ID.
            let (_, pn_len) =
                unprotect_header(keys.header.as_ref(), &mut datagram[..size], 9).unwrap();
            let truncated = datagram[9..9 + pn_len]
                .iter()
                .fold(0u64, |n, b| n * 256 + u64::from(*b));
            assert_eq!(
                truncated, packets,
                "every packet number reaches the receiver in order"
            );
            let (header, body) = datagram[..size].split_at_mut(9 + pn_len);
            let plain = keys.packet.decrypt_in_place(packets, header, body).unwrap();
            for frame in crate::quic::frame::Iter::new(plain) {
                match frame.unwrap() {
                    Frame::Stream {
                        id,
                        offset,
                        data,
                        fin,
                    } => {
                        assert_eq!(id, 0);
                        assert_eq!(offset as usize, received.len());
                        received.extend_from_slice(data);
                        if fin {
                            fins += 1;
                            assert_eq!(received, request);
                        }
                    }
                    Frame::Padding | Frame::Ping => {}
                    other => panic!("unexpected frame {other:?}"),
                }
            }
            packets += 1;
        }
        recycle(&mut conn);
        conn.sending = false;
        batches += 1;
        assert!(batches < 512);
    }
    assert!(batches > 2);
    assert!(packets > 128);
    assert_eq!(received, request);
    assert_eq!(fins, 1);
}

#[test]
fn gso_batches_fit_ipv4_messages_and_preserve_bytes() {
    exercise("127.0.0.1:0", true, false);
}

#[test]
fn gso_batches_fit_ipv6_messages_and_preserve_bytes() {
    exercise("[::1]:0", true, false);
}

#[test]
fn gso_probes_keep_the_two_datagram_limit() {
    exercise("127.0.0.1:0", true, true);
}

#[test]
fn plain_sends_keep_one_datagram_per_message() {
    exercise("127.0.0.1:0", false, false);
}
