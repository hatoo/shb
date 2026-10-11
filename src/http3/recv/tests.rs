use super::*;
use crate::buf_ring::BufRing;
use crate::http3::Conn;
use crate::uring;
use std::net::UdpSocket;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::time::{Duration, Instant};

fn message(payload: &[u8], segment: Option<i32>) -> Vec<u8> {
    let mut buf = vec![0; PAYLOAD_OFFSET + payload.len()];
    buf[4..8].copy_from_slice(
        &(if segment.is_some() {
            CONTROL_SIZE as u32
        } else {
            0
        })
        .to_ne_bytes(),
    );
    buf[8..12].copy_from_slice(&(payload.len() as u32).to_ne_bytes());
    if let Some(size) = segment {
        let header = libc::cmsghdr {
            cmsg_len: unsafe { libc::CMSG_LEN(4) as _ },
            cmsg_level: libc::IPPROTO_UDP,
            cmsg_type: libc::UDP_GRO,
        };
        unsafe {
            buf.as_mut_ptr()
                .add(PREFIX_SIZE)
                .cast::<libc::cmsghdr>()
                .write_unaligned(header)
        };
        let data_start = PREFIX_SIZE + unsafe { libc::CMSG_LEN(0) as usize };
        buf[data_start..data_start + 4].copy_from_slice(&size.to_ne_bytes());
    }
    buf[PAYLOAD_OFFSET..].copy_from_slice(payload);
    buf
}

#[test]
fn splitting_keeps_boundaries_tails_and_mutable_payloads() {
    let msg = template();
    for (payload, segment, lengths) in [
        (&b"abcdefghij"[..], Some(4), vec![4, 4, 2]),
        (&b"abcdefgh"[..], Some(4), vec![4, 4]),
        (&b"ab"[..], Some(4), vec![2]),
        (&b"plain"[..], None, vec![5]),
        (&b""[..], None, vec![]),
    ] {
        let mut buf = message(payload, segment);
        let metadata = buf[..PAYLOAD_OFFSET].to_vec();
        let received = decode(&mut buf, &msg).unwrap();
        assert_eq!(
            received.payload.len(),
            payload.len(),
            "count payload bytes only"
        );
        let got: Vec<_> = received
            .payload
            .chunks_mut(received.segment_size)
            .enumerate()
            .map(|(i, datagram)| {
                let n = datagram.len();
                datagram.fill(i as u8);
                n
            })
            .collect();
        assert_eq!(got, lengths);
        assert_eq!(buf[..PAYLOAD_OFFSET], metadata);
        let expected: Vec<_> = lengths
            .iter()
            .enumerate()
            .flat_map(|(i, &n)| vec![i as u8; n])
            .collect();
        assert_eq!(buf[PAYLOAD_OFFSET..], expected);
    }
}

#[test]
fn rejects_truncation_and_inconsistent_lengths_before_delivering_any_payload() {
    let msg = template();
    let good = message(b"abcdefghij", Some(4));
    for n in 0..good.len() {
        assert!(
            decode(&mut good[..n].to_vec(), &msg).is_none(),
            "cut at {n}"
        );
    }
    for flags in [
        libc::MSG_TRUNC,
        libc::MSG_CTRUNC,
        libc::MSG_TRUNC | libc::MSG_CTRUNC,
    ] {
        let mut buf = good.clone();
        buf[12..16].copy_from_slice(&(flags as u32).to_ne_bytes());
        assert!(decode(&mut buf, &msg).is_none());
    }
    for (offset, values) in [
        (4, vec![1, 8, CONTROL_SIZE as u32 + 1, u32::MAX]),
        (8, vec![0, 9, 11, u32::MAX]),
    ] {
        for value in values {
            let mut buf = good.clone();
            buf[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
            assert!(
                decode(&mut buf, &msg).is_none(),
                "offset {offset}, value {value}"
            );
        }
    }
    assert!(decode(&mut message(&vec![0; 65537], Some(1200)), &msg).is_none());
    assert_eq!(
        decode(&mut message(&vec![0; 65536], Some(1200)), &msg)
            .unwrap()
            .payload
            .len(),
        65536
    );
}

#[test]
fn rejects_invalid_gro_sizes_and_control_headers_without_alignment_assumptions() {
    let msg = template();
    for size in [i32::MIN, -1, 0, 65536, i32::MAX] {
        assert!(decode(&mut message(b"12345678", Some(size)), &msg).is_none());
    }
    assert!(decode(&mut message(b"", Some(4)), &msg).is_none());
    for len in [
        0,
        1,
        unsafe { libc::CMSG_LEN(0) } as usize,
        CONTROL_SIZE + 1,
        usize::MAX,
    ] {
        let mut buf = message(b"12345678", Some(4));
        buf[PREFIX_SIZE..PREFIX_SIZE + std::mem::size_of::<usize>()]
            .copy_from_slice(&len.to_ne_bytes());
        assert!(decode(&mut buf, &msg).is_none());
    }
    let good = message(b"abcdefghij", Some(4));
    // Offset by one byte deliberately. Neither the io_uring prefix nor cmsg
    // header requires a Rust-aligned reference into the provided byte array.
    let mut unaligned = vec![0];
    unaligned.extend_from_slice(&good);
    assert_eq!(decode(&mut unaligned[1..], &msg).unwrap().segment_size, 4);
}

fn set_udp_option(socket: &UdpSocket, option: libc::c_int, value: libc::c_int) {
    assert_eq!(
        unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_UDP,
                option,
                (&value as *const libc::c_int).cast(),
                std::mem::size_of_val(&value) as _,
            )
        },
        0,
        "{}",
        std::io::Error::last_os_error()
    );
}

fn socket_pair(bind: &str, gro: bool) -> (UdpSocket, UdpSocket) {
    let sender = UdpSocket::bind(bind).unwrap();
    let receiver = unsafe {
        UdpSocket::from_raw_fd(uring::make_udp_socket(&sender.local_addr().unwrap()).unwrap())
    };
    set_udp_option(&receiver, libc::UDP_GRO, gro as _);
    sender.connect(receiver.local_addr().unwrap()).unwrap();
    (sender, receiver)
}

#[test]
fn kernel_gro_and_plain_udp_preserve_datagrams_and_recycle_buffers_ipv4_ipv6() {
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        for gro in [false, true] {
            let (sender, receiver) = socket_pair(bind, gro);
            let mut buffers = BufRing::with_buffer_size(8, BUFFER_SIZE).unwrap();
            let msg = template();
            let mut ring = uring::build_worker_ring(1).unwrap();
            let (mut submitter, mut sq, mut cq) = ring.split();
            uring::register_worker(&mut submitter, 1, &buffers).unwrap();
            submitter
                .register_files_update(0, &[receiver.as_raw_fd()])
                .unwrap();
            uring::push_recvmsg_multi(&submitter, &mut sq, 0, 0, &msg).unwrap();
            // More rounds than buffers, with different lengths, expose stale
            // control data and failure to return a provided buffer.
            let mut completions = 0;
            for round in 0..12 {
                let payload: Vec<u8> = (0..257).map(|i| (i + round) as u8).collect();
                set_udp_option(&sender, libc::UDP_SEGMENT, 64);
                assert_eq!(sender.send(&payload).unwrap(), payload.len());
                set_udp_option(&sender, libc::UDP_SEGMENT, 0);
                sender.send(b"plain").unwrap();
                sender.send(b"").unwrap();
                let mut datagrams = Vec::new();
                let deadline = Instant::now() + Duration::from_secs(3);
                while datagrams.len() < 7 {
                    assert!(Instant::now() < deadline, "receive deadline");
                    sq.sync();
                    uring::submit_and_wait_timeout(&submitter, Duration::from_millis(20), 1)
                        .unwrap();
                    cq.sync();
                    for cqe in &mut cq {
                        assert!(
                            cqe.result() > 0,
                            "recvmsg includes a prefix, even for empty UDP: {}",
                            cqe.result()
                        );
                        let bid = io_uring::cqueue::buffer_select(cqe.flags()).unwrap();
                        let received =
                            decode(buffers.data_mut(bid, cqe.result() as usize), &msg).unwrap();
                        if received.payload.is_empty() {
                            datagrams.push(vec![]);
                        } else {
                            datagrams.extend(
                                received
                                    .payload
                                    .chunks_mut(received.segment_size)
                                    .map(|d| d.to_vec()),
                            );
                        }
                        completions += 1;
                        buffers.recycle(bid);
                        if !io_uring::cqueue::more(cqe.flags()) {
                            uring::push_recvmsg_multi(&submitter, &mut sq, 0, 0, &msg).unwrap();
                        }
                    }
                }
                let mut expected: Vec<_> = payload.chunks(64).map(|d| d.to_vec()).collect();
                expected.extend([b"plain".to_vec(), vec![]]);
                assert_eq!(datagrams, expected, "{bind}, gro={gro}, round={round}");
            }
            if gro {
                assert!(completions < 84, "GRO aggregates on loopback");
            } else {
                assert_eq!(completions, 84);
            }
            eprintln!(
                "UDP receive mechanism {bind}, gro={gro}: {completions} CQEs / 84 datagrams; buffers={} bytes",
                8 * BUFFER_SIZE
            );
        }
    }
}

#[test]
fn exhausted_multishot_rearms_once_and_delivers_every_datagram_after_recycling() {
    let (sender, receiver) = socket_pair("127.0.0.1:0", false);
    let mut buffers = BufRing::with_buffer_size(2, BUFFER_SIZE).unwrap();
    let msg = template();
    let mut conn = Conn::new();
    let mut ring = uring::build_worker_ring(1).unwrap();
    let (mut submitter, mut sq, mut cq) = ring.split();
    uring::register_worker(&mut submitter, 1, &buffers).unwrap();
    submitter
        .register_files_update(0, &[receiver.as_raw_fd()])
        .unwrap();
    conn.arm_recv(&submitter, &mut sq, 0, &msg).unwrap();
    conn.arm_recv(&submitter, &mut sq, 0, &msg).unwrap();
    assert_eq!(sq.len(), 1, "an armed receive is never duplicated");
    for i in 0..5 {
        sender.send(&[i]).unwrap();
    }
    let mut got = Vec::new();
    let mut held = Vec::new();
    let mut exhausted = 0;
    let deadline = Instant::now() + Duration::from_secs(3);
    while got.len() < 5 {
        assert!(Instant::now() < deadline, "receive deadline");
        sq.sync();
        uring::submit_and_wait_timeout(&submitter, Duration::from_millis(20), 1).unwrap();
        cq.sync();
        for cqe in &mut cq {
            if !io_uring::cqueue::more(cqe.flags()) {
                conn.recv_armed = false;
            }
            if cqe.result() == -libc::ENOBUFS {
                assert!(!conn.recv_armed);
                exhausted += 1;
                for bid in held.drain(..) {
                    buffers.recycle(bid);
                }
                conn.arm_recv(&submitter, &mut sq, 0, &msg).unwrap();
            } else {
                assert!(cqe.result() > 0);
                let bid = io_uring::cqueue::buffer_select(cqe.flags()).unwrap();
                got.extend_from_slice(
                    decode(buffers.data_mut(bid, cqe.result() as usize), &msg)
                        .unwrap()
                        .payload,
                );
                held.push(bid);
            }
        }
    }
    for bid in held {
        buffers.recycle(bid);
    }
    assert_eq!(got, [0, 1, 2, 3, 4]);
    assert_eq!(exhausted, 2);
}

#[test]
fn a_queued_old_generation_keeps_its_template_until_submission_and_recycles_stale_data() {
    let (_old_sender, receiver) = socket_pair("127.0.0.1:0", true);
    let mut buffers = BufRing::with_buffer_size(2, BUFFER_SIZE).unwrap();
    let msg = template();
    let address = (&*msg) as *const libc::msghdr;
    let mut conn = Conn::new();
    conn.fd = receiver.into_raw_fd();
    let mut retired = Vec::new();
    let mut ring = uring::build_worker_ring(1).unwrap();
    let (mut submitter, mut sq, mut cq) = ring.split();
    uring::register_worker(&mut submitter, 1, &buffers).unwrap();
    submitter.register_files_update(0, &[conn.fd]).unwrap();
    conn.arm_recv(&submitter, &mut sq, 0, &msg).unwrap();
    conn.close(0, &mut retired);
    assert_eq!(conn.generation, 1);
    assert_eq!((&*msg) as *const libc::msghdr, address);
    // Replace the registered socket before the old SQE is submitted, just as
    // an immediate reconnect can do. Both generations share the live template.
    let (sender, receiver) = socket_pair("127.0.0.1:0", true);
    conn.fd = receiver.into_raw_fd();
    submitter.register_files_update(0, &[conn.fd]).unwrap();
    // The old SQE has not even been submitted when close bumps the generation.
    sender.send(b"stale").unwrap();
    sq.sync();
    uring::submit_and_wait_timeout(&submitter, Duration::from_secs(1), 1).unwrap();
    cq.sync();
    let completion = cq.next().expect("old receive");
    assert_eq!(
        uring::decode_user_data(completion.user_data()),
        (uring::OP_RECV, 0, 0)
    );
    let bid = io_uring::cqueue::buffer_select(completion.flags()).unwrap();
    // Same stale-generation path as the worker: do not decode or account it.
    buffers.recycle(bid);
    cq.sync();
    let cancel = io_uring::opcode::AsyncCancel::new(completion.user_data())
        .build()
        .user_data(99);
    uring::push_sqe(&submitter, &mut sq, cancel).unwrap();
    sq.sync();
    let mut cancelled = 0;
    let deadline = Instant::now() + Duration::from_secs(3);
    while cancelled < 2 {
        assert!(Instant::now() < deadline, "cancel deadline");
        uring::submit_and_wait_timeout(&submitter, Duration::from_millis(20), 1).unwrap();
        cq.sync();
        for cqe in &mut cq {
            assert!(cqe.result() == 0 || cqe.result() == -libc::ECANCELED);
            cancelled += 1;
        }
    }
    conn.arm_recv(&submitter, &mut sq, 0, &msg).unwrap();
    sender.send(b"current").unwrap();
    sq.sync();
    uring::submit_and_wait_timeout(&submitter, Duration::from_secs(1), 1).unwrap();
    cq.sync();
    let cqe = cq.find(|cqe| cqe.result() > 0).expect("new receive");
    assert_eq!(
        uring::decode_user_data(cqe.user_data()),
        (uring::OP_RECV, 0, 1)
    );
    let bid = io_uring::cqueue::buffer_select(cqe.flags()).unwrap();
    assert_eq!(
        decode(buffers.data_mut(bid, cqe.result() as usize), &msg)
            .unwrap()
            .payload,
        b"current"
    );
    buffers.recycle(bid);
    conn.close(0, &mut retired);
}

#[test]
fn a_full_size_udp_payload_fits_and_a_truncated_one_is_rejected_then_recycled() {
    for capacity in [PAYLOAD_OFFSET + 64, BUFFER_SIZE] {
        let (sender, receiver) = socket_pair("127.0.0.1:0", true);
        let mut buffers = BufRing::with_buffer_size(1, capacity).unwrap();
        let msg = template();
        let mut ring = uring::build_worker_ring(1).unwrap();
        let (mut submitter, mut sq, mut cq) = ring.split();
        uring::register_worker(&mut submitter, 1, &buffers).unwrap();
        submitter
            .register_files_update(0, &[receiver.as_raw_fd()])
            .unwrap();
        uring::push_recvmsg_multi(&submitter, &mut sq, 0, 0, &msg).unwrap();
        let payload: Vec<_> = (0..65507).map(|i| i as u8).collect();
        assert_eq!(sender.send(&payload).unwrap(), payload.len());
        sq.sync();
        uring::submit_and_wait_timeout(&submitter, Duration::from_secs(1), 1).unwrap();
        cq.sync();
        let cqe = cq.next().expect("aggregate");
        assert!(cqe.result() > 0);
        let bid = io_uring::cqueue::buffer_select(cqe.flags()).unwrap();
        let received = decode(buffers.data_mut(bid, cqe.result() as usize), &msg);
        if capacity == BUFFER_SIZE {
            let received = received.unwrap();
            assert!(received.payload == payload);
            assert_eq!(received.segment_size, payload.len());
        } else {
            assert!(
                received.is_none(),
                "a truncated UDP payload must not enter QUIC"
            );
        }
        buffers.recycle(bid);
        // A 1-entry buffer ring may also return ENOBUFS in this pass. Finish
        // that shot, then verify the same storage can receive a plain payload.
        let mut armed = io_uring::cqueue::more(cqe.flags());
        cq.sync();
        for cqe in &mut cq {
            assert_eq!(cqe.result(), -libc::ENOBUFS);
            armed = false;
        }
        if !armed {
            uring::push_recvmsg_multi(&submitter, &mut sq, 0, 0, &msg).unwrap();
        }
        set_udp_option(&sender, libc::UDP_SEGMENT, 0);
        sender.send(b"ok").unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            assert!(Instant::now() < deadline, "reuse deadline");
            sq.sync();
            uring::submit_and_wait_timeout(&submitter, Duration::from_millis(20), 1).unwrap();
            cq.sync();
            let mut received_ok = false;
            for cqe in &mut cq {
                if cqe.result() == -libc::ENOBUFS {
                    uring::push_recvmsg_multi(&submitter, &mut sq, 0, 0, &msg).unwrap();
                    continue;
                }
                assert!(cqe.result() > 0);
                let bid = io_uring::cqueue::buffer_select(cqe.flags()).unwrap();
                let buffer = buffers.data_mut(bid, cqe.result() as usize);
                if let Some(received) = decode(buffer, &msg) {
                    assert_eq!(received.payload, b"ok");
                    received_ok = true;
                } else {
                    panic!("the small plain datagram after a truncated one must fit");
                }
                buffers.recycle(bid);
            }
            if received_ok {
                break;
            }
        }
    }
}

#[test]
fn large_gso_sends_keep_all_original_boundaries_across_multiple_completions() {
    let (sender, receiver) = socket_pair("127.0.0.1:0", true);
    let mut buffers = BufRing::with_buffer_size(8, BUFFER_SIZE).unwrap();
    let msg = template();
    let mut ring = uring::build_worker_ring(1).unwrap();
    let (mut submitter, mut sq, mut cq) = ring.split();
    uring::register_worker(&mut submitter, 1, &buffers).unwrap();
    submitter
        .register_files_update(0, &[receiver.as_raw_fd()])
        .unwrap();
    uring::push_recvmsg_multi(&submitter, &mut sq, 0, 0, &msg).unwrap();
    let payload: Vec<_> = (0..65507).map(|i| (i / 1024) as u8).collect();
    set_udp_option(&sender, libc::UDP_SEGMENT, 1024);
    sender.send(&payload).unwrap();
    let mut datagrams = Vec::new();
    let mut completions = 0;
    let deadline = Instant::now() + Duration::from_secs(3);
    while datagrams.len() < 64 {
        assert!(Instant::now() < deadline, "large GSO receive deadline");
        sq.sync();
        uring::submit_and_wait_timeout(&submitter, Duration::from_millis(20), 1).unwrap();
        cq.sync();
        for cqe in &mut cq {
            if cqe.result() == -libc::ENOBUFS {
                uring::push_recvmsg_multi(&submitter, &mut sq, 0, 0, &msg).unwrap();
                continue;
            }
            assert!(cqe.result() > 0);
            let bid = io_uring::cqueue::buffer_select(cqe.flags()).unwrap();
            let received = decode(buffers.data_mut(bid, cqe.result() as usize), &msg).unwrap();
            datagrams.extend(
                received
                    .payload
                    .chunks(received.segment_size)
                    .map(|d| d.to_vec()),
            );
            buffers.recycle(bid);
            completions += 1;
            if !io_uring::cqueue::more(cqe.flags()) {
                uring::push_recvmsg_multi(&submitter, &mut sq, 0, 0, &msg).unwrap();
            }
        }
    }
    let expected: Vec<_> = payload.chunks(1024).map(|d| d.to_vec()).collect();
    assert!(
        datagrams == expected,
        "all 64 datagrams, including the short tail, must be intact"
    );
    eprintln!("Large GSO: {completions} CQEs / 64 datagrams / 65507 payload bytes");
}

#[test]
fn successful_terminal_completions_rearm_after_cq_pressure_without_losing_bytes() {
    let (sender, receiver) = socket_pair("127.0.0.1:0", false);
    let mut buffers = BufRing::with_buffer_size(8, BUFFER_SIZE).unwrap();
    let msg = template();
    let mut conn = Conn::new();
    let mut stats = crate::stats::Stats::default();
    // More queued datagrams than CQ slots forces a successful final CQE:
    // checking only a negative result would leave the receive permanently off.
    let mut ring: io_uring::IoUring = io_uring::IoUring::builder()
        .setup_cqsize(2)
        .build(2)
        .unwrap();
    let (mut submitter, mut sq, mut cq) = ring.split();
    uring::register_worker(&mut submitter, 1, &buffers).unwrap();
    submitter
        .register_files_update(0, &[receiver.as_raw_fd()])
        .unwrap();
    conn.arm_recv(&submitter, &mut sq, 0, &msg).unwrap();
    for i in 0..32 {
        sender.send(&[i]).unwrap();
    }
    let mut got = Vec::new();
    let mut terminal_successes = 0;
    let deadline = Instant::now() + Duration::from_secs(3);
    while got.len() < 32 {
        assert!(Instant::now() < deadline, "CQ pressure receive deadline");
        sq.sync();
        uring::submit_and_wait_timeout(&submitter, Duration::from_millis(20), 1).unwrap();
        cq.sync();
        for cqe in &mut cq {
            if cqe.result() >= 0 {
                let bid = io_uring::cqueue::buffer_select(cqe.flags()).unwrap();
                got.extend_from_slice(
                    decode(buffers.data_mut(bid, cqe.result() as usize), &msg)
                        .unwrap()
                        .payload,
                );
                terminal_successes += usize::from(!io_uring::cqueue::more(cqe.flags()));
            }
            assert!(!complete(
                &mut conn,
                &mut stats,
                minstant::Instant::now(),
                cqe.result(),
                cqe.flags(),
                &mut buffers,
                &msg
            ));
        }
        conn.arm_recv(&submitter, &mut sq, 0, &msg).unwrap();
        conn.arm_recv(&submitter, &mut sq, 0, &msg).unwrap();
        assert!(sq.len() <= 1, "at most one replacement receive");
    }
    assert_eq!(got, (0..32).collect::<Vec<_>>());
    assert!(
        terminal_successes > 0,
        "exercise a real successful terminal CQE"
    );
    assert_eq!(stats.bytes_received, 32, "exclude every recvmsg prefix");
    assert_eq!(
        (stats.completed, stats.errors, stats.connect_errors),
        (0, 0, 0)
    );
    assert!(stats.latencies_ns.is_empty());
    assert!(conn.pending);
}

#[test]
fn truncated_kernel_completion_returns_its_buffer_without_counting_partial_bytes() {
    let (sender, receiver) = socket_pair("127.0.0.1:0", true);
    let mut buffers = BufRing::with_buffer_size(1, PAYLOAD_OFFSET + 8).unwrap();
    let msg = template();
    let mut conn = Conn::new();
    let mut stats = crate::stats::Stats::default();
    let mut ring = uring::build_worker_ring(1).unwrap();
    let (mut submitter, mut sq, mut cq) = ring.split();
    uring::register_worker(&mut submitter, 1, &buffers).unwrap();
    submitter
        .register_files_update(0, &[receiver.as_raw_fd()])
        .unwrap();
    conn.arm_recv(&submitter, &mut sq, 0, &msg).unwrap();
    sender.send(&[0; 128]).unwrap();
    sender.send(b"next").unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut rejected = 0;
    while stats.bytes_received == 0 {
        assert!(
            Instant::now() < deadline,
            "truncation/recycle receive deadline"
        );
        sq.sync();
        uring::submit_and_wait_timeout(&submitter, Duration::from_millis(20), 1).unwrap();
        cq.sync();
        for cqe in &mut cq {
            let broken = complete(
                &mut conn,
                &mut stats,
                minstant::Instant::now(),
                cqe.result(),
                cqe.flags(),
                &mut buffers,
                &msg,
            );
            if broken {
                rejected += 1;
                assert_eq!(stats.bytes_received, 0);
                assert!(!conn.pending);
            }
        }
        // A worker closes on malformed input. The fixture continues to prove
        // that even the rejected completion returned the sole selected buffer.
        conn.arm_recv(&submitter, &mut sq, 0, &msg).unwrap();
    }
    assert_eq!(rejected, 1);
    assert_eq!(stats.bytes_received, 4);
    assert_eq!(
        (stats.completed, stats.errors, stats.connect_errors),
        (0, 0, 0)
    );
    assert!(stats.latencies_ns.is_empty());
}

#[test]
fn success_without_a_selected_buffer_is_not_silently_counted() {
    let mut buffers = BufRing::with_buffer_size(1, BUFFER_SIZE).unwrap();
    let msg = template();
    let mut conn = Conn::new();
    conn.recv_armed = true;
    let mut stats = crate::stats::Stats::default();
    assert!(complete(
        &mut conn,
        &mut stats,
        minstant::Instant::now(),
        PAYLOAD_OFFSET as i32,
        0,
        &mut buffers,
        &msg
    ));
    assert!(!conn.recv_armed && !conn.pending);
    assert_eq!(stats.bytes_received, 0);
    assert_eq!(
        (stats.completed, stats.errors, stats.connect_errors),
        (0, 0, 0)
    );
    assert!(stats.latencies_ns.is_empty());
}
