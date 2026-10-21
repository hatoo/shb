use super::*;

/// The peer is deliberately plain UDP: arbitrary bytes make it possible to
/// distinguish socket generations independently of QUIC retransmission.
struct Fixture {
    // Drop the ring before anything referenced by an SQE or the buffer ring.
    ring: io_uring::IoUring,
    msg: Box<libc::msghdr>,
    buffers: BufRing,
    conn: Conn,
    retired: Vec<Retired>,
    peer: UdpSocket,
    target: Target,
    tls: Arc<rustls::ClientConfig>,
    stats: Stats,
    started: u64,
    received: Vec<(u64, Vec<u8>)>,
    terminals: Vec<(u64, i32)>,
    selected: usize,
    returned: usize,
}

impl Fixture {
    fn new() -> Self {
        Self::sized(8, false)
    }

    fn sized(entries: u16, tiny_cq: bool) -> Self {
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let target = crate::target::parse_target(
            &format!("https://{}/", peer.local_addr().unwrap()),
            "GET",
            &[],
            None,
            false,
        )
        .unwrap();
        let buffers = BufRing::with_buffer_size(entries, recv::BUFFER_SIZE).unwrap();
        let msg = recv::template();
        let mut conn = Conn::new();
        conn.fd = uring::make_udp_socket(&target.addr).unwrap();
        let mut ring = if tiny_cq {
            io_uring::IoUring::builder()
                .setup_cqsize(2)
                .build(2)
                .unwrap()
        } else {
            uring::build_worker_ring(1).unwrap()
        };
        let (submitter, _, _) = ring.split();
        let submitter = uring::register_worker(submitter, 1, &buffers).unwrap();
        submitter.register_files_update(0, &[conn.fd]).unwrap();
        drop(submitter);
        Self {
            ring,
            msg,
            buffers,
            conn,
            retired: Vec::new(),
            peer,
            target,
            tls: crate::tls::client_config(b"h3").unwrap(),
            stats: Stats::default(),
            started: 0,
            received: Vec::new(),
            terminals: Vec::new(),
            selected: 0,
            returned: 0,
        }
    }

    fn arm(&mut self, submit: bool) {
        let (submitter, mut sq, _) = self.ring.split();
        self.conn
            .arm_recv(&submitter, &mut sq, 0, &self.msg)
            .unwrap();
        if submit {
            sq.sync();
            submitter.submit().unwrap();
        }
    }

    fn close(&mut self, stop: bool) {
        let (submitter, mut sq, _) = self.ring.split();
        begin_close(
            &submitter,
            &mut sq,
            0,
            &mut self.conn,
            &mut self.stats,
            &self.tls,
            Duration::from_secs(5),
            None,
            &self.target,
            &mut self.started,
            Budget::Requests(1000),
            stop,
            &mut Vec::new(),
            false,
            Instant::now(),
            &mut self.retired,
            &self.msg,
        )
        .unwrap();
    }

    fn finish(&mut self, stop: bool) {
        let (submitter, mut sq, _) = self.ring.split();
        finish_close(
            &submitter,
            &mut sq,
            0,
            &mut self.conn,
            &self.tls,
            Duration::from_secs(5),
            None,
            &self.target,
            &mut self.started,
            Budget::Requests(1000),
            stop,
            &mut Vec::new(),
            false,
            &mut self.retired,
            &self.msg,
        )
        .unwrap();
    }

    fn completions(&mut self) -> Vec<io_uring::cqueue::Entry> {
        let (submitter, mut sq, mut cq) = self.ring.split();
        sq.sync();
        uring::submit_and_wait_timeout(&submitter, Duration::from_millis(20), 1).unwrap();
        cq.sync();
        cq.collect()
    }

    fn handle(&mut self, cqe: io_uring::cqueue::Entry) {
        let (op, idx, generation) = uring::decode_user_data(cqe.user_data());
        assert_eq!(idx, 0);
        let bid = io_uring::cqueue::buffer_select(cqe.flags());
        if let Some(bid) = bid {
            self.selected += 1;
            let payload =
                recv::decode(self.buffers.data_mut(bid, cqe.result() as usize), &self.msg)
                    .unwrap()
                    .payload
                    .to_vec();
            self.received.push((generation, payload));
        }
        if op == OP_RECV && !io_uring::cqueue::more(cqe.flags()) {
            self.terminals.push((generation, cqe.result()));
        }
        if generation != self.conn.generation {
            if let Some(bid) = bid {
                self.buffers.recycle(bid);
                self.returned += 1;
            }
            if op == OP_SEND {
                self.retired.retain(|r| r.user_data != cqe.user_data());
            }
            return;
        }
        let (submitter, mut sq, _) = self.ring.split();
        match op {
            OP_RECV => {
                assert!(!recv::complete(
                    &mut self.conn,
                    &mut self.stats,
                    Instant::now(),
                    cqe.result(),
                    cqe.flags(),
                    &mut self.buffers,
                    &self.msg
                ));
                self.returned += usize::from(bid.is_some());
                self.conn
                    .arm_recv(&submitter, &mut sq, 0, &self.msg)
                    .unwrap();
            }
            OP_SEND => {
                assert!(cqe.result() >= 0);
                self.stats.bytes_sent += cqe.result() as u64;
                self.conn.sending = false;
                recycle(&mut self.conn);
                push_front_send(&submitter, &mut sq, 0, &mut self.conn).unwrap();
            }
            _ => panic!("unexpected operation {op}"),
        }
    }

    fn step(&mut self) {
        for cqe in self.completions() {
            self.handle(cqe);
        }
    }

    fn address(&self) -> std::net::SocketAddr {
        let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(self.conn.fd) };
        socket2::SockRef::from(&borrowed)
            .local_addr()
            .unwrap()
            .as_socket()
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.conn.close(0, &mut self.retired);
    }
}

#[test]
fn queued_receive_cannot_steal_replacement_socket_datagrams() {
    for submitted in [false, true] {
        let mut f = Fixture::new();
        f.arm(submitted);
        f.close(false);
        assert_eq!(f.conn.generation, 1);
        assert_eq!(
            (f.started, f.stats.errors, f.stats.connect_errors),
            (1, 1, 1)
        );
        // Queue the datagram before submitting the replacement receive. If an
        // older SQE can still resolve this fixed-file slot it will consume it.
        f.peer.send_to(b"replacement", f.address()).unwrap();
        let (submitter, mut sq, mut cq) = f.ring.split();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let mut received = Vec::new();
        while received.is_empty() {
            assert!(std::time::Instant::now() < deadline, "receive deadline");
            sq.sync();
            uring::submit_and_wait_timeout(&submitter, Duration::from_millis(20), 1).unwrap();
            cq.sync();
            for cqe in &mut cq {
                if let Some(bid) = io_uring::cqueue::buffer_select(cqe.flags()) {
                    let payload =
                        recv::decode(f.buffers.data_mut(bid, cqe.result() as usize), &f.msg)
                            .unwrap()
                            .payload
                            .to_vec();
                    f.buffers.recycle(bid);
                    received.push((uring::decode_user_data(cqe.user_data()), payload));
                }
            }
        }
        assert_eq!(
            received,
            vec![((OP_RECV, 0, 1), b"replacement".to_vec())],
            "submitted={submitted}: a stale generation must never consume the new socket"
        );
    }
}

#[test]
fn reconnect_churn_releases_each_old_socket_and_receive() {
    let mut f = Fixture::new();
    f.arm(false);
    for generation in 1u64..=64 {
        let old_address = f.address();
        f.close(false);
        f.conn.quic = None; // Inspect the transport without parsing the marker as QUIC.
        assert_eq!(f.conn.generation, generation);
        f.peer
            .send_to(&generation.to_le_bytes(), f.address())
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while f.stats.bytes_received < generation * 8 || f.conn.sending {
            assert!(std::time::Instant::now() < deadline, "churn deadline");
            f.step();
        }
        assert_eq!(
            f.received.last(),
            Some(&(generation, generation.to_le_bytes().to_vec()))
        );
        assert_eq!(f.terminals.len(), generation as usize);
        assert_eq!(
            f.terminals.last(),
            Some(&(generation - 1, -libc::ECANCELED))
        );
        assert_eq!(f.selected, f.returned);
        assert!(f.retired.is_empty());
        // Closing only the userspace descriptor is insufficient: a forgotten
        // multishot receive or fixed-file reference would keep this port bound.
        let _rebound = UdpSocket::bind(old_address).expect("retired socket was released");
    }
    let last_address = f.address();
    f.close(true);
    f.step();
    let _rebound = UdpSocket::bind(last_address).expect("stopped slot was unregistered");
    assert_eq!(f.conn.fd, -1);
    assert_eq!(f.terminals.len(), 65);
    assert_eq!(f.received.len(), 64);
    assert_eq!(f.stats.bytes_received, 512);
    assert_eq!(
        (f.started, f.stats.errors, f.stats.connect_errors),
        (65, 65, 65)
    );
    assert_eq!(f.stats.completed, 0);
    assert!(f.stats.latencies_ns.is_empty());
}

#[test]
fn close_handles_exhausted_and_successful_terminal_receives_with_or_without_queued_rearm() {
    for tiny_cq in [false, true] {
        for rearm in [false, true] {
            let mut f = Fixture::sized(if tiny_cq { 8 } else { 2 }, tiny_cq);
            f.arm(false);
            for _ in 0..8 {
                f.peer.send_to(b"old", f.address()).unwrap();
            }
            // Retain selected buffers until the terminal CQE appears. The
            // two-buffer pool produces ENOBUFS; a tiny CQ ends a successful shot.
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            let mut completions = Vec::new();
            while !completions
                .iter()
                .any(|c: &io_uring::cqueue::Entry| !io_uring::cqueue::more(c.flags()))
            {
                assert!(std::time::Instant::now() < deadline, "terminal deadline");
                completions.extend(f.completions());
            }
            let terminal = completions
                .iter()
                .find(|c| !io_uring::cqueue::more(c.flags()))
                .unwrap();
            if tiny_cq {
                assert!(terminal.result() > 0);
            } else {
                assert_eq!(terminal.result(), -libc::ENOBUFS);
            }
            // The unreaped terminal leaves recv_armed=true and cancellation
            // returns ENOENT. Alternatively reap it and queue the rearm exactly
            // as the worker does, then close before another submission.
            if rearm {
                for c in completions.drain(..) {
                    f.handle(c);
                }
            }
            f.close(false);
            f.conn.quic = None;
            for c in completions {
                f.handle(c);
            }
            let before = f.stats.bytes_received;
            let first_new = f.received.len();
            f.peer.send_to(b"current", f.address()).unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            while f.stats.bytes_received == before || f.conn.sending {
                assert!(std::time::Instant::now() < deadline, "replacement deadline");
                f.step();
            }
            assert_eq!(f.stats.bytes_received - before, 7);
            assert_eq!(
                f.received[first_new..]
                    .iter()
                    .filter(|(g, _)| *g == 1)
                    .cloned()
                    .collect::<Vec<_>>(),
                vec![(1, b"current".to_vec())]
            );
            assert_eq!(f.selected, f.returned);
            assert!(f.conn.recv_armed);
        }
    }
}

#[test]
fn grace_expiry_binds_queued_plain_and_gso_sends_to_the_retired_socket() {
    for segment_size in [0, 4] {
        let mut f = Fixture::new();
        let old_address = f.address();
        f.arm(false);
        let payload = b"old!old!old!";
        f.conn.out_queue.push_back(Datagram {
            buf: payload.to_vec(),
            segment_size,
        });
        let (submitter, mut sq, _) = f.ring.split();
        push_front_send(&submitter, &mut sq, 0, &mut f.conn).unwrap();
        drop(sq);
        f.close(false);
        assert_eq!(f.conn.generation, 0, "wait for the queued send");
        f.finish(false); // The worker's CLOSE_GRACE deadline takes this path.
        assert_eq!(f.retired.len(), 1, "retain the send buffers until its CQE");
        f.peer
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut got = Vec::new();
        while got.len() < payload.len() {
            let mut buf = [0; 2048];
            let (n, source) = f.peer.recv_from(&mut buf).unwrap();
            assert_eq!(
                source, old_address,
                "old send must not use the replacement socket"
            );
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, payload);
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while !f.retired.is_empty() || f.conn.sending {
            assert!(
                std::time::Instant::now() < deadline,
                "send retirement deadline"
            );
            f.step();
        }
        assert_eq!(f.terminals, vec![(0, -libc::ECANCELED)]);
        let _rebound = UdpSocket::bind(old_address).expect("old send and receive released");
    }
}

#[test]
fn replacement_completes_quinn_request_without_stale_receive_consumption() {
    // Match the production worker's minimum pool. Unlike the marker fixtures,
    // an independent QUIC peer can deliver more than eight packets before a
    // completion batch is drained. Exhaustion is exercised separately below.
    let mut f = Fixture::sized(64, false);
    f.arm(false);
    f.target = crate::target::parse_target(
        &format!("https://{}/", test_server::h3_server_addr()),
        "GET",
        &[],
        None,
        false,
    )
    .unwrap();
    f.close(false);
    let request = proto::request_bytes(&build_field_section(&f.target), &[]);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while f.stats.completed == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "independent QUIC peer deadline"
        );
        f.step();
        assert!(drive(
            &mut f.conn,
            &mut f.stats,
            &request,
            1,
            &mut f.started,
            Budget::Requests(2),
            false
        ));
        let (submitter, mut sq, _) = f.ring.split();
        pump_transmits(
            &submitter,
            &mut sq,
            0,
            &mut f.conn,
            Instant::now(),
            &mut Vec::new(),
            false,
        )
        .unwrap();
    }
    assert_eq!(
        (
            f.started,
            f.stats.completed,
            f.stats.errors,
            f.stats.connect_errors
        ),
        (2, 1, 1, 1)
    );
    assert_eq!(f.stats.status_counts[200], 1);
    assert_eq!(f.stats.status_counts.iter().sum::<u64>(), 1);
    assert_eq!(f.stats.latencies_ns.len(), 1);
    assert!(f.stats.latencies_ns[0] > 0);
    assert!(f.stats.bytes_received > 0);
    assert!(f.received.iter().all(|(generation, _)| *generation == 1));
    assert_eq!(f.selected, f.returned);
    assert_eq!(f.terminals, vec![(0, -libc::ECANCELED)]);
}

#[test]
fn replacement_recovers_current_receive_buffer_exhaustion() {
    for entries in [8, 64] {
        let mut f = Fixture::sized(entries, false);
        f.arm(false);
        f.close(false);
        f.conn.quic = None; // Marker bytes distinguish the receive generations.
        // Observe retirement before introducing the controlled current burst;
        // cancellation and replacement receive CQEs need not arrive in order.
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while f.terminals.is_empty() || f.conn.sending {
            assert!(std::time::Instant::now() < deadline, "retirement deadline");
            f.step();
        }
        assert_eq!(f.terminals, vec![(0, -libc::ECANCELED)]);
        for marker in 0u64..32 {
            f.peer.send_to(&marker.to_le_bytes(), f.address()).unwrap();
        }

        // Hold selected buffers until the whole burst fits or the shot ends.
        // This forces current-generation ENOBUFS with eight buffers without
        // relying on the independent QUIC peer's timing or packetization.
        let mut completions = Vec::new();
        loop {
            assert!(std::time::Instant::now() < deadline, "burst deadline");
            completions.extend(f.completions());
            let selected = completions
                .iter()
                .filter(|c| io_uring::cqueue::buffer_select(c.flags()).is_some())
                .count();
            let terminal = completions.iter().find(|c| {
                uring::decode_user_data(c.user_data()) == (OP_RECV, 0, 1)
                    && !io_uring::cqueue::more(c.flags())
            });
            if entries == 8 {
                if let Some(terminal) = terminal {
                    assert_eq!(terminal.result(), -libc::ENOBUFS);
                    assert_eq!(selected, 8);
                    break;
                }
            } else {
                assert!(terminal.is_none());
                if selected == 32 {
                    break;
                }
            }
        }
        for cqe in completions {
            f.handle(cqe);
        }
        while f.received.len() < 32 {
            assert!(std::time::Instant::now() < deadline, "rearm deadline");
            f.step();
        }
        assert_eq!(
            f.received,
            (0u64..32)
                .map(|marker| (1, marker.to_le_bytes().to_vec()))
                .collect::<Vec<_>>()
        );
        assert_eq!((f.selected, f.returned), (32, 32));
        assert_eq!(f.stats.bytes_received, 32 * 8);
        assert_eq!(
            (
                f.started,
                f.stats.completed,
                f.stats.errors,
                f.stats.connect_errors
            ),
            (1, 0, 1, 1)
        );
        assert!(f.stats.latencies_ns.is_empty());
        assert!(f.conn.recv_armed);
        assert!(f.retired.is_empty());
        assert_eq!(f.terminals[0], (0, -libc::ECANCELED));
        if entries == 8 {
            assert!(f.terminals.len() > 1);
            assert!(f.terminals[1..].iter().all(|&t| t == (1, -libc::ENOBUFS)));
        } else {
            assert_eq!(f.terminals, vec![(0, -libc::ECANCELED)]);
        }
    }
}
