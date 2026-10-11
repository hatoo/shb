use super::*;

/// Keep the actual registered socket and send buffers alive until the ring is
/// dropped, just as the worker does. The receiver need not implement QUIC:
/// these tests control the ordering of close notifications and completions.
struct Fixture {
    ring: io_uring::IoUring,
    recv_msg: Box<libc::msghdr>,
    conn: Conn,
    retired: Vec<Retired>,
    _buffers: BufRing,
    _receiver: UdpSocket,
    tls: Arc<rustls::ClientConfig>,
    target: Target,
}

impl Fixture {
    fn new() -> Self {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let target = crate::target::parse_target(
            &format!("https://{}/", receiver.local_addr().unwrap()),
            "GET",
            &[],
            None,
            false,
        )
        .unwrap();
        let tls = crate::tls::client_config(b"h3").unwrap();
        let buffers = BufRing::with_buffer_size(64, recv::BUFFER_SIZE).unwrap();
        let recv_msg = recv::template();
        let mut conn = Conn::new();
        conn.fd = uring::make_udp_socket(&target.addr).unwrap();
        conn.quic = Some(
            Connection::connect(
                tls.clone(),
                &target.host,
                local_params(Duration::from_secs(5), None),
            )
            .unwrap(),
        );
        let mut ring = uring::build_worker_ring(1).unwrap();
        let (submitter, _, _) = ring.split();
        let submitter = uring::register_worker(submitter, 1, &buffers).unwrap();
        submitter.register_files_update(0, &[conn.fd]).unwrap();
        drop(submitter);
        Self {
            ring,
            recv_msg,
            conn,
            retired: Vec::new(),
            _buffers: buffers,
            _receiver: receiver,
            tls,
            target,
        }
    }

    fn queue_send(&mut self) {
        self.conn.out_queue.push_back(Datagram {
            buf: vec![1, 2, 3],
            segment_size: 0,
        });
        let (submitter, mut sq, _) = self.ring.split();
        push_front_send(&submitter, &mut sq, 0, &mut self.conn).unwrap();
        assert!(self.conn.sending);
    }

    fn complete_send(&mut self) {
        let (submitter, mut sq, mut cq) = self.ring.split();
        sq.sync();
        submitter.submit_and_wait(1).unwrap();
        cq.sync();
        let cqe = cq.next().unwrap();
        assert_eq!(
            uring::decode_user_data(cqe.user_data()),
            (OP_SEND, 0, self.conn.generation)
        );
        assert_eq!(cqe.result(), self.conn.out_queue[0].buf.len() as i32);
        assert!(cq.next().is_none());
        self.conn.sending = false;
        recycle(&mut self.conn);
    }

    fn close(&mut self, stats: &mut Stats, started: &mut u64, budget: Budget, stop: bool) {
        let (submitter, mut sq, _) = self.ring.split();
        begin_close(
            &submitter,
            &mut sq,
            0,
            &mut self.conn,
            stats,
            &self.tls,
            Duration::from_secs(5),
            None,
            &self.target,
            started,
            budget,
            stop,
            &mut Vec::new(),
            false,
            Instant::now(),
            &mut self.retired,
            &self.recv_msg,
        )
        .unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.conn.close(0, &mut self.retired);
    }
}

fn assert_samples(stats: &Stats, completed: u64) {
    assert_eq!(stats.completed, completed);
    assert_eq!(stats.latencies_ns.len() as u64, completed);
    assert_eq!(stats.status_counts.iter().sum::<u64>(), completed);
}

#[test]
fn late_handshake_failure_cannot_consume_another_connections_live_requests() {
    let mut fixture = Fixture::new();
    let mut ready = Conn::new();
    let mut quic = Connection::connect(
        fixture.tls.clone(),
        &fixture.target.host,
        local_params(Duration::from_secs(5), None),
    )
    .unwrap();
    quic.test_send_limits(4096, 1024);
    ready.quic = Some(quic);
    ready.h3_ready = true;
    let budget = Budget::Requests(3);
    let mut started = 0;
    let mut stats = Stats::default();
    fill_streams(&mut ready, b"request", 3, &mut started, budget, false).unwrap();
    assert_eq!(started, 3);
    let starts: Vec<_> = ready.streams.iter().map(|s| s.start).collect();

    fixture.queue_send();
    for _ in 0..3 {
        fixture.close(&mut stats, &mut started, budget, false);
        assert_eq!((started, stats.errors, stats.connect_errors), (3, 0, 0));
        assert!(fixture.conn.closing.is_some());
        assert!(fixture.conn.fd >= 0);
    }
    fixture.complete_send();
    fixture.close(&mut stats, &mut started, budget, false);
    assert_eq!(fixture.conn.fd, -1);
    assert!(fixture.conn.quic.is_none());
    assert_eq!(fixture.conn.generation, 1);
    assert_ne!(
        uring::decode_user_data(uring::user_data(0, 0, OP_RECV)).2,
        fixture.conn.generation,
        "old completions cannot be charged to the next generation"
    );
    assert!(ready.streams.iter().map(|s| s.start).eq(starts));
    for id in [4, 8, 0] {
        let request = ready.streams.take(id).unwrap();
        stats.record_success(200, request.start);
    }
    assert_eq!((started, stats.errors, stats.connect_errors), (3, 0, 0));
    assert_samples(&stats, 3);
}

#[test]
fn handshake_failures_charge_only_available_budget_at_every_boundary() {
    for initial in [0, 2, 3, 4] {
        let mut fixture = Fixture::new();
        let mut stats = Stats::default();
        let mut started = initial;
        fixture.queue_send();
        // Stopping prevents a replacement; it must not hide a failure of an
        // already pending handshake when an unassigned request still exists.
        fixture.close(&mut stats, &mut started, Budget::Requests(3), true);
        fixture.close(&mut stats, &mut started, Budget::Requests(3), true);
        fixture.complete_send();
        fixture.close(&mut stats, &mut started, Budget::Requests(3), true);
        let charged = u64::from(initial < 3);
        assert_eq!(started, initial + charged);
        assert_eq!((stats.errors, stats.connect_errors), (charged, charged));
        assert_samples(&stats, 0);
        assert_eq!(fixture.conn.fd, -1);
        assert_eq!(fixture.conn.generation, 1);
    }
}

#[test]
fn failed_handshakes_reconnect_until_the_last_request_unit_is_charged() {
    let mut fixture = Fixture::new();
    let mut stats = Stats::default();
    let mut started = 0;
    let budget = Budget::Requests(2);
    fixture.close(&mut stats, &mut started, budget, false);
    assert_eq!((started, stats.errors, stats.connect_errors), (1, 1, 1));
    assert_eq!(fixture.conn.generation, 1);
    assert!(fixture.conn.quic.is_some());
    assert!(fixture.conn.recv_armed);
    assert!(fixture.conn.sending);
    fixture.close(&mut stats, &mut started, budget, false);
    fixture.close(&mut stats, &mut started, budget, false);
    assert_eq!((started, stats.errors, stats.connect_errors), (2, 2, 2));
    fixture.complete_send();
    fixture.close(&mut stats, &mut started, budget, false);
    assert_eq!((started, stats.errors, stats.connect_errors), (2, 2, 2));
    assert_eq!(fixture.conn.generation, 2);
    assert_eq!(fixture.conn.fd, -1);
    assert!(fixture.conn.quic.is_none());
    assert_samples(&stats, 0);
}

#[test]
fn exhausted_budget_still_counts_live_requests_and_unjudged_give_backs() {
    let mut fixture = Fixture::new();
    fixture.conn.h3_ready = true;
    fixture
        .conn
        .quic
        .as_mut()
        .unwrap()
        .test_send_limits(4096, 1024);
    let mut stats = Stats::default();
    let mut started = 0;
    let budget = Budget::Requests(4);
    fill_streams(
        &mut fixture.conn,
        b"request",
        4,
        &mut started,
        budget,
        false,
    )
    .unwrap();
    // GOAWAY arrived before any response, so its verdict is still pending.
    fixture.conn.streams.take(12).unwrap();
    fixture
        .conn
        .give_backs
        .give_back(4, &mut stats, &mut started);
    let request = fixture.conn.streams.take(0).unwrap();
    stats.record_success(200, request.start);
    let sample = stats.latencies_ns.clone();
    fixture.queue_send();
    fixture.close(&mut stats, &mut started, budget, false);
    fixture.close(&mut stats, &mut started, budget, false);
    fixture.complete_send();
    fixture.close(&mut stats, &mut started, budget, false);
    assert_eq!((started, stats.errors, stats.connect_errors), (4, 3, 0));
    assert_eq!(stats.latencies_ns, sample);
    assert_samples(&stats, 1);
}

#[test]
fn a_returned_request_can_be_charged_by_a_pending_handshake_failure() {
    let mut fixture = Fixture::new();
    let mut stats = Stats::default();
    stats.record_success(200, Instant::now());
    let sample = stats.latencies_ns.clone();
    let mut started = 2;
    let mut give_backs = GiveBacks {
        completed: 1,
        ..GiveBacks::default()
    };
    give_backs.give_back(1, &mut stats, &mut started);
    assert_eq!(started, 1);
    fixture.close(&mut stats, &mut started, Budget::Requests(2), false);
    assert_eq!((started, stats.errors, stats.connect_errors), (2, 1, 1));
    assert_eq!(stats.latencies_ns, sample);
    assert_samples(&stats, 1);
    assert_eq!(fixture.conn.fd, -1);
}

#[test]
fn duration_stop_keeps_pending_handshake_errors_without_reconnecting() {
    let mut fixture = Fixture::new();
    let mut stats = Stats::default();
    let mut started = 7;
    let budget = Budget::Duration(Duration::from_secs(1));
    fixture.queue_send();
    fixture.close(&mut stats, &mut started, budget, true);
    fixture.close(&mut stats, &mut started, budget, true);
    fixture.complete_send();
    fixture.close(&mut stats, &mut started, budget, true);
    assert_eq!((started, stats.errors, stats.connect_errors), (8, 1, 1));
    assert_eq!(fixture.conn.fd, -1);
    assert_samples(&stats, 0);
}
