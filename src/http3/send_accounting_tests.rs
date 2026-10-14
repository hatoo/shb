use super::*;
use std::os::fd::AsRawFd;

struct Fixture {
    // Ring first: it must release every pointer before its backing storage.
    ring: io_uring::IoUring,
    buffers: BufRing,
    msg: Box<libc::msghdr>,
    conns: Vec<Conn>,
    retired: Vec<Retired>,
    senders: Vec<UdpSocket>,
    peer: UdpSocket,
}

impl Fixture {
    fn new(count: usize, address: &str, worker_ring: bool) -> Self {
        let peer = UdpSocket::bind(address).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let buffers = BufRing::with_buffer_size(8, recv::BUFFER_SIZE).unwrap();
        let mut senders = Vec::new();
        let mut conns = Vec::new();
        for _ in 0..count {
            let socket = UdpSocket::bind(address).unwrap();
            socket.connect(peer.local_addr().unwrap()).unwrap();
            socket.set_nonblocking(true).unwrap();
            let mut conn = Conn::new();
            conn.fd = socket.as_raw_fd();
            conns.push(conn);
            senders.push(socket);
        }
        let ring = if worker_ring {
            uring::build_worker_ring(count).unwrap()
        } else {
            io_uring::IoUring::new(32).unwrap()
        };
        ring.submitter()
            .register_files(&senders.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>())
            .unwrap();
        unsafe {
            ring.submitter()
                .register_buf_ring_with_flags(
                    buffers.ring_ptr as u64,
                    buffers.entries,
                    uring::BUF_GROUP,
                    0,
                )
                .unwrap();
        }
        Self {
            ring,
            buffers,
            msg: recv::template(),
            conns,
            retired: Vec::new(),
            senders,
            peer,
        }
    }

    fn queue(&mut self, index: usize, bytes: &[u8], segment_size: usize) {
        self.conns[index].out_queue.push_back(Datagram {
            buf: bytes.to_vec(),
            segment_size,
        });
        let (submitter, mut sq, _) = self.ring.split();
        push_front_send(&submitter, &mut sq, index, &mut self.conns[index]).unwrap();
    }

    fn finish(&mut self, stats: &mut Stats) {
        let (submitter, mut sq, mut cq) = self.ring.split();
        finish_io(
            &submitter,
            &mut sq,
            &mut cq,
            &mut self.conns,
            &mut self.retired,
            &mut self.buffers,
            stats,
        )
        .unwrap();
        assert!(sq.is_empty() && cq.is_empty());
        let sent = stats.bytes_sent;
        drain_final_completions(
            &mut cq,
            &mut self.conns,
            &mut self.retired,
            &mut self.buffers,
            stats,
        );
        assert_eq!(stats.bytes_sent, sent, "a CQE is counted once");
    }

    fn receive(&self, bytes: &[u8]) {
        let mut buf = vec![0; 65536];
        let n = self.peer.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], bytes);
    }
}

#[test]
fn final_singleton_and_gso_sends_match_socket_bytes_without_changing_samples() {
    for worker_ring in [false, true] {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            for segment_size in [0, 4] {
                let mut f = Fixture::new(3, address, worker_ring);
                if segment_size != 0 && !probe_gso(&f.peer.local_addr().unwrap()) {
                    continue;
                }
                let start = Instant::now();
                let mut stats = Stats {
                    bytes_sent: 123,
                    bytes_received: 456,
                    completed: 2,
                    errors: 3,
                    connect_errors: 1,
                    latencies_ns: vec![17, 29],
                    ..Stats::default()
                };
                stats.status_counts[200] = 2;
                for index in 0..3 {
                    f.conns[index].streams.push(
                        0,
                        InFlight {
                            stream_id: 0,
                            start,
                            reader: ResponseReader::default(),
                            unsent: Vec::new(),
                        },
                    );
                    f.queue(index, b"abcdEFGHij", segment_size);
                    // The queue tail has no SQE. Shutdown must not start it.
                    f.conns[index].out_queue.push_back(Datagram {
                        buf: b"unscheduled".to_vec(),
                        segment_size: 0,
                    });
                }
                f.finish(&mut stats);
                for _ in 0..3 {
                    for bytes in b"abcdEFGHij".chunks(if segment_size == 0 { 10 } else { 4 }) {
                        f.receive(bytes);
                    }
                }
                assert_eq!(stats.bytes_sent, 123 + 30);
                assert_eq!(stats.bytes_received, 456);
                assert_eq!(
                    (stats.completed, stats.errors, stats.connect_errors),
                    (2, 3, 1)
                );
                assert_eq!(stats.latencies_ns, [17, 29]);
                assert_eq!(stats.status_counts[200], 2);
                assert_eq!(stats.status_counts.iter().sum::<u64>(), 2);
                for conn in &mut f.conns {
                    assert!(!conn.sending);
                    assert_eq!(conn.out_queue.len(), 1);
                    assert_eq!(conn.out_queue[0].buf, b"unscheduled");
                    assert!(conn.streams.get_mut(0).unwrap().start == start);
                }
                f.peer.set_nonblocking(true).unwrap();
                assert_eq!(
                    f.peer.recv(&mut [0; 32]).unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock
                );
            }
        }
    }
}

#[test]
fn final_zero_and_oversized_datagrams_add_no_bytes_or_errors() {
    for bytes in [Vec::new(), vec![7; 65508]] {
        let mut f = Fixture::new(1, "127.0.0.1:0", true);
        f.queue(0, &bytes, 0);
        let mut stats = Stats::default();
        f.finish(&mut stats);
        assert_eq!((stats.bytes_sent, stats.errors, stats.completed), (0, 0, 0));
        assert!(stats.latencies_ns.is_empty() && !f.conns[0].sending);
        if bytes.is_empty() {
            f.receive(&[]);
        } else {
            f.peer.set_nonblocking(true).unwrap();
            assert_eq!(
                f.peer.recv(&mut [0; 1]).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
    }
}

#[test]
fn final_blocked_send_is_cancelled_without_sending_or_counting_it() {
    let mut f = Fixture::new(1, "127.0.0.1:0", true);
    f.conns[0].out_queue.push_back(Datagram {
        buf: b"blocked".to_vec(),
        segment_size: 0,
    });
    f.conns[0].sending = true;
    let (submitter, mut sq, _) = f.ring.split();
    // A linked send behind an unreadable socket deterministically remains
    // pending until shutdown cancels it. Both CQEs are real kernel results.
    let poll = io_uring::opcode::PollAdd::new(io_uring::types::Fixed(0), libc::POLLIN as u32)
        .build()
        .user_data(TIMEOUT_USER_DATA)
        .flags(io_uring::squeue::Flags::IO_LINK);
    uring::push_sqe(&submitter, &mut sq, poll).unwrap();
    uring::push_send_slice(&submitter, &mut sq, 0, 0, &f.conns[0].out_queue[0].buf).unwrap();
    drop(sq);
    let mut stats = Stats::default();
    f.finish(&mut stats);
    assert_eq!((stats.bytes_sent, stats.errors, stats.completed), (0, 0, 0));
    assert!(!f.conns[0].sending && f.conns[0].out_queue.is_empty());
    f.peer.set_nonblocking(true).unwrap();
    assert_eq!(
        f.peer.recv(&mut [0; 16]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn final_retired_send_counts_once_without_touching_replacement() {
    for segment_size in [0, 4] {
        let mut f = Fixture::new(1, "127.0.0.1:0", true);
        if segment_size != 0 && !probe_gso(&f.peer.local_addr().unwrap()) {
            continue;
        }
        f.queue(0, b"old!old!tail", segment_size);
        let (submitter, mut sq, _) = f.ring.split();
        sq.sync();
        submitter.submit().unwrap();
        drop(sq);
        // Preserve the backing send exactly as close() does, but the fixture
        // retains ownership of its raw socket to avoid closing it twice.
        let datagram = f.conns[0].out_queue.pop_front().unwrap();
        let state = std::mem::replace(
            &mut f.conns[0].msg_state,
            Box::new(unsafe { std::mem::zeroed() }),
        );
        f.retired.push(Retired {
            user_data: uring::user_data(0, 0, OP_SEND),
            _datagram: datagram,
            _msg_state: state,
        });
        f.conns[0].generation = 1;
        f.queue(0, b"replacement", 0);
        let mut stats = Stats::default();
        f.finish(&mut stats);
        for bytes in b"old!old!tail".chunks(if segment_size == 0 { 12 } else { 4 }) {
            f.receive(bytes);
        }
        f.receive(b"replacement");
        assert_eq!(stats.bytes_sent, 12 + 11);
        assert!(f.retired.is_empty());
        assert!(!f.conns[0].sending && f.conns[0].out_queue.is_empty());
        // An unknown/already retired identity must not be counted twice.
        complete_retired_send(
            uring::user_data(0, 0, OP_SEND),
            12,
            &mut f.retired,
            &mut stats,
        );
        assert_eq!(stats.bytes_sent, 12 + 11);
    }
}

#[test]
fn final_receives_and_deadlines_are_recycled_without_processing_responses() {
    let mut f = Fixture::new(1, "127.0.0.1:0", true);
    let before =
        unsafe { std::ptr::read_volatile(io_uring::types::BufRingEntry::tail(f.buffers.ring_ptr)) };
    let (submitter, mut sq, _) = f.ring.split();
    f.conns[0].arm_recv(&submitter, &mut sq, 0, &f.msg).unwrap();
    let deadline = uring::arm_deadline(&submitter, &mut sq, Some(Duration::from_secs(10))).unwrap();
    f.peer
        .send_to(b"unprocessed response", f.senders[0].local_addr().unwrap())
        .unwrap();
    sq.sync();
    uring::submit_and_wait_timeout(&submitter, Duration::from_secs(1), 1).unwrap();
    drop(sq);
    let mut stats = Stats::default();
    f.finish(&mut stats);
    let after =
        unsafe { std::ptr::read_volatile(io_uring::types::BufRingEntry::tail(f.buffers.ring_ptr)) };
    assert_eq!(
        after.wrapping_sub(before),
        1,
        "return the selected receive buffer"
    );
    assert_eq!(
        (
            stats.bytes_sent,
            stats.bytes_received,
            stats.completed,
            stats.errors
        ),
        (0, 0, 0, 0)
    );
    assert!(stats.latencies_ns.is_empty() && !f.conns[0].pending);
    drop(deadline);
}
