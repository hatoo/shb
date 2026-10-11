use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::fd::IntoRawFd;

struct Fixture {
    // Fields drop in declaration order, including after a failed assertion.
    ring: io_uring::IoUring,
    buffers: BufRing,
    conn: Conn,
    peer: TcpStream,
}

impl Fixture {
    fn new() -> Self {
        Self::with_buffers(8)
    }

    fn with_buffers(entries: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        socket.set_nodelay(true).unwrap();
        let buffers = BufRing::new(entries).unwrap();
        let mut conn = Conn::new();
        conn.fd = socket.into_raw_fd();
        conn.connected = true;
        let mut ring = uring::build_worker_ring(1).unwrap();
        let (submitter, _, _) = ring.split();
        let submitter = uring::register_worker(submitter, 1, &buffers).unwrap();
        submitter.register_files_update(0, &[conn.fd]).unwrap();
        drop(submitter);
        Self {
            ring,
            buffers,
            conn,
            peer,
        }
    }

    fn arm(&mut self, submit: bool) {
        let (submitter, mut sq, _) = self.ring.split();
        uring::push_recv_multi(&submitter, &mut sq, 0, self.conn.generation).unwrap();
        self.conn.recv_armed = true;
        if submit {
            sq.sync();
            submitter.submit().unwrap();
        }
    }

    fn retire(&mut self) {
        let (submitter, mut sq, _) = self.ring.split();
        retire(&submitter, &mut sq, 0, &mut self.conn).unwrap();
    }

    fn completions(&mut self) -> Vec<io_uring::cqueue::Entry> {
        let (submitter, mut sq, mut cq) = self.ring.split();
        sq.sync();
        uring::submit_and_wait_timeout(&submitter, Duration::from_millis(20), 1).unwrap();
        cq.sync();
        cq.collect()
    }

    fn recycle(&mut self, cqes: &[io_uring::cqueue::Entry]) {
        for cqe in cqes {
            if let Some(bid) = cqueue::buffer_select(cqe.flags()) {
                self.buffers.recycle(bid);
            }
        }
    }

    fn reconnect(&mut self) -> TcpStream {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let raw_addr = socket2::SockAddr::from(addr);
        let timeout = types::Timespec::from(Duration::from_secs(2));
        {
            let (submitter, mut sq, _) = self.ring.split();
            self.conn.fd = uring::start_connect(
                &submitter,
                &mut sq,
                0,
                self.conn.generation,
                &addr,
                &raw_addr,
                &timeout,
            )
            .unwrap();
        }
        let mut connected = false;
        for _ in 0..100 {
            let cqes = self.completions();
            for cqe in &cqes {
                if cqe.user_data() == uring::user_data(0, self.conn.generation, OP_CONNECT) {
                    assert_eq!(cqe.result(), 0);
                    connected = true;
                }
            }
            self.recycle(&cqes);
            if connected {
                break;
            }
        }
        assert!(connected);
        self.conn.connected = true;
        let (peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        std::mem::replace(&mut self.peer, peer)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // close does not deallocate out; the ring is then dropped first.
        self.conn.close();
    }
}

#[test]
fn retirement_cancels_queued_and_submitted_receives_and_releases_the_socket() {
    for submitted in [false, true] {
        let mut f = Fixture::new();
        f.arm(submitted);
        f.retire();
        let cqes = f.completions();
        f.recycle(&cqes);
        assert!(
            cqes.iter()
                .any(|c| c.user_data() == uring::user_data(0, 0, OP_RECV)
                    && c.result() == -libc::ECANCELED
                    && !cqueue::more(c.flags())),
            "old receive must be terminal before socket reuse (submitted={submitted})"
        );
        let mut byte = [0];
        assert_eq!(
            f.peer.read(&mut byte).unwrap(),
            0,
            "peer observes EOF before ring teardown"
        );
    }
}

#[test]
fn retirement_completes_a_queued_send_before_clearing_its_storage() {
    for tls in [false, true] {
        let mut f = Fixture::new();
        let mut h2 = Connection::new();
        if tls {
            f.conn.tls =
                Some(TlsSession::new(&crate::tls::setup("localhost", b"h2").unwrap()).unwrap());
        } else {
            h2.initiate();
        }
        f.conn.h2 = Some(h2);
        {
            let (submitter, mut sq, _) = f.ring.split();
            flush(&submitter, &mut sq, 0, &mut f.conn).unwrap();
        }
        let sent = f.conn.out.clone();
        f.retire();
        // Read the CQ without submitting anything: retire must consume the queued
        // SQE and finish/cancel its access to out before close clears it.
        let cqes: Vec<_> = f.ring.completion().collect();
        assert!(
            cqes.iter()
                .any(|c| c.user_data() == uring::user_data(0, 0, OP_SEND)
                    && c.result() == sent.len() as i32),
            "queued send still references cleared storage"
        );
        let mut received = Vec::new();
        f.peer.read_to_end(&mut received).unwrap();
        assert_eq!(received, sent);
        let _old_peer = f.reconnect();
        // Replacing the output allocation must not feed the previous socket or
        // reuse its send identity, for either h2 plaintext or TLS ciphertext.
        let mut next = Connection::new();
        next.initiate();
        f.conn.h2 = Some(next);
        {
            let (submitter, mut sq, _) = f.ring.split();
            flush(&submitter, &mut sq, 0, &mut f.conn).unwrap();
        }
        let expected = f.conn.out.clone();
        let cqes = f.completions();
        assert!(
            cqes.iter()
                .any(|c| c.user_data() == uring::user_data(0, 1, OP_SEND)
                    && c.result() as usize == expected.len())
        );
        let mut got = vec![0; expected.len()];
        f.peer.read_exact(&mut got).unwrap();
        assert_eq!(got, expected);
        f.retire();
    }
}

#[test]
fn terminal_receives_and_enobufs_rearms_do_not_cross_reconnects() {
    for enobufs in [false, true] {
        for rearm in [false, true] {
            let mut f = Fixture::with_buffers(1);
            f.arm(true);
            f.peer.write_all(b"old generation").unwrap();
            let first = f.completions();
            assert_eq!(first.len(), 1);
            assert!(first[0].result() > 0);
            assert!(cqueue::more(first[0].flags()));
            if enobufs {
                // Withhold the selected buffer, forcing the next receive to
                // terminate with ENOBUFS before recycling it below.
                f.peer.write_all(b"still old").unwrap();
            } else {
                f.recycle(&first);
                f.peer.shutdown(std::net::Shutdown::Write).unwrap();
            }
            let terminal = f.completions();
            assert_eq!(terminal.len(), 1);
            assert_eq!(
                terminal[0].result(),
                if enobufs { -libc::ENOBUFS } else { 0 }
            );
            assert!(!cqueue::more(terminal[0].flags()));
            if enobufs {
                f.recycle(&first);
            }
            f.recycle(&terminal);
            f.conn.recv_armed = false;
            if rearm {
                f.arm(false);
            }
            f.retire();
            let _old_peer = f.reconnect();
            f.arm(true);
            f.peer.write_all(b"new generation").unwrap();
            let cqes = f.completions();
            let mut bytes = Vec::new();
            for cqe in &cqes {
                if let Some(bid) = cqueue::buffer_select(cqe.flags()) {
                    assert_eq!(cqe.user_data(), uring::user_data(0, 1, OP_RECV));
                    bytes.extend_from_slice(f.buffers.data(bid, cqe.result() as usize));
                }
            }
            f.recycle(&cqes);
            assert_eq!(bytes, b"new generation");
            f.retire();
        }
    }
}

fn connect_completions(f: &mut Fixture) -> Vec<io_uring::cqueue::Entry> {
    let mut cqes = Vec::new();
    // With deferred task work the linked timeout can be posted by a later
    // enter than its connect. Neither may remain alive until its 30s deadline.
    for _ in 0..50 {
        cqes.extend(f.completions());
        if cqes.len() >= 2 {
            break;
        }
    }
    cqes
}

#[test]
fn retirement_finishes_a_queued_connect_and_its_linked_timeout() {
    let mut f = Fixture::new();
    f.retire();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let raw_addr = socket2::SockAddr::from(addr);
    let timeout = types::Timespec::from(Duration::from_secs(30));
    {
        let (submitter, mut sq, _) = f.ring.split();
        f.conn.fd =
            uring::start_connect(&submitter, &mut sq, 0, 1, &addr, &raw_addr, &timeout).unwrap();
    }
    f.retire();
    assert!(
        f.ring.submission().is_empty(),
        "connect cannot remain queued across retirement"
    );
    let cqes = connect_completions(&mut f);
    for op in [OP_CONNECT, OP_CONNECT_TIMEOUT] {
        assert_eq!(
            cqes.iter()
                .filter(|c| c.user_data() == uring::user_data(0, 1, op))
                .count(),
            1
        );
    }
    assert!(
        cqes.iter()
            .all(|c| c.result() == 0 || c.result() == -libc::ECANCELED)
    );
}

#[test]
fn retirement_cancels_a_pending_connect_and_its_linked_timeout() {
    let mut f = Fixture::new();
    f.retire();
    let listener =
        socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    listener
        .bind(
            &"127.0.0.1:0"
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .into(),
        )
        .unwrap();
    listener.listen(0).unwrap();
    let raw_addr = listener.local_addr().unwrap();
    let addr = raw_addr.as_socket().unwrap();
    // Fill the listener's one backlog entry without accepting it. A second
    // connection now waits in SYN_SENT; no unreachable external host needed.
    let _first = TcpStream::connect(addr).unwrap();
    let timeout = types::Timespec::from(Duration::from_secs(30));
    {
        let (submitter, mut sq, _) = f.ring.split();
        f.conn.fd =
            uring::start_connect(&submitter, &mut sq, 0, 1, &addr, &raw_addr, &timeout).unwrap();
    }
    assert!(
        f.completions().is_empty(),
        "connect must be pending before retirement"
    );
    f.retire();
    let cqes = connect_completions(&mut f);
    for op in [OP_CONNECT, OP_CONNECT_TIMEOUT] {
        let cqe = cqes
            .iter()
            .find(|c| c.user_data() == uring::user_data(0, 1, op))
            .unwrap();
        assert_eq!(cqe.result(), -libc::ECANCELED);
    }
}

#[test]
fn retirement_cancels_a_blocked_send_before_reusing_its_storage() {
    let mut f = Fixture::new();
    let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(f.conn.fd) };
    let socket = socket2::SockRef::from(&borrowed);
    socket.set_send_buffer_size(4096).unwrap();
    socket.set_nonblocking(true).unwrap();
    socket2::SockRef::from(&f.peer)
        .set_recv_buffer_size(4096)
        .unwrap();
    let fill = [0x35; 65536];
    loop {
        let n = unsafe {
            libc::send(
                f.conn.fd,
                fill.as_ptr().cast(),
                fill.len(),
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if n < 0 {
            assert_eq!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::WouldBlock
            );
            break;
        }
    }
    f.conn.out = vec![0x76; 4 * 1024 * 1024];
    f.conn.sending = true;
    loop {
        {
            let (submitter, mut sq, _) = f.ring.split();
            uring::push_send_slice(&submitter, &mut sq, 0, 0, &f.conn.out[f.conn.out_off..])
                .unwrap();
        }
        let cqes = f.completions();
        if cqes.is_empty() {
            break;
        }
        assert_eq!(cqes.len(), 1);
        assert!(cqes[0].result() > 0);
        f.conn.out_off += cqes[0].result() as usize;
        assert!(
            f.conn.out_off < f.conn.out.len(),
            "test must leave a partial send pending"
        );
    }
    f.retire();
    let cqes = f.completions();
    assert!(
        cqes.iter()
            .any(|c| c.user_data() == uring::user_data(0, 0, OP_SEND)),
        "blocked send must stop borrowing out before it is cleared"
    );
    // No kernel reference remains, so growing/replacing out is safe now.
    f.conn.out = vec![0x92; 8 * 1024 * 1024];
}

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = (payload.len() as u32).to_be_bytes()[1..].to_vec();
    bytes.extend([kind, flags]);
    bytes.extend(stream.to_be_bytes());
    bytes.extend(payload);
    bytes
}

fn server_config() -> std::sync::Arc<rustls::ServerConfig> {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
    let mut config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![certified.cert.der().clone()], key.into())
    .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    std::sync::Arc::new(config)
}

fn answer_then_wait_for_eof(mut peer: impl Read + Write) {
    let mut preface = [0; 24];
    peer.read_exact(&mut preface).unwrap();
    assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    peer.write_all(&frame(4, 0, 0, &[])).unwrap();
    loop {
        let mut header = [0; 9];
        peer.read_exact(&mut header).unwrap();
        let len = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
        let mut payload = vec![0; len];
        peer.read_exact(&mut payload).unwrap();
        if header[3] == 1 {
            assert_eq!(header[4] & 5, 5);
            assert_eq!(&header[5..], &1u32.to_be_bytes());
            let mut response = frame(1, 5, 1, &[0x88]);
            response.extend(frame(7, 0, 0, &[0, 0, 0, 1, 0, 0, 0, 0]));
            peer.write_all(&response).unwrap();
            peer.flush().unwrap();
            break;
        }
    }
    // Keep the peer's write side open. A retired multishot receive must not
    // pin this socket until the replacement connection or worker finishes.
    let mut trailing = [0; 1024];
    loop {
        match peer.read(&mut trailing) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => panic!("client retained a retired socket: {e}"),
        }
    }
}

fn goaway_worker(tls: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let config = tls.then(server_config);
    let server = std::thread::spawn(move || {
        // Unlike a peer that immediately closes after GOAWAY, this detects
        // whether the worker actually releases each socket before moving on.
        for _ in 0..4 {
            let (mut peer, _) = listener.accept().unwrap();
            peer.set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
            peer.set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            if let Some(config) = &config {
                let mut session = rustls::ServerConnection::new(config.clone()).unwrap();
                answer_then_wait_for_eof(rustls::Stream::new(&mut session, &mut peer));
            } else {
                answer_then_wait_for_eof(peer);
            }
        }
    });
    let scheme = if tls { "https" } else { "http" };
    let target =
        crate::target::parse_target(&format!("{scheme}://{addr}/"), "GET", &[], None, false)
            .unwrap();
    let setup = tls.then(|| crate::tls::setup("localhost", b"h2").unwrap());
    let stats = run_worker(
        &target,
        setup.as_ref(),
        1,
        Budget::Requests(4),
        Duration::from_secs(1),
        Some(Duration::from_secs(2)),
        1,
    )
    .unwrap();
    server.join().unwrap();
    assert_eq!(
        (stats.completed, stats.errors, stats.connect_errors),
        (4, 0, 0)
    );
    assert_eq!(stats.latencies_ns.len(), 4);
    assert_eq!(stats.status_counts.iter().sum::<u64>(), 4);
}

#[test]
fn goaway_releases_each_plain_socket_before_the_replacement_answers() {
    goaway_worker(false);
}

#[test]
fn goaway_releases_each_tls_socket_before_the_replacement_answers() {
    goaway_worker(true);
}
