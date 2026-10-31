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
        push_recv(&submitter, &mut sq, 0, &mut self.conn).unwrap();
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
        let mut timeout_finished = false;
        for _ in 0..100 {
            let cqes = self.completions();
            for cqe in &cqes {
                if cqe.user_data() == uring::user_data(0, self.conn.generation, OP_CONNECT) {
                    assert_eq!(cqe.result(), 0);
                    connected = true;
                    self.conn.connected = true;
                }
                if cqe.user_data() == uring::user_data(0, self.conn.generation, OP_CONNECT_TIMEOUT)
                {
                    assert_eq!(cqe.result(), -libc::ECANCELED);
                    timeout_finished = true;
                }
            }
            self.recycle(&cqes);
            // Deferred task work may publish the linked timeout after the
            // Connect CQE. Leave no setup CQEs for the next receive assertion.
            if connected && timeout_finished {
                break;
            }
        }
        assert!(connected && timeout_finished);
        let (peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        std::mem::replace(&mut self.peer, peer)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Do not mutate borrowed ciphertext on a failed assertion. Close the
        // raw fd only; declaration order destroys the ring before its storage.
        if self.conn.fd >= 0 {
            drop(unsafe { TcpStream::from_raw_fd(self.conn.fd) });
            self.conn.fd = -1;
        }
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
        let request = b"GET /old HTTP/1.1\r\nHost: localhost\r\n\r\n";
        if tls {
            f.conn.tls = Some(
                TlsSession::new(&crate::tls::setup("localhost", b"http/1.1").unwrap()).unwrap(),
            );
        }
        {
            let (submitter, mut sq, _) = f.ring.split();
            queue_and_flush_request(&submitter, &mut sq, 0, &mut f.conn, request).unwrap();
        }
        let sent = f.conn.outbound(request).to_vec();
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
        // A replacement uses the new generation and request bytes, for both
        // the shared plain request and connection-owned TLS output paths.
        let request = b"GET /replacement HTTP/1.1\r\nHost: localhost\r\n\r\n";
        if tls {
            f.conn.tls = Some(
                TlsSession::new(&crate::tls::setup("localhost", b"http/1.1").unwrap()).unwrap(),
            );
        }
        {
            let (submitter, mut sq, _) = f.ring.split();
            queue_and_flush_request(&submitter, &mut sq, 0, &mut f.conn, request).unwrap();
        }
        let expected = f.conn.outbound(request).to_vec();
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
    f.conn.recv_single = true;
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
    f.conn.recv_single = true;
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
    for single in [false, true] {
        blocked_send_retirement(single);
    }
}

fn blocked_send_retirement(single: bool) {
    let mut f = Fixture::new();
    f.conn.recv_single = single;
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
    if !single {
        f.conn.tls =
            Some(TlsSession::new(&crate::tls::setup("localhost", b"http/1.1").unwrap()).unwrap());
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

fn server_config() -> std::sync::Arc<rustls::ServerConfig> {
    server_config_for(rustls::DEFAULT_VERSIONS)
}

fn server_config_for(
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> std::sync::Arc<rustls::ServerConfig> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    std::sync::Arc::new(
        rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key.into())
        .unwrap(),
    )
}

fn request_then_eof(peer: &mut (impl Read + Write), expected: &[u8], answer: bool) {
    let mut request = vec![0; expected.len()];
    peer.read_exact(&mut request).unwrap();
    assert_eq!(request, expected);
    if answer {
        peer.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .unwrap();
        peer.flush().unwrap();
    }
    let mut byte = [0];
    assert_eq!(peer.read(&mut byte).unwrap(), 0, "retired socket retained");
}

fn close_worker(tls: bool, expire_first: bool, disable_keepalive: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let scheme = if tls { "https" } else { "http" };
    let target = crate::target::parse_target(
        &format!("{scheme}://{address}/"),
        "GET",
        &[],
        None,
        disable_keepalive,
    )
    .unwrap();
    let expected = target.request_bytes.clone();
    let config = tls.then(server_config);
    let server = std::thread::spawn(move || {
        // Do not service a replacement until the previous socket has closed.
        // A TLS alert alone is insufficient: also check for the TCP FIN.
        for i in 0..4 {
            let (mut peer, _) = listener.accept().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            peer.set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            if let Some(config) = &config {
                let mut session = rustls::ServerConnection::new(config.clone()).unwrap();
                request_then_eof(
                    &mut rustls::Stream::new(&mut session, &mut peer),
                    &expected,
                    !expire_first || i != 0,
                );
                assert!(session.process_new_packets().unwrap().peer_has_closed());
                let mut byte = [0];
                assert_eq!(peer.read(&mut byte).unwrap(), 0, "TLS socket retained");
            } else {
                request_then_eof(&mut peer, &expected, !expire_first || i != 0);
            }
        }
    });
    let setup = tls.then(|| crate::tls::setup("localhost", b"http/1.1").unwrap());
    let stats = run_worker(
        &target,
        setup.as_ref(),
        1,
        Budget::Requests(4),
        Duration::from_secs(1),
        Some(Duration::from_millis(if expire_first { 500 } else { 5000 })),
    )
    .unwrap();
    server.join().unwrap();
    let errors = u64::from(expire_first);
    assert_eq!(
        (stats.completed, stats.errors, stats.connect_errors),
        (4 - errors, errors, 0)
    );
    assert_eq!(stats.latencies_ns.len() as u64, 4 - errors);
    assert_eq!(stats.status_counts[200], 4 - errors);
    assert_eq!(stats.status_counts.iter().sum::<u64>(), 4 - errors);
}

#[test]
fn close_releases_each_plain_socket_before_the_replacement_answers() {
    close_worker(false, false, false);
}

#[test]
fn close_notify_and_tcp_fin_precede_the_replacement_tls_response() {
    close_worker(true, false, false);
}

#[test]
fn timeout_releases_each_socket_and_preserves_the_request_budget() {
    for tls in [false, true] {
        close_worker(tls, true, false);
        close_worker(tls, true, true);
    }
}

#[test]
fn partial_tls_upload_timeout_closes_before_a_complete_replacement_upload() {
    for established in [false, true] {
        partial_tls_upload_timeout(established);
    }
}

fn partial_tls_upload_timeout(established: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    // Far larger than the TCP buffers, with a pattern that exposes a spliced
    // prefix or reused ciphertext rather than merely checking a byte count.
    let body: Vec<_> = (0..8 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let target = crate::target::parse_target(
        &format!("https://{address}/"),
        "POST",
        &[],
        Some(&body),
        false,
    )
    .unwrap();
    let expected = target.request_bytes.clone();
    let config = server_config();
    let server = std::thread::spawn(move || {
        let (mut first, _) = listener.accept().unwrap();
        first
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        first
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut session = rustls::ServerConnection::new(config.clone()).unwrap();
        let mut stream = rustls::Stream::new(&mut session, &mut first);
        if established {
            let mut complete = vec![0; expected.len()];
            stream.read_exact(&mut complete).unwrap();
            assert_eq!(complete, expected);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
            stream.flush().unwrap();
        }
        let mut prefix = [0; 1024];
        stream.read_exact(&mut prefix).unwrap();
        assert_eq!(prefix, expected[..prefix.len()]);
        // Stop reading until the request expires. A send remains blocked;
        // retirement must cancel it without appending close_notify to a
        // partially transmitted TLS record.
        std::thread::sleep(Duration::from_millis(1250));
        let mut received = prefix.to_vec();
        let mut bytes = [0; 32768];
        loop {
            match stream.read(&mut bytes) {
                Ok(0) => panic!("partial TLS upload must not send close_notify"),
                Ok(n) => received.extend_from_slice(&bytes[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => panic!("partial TLS upload did not retire cleanly: {e}"),
            }
        }
        assert!(received.len() < expected.len(), "upload was not blocked");
        assert_eq!(received, expected[..received.len()]);
        // No alert was spliced into the partial record. The exact replacement
        // request must now arrive on a fresh TLS connection.
        let (mut second, _) = listener.accept().unwrap();
        second
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        second
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut session = rustls::ServerConnection::new(config).unwrap();
        request_then_eof(
            &mut rustls::Stream::new(&mut session, &mut second),
            &expected,
            true,
        );
        assert!(session.process_new_packets().unwrap().peer_has_closed());
        assert_eq!(second.read(&mut [0]).unwrap(), 0);
    });
    let setup = crate::tls::setup("localhost", b"http/1.1").unwrap();
    let stats = run_worker(
        &target,
        Some(&setup),
        1,
        Budget::Requests(2 + u64::from(established)),
        Duration::from_secs(5),
        Some(Duration::from_secs(1)),
    )
    .unwrap();
    server.join().unwrap();
    assert_eq!(
        (stats.completed, stats.errors, stats.connect_errors),
        (1 + u64::from(established), 1, 0)
    );
    assert_eq!(stats.latencies_ns.len(), 1 + usize::from(established));
    assert_eq!(stats.status_counts[200], 1 + u64::from(established));
    assert_eq!(
        stats.status_counts.iter().sum::<u64>(),
        1 + u64::from(established)
    );
}

#[test]
fn early_responses_preserve_complete_plain_and_tls_upload_order() {
    for tls in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let body: Vec<_> = (0..4 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        let scheme = if tls { "https" } else { "http" };
        let target = crate::target::parse_target(
            &format!("{scheme}://{address}/"),
            "POST",
            &[],
            Some(&body),
            false,
        )
        .unwrap();
        let expected = target.request_bytes.clone();
        let server = std::thread::spawn(move || {
            let (peer, _) = listener.accept().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            peer.set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut stream: Box<dyn ReadWrite> = if tls {
                Box::new(rustls::StreamOwned::new(
                    rustls::ServerConnection::new(server_config()).unwrap(),
                    peer,
                ))
            } else {
                Box::new(peer)
            };
            for i in 0..3 {
                let mut prefix = [0; 1024];
                stream.read_exact(&mut prefix).unwrap();
                assert_eq!(prefix, expected[..prefix.len()]);
                if i < 2 {
                    stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        .unwrap();
                    stream.flush().unwrap();
                    std::thread::sleep(Duration::from_millis(50));
                }
                let mut remaining = vec![0; expected.len() - prefix.len()];
                stream.read_exact(&mut remaining).unwrap();
                assert_eq!(remaining, expected[prefix.len()..]);
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .unwrap();
            stream.flush().unwrap();
            assert_eq!(stream.read(&mut [0]).unwrap(), 0);
        });
        let setup = tls.then(|| crate::tls::setup("localhost", b"http/1.1").unwrap());
        let stats = run_worker(
            &target,
            setup.as_ref(),
            1,
            Budget::Requests(3),
            Duration::from_secs(5),
            Some(Duration::from_secs(5)),
        )
        .unwrap();
        server.join().unwrap();
        assert_eq!(
            (stats.completed, stats.errors, stats.connect_errors),
            (3, 0, 0)
        );
        assert_eq!(stats.latencies_ns.len(), 3);
        assert_eq!(stats.status_counts[200], 3);
        assert!(stats.bytes_sent >= 3 * target.request_bytes.len() as u64);
    }
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

fn decrypt_upload(server: &mut rustls::ServerConnection, mut wire: &[u8]) -> Vec<u8> {
    let mut received = Vec::new();
    while !wire.is_empty() {
        assert!(server.read_tls(&mut wire).unwrap() > 0);
        server.process_new_packets().unwrap();
        loop {
            let mut scratch = [0; 997];
            match server.reader().read(&mut scratch) {
                Ok(0) => break,
                Ok(n) => received.extend_from_slice(&scratch[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("upload decrypt failed: {e}"),
            }
        }
    }
    received
}

fn establish_tls(
    f: &mut Fixture,
    version: &'static rustls::SupportedProtocolVersion,
) -> rustls::ServerConnection {
    let mut tls = TlsSession::new(&crate::tls::setup("localhost", b"http/1.1").unwrap()).unwrap();
    let mut peer = rustls::ServerConnection::new(server_config_for(&[version])).unwrap();
    for _ in 0..16 {
        let sent = tls.take_ciphertext().unwrap();
        assert!(decrypt_upload(&mut peer, &sent).is_empty());
        let mut reply = Vec::new();
        while peer.wants_write() {
            peer.write_tls(&mut reply).unwrap();
        }
        tls.feed_into(&reply, &mut [0; 1024], |_| panic!("unexpected response"))
            .unwrap();
        if sent.is_empty() && reply.is_empty() {
            assert!(!tls.is_handshaking());
            assert!(!peer.is_handshaking());
            f.conn.tls = Some(tls);
            return peer;
        }
    }
    panic!("handshake did not finish");
}

#[test]
fn next_tls_request_preserves_pending_send_storage_and_clock() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let mut f = Fixture::new();
        let mut peer = establish_tls(&mut f, version);
        let first = b"GET /first HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let next: Vec<_> = (0..131073).map(|i| (i % 251) as u8).collect();
        f.conn.begin_request(Some(Duration::from_secs(5)));
        let deadline = f.conn.deadline;
        {
            let (submitter, mut sq, _) = f.ring.split();
            queue_and_flush_request(&submitter, &mut sq, 0, &mut f.conn, first).unwrap();
        }
        assert!(f.conn.sending && !f.conn.unsent && f.conn.active);
        assert_eq!(f.conn.deadline, deadline);
        let wire = f.conn.out.clone();
        assert!(
            !wire.is_empty(),
            "prepared ciphertext was cleared before submission"
        );
        let storage = (f.conn.out.as_ptr(), f.conn.out.capacity(), f.conn.out_off);
        let first_start = f.conn.request_start;

        // A response may finish before its Send CQE is processed. Queuing the
        // next request must neither rewrite the old ciphertext nor start the
        // next latency clock. Leave the SQE queued to make this deterministic.
        f.conn.end_request();
        f.conn.begin_request(Some(Duration::from_secs(7)));
        let next_deadline = f.conn.deadline;
        {
            let (submitter, mut sq, _) = f.ring.split();
            queue_and_flush_request(&submitter, &mut sq, 0, &mut f.conn, &next).unwrap();
            flush(&submitter, &mut sq, 0, &mut f.conn, &next).unwrap();
            assert_eq!(sq.len(), 1);
        }
        assert_eq!(f.conn.out, wire);
        assert_eq!(
            (f.conn.out.as_ptr(), f.conn.out.capacity(), f.conn.out_off),
            storage
        );
        assert!(f.conn.unsent && f.conn.active);
        assert_eq!(f.conn.request_start, first_start);
        assert_eq!(f.conn.deadline, next_deadline);

        let cqes = f.completions();
        assert_eq!(cqes.len(), 1);
        assert_eq!(cqes[0].user_data(), uring::user_data(0, 0, OP_SEND));
        assert_eq!(cqes[0].result() as usize, wire.len());
        let mut received = vec![0; wire.len()];
        f.peer.read_exact(&mut received).unwrap();
        assert_eq!(received, wire);
        assert_eq!(decrypt_upload(&mut peer, &received), first);
        f.conn.sending = false;
        {
            let (submitter, mut sq, _) = f.ring.split();
            flush(&submitter, &mut sq, 0, &mut f.conn, &next).unwrap();
        }
        assert!(!f.conn.unsent && f.conn.sending);
        assert!(f.conn.request_start >= first_start);
        assert_eq!(f.conn.deadline, next_deadline);
        let wire = f.conn.out.clone();
        let mut received = Vec::new();
        while f.conn.out_off < wire.len() {
            let cqes = f.completions();
            assert_eq!(cqes.len(), 1);
            assert_eq!(cqes[0].user_data(), uring::user_data(0, 0, OP_SEND));
            assert!(cqes[0].result() > 0);
            let n = cqes[0].result() as usize;
            let mut part = vec![0; n];
            f.peer.read_exact(&mut part).unwrap();
            received.extend_from_slice(&part);
            f.conn.out_off += n;
            if f.conn.out_off < wire.len() {
                let (submitter, mut sq, _) = f.ring.split();
                uring::push_send_slice(&submitter, &mut sq, 0, 0, &f.conn.out[f.conn.out_off..])
                    .unwrap();
            }
        }
        assert_eq!(received, wire);
        assert_eq!(decrypt_upload(&mut peer, &received), next);
        f.conn.sending = false;
        {
            let (submitter, mut sq, _) = f.ring.split();
            flush(&submitter, &mut sq, 0, &mut f.conn, &next).unwrap();
            assert!(sq.is_empty(), "request was submitted twice");
        }
        f.retire();
    }
}

#[test]
fn complete_tls_uploads_preserve_keepalive_bytes_and_every_sample() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for size in [256, 16384, 1048576] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let body: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
            let target = crate::target::parse_target(
                &format!("https://{}/", listener.local_addr().unwrap()),
                "POST",
                &[],
                Some(&body),
                false,
            )
            .unwrap();
            let expected = target.request_bytes.clone();
            let server = std::thread::spawn(move || {
                let (socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut stream = rustls::StreamOwned::new(
                    rustls::ServerConnection::new(server_config_for(&[version])).unwrap(),
                    socket,
                );
                for i in 0..3 {
                    let mut got = vec![0; expected.len()];
                    stream.read_exact(&mut got).unwrap();
                    assert_eq!(got, expected);
                    stream
                        .write_all(if i == 2 {
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        } else {
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
                        })
                        .unwrap();
                    stream.flush().unwrap();
                }
                assert_eq!(stream.read(&mut [0]).unwrap(), 0);
            });
            let setup = crate::tls::setup("localhost", b"http/1.1").unwrap();
            let stats = run_worker(
                &target,
                Some(&setup),
                1,
                Budget::Requests(3),
                Duration::from_secs(5),
                Some(Duration::from_secs(5)),
            )
            .unwrap();
            server.join().unwrap();
            assert_eq!(
                (stats.completed, stats.errors, stats.connect_errors),
                (3, 0, 0)
            );
            assert_eq!(stats.latencies_ns.len(), 3);
            assert_eq!(stats.status_counts[200], 3);
            assert_eq!(stats.status_counts.iter().sum::<u64>(), 3);
            assert!(stats.bytes_sent >= 3 * target.request_bytes.len() as u64);
        }
    }
}

#[path = "oneshot_tests.rs"]
mod oneshot_tests;
