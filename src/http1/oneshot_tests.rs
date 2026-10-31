use super::*;

fn single(entries: u16) -> Fixture {
    let mut f = Fixture::with_buffers(entries);
    f.conn.recv_single = true;
    f
}

fn receive(f: &mut Fixture) -> io_uring::cqueue::Entry {
    let cqes = f.completions();
    assert_eq!(cqes.len(), 1);
    let cqe = cqes.into_iter().next().unwrap();
    assert_eq!(
        cqe.user_data(),
        uring::user_data(0, f.conn.generation, OP_RECV)
    );
    assert!(!cqueue::more(cqe.flags()), "single receive must terminate");
    f.conn.recv_armed = false;
    cqe
}

#[test]
fn single_receive_rearms_fragments_and_recycles_one_buffer() {
    let mut f = single(1);
    f.conn.begin_request(None);
    for part in [
        &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
        &b"3\r\nabc\r\n"[..],
        &b"0\r\n\r\n"[..],
    ] {
        f.arm(true);
        assert!(!f.conn.io_quiescent());
        f.peer.write_all(part).unwrap();
        let cqe = receive(&mut f);
        assert_eq!(cqe.result() as usize, part.len());
        let bid = cqueue::buffer_select(cqe.flags()).unwrap();
        let bytes = f.buffers.data(bid, part.len());
        assert_eq!(bytes, part);
        let done = f.conn.parser.feed(bytes).unwrap();
        assert_eq!(done, usize::from(part == b"0\r\n\r\n"));
        f.buffers.recycle(bid);
        assert!(f.conn.io_quiescent());
    }
    f.retire();
    let mut byte = [0];
    assert_eq!(f.peer.read(&mut byte).unwrap(), 0);
    assert!(f.completions().is_empty());
}

#[test]
fn single_receive_enobufs_is_terminal_and_recycling_recovers() {
    let mut f = single(1);
    f.arm(true);
    f.peer.write_all(b"first").unwrap();
    let first = receive(&mut f);
    assert_eq!(first.result(), 5);
    // Withhold the sole buffer while another receive tries to select it.
    f.arm(true);
    f.peer.write_all(b"second").unwrap();
    let exhausted = receive(&mut f);
    assert_eq!(exhausted.result(), -libc::ENOBUFS);
    assert!(cqueue::buffer_select(exhausted.flags()).is_none());
    f.recycle(&[first]);
    f.arm(true);
    let recovered = receive(&mut f);
    assert_eq!(recovered.result(), 6);
    let bid = cqueue::buffer_select(recovered.flags()).unwrap();
    assert_eq!(f.buffers.data(bid, 6), b"second");
    f.buffers.recycle(bid);
    f.retire();
}

#[test]
fn single_receive_retirement_cancels_queued_and_submitted_rearms() {
    for submitted in [false, true] {
        let mut f = single(1);
        f.arm(submitted);
        f.retire();
        // No SQE may remain to resolve the replacement slot. Deferred task
        // work can publish the cancellation CQE on the next enter even though
        // synchronous cancellation has already ended the receive itself.
        assert!(f.ring.submission().is_empty());
        let cqes = f.completions();
        assert!(cqes.iter().any(|c| c.result() == -libc::ECANCELED
            && c.user_data() == uring::user_data(0, 0, OP_RECV)
            && !cqueue::more(c.flags())));
        f.recycle(&cqes);
        let mut byte = [0];
        assert_eq!(f.peer.read(&mut byte).unwrap(), 0);
        let _old_peer = f.reconnect();
        assert!(f.conn.recv_single);
        f.arm(true);
        f.peer.write_all(b"replacement").unwrap();
        let next = receive(&mut f);
        assert_eq!(next.result(), 11);
        let bid = cqueue::buffer_select(next.flags()).unwrap();
        assert_eq!(f.buffers.data(bid, 11), b"replacement");
        f.buffers.recycle(bid);
        f.retire();
    }
}

#[test]
fn single_receive_stale_selected_buffer_survives_slot_reuse() {
    let mut f = single(1);
    f.arm(true);
    f.peer.write_all(b"old").unwrap();
    let old = f.completions();
    assert_eq!(old.len(), 1);
    assert_eq!(old[0].result(), 3);
    // Leave recv_armed set, as if the worker had not dispatched this CQE.
    f.retire();
    let _old_peer = f.reconnect();
    let (_, _, generation) = uring::decode_user_data(old[0].user_data());
    assert_ne!(generation, f.conn.generation);
    // The stale-generation path must return the selected buffer even though
    // it may no longer feed bytes into the connection's parser.
    f.recycle(&old);
    f.arm(true);
    f.peer.write_all(b"new").unwrap();
    let next = receive(&mut f);
    let bid = cqueue::buffer_select(next.flags()).unwrap();
    assert_eq!(f.buffers.data(bid, next.result() as usize), b"new");
    f.buffers.recycle(bid);
    f.retire();
}

#[test]
fn terminal_response_does_not_bypass_a_queued_upload() {
    let mut f = single(1);
    f.arm(true);
    f.peer
        .write_all(b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\n\r\n")
        .unwrap();
    let response = receive(&mut f);
    f.recycle(&[response]);
    let request = b"POST / HTTP/1.1\r\nContent-Length: 7\r\n\r\npayload";
    {
        let (submitter, mut sq, _) = f.ring.split();
        queue_and_flush_request(&submitter, &mut sq, 0, &mut f.conn, request).unwrap();
    }
    assert!(!f.conn.io_quiescent());
    f.retire();
    let cqes: Vec<_> = f.ring.completion().collect();
    assert!(
        cqes.iter()
            .any(|c| c.user_data() == uring::user_data(0, 0, OP_SEND)
                && c.result() as usize == request.len())
    );
    let mut got = Vec::new();
    f.peer.read_to_end(&mut got).unwrap();
    assert_eq!(got, request);
}

fn worker_response(method: &str, parts: Vec<Vec<u8>>, eof: bool, success: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let target =
        crate::target::parse_target(&format!("http://{addr}/"), method, &[], None, true).unwrap();
    let expected = target.request_bytes.clone();
    let received: usize = parts.iter().map(Vec::len).sum();
    let server = std::thread::spawn(move || {
        for _ in 0..8 {
            let (mut peer, _) = listener.accept().unwrap();
            peer.set_nodelay(true).unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            peer.set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = vec![0; expected.len()];
            peer.read_exact(&mut request).unwrap();
            assert_eq!(request, expected);
            for part in &parts {
                peer.write_all(part).unwrap();
                std::thread::sleep(Duration::from_millis(2));
            }
            if eof {
                peer.shutdown(std::net::Shutdown::Write).unwrap();
            }
            let mut byte = [0];
            assert_eq!(peer.read(&mut byte).unwrap(), 0);
        }
    });
    let stats = run_worker(
        &target,
        None,
        1,
        Budget::Requests(8),
        Duration::from_secs(2),
        Some(Duration::from_secs(5)),
    )
    .unwrap();
    server.join().unwrap();
    let ok = if success { 8 } else { 0 };
    assert_eq!(
        (stats.completed, stats.errors, stats.connect_errors),
        (ok, 8 - ok, 0)
    );
    assert_eq!(stats.status_counts[200], ok);
    assert_eq!(stats.latencies_ns.len() as u64, ok);
    assert_eq!(stats.bytes_sent, 8 * target.request_bytes.len() as u64);
    assert_eq!(stats.bytes_received, 8 * received as u64);
}

#[test]
fn single_receive_worker_preserves_fragment_head_eof_and_chunked_accounting() {
    for (method, wire, eof, success) in [
        ("GET", &b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc"[..], false, true),
        ("HEAD", &b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n"[..], false, true),
        ("GET", &b"HTTP/1.1 200 OK\r\n\r\nabc"[..], true, true),
        ("GET", &b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabc"[..], true, false),
        ("GET", &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-Trailer: yes\r\n\r\n"[..], false, true),
    ] {
        worker_response(method, wire.chunks(7).map(<[u8]>::to_vec).collect(), eof, success);
    }
}

#[test]
fn single_receive_worker_reads_bodies_larger_than_the_buffer() {
    let body = vec![b'x'; 3 * crate::buf_ring::RECV_BUF_SIZE + 1];
    let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
    worker_response("GET", vec![header.into_bytes(), body], false, true);
}
