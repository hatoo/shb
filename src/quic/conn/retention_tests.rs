use super::*;

fn client() -> Connection {
    let mut conn = Connection::connect(
        crate::tls::client_config(b"h3").unwrap(),
        "localhost",
        LocalParamsInput {
            initial_max_data: 1 << 30,
            initial_max_stream_data: 1 << 20,
            initial_max_streams_uni: 3,
            max_idle_timeout_ms: 5000,
            handshake_timeout_ms: 5000,
        },
    )
    .unwrap();
    conn.max_streams_bidi = 1 << 40;
    conn.max_data_peer = 1 << 30;
    conn.params.initial_max_stream_data_bidi_remote = 1 << 20;
    conn
}

fn send(conn: &mut Connection) -> Vec<SentFrame> {
    let mut out = Vec::new();
    let mut frames = Vec::new();
    conn.fill_data_payload(&mut out, 1200, 0, &mut frames, false)
        .unwrap();
    frames
}

fn answer(conn: &mut Connection, id: u64) {
    conn.on_stream(id, 0, b"reply", true).unwrap();
    assert_eq!(
        conn.consume(id, |data| {
            assert_eq!(data, b"reply");
            Ok(())
        })
        .unwrap(),
        5
    );
    assert_eq!(conn.poll_event(), Some(Event::Readable(id)));
    assert_eq!(conn.poll_event(), Some(Event::Finished { id, reset: None }));
    assert!(conn.poll_event().is_none());
    conn.retire(id, 0x10c);
}

fn complete_higher(conn: &mut Connection, count: u64) {
    for _ in 0..count {
        let (id, n) = conn.send_oneshot(b"request").unwrap();
        assert_eq!(n, 7);
        for frame in send(conn) {
            conn.on_frame_acked(frame);
        }
        answer(conn, id);
        assert!(conn.stream_mut(id).is_none());
    }
}

#[test]
fn a_delayed_response_does_not_retain_all_completed_pairs() {
    let mut conn = client();
    for n in 0..32 {
        assert_eq!(conn.send_oneshot(b"request"), Some((n * 4, 7)));
    }
    for frame in send(&mut conn) {
        conn.on_frame_acked(frame);
    }
    for n in 32..100_032 {
        assert_eq!(conn.send_oneshot(b"request"), Some((n * 4, 7)));
        for frame in send(&mut conn) {
            conn.on_frame_acked(frame);
        }
        answer(&mut conn, (n - 31) * 4);
        assert_eq!(conn.unanswered, 32);
        assert!(conn.stream_mut(0).is_some());
    }
    assert_eq!(conn.data_sent, 100_032 * 7);
    assert_eq!(conn.data_received, 100_000 * 5);
    assert!(
        conn.streams.capacity() <= 128,
        "capacity {}",
        conn.streams.capacity()
    );
    answer(&mut conn, 0);
    for n in 100_001..100_032 {
        answer(&mut conn, n * 4);
    }
    assert_eq!(conn.unanswered, 0);
    assert_eq!(conn.streams.len(), 0);
    assert_eq!(conn.data_received, 100_032 * 5);
    assert_eq!(conn.spare_bufs.len(), 33);
    // Ordinary traffic after the gap closes still reuses the same buffers.
    complete_higher(&mut conn, 1000);
    assert_eq!(conn.spare_bufs.len(), 33);
    assert!(conn.streams.capacity() <= 64);
}

#[test]
fn retired_unacknowledged_pairs_survive_packing_and_sparse_loss() {
    let mut conn = client();
    let (id, _) = conn.send_oneshot(b"request").unwrap();
    let original = send(&mut conn);
    answer(&mut conn, id);
    complete_higher(&mut conn, 1000);
    assert!(conn.streams.capacity() <= 128);
    assert_eq!(conn.unanswered, 0);
    let pair = conn.stream_mut(id).unwrap();
    assert!(pair.retired);
    assert!(!pair.send.is_settled());
    let sent = conn.data_sent;
    conn.max_data_peer = sent;
    conn.on_frame_lost(Space::Data, original[0]);
    let data = send(&mut conn);
    let fin = send(&mut conn);
    assert_eq!(
        data,
        vec![SentFrame::Stream {
            id,
            offset: 0,
            len: 7,
            fin: false
        }]
    );
    assert_eq!(
        fin,
        vec![SentFrame::Stream {
            id,
            offset: 7,
            len: 0,
            fin: true
        }]
    );
    assert_eq!(
        conn.data_sent, sent,
        "retransmissions consume no fresh credit"
    );
    conn.on_frame_acked(fin[0]);
    assert!(
        conn.stream_mut(id).is_some(),
        "sparse ACK still leaves a data gap"
    );
    conn.on_frame_acked(data[0]);
    assert!(conn.stream_mut(id).is_none());
    // Late ACKs, loss and response copies must never resurrect a settled pair.
    conn.on_frame_acked(original[0]);
    conn.on_frame_lost(Space::Data, original[0]);
    conn.on_stream(id, 0, b"reply", true).unwrap();
    conn.on_reset(id, 0x10c, 5).unwrap();
    assert!(conn.poll_event().is_none());
    assert!(send(&mut conn).is_empty());
    assert_eq!(conn.unanswered, 0);
    assert_eq!(conn.streams.len(), 0);
}

#[test]
fn early_response_reset_survives_packing_and_loss() {
    let mut conn = client();
    let (id, _) = conn.send_oneshot(&[b'x'; 4000]).unwrap();
    let original = send(&mut conn);
    let sent = conn.data_sent;
    assert!(sent > 0 && sent < 4000);
    answer(&mut conn, id);
    let reset = send(&mut conn);
    assert_eq!(
        reset,
        vec![SentFrame::ResetStream {
            id,
            error: 0x10c,
            final_size: sent
        }]
    );
    complete_higher(&mut conn, 1000);
    assert!(conn.streams.capacity() <= 128);
    assert!(conn.stream_mut(id).is_some());
    conn.on_frame_lost(Space::Data, reset[0]);
    assert_eq!(send(&mut conn), reset);
    conn.on_frame_acked(original[0]);
    assert!(
        conn.stream_mut(id).is_some(),
        "body ACK cannot settle the reset"
    );
    conn.on_frame_acked(reset[0]);
    conn.on_frame_lost(Space::Data, original[0]);
    assert!(conn.stream_mut(id).is_none());
    assert!(send(&mut conn).is_empty());
    assert_eq!(conn.unanswered, 0);
}

#[test]
fn packed_streams_preserve_receive_credit_events_and_peer_id_checks() {
    let mut conn = client();
    let (id, _) = conn.send_oneshot(b"request").unwrap();
    for frame in send(&mut conn) {
        conn.on_frame_acked(frame);
    }
    complete_higher(&mut conn, 1000);
    assert!(conn.streams.capacity() <= 128);
    conn.stream_window = 8;
    conn.stream_mut(id).unwrap().recv = RecvStream::new(8);
    conn.on_stream(id, 4, b"efgh", false).unwrap();
    assert!(conn.poll_event().is_none());
    conn.on_stream(id, 0, b"abcd", false).unwrap();
    assert_eq!(conn.poll_event(), Some(Event::Readable(id)));
    assert_eq!(
        conn.consume(id, |data| {
            assert_eq!(data, b"abcdefgh");
            Ok(())
        })
        .unwrap(),
        8
    );
    let credit = send(&mut conn);
    assert_eq!(credit, vec![SentFrame::MaxStreamData { id, limit: 16 }]);
    conn.on_frame_lost(Space::Data, credit[0]);
    assert_eq!(send(&mut conn), credit);
    conn.on_stream(id, 4, b"efgh", false).unwrap();
    assert!(conn.poll_event().is_none());
    conn.on_reset(id, 0x10c, 8).unwrap();
    assert_eq!(
        conn.poll_event(),
        Some(Event::Finished {
            id,
            reset: Some(0x10c)
        })
    );
    conn.on_reset(id, 0x10c, 8).unwrap();
    assert!(conn.poll_event().is_none());
    conn.retire(id, 0x10c);
    assert_eq!(conn.unanswered, 0);
    assert_eq!(conn.data_received, 5008);
    assert!(conn.on_stream(conn.next_bidi * 4, 0, b"x", true).is_err());
    assert!(conn.on_stream(2, 0, b"x", true).is_err());
    // Every completed higher stream remains retired, even after its slot is gone.
    conn.on_stream(4000, 0, b"reply", true).unwrap();
    assert!(conn.poll_event().is_none());
    assert_eq!(conn.data_received, 5008);
}
