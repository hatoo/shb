//! Flow-control updates must reach both kinds of locally opened send stream.
use super::*;

mod wire;

fn fixture(limit: u64) -> Connection {
    let mut conn = client();
    conn.params.initial_max_streams_uni = 3;
    conn.params.initial_max_stream_data_uni = limit;
    conn.params.initial_max_stream_data_bidi_remote = limit;
    conn.max_streams_bidi = 3;
    conn.max_data_peer = 100;
    conn
}

fn grant(conn: &mut Connection, id: u64, limit: u64) {
    conn.handle_frame(
        Space::Data,
        Frame::MaxStreamData { id, limit },
        Instant::now(),
    )
    .unwrap();
}

fn flush(conn: &mut Connection, expected: &[(u64, u64, &[u8], bool)]) -> Vec<SentFrame> {
    let mut out = Vec::new();
    let mut frames = Vec::new();
    conn.fill_data_payload(&mut out, 1200, 0, &mut frames, false)
        .unwrap();
    let wire: Vec<_> = frame::Iter::new(&out).map(Result::unwrap).collect();
    let expected: Vec<_> = expected
        .iter()
        .map(|&(id, offset, data, fin)| Frame::Stream {
            id,
            offset,
            data,
            fin,
        })
        .collect();
    assert_eq!(wire, expected);
    frames
}

#[test]
fn max_stream_data_resumes_local_uni_writes() {
    let mut conn = fixture(2);
    let id = conn.open_uni().unwrap();
    assert_eq!(conn.write(id, b"abcdef"), 2);
    assert_eq!(conn.write(id, b"cdef"), 0);
    grant(&mut conn, id, 6);
    assert_eq!(conn.write(id, b"cdef"), 4);
    conn.finish(id);
    flush(&mut conn, &[(id, 0, b"abcdef", true)]);
    assert_eq!(conn.data_sent, 6);
}

#[test]
fn stream_grants_are_monotone_and_only_update_the_named_send_half() {
    let mut conn = fixture(0);
    let mut ids = Vec::new();
    for _ in 0..3 {
        ids.push(conn.open_bi().unwrap());
        ids.push(conn.open_uni().unwrap());
    }
    for &id in &ids {
        assert_eq!(conn.write(id, b"abc"), 0);
    }
    for (i, &id) in ids.iter().enumerate() {
        grant(&mut conn, id, 3);
        grant(&mut conn, id, 1);
        grant(&mut conn, id, 3);
        assert_eq!(conn.write(id, b"abc-extra"), 3);
        assert_eq!(conn.write(id, b"extra"), 0);
        for &other in &ids[i + 1..] {
            assert_eq!(conn.write(other, b"abc"), 0, "grant leaked to {other}");
        }
    }
}

#[test]
fn uni_grants_use_absolute_offsets_after_acknowledged_prefixes() {
    let mut conn = fixture(2);
    let id = conn.open_uni().unwrap();
    assert_eq!(conn.write(id, b"ab"), 2);
    let frames = flush(&mut conn, &[(id, 0, b"ab", false)]);
    conn.on_frame_acked(frames[0]);
    grant(&mut conn, id, 2);
    assert_eq!(
        conn.write(id, b"cdef"),
        0,
        "ACKs do not renew stream credit"
    );
    grant(&mut conn, id, 6);
    grant(&mut conn, id, 4);
    assert_eq!(conn.write(id, b"cdef-extra"), 4);
    conn.finish(id);
    let frames = flush(&mut conn, &[(id, 2, b"cdef", true)]);
    conn.on_frame_acked(frames[0]);
    assert!(conn.send_mut(id).unwrap().is_settled());
    assert_eq!(conn.data_sent, 6);
}

#[test]
fn uni_stream_grant_preserves_connection_credit_and_late_ack_cancellation() {
    let mut conn = fixture(2);
    conn.max_data_peer = 2;
    let id = conn.open_uni().unwrap();
    assert_eq!(conn.write(id, b"ab"), 2);
    let original = flush(&mut conn, &[(id, 0, b"ab", false)])[0];
    grant(&mut conn, id, 6);
    assert_eq!(conn.write(id, b"cdef"), 4);
    conn.finish(id);
    flush(&mut conn, &[]);
    conn.on_frame_lost(Space::Data, original);
    flush(&mut conn, &[(id, 0, b"ab", false)]);
    assert_eq!(conn.data_sent, 2, "retry consumes no new connection credit");
    conn.on_frame_lost(Space::Data, original);
    conn.on_frame_acked(original);
    flush(&mut conn, &[]);
    conn.handle_frame(Space::Data, Frame::MaxData(6), Instant::now())
        .unwrap();
    flush(&mut conn, &[(id, 2, b"cdef", true)]);
    assert_eq!(conn.data_sent, 6);
}

#[test]
fn uni_stream_grant_after_stop_sending_cannot_resume_data_or_fin() {
    let mut conn = fixture(2);
    let id = conn.open_uni().unwrap();
    assert_eq!(conn.write(id, b"ab"), 2);
    let original = flush(&mut conn, &[(id, 0, b"ab", false)])[0];
    grant(&mut conn, id, 6);
    assert_eq!(conn.write(id, b"cdef"), 4);
    conn.on_stop_sending(id, 42);
    grant(&mut conn, id, 100);
    assert_eq!(conn.write(id, b"extra"), 0);
    conn.finish(id);
    conn.on_frame_lost(Space::Data, original);
    let mut out = Vec::new();
    let mut frames = Vec::new();
    conn.fill_data_payload(&mut out, 1200, 0, &mut frames, false)
        .unwrap();
    assert_eq!(
        frames,
        [SentFrame::ResetStream {
            id,
            error: 42,
            final_size: 2,
        }]
    );
    assert_eq!(conn.data_sent, 2);
    conn.on_frame_acked(frames[0]);
    assert!(conn.send_mut(id).unwrap().is_settled());
    flush(&mut conn, &[]);
}
