//! Receive-window regressions: offsets, rather than buffered byte counts, spend credit.
use super::*;

fn fixture(stream_window: u64, connection_window: u64) -> (Connection, u64) {
    let mut conn = client();
    conn.stream_window = stream_window;
    conn.max_data_local = connection_window;
    conn.max_data_window = connection_window;
    conn.max_streams_bidi = 16;
    let id = conn.open_bi().unwrap();
    conn.events.clear();
    (conn, id)
}

#[test]
fn reset_final_size_consumes_connection_credit_once() {
    let (mut conn, id) = fixture(16, 16);
    conn.on_stream(id, 2, b"cd", false).unwrap();
    assert_eq!(conn.data_received, 4);
    conn.on_reset(id, 42, 8).unwrap();
    assert_eq!(conn.data_received, 8);
    conn.on_reset(id, 42, 8).unwrap();
    assert_eq!(conn.data_received, 8);
    assert_eq!(conn.unanswered, 0);
    assert_eq!(
        conn.events
            .iter()
            .filter(|ev| matches!(ev, Event::Finished { .. }))
            .count(),
        1
    );
}

#[test]
fn stream_window_rejects_before_buffering_or_finishing() {
    let (mut conn, id) = fixture(8, 16);
    assert!(conn.on_stream(id, 0, b"123456789", true).is_err());
    assert_eq!(conn.data_received, 0);
    assert_eq!(conn.unanswered, 1);
    assert!(conn.events.is_empty());
    assert!(!conn.recv_mut(id).unwrap().has_data());
    assert!(!conn.recv_mut(id).unwrap().size_known());
}

#[test]
fn connection_window_rejects_before_buffering_or_finishing() {
    let (mut conn, id) = fixture(16, 8);
    assert!(conn.on_stream(id, 0, b"123456789", true).is_err());
    assert_eq!(conn.data_received, 0);
    assert_eq!(conn.unanswered, 1);
    assert!(conn.events.is_empty());
    assert!(!conn.recv_mut(id).unwrap().has_data());
    assert!(!conn.recv_mut(id).unwrap().size_known());
}

#[test]
fn reset_limits_reject_without_charging_or_completing_a_request() {
    for (stream, connection) in [(8, 16), (16, 8)] {
        let (mut conn, id) = fixture(stream, connection);
        let error = conn.on_reset(id, 42, 9).unwrap_err();
        assert_eq!(
            error.downcast_ref::<RecvError>(),
            Some(&RecvError::FlowControl)
        );
        assert_eq!(conn.data_received, 0);
        assert_eq!(conn.unanswered, 1);
        assert!(conn.events.is_empty());
        assert!(!conn.recv_mut(id).unwrap().size_known());
    }
}

#[test]
fn peer_uni_reset_before_data_consumes_credit_and_rejects_before_registration() {
    let (mut conn, id) = fixture(8, 12);
    conn.on_reset(3, 42, 8).unwrap();
    assert_eq!(conn.data_received, 8);
    assert_eq!(conn.peer_uni.len(), 1);
    assert_eq!(conn.events.pop_front(), Some(Event::Opened(3)));
    conn.on_reset(3, 42, 8).unwrap();
    conn.on_stream(3, 4, b"efgh", true).unwrap();
    assert_eq!(conn.data_received, 8);
    conn.on_stream(id, 0, b"abcd", true).unwrap();
    assert_eq!(conn.data_received, 12);
    conn.events.clear();
    assert!(conn.on_reset(7, 42, 1).is_err());
    assert!(conn.on_stream(7, 0, b"x", true).is_err());
    assert_eq!(conn.peer_uni.len(), 1);
    assert_eq!(conn.data_received, 12);
    assert!(conn.events.is_empty());
}

#[test]
fn mixed_streams_resets_and_gap_filling_spend_only_new_offsets() {
    let (mut conn, a) = fixture(8, 12);
    let b = conn.open_bi().unwrap();
    conn.on_stream(a, 4, b"ef", false).unwrap();
    conn.on_stream(b, 0, b"ab", false).unwrap();
    assert_eq!(conn.data_received, 8);
    conn.on_reset(a, 42, 8).unwrap();
    conn.on_stream(a, 0, b"abcdefgh", true).unwrap();
    assert_eq!(conn.data_received, 10);
    conn.on_stream(b, 2, b"cd", true).unwrap();
    assert_eq!(conn.data_received, 12);
    conn.on_reset(b, 42, 4).unwrap();
    assert_eq!(conn.data_received, 12);
    assert_eq!(conn.unanswered, 0);
    assert_eq!(
        conn.events
            .iter()
            .filter(|ev| matches!(ev, Event::Finished { .. }))
            .count(),
        2
    );
}

#[test]
fn connection_grant_is_effective_only_when_it_fits_in_a_packet() {
    let (mut conn, id) = fixture(32, 8);
    conn.on_stream(id, 0, b"abcd", false).unwrap();
    let mut out = Vec::new();
    let mut frames = Vec::new();
    conn.fill_data_payload(&mut out, 0, 0, &mut frames, true)
        .unwrap();
    assert_eq!(conn.max_data_local, 8);
    assert!(out.is_empty());
    assert!(conn.on_stream(id, 4, b"efghi", false).is_err());
    conn.fill_data_payload(&mut out, 1200, 0, &mut frames, true)
        .unwrap();
    assert_eq!(frames, vec![SentFrame::MaxData(12)]);
    conn.on_stream(id, 4, b"efghijkl", true).unwrap();
    assert_eq!(conn.data_received, 12);
    conn.on_frame_lost(Space::Data, SentFrame::MaxData(12));
    out.clear();
    frames.clear();
    conn.fill_data_payload(&mut out, 1200, 0, &mut frames, true)
        .unwrap();
    assert_eq!(frames, vec![SentFrame::MaxData(20)]);
    assert_eq!(conn.max_data_local, 20);
}

#[test]
fn receive_limits_reset_retirement_does_not_charge_recycled_buffers_twice() {
    let (mut conn, id) = fixture(8, 16);
    conn.on_reset(id, 42, 8).unwrap();
    conn.retire(id, 42);
    conn.on_frame_acked(SentFrame::ResetStream {
        id,
        error: 42,
        final_size: 0,
    });
    assert!(conn.stream_mut(id).is_none());
    conn.on_reset(id, 42, 8).unwrap();
    conn.on_stream(id, 0, b"abcdefgh", true).unwrap();
    assert_eq!(conn.data_received, 8);
    let next = conn.open_bi().unwrap();
    conn.on_stream(next, 0, b"abcdefgh", true).unwrap();
    assert_eq!(conn.data_received, 16);
}
